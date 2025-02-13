/*
 * lldp_neighbor.c
 *
 *  Created on: Oct 31, 2016
 *      Author: zhurish
 */

#include <zebra.h>
#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "sockopt.h"
#include "zclient.h"


#include "lldpd.h"
#include "lldp_interface.h"
#include "lldp_neighbor.h"
#include "lldp_db.h"
#include "lldp_packet.h"
#include "lldp_socket.h"


static struct lldp_neighbor *tlv_ndb = NULL;
static int lldp_neighbor_time(struct thread *thread);


struct tlv_db *lldp_neighbor_new(struct tlv_db_id *id)
{
	struct tlv_db *db;
	if (tlv_ndb == NULL || tlv_ndb->tlv_neighbor_list == NULL)
		return NULL;
	db = XMALLOC(MTYPE_LLDP_NEIGHBOR, sizeof(struct tlv_db));
	if (db == NULL)
		return NULL;

	memset(db, 0, sizeof(struct tlv_db));
	memcpy(&db->id, id, sizeof(struct tlv_db_id));

	//db->unknown_list = list_new ();
	db->org_list = list_new();

	listnode_add(tlv_ndb->tlv_neighbor_list, db);
	if (tlv_ndb->t_ckeck_time == NULL)
		tlv_ndb->t_ckeck_time = thread_add_timer(master, lldp_neighbor_time, NULL,
							 tlv_ndb->lldp_db_interval);
	return db;
}

int lldp_neighbor_free(struct tlv_db *db)
{
	if (tlv_ndb == NULL || tlv_ndb->tlv_neighbor_list == NULL)
		return -1;
	if (db == NULL)
		return 0;
	listnode_delete(tlv_ndb->tlv_neighbor_list, db);
	if (db->system_name)
		XFREE(MTYPE_LLDP_SYSTEM, db->system_name); /* 系统名称 */
	if (db->system_desc)
		XFREE(MTYPE_LLDP_SYSTEM, db->system_desc); /* 系统描述 */
	if (db->port_desc)
		XFREE(MTYPE_LLDP_PORT_DESC, db->port_desc); /* 系统描述 */

	if (db->capability)
		XFREE(MTYPE_LLDP_SYSTEM, db->capability); /* 系统性能 */

	if (db->mgt_address)
		XFREE(MTYPE_LLDP_SYSTEM, db->mgt_address); /* 管理地址 */
	//if(db->unknown_list)
	//	list_delete_all_node (db->unknown_list);
	if (db->org_list)
		list_delete_all_node(db->org_list);
	XFREE(MTYPE_LLDP_NEIGHBOR, db);

	if (listcount(tlv_ndb->tlv_neighbor_list) == 0) {
		if (tlv_ndb->t_ckeck_time)
			thread_cancel(tlv_ndb->t_ckeck_time);
		tlv_ndb->t_ckeck_time = NULL;
	}
	return 0;
}

struct tlv_db *lldp_neighbor_lookup(struct tlv_db_id *id)
{
	struct listnode *node;
	struct tlv_db *db;
	if (tlv_ndb == NULL || tlv_ndb->tlv_neighbor_list == NULL)
		return NULL;
	for (ALL_LIST_ELEMENTS_RO(tlv_ndb->tlv_neighbor_list, node, db)) {
		if (db) {
			if (db->id.chassis_type == id->chassis_type &&
			    db->id.chassis_len == id->chassis_len &&
			    db->id.port_id_type == id->port_id_type &&
			    db->id.port_id_len == id->port_id_len) {
				if ((memcmp(db->id.chassis_value, id->chassis_value,
					    db->id.chassis_len) == 0) &&
				    (memcmp(db->id.port_id_value, id->port_id_value,
					    db->id.port_id_len) == 0))
					return db;
			}
		}
	}
	return NULL;
}

struct tlv_db *lldp_neighbor_get(struct tlv_db_id *id)
{
	struct tlv_db *db = NULL;
	if (tlv_ndb == NULL || tlv_ndb->tlv_neighbor_list == NULL)
		return NULL;
	db = lldp_neighbor_lookup(id);
	if (db == NULL)
		return lldp_neighbor_new(id);
}

/*
static struct tlv_db * lldp_neighbor_update (struct tlv_db *db, char *buf)
{
	return db;
}
*/
static int lldp_neighbor_time(struct thread *thread)
{
	struct listnode *node;
	struct tlv_db *db;
	if (tlv_ndb == NULL || tlv_ndb->tlv_neighbor_list == NULL)
		return -1;
	//t_ckeck_time
	for (ALL_LIST_ELEMENTS_RO(tlv_ndb->tlv_neighbor_list, node, db)) {
		if (db) {
			if (db->time_interval)
				db->time_interval -= TLV_DB_CHECK_TIME;
			else {
				lldp_neighbor_free(db);
			}
		}
	}
	tlv_ndb->t_ckeck_time = thread_add_timer(master, lldp_neighbor_time, NULL,
						 tlv_ndb->lldp_db_interval);
	return 0;
}

int lldp_local_db_init(void)
{
	int len = 0;
	int change = 0;
	char *system_name = NULL;
	struct tlv_sub_head head;
	struct mgt_address mgt_address;
	struct system_capability capability;
	if (tlv_ndb && tlv_ndb->tlv_local) {
		system_name = lldp_ststem_name();
		if (tlv_ndb->tlv_local->db_init == 0) {
			if (system_name)
				tlv_ndb->tlv_local->system_name = XSTRDUP(MTYPE_LLDP_SYSTEM,
									  system_name);
			if (lldp_ststem_description())
				tlv_ndb->tlv_local->system_desc =
					XSTRDUP(MTYPE_LLDP_SYSTEM, lldp_ststem_description());

			len = lldp_chassis_id(&head);
			if (len) {
				tlv_ndb->tlv_local->chassis_type = head.subtype;
				tlv_ndb->tlv_local->chassis_len = len;
				memcpy(tlv_ndb->tlv_local->chassis_value, head.value, len);
			}
			len = lldp_system_caability(&capability);
			if (len) {
				tlv_ndb->tlv_local->capability =
					XMALLOC(MTYPE_LLDP_SYSTEM, sizeof(struct system_capability));
				if (tlv_ndb->tlv_local->capability)
					memcpy(tlv_ndb->tlv_local->capability, &capability, len);
			}
			len = lldp_ststem_mgt_address(&mgt_address);
			if (len) {
				tlv_ndb->tlv_local->mgt_address =
					XMALLOC(MTYPE_LLDP_SYSTEM, sizeof(struct mgt_address));
				if (tlv_ndb->tlv_local->mgt_address)
					memcpy(tlv_ndb->tlv_local->mgt_address, &mgt_address,
					       sizeof(struct mgt_address));
			}
			//unsigned char chassis_type;  /* 子TLV 类型*/
			//unsigned int chassis_len;  /* 数据长度 */
			//unsigned char chassis_value[LLDP_SUB_TLV_STR_MAX_LEN];  /* 数据*/
			//struct system_capability *capability;  /* 系统性能 */
			//struct mgt_address *mgt_address;  /* 管理地址 */

			tlv_ndb->tlv_local->db_init = 1;
			change = 0;
		} else {
			if (tlv_ndb->tlv_local->system_name && system_name &&
			    (strcmp(tlv_ndb->tlv_local->system_name, system_name) != 0)) {
				XFREE(MTYPE_LLDP_SYSTEM, tlv_ndb->tlv_local->system_name);
				tlv_ndb->tlv_local->system_name = XSTRDUP(MTYPE_LLDP_SYSTEM,
									  system_name);
				change = 1;
			}
			if (tlv_ndb->tlv_local->system_desc && lldp_ststem_description() &&
			    (strcmp(tlv_ndb->tlv_local->system_desc, lldp_ststem_description()) !=
			     0)) {
				XFREE(MTYPE_LLDP_SYSTEM, tlv_ndb->tlv_local->system_desc);
				tlv_ndb->tlv_local->system_desc =
					XSTRDUP(MTYPE_LLDP_SYSTEM, lldp_ststem_description());
				change = 1;
			}
			len = lldp_chassis_id(&head);
			if (len) {
				if ((tlv_ndb->tlv_local->chassis_type != head.subtype) ||
				    (tlv_ndb->tlv_local->chassis_len != len) ||
				    (memcmp(tlv_ndb->tlv_local->chassis_value, head.value, len) !=
				     0)) {
					tlv_ndb->tlv_local->chassis_type = head.subtype;
					tlv_ndb->tlv_local->chassis_len = len;
					memcpy(tlv_ndb->tlv_local->chassis_value, head.value, len);
					change = 1;
				}
			} else {
				tlv_ndb->tlv_local->chassis_type = 0;
				tlv_ndb->tlv_local->chassis_len = 0;
				memset(tlv_ndb->tlv_local->chassis_value, 0,
				       LLDP_SUB_TLV_STR_MAX_LEN);
				change = 1;
			}
			if (tlv_ndb->tlv_local->capability) {
				len = lldp_system_caability(&capability);
				if (len) {
					if (memcmp(tlv_ndb->tlv_local->capability, &capability,
						   len) != 0) {
						memcpy(tlv_ndb->tlv_local->capability, &capability,
						       len);
						change = 1;
					}
				} else {
					XFREE(MTYPE_LLDP_SYSTEM, tlv_ndb->tlv_local->capability);
					tlv_ndb->tlv_local->capability = NULL;
					change = 1;
				}
			}
			if (tlv_ndb->tlv_local->mgt_address) {
				len = lldp_ststem_mgt_address(&mgt_address);
				if (len) {
					if (memcmp(tlv_ndb->tlv_local->mgt_address, &mgt_address,
						   sizeof(struct mgt_address)) != 0) {
						memcpy(tlv_ndb->tlv_local->mgt_address,
						       &mgt_address, sizeof(struct mgt_address));
						change = 1;
					}
				} else {
					XFREE(MTYPE_LLDP_SYSTEM, tlv_ndb->tlv_local->mgt_address);
					tlv_ndb->tlv_local->mgt_address = NULL;
					change = 1;
				}
			}
		}
	}
	return change;
}

static int show_lldp_neighbor_db(struct tlv_db *db, struct vty *vty, int detail)
{
	struct interface *ifp;
	struct lldp_interface *lifp;
	ifp = if_lookup_by_index(db->ifindex);
	if (ifp == NULL)
		return CMD_SUCCESS;
	lifp = ifp->info;
	if (lifp == NULL)
		return CMD_SUCCESS;
	/*
	 * Neighbor Disccovery Protocol is enabled.
	 * Neighbor Disccovery Protocol Ver:1, Hello Timer: 60(s),Aging Timer:180(s).
	 * Interface :eth0
	 *   Status: Enabled, Pkts Send:44, Okts Rvd:55,Pkts Err:0
	 *   Neighbor:
	 *      Aging Timer :11(s)
	 *      MAC Address:00:00:00:00:00:00
	 *      Port Name	:eth-0-1
	 *      Software Ver: V0.0.0.2
	 *      Device Name:route
	 *      Port Duplex:Auto
	 *      Product Ver:333-11
	 *
	 *      chassis id type :mac address
	 *      chassis id :00:00:00:00:00:00
	 *      port id type :Interface name
	 *      port id :eth-0-1
	 *      ttl:160
	 *      aging:44
	 */
	vty_out(vty, " Interface: %s%s", ifp->name, VTY_NEWLINE);
	vty_out(vty, "  Status: %s, Pkts Send:%d, Okts Rvd:%d,Pkts Err:%d%s",
		lifp->mode ? "enable" : "disable", lifp->sen_pkts, lifp->rcv_pkts, lifp->err_pkts,
		VTY_NEWLINE);
	vty_out(vty, "  Neighbor:%s", VTY_NEWLINE);
	vty_out(vty, "    Aging Timer: %d(s)/%d(s)%s", db->time_interval, db->holdtime, VTY_NEWLINE);
	if (db->system_name)
		vty_out(vty, "    System Name: %s%s", db->system_name, VTY_NEWLINE);
	if (detail && db->system_desc)
		vty_out(vty, "    System Desc: %s%s", db->system_desc, VTY_NEWLINE);
	if (db->id.chassis_type == LLDP_SUB_MAC_ADDR_ID) {
		unsigned char mac[64];
		memset(mac, 0, sizeof(mac));
		sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", db->id.chassis_value[0],
			db->id.chassis_value[1], db->id.chassis_value[2], db->id.chassis_value[3],
			db->id.chassis_value[4], db->id.chassis_value[5]);
		vty_out(vty, "    Chassis ID Type: MAC Address%s", VTY_NEWLINE);
		vty_out(vty, "    Chassis ID: %s%s", mac, VTY_NEWLINE);

	} else //if(db->id.chassis_type == LLDP_SUB_MAC_ADDR_ID)
	{
		//vty_out (vty, "    MAC Address: %s%s", mac,VTY_NEWLINE);
		vty_out(vty, "    Chassis ID: %s%s", db->id.chassis_value, VTY_NEWLINE);
	}
	if (db->id.chassis_type == LLDP_SUB_PORT_MAC_ADDR_ID) {
		unsigned char mac[64];
		memset(mac, 0, sizeof(mac));
		sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", db->id.chassis_value[0],
			db->id.chassis_value[1], db->id.chassis_value[2], db->id.chassis_value[3],
			db->id.chassis_value[4], db->id.chassis_value[5]);
		vty_out(vty, "    Port ID Type: MAC Address%s", VTY_NEWLINE);
		vty_out(vty, "    Port ID: %s%s", mac, VTY_NEWLINE);
		if (detail && db->port_desc)
			vty_out(vty, "    Port Desc: %s%s", db->port_desc, VTY_NEWLINE);
	} else {
		vty_out(vty, "    Port ID: %s%s", db->id.port_id_value, VTY_NEWLINE);
		if (detail && db->port_desc)
			vty_out(vty, "    Port Desc: %s%s", db->port_desc, VTY_NEWLINE);
	}
	if (detail) {
		if (db->capability)
			vty_out(vty, "    System Capability: 0x%x(Enabled) 0x%x(Supported)%s",
				db->capability->CapEnabled, db->capability->CapSupported,
				VTY_NEWLINE);
		/* 管理地址 */
		if (db->mgt_address && db->mgt_address->subtype == LLDP_SUB_PORT_MAC_ADDR_ID &&
		    db->mgt_address->addr_len) {
			unsigned char mac[64];
			memset(mac, 0, sizeof(mac));
			sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", db->mgt_address->value[0],
				db->mgt_address->value[1], db->mgt_address->value[2],
				db->mgt_address->value[3], db->mgt_address->value[4],
				db->mgt_address->value[5]);
			vty_out(vty, "    Management Address Type: MAC Address%s", VTY_NEWLINE);
			vty_out(vty, "    Management Address: %s%s", mac, VTY_NEWLINE);
		} else if (db->mgt_address && db->mgt_address->addr_len) {
			vty_out(vty, "    Management Address: %s%s", db->mgt_address->value,
				VTY_NEWLINE);
		}
		if (db->mgt_address && db->mgt_address->oidlen) {
			int i = 0;
			vty_out(vty, "    Management OID: ");
			for (i = 0; i < db->mgt_address->oidlen; i++) {
				vty_out(vty, "%d", db->mgt_address->oid[i]);
				if ((i + 1) < db->mgt_address->oidlen)
					vty_out(vty, ".");
			}
			vty_out(vty, "%s", VTY_NEWLINE);
		}
		//struct list *org_list;
	}
	return CMD_SUCCESS;
}


DEFUN (show_lldp_neighbor,
		show_lldp_neighbor_cmd,
	    "show lldp neighbor",
		SHOW_STR
		LLDP_STR
		"lldpd neighbor information\n")
{
	struct listnode *node = NULL;
	struct tlv_db *db = NULL;
	if (lldpd_config == NULL)
		return CMD_SUCCESS;

	vty_out(vty, "Neighbor Disccovery Protocol is %s.%s",
		lldpd_config->lldp_enable ? "enabled" : "disabled", VTY_NEWLINE);
	vty_out(vty, "Neighbor Disccovery Protocol Ver:1, check Timer:180(s).",
		lldpd_config->version, lldpd_config->t_ckeck_time, VTY_NEWLINE);

	if (tlv_ndb == NULL || tlv_ndb->tlv_neighbor_list == NULL)
		return CMD_SUCCESS;

	for (ALL_LIST_ELEMENTS_RO(tlv_ndb->tlv_neighbor_list, node, db)) {
		show_lldp_neighbor_db(db, vty, 0);
	}
	return CMD_SUCCESS;
}
DEFUN (show_lldp_neighbor_detail,
		show_lldp_neighbor_detail_cmd,
	    "show lldp neighbor detail",
		SHOW_STR
		LLDP_STR
		"lldpd neighbor information\n"
		"lldpd neighbor detail information\n")
{
	struct listnode *node = NULL;
	struct tlv_db *db = NULL;
	if (lldpd_config == NULL)
		return CMD_SUCCESS;

	vty_out(vty, "Neighbor Disccovery Protocol is %s.%s",
		lldpd_config->lldp_enable ? "enabled" : "disabled", VTY_NEWLINE);
	vty_out(vty, "Neighbor Disccovery Protocol Ver:1, check Timer:180(s).",
		lldpd_config->version, lldpd_config->t_ckeck_time, VTY_NEWLINE);

	if (tlv_ndb == NULL || tlv_ndb->tlv_neighbor_list == NULL)
		return CMD_SUCCESS;

	for (ALL_LIST_ELEMENTS_RO(tlv_ndb->tlv_neighbor_list, node, db)) {
		show_lldp_neighbor_db(db, vty, 1);
	}
	return CMD_SUCCESS;
}
int lldp_neighbor_init(void)
{
	tlv_ndb = XMALLOC(MTYPE_LLDP_NEIGHBOR, sizeof(struct lldp_neighbor));
	if (tlv_ndb) {
		tlv_ndb->tlv_local = XMALLOC(MTYPE_LLDP_NEIGHBOR, sizeof(struct tlv_local_db));
		tlv_ndb->tlv_neighbor_list = list_new();
		tlv_ndb->t_ckeck_time = NULL;
	}
	install_element(VIEW_NODE, &show_lldp_neighbor_cmd);
	install_element(ENABLE_NODE, &show_lldp_neighbor_cmd);
	return 0;
}
