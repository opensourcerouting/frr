/*
 * lldp_read.c
 *
 *  Created on: Oct 25, 2016
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

#include <linux/if_ether.h>


struct vlan_hdr {
	unsigned int vlan_pri : 3;  /*  */
	unsigned int vlan_cfi : 1;  /*  */
	unsigned int vlan_vid : 12; /*  */
};
static int lldp_tlv_org_free(struct tlv_db_head *head)
{
	XFREE(MTYPE_LLDP_ORG, head->value);
	return 0;
}
static struct tlv_db_head *lldp_tlv_org_lookup(struct tlv_db *db, int orgtype, int subtype)
{
	struct listnode *node;
	struct tlv_db_head *org;
	if (db->org_list == NULL || db->org_list == NULL)
		return NULL;
	if (db->org_list)
		db->org_list->del = lldp_tlv_org_free;
	for (ALL_LIST_ELEMENTS_RO(db->org_list, node, org)) {
		if (org) {
			if (org->type == orgtype && org->subtype == subtype) {
				return org;
			}
		}
	}
	return NULL;
}
static int lldp_tlv_org_process(struct tlv_db *db, struct lldp_interface *lifp, char *ibuf, int len,
				int type)
{
	int orgtype = 0;
	struct tlv_db_head *head = NULL;
	unsigned char id_8021[3] = { 0x00, 0x80, 0xc2 };
	unsigned char id_8023[3] = { 0x00, 0x12, 0x0f };
	unsigned char id_tia[3] = { 0x00, 0x12, 0xBB };
	unsigned char *subtype = (unsigned char *)(ibuf + 3);

	if (memcmp(id_8021, ibuf, sizeof(id_8021)) == 0)
		orgtype = LLDP_8021_ORG;
	else if (memcmp(id_8023, ibuf, sizeof(id_8023)) == 0)
		orgtype = LLDP_8023_ORG;
	else if (memcmp(id_tia, ibuf, sizeof(id_tia)) == 0)
		orgtype = LLDP_TIA_TR41;

	switch (orgtype) {
	case LLDP_8021_ORG:
	case LLDP_8023_ORG:
		head = lldp_tlv_org_lookup(db, orgtype, *subtype);
		if (head) {
			//head->type = orgtype;
			//head->subtype = *subtype;
			if (head->value)
				XFREE(MTYPE_LLDP_ORG, head->value);
			head->value = XMALLOC(MTYPE_LLDP_ORG, len - 4);
			memcpy(head->value, ibuf + 3, len - 4);
			//listnode_add (db->org_list, head);
			LLDP_DEBUG_LOG("get neighbor and update IEEE 802.1 / 802.3(%d)", orgtype);
		} else {
			head = XMALLOC(MTYPE_LLDP_ORG, sizeof(struct tlv_db_head));
			head->type = orgtype;
			head->subtype = *subtype;
			head->value = XMALLOC(MTYPE_LLDP_ORG, len - 4);
			memcpy(head->value, ibuf + 3, len - 4);
			listnode_add(db->org_list, head);
			LLDP_DEBUG_LOG("get neighbor and add IEEE 802.1 / 802.3(%d)", orgtype);
		}
		break;
	default:
		LLDP_DEBUG_LOG("get neighbor unknown TLV (%d)", orgtype);
		db->unknown_count++;
		break;
	}
	return 0;
}
static int lldp_tlv_process(struct tlv_db **db, struct lldp_interface *lifp, char *ibuf, int len,
			    int type)
{
	static int db_id = 0;
	static struct tlv_db_id id;
	struct tlv_db *ndb = *db;
	struct tlv_sub_head *head = (struct tlv_sub_head *)ibuf;
	//unsigned char *subtype = (unsigned char *)(ibuf + 3);
	if (db_id == 0) {
		db_id = 1;
		memset(&id, 0, sizeof(id));
	}
	switch (type) {
	case LDDP_END: /* End Of LLDPPDU */
		db_id = 0;
		if (ndb) {
			ndb->time_interval = TLV_DB_CHECK_TIME;
			ndb->ifindex = lifp->ifp->ifindex;
		}
		break;
	case LLDP_CHASSIS_ID: /* Chassis ID */
		id.chassis_len = len;
		id.chassis_type = head->subtype;
		memcpy(id.chassis_value, head->value, id.chassis_len);
		LLDP_DEBUG_LOG("get chassis type:%d len:%d value:%s ", id.chassis_type,
			       id.chassis_len, id.chassis_value);
		break;
	case LLDP_PORT_ID: /* Port ID */
		id.port_id_len = len;
		id.port_id_type = head->subtype;
		memcpy(id.port_id_value, head->value, id.chassis_len);
		LLDP_DEBUG_LOG("get port id type:%d len:%d value:%s ", id.port_id_type,
			       id.port_id_len, id.chassis_value);
		break;
	case LLDP_TTL_ID: /* Time To Live */
		if (ndb) {
			ndb->holdtime = ntohs((unsigned short)ibuf);
			LLDP_DEBUG_LOG("get lldp db hold time:%d", ndb->holdtime);
		}
		break;
	case LLDP_PORT_DESC_ID: /* Port Description */
		if (ndb) {
			if (ndb->port_desc)
				XFREE(MTYPE_LLDP_PORT_DESC, ndb->port_desc);
			ndb->port_desc = XMALLOC(MTYPE_LLDP_PORT_DESC, len + 1);
			memset(ndb->port_desc, 0, len + 1);
			memcpy(ndb->port_desc, ibuf, len);
			LLDP_DEBUG_LOG("get port desc:%s", ndb->port_desc);
		}
		break;
	case LLDP_SYSTEM_NAME_ID: /* System Name */
		if (ndb) {
			if (ndb->system_name)
				XFREE(MTYPE_LLDP_SYSTEM, ndb->system_name);
			ndb->system_name = XMALLOC(MTYPE_LLDP_SYSTEM, len + 1);
			memset(ndb->system_name, 0, len + 1);
			memcpy(ndb->system_name, ibuf, len);
			LLDP_DEBUG_LOG("get neighbor system name:%s", ndb->system_name);
		}
		break;
	case LLDP_SYSTEM_DESC_ID: /* System Description */
		if (ndb) {
			if (ndb->system_desc)
				XFREE(MTYPE_LLDP_SYSTEM, ndb->system_desc);
			ndb->system_desc = XMALLOC(MTYPE_LLDP_SYSTEM, len + 1);
			memset(ndb->system_desc, 0, len + 1);
			memcpy(ndb->system_desc, ibuf, len);
			LLDP_DEBUG_LOG("get neighbor system desc:%s", ndb->system_desc);
		}
		break;
	case LLDP_SYSTEM_CAPA_ID: /* System Capabilities */
		if (ndb) {
			if (ndb->system_desc)
				XFREE(MTYPE_LLDP_SYSTEM, ndb->system_desc);
			ndb->system_desc = XMALLOC(MTYPE_LLDP_SYSTEM,
						   sizeof(struct system_capability));
			memset(ndb->capability, 0, sizeof(struct system_capability));
			memcpy(ndb->capability, ibuf, len);
			LLDP_DEBUG_LOG("get neighbor capability:%x %x", ndb->capability->CapEnabled,
				       ndb->capability->CapSupported);
		}
		break;
	case LLDP_MGT_ADDR_ID: /* Management Address */
		if (ndb) {
			struct mgt_address *mgt = (struct mgt_address *)ibuf;
			if (ndb->mgt_address)
				XFREE(MTYPE_LLDP_SYSTEM, ndb->mgt_address);
			ndb->mgt_address = XMALLOC(MTYPE_LLDP_SYSTEM, sizeof(struct mgt_address));
			memset(ndb->mgt_address, 0, sizeof(struct mgt_address));

			ndb->mgt_address->subtype = mgt->subtype;
			ndb->mgt_address->addr_len = mgt->addr_len;
			memset(ndb->mgt_address->value, 0, sizeof(ndb->mgt_address->value));
			memcpy(ndb->mgt_address->value, mgt->value, mgt->addr_len);
			ndb->mgt_address->ifsubtype = mgt->ifsubtype;
			ndb->mgt_address->idindex = ntohl(mgt->idindex);
			ndb->mgt_address->oidlen = mgt->oidlen;
			memset(ndb->mgt_address->oid, 0, sizeof(ndb->mgt_address->oid));
			if (ndb->mgt_address->oidlen)
				memcpy(ndb->mgt_address->oid, mgt->oid, ndb->mgt_address->oidlen);

			LLDP_DEBUG_LOG("get neighbor Management Address");
		}
		break;
	case LLDP_ORG_TLV_ID:
		lldp_tlv_org_process(ndb, lifp, ibuf, len, type);
		break;
	}
	if (id.port_id_len && id.chassis_len) {
		*db = lldp_neighbor_get(&id);
		ndb = *db;
	}
	return 0;
}
static int lldp_read_process(struct lldp_interface *lifp, char *ibuf, int len, int type)
{
	int tlv = 0;
	int tlv_len = 0;
	int nbyte = len;
	int offset = 0;
	char *buf = ibuf;
	struct tlv_db *db = NULL;
	tlv = LLDP_TLV_HDR_TYPE(buf);
	//if(tlv == LLDP_ORG_TLV_ID)
	//	buf += 3;
	tlv_len = LLDP_TLV_HDR_LEN(buf);

	while (nbyte) {
		if (tlv == LLDP_ORG_TLV_ID)
			offset = 2; //5;
		else
			offset = 2;

		lldp_tlv_process(&db, lifp, buf + offset, tlv_len, tlv);

		buf += offset;
		tlv = LLDP_TLV_HDR_TYPE(buf);
		//if(tlv == LLDP_ORG_TLV_ID)
		//	buf += 3;
		tlv_len = LLDP_TLV_HDR_LEN(buf);
		nbyte = len - tlv_len;
	}
	lifp->rcv_pkts++;
	return 0;
}
static int lldp_read_packet(struct lldp_interface *lifp)
{
	int len = 0;
	int offset = 0;
	char *ibuf = NULL;
	struct ethhdr *eth_hdr = NULL;
	unsigned short *h_proto = NULL;
	//struct vlan_hdr *vlan;
	ibuf = STREAM_DATA(lifp->ibuf);
	len = stream_get_endp(lifp->ibuf);
	if (ibuf == NULL || len < 16)
		return -1;
	if (!lldpd_config || lldpd_config->lldp_enable == 0)
		return -1;
	eth_hdr = (struct ethhdr *)ibuf;
	offset = sizeof(struct ethhdr);
	h_proto = eth_hdr->h_proto;
	if (ntohs(h_proto) == ETH_P_8021Q)
		offset += sizeof(struct vlan_hdr);
	//ip_hdr = (struct ip *)(ibuf + offset);
	h_proto = (unsigned short *)(ibuf + offset);
	if (ntohs(h_proto) == ETH_P_LLDP) {
		offset += sizeof(unsigned short);
		return lldp_read_process(lifp, ibuf + offset, len - offset, ETH_P_LLDP);
	} else if (ntohs(h_proto) == ETH_P_SLLDP) {
		offset += 8;
		return lldp_read_process(lifp, ibuf + offset, len - offset, ETH_P_SLLDP);
	}
	return 0;
}


int lldp_read(struct thread *thread)
{
	int sock;
	struct stream *ibuf;
	struct interface *ifp;
	struct interface *get_ifp;
	struct lldp_interface *lifp;
	/* first of all get interface pointer. */
	ifp = THREAD_ARG(thread);
	sock = THREAD_FD(thread);

	lifp = ifp->info;
	if (lifp == NULL)
		return -1;
	/* prepare for next packet. */
	lifp->t_read = thread_add_read(master, lldp_recv_packet, ifp, sock);

	stream_reset(lifp->ibuf);
	if (!(ibuf = lldp_recv_packet(lifp->sock, &get_ifp, lifp->ibuf)))
		return -1;

	if (get_ifp == NULL)
		return -1;

	lifp = get_ifp->info;
	if (lifp) {
		lldp_read_packet(lifp);
	}
	return CMD_SUCCESS;
}
