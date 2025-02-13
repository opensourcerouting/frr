/*
 * lldp_db.c
 *
 *  Created on: Oct 30, 2016
 *      Author: zhurish
 */

#include <zebra.h>
#include <lib/version.h>
#include "thread.h"
#include "command.h"
#include "prefix.h"
#include "plist.h"
#include "if.h"
#include "stream.h"
#include "log.h"
#include "memory.h"

#include "lldpd.h"
#include "lldp_interface.h"
#include "lldp_db.h"
//#include "lldp_packet.h"
//#include "lldp_socket.h"


const char *lldp_ststem_name(void)
{
	return host.name;
}

const char *lldp_ststem_description(void)
{
	static unsigned char system_desc[LLDP_SYSTEM_DESCR_MAX_LEN];
	memset(system_desc, 0, LLDP_SYSTEM_DESCR_MAX_LEN);
#ifdef IMISH_IMI_MODULE
	sprintf(system_desc, "%s(%s) - Version %s. ", host.name, OEM_PACKAGE_NAME, OEM_VERSION);
	strcat(system_desc, OEM_PACKAGE_COPYRIGHT);
	strcat(system_desc, " Design it Base on ");
	strcat(system_desc, OEM_PACKAGE_BASE);
	strcat(system_desc, ".");
	strcat(system_desc, " Build ");
	strcat(system_desc, __DATE__);
	strcat(system_desc, " ");
	strcat(system_desc, __TIME__);
	strcat(system_desc, ".");
#else  /* IMISH_IMI_MODULE */
	sprintf(system_desc, "%s(%s) - Version %s. ", host.name, QUAGGA_VERSION);
	strcat(system_desc, QUAGGA_COPYRIGHT);
	strcat(system_desc, " Build ");
	strcat(system_desc, __DATE__);
	strcat(system_desc, " ");
	strcat(system_desc, __TIME__);
	strcat(system_desc, ".");
#endif /* IMISH_IMI_MODULE */
	return system_desc;
}
int lldp_system_caability(struct system_capability *head)
{
	memset(head, 0, sizeof(struct system_capability));
	head->CapEnabled = 1;
	head->CapSupported = 1;
	return sizeof(struct system_capability);
}
int lldp_ststem_mgt_address(struct mgt_address *mgt)
{
	int len = 0;
	in_addr_t address;
	memset(mgt, 0, sizeof(struct mgt_address));

	address = inet_addr("192.168.1.101");
	len = sizeof(in_addr_t);
	memcpy(mgt->value, &address, len);
	mgt->subtype = 1;
	mgt->addr_len = sizeof(mgt->subtype) + len;

	mgt->ifsubtype = 2;
	mgt->idindex = htonl(5);
	mgt->oidlen = 1;
	mgt->oid[0] = 0;
	return 0;
}
int lldp_chassis_id(struct tlv_sub_head *head)
{
	//struct lldp_interface *lifp = (struct lldp_interface *)ifp->info;
	memset(head, 0, sizeof(struct tlv_sub_head));
	head->subtype = LLDP_SUB_MAC_ADDR_ID;
	//memcpy(head->value, lifp->own_mac, ETH_ALEN);
	return (1 + ETH_ALEN);
}
int lldp_port_id(struct interface *ifp, struct tlv_sub_head *head)
{
	struct lldp_interface *lifp = (struct lldp_interface *)ifp->info;
	memset(head, 0, sizeof(struct tlv_sub_head));
	head->subtype = LLDP_SUB_PORT_IF_NAME_ID;
	sprintf((char *restrict)head->value, "%s", ifindex2ifname(ifp->ifindex));
	return TLV_SUB_HDR(*head);
}
int lldp_port_link(struct interface *ifp)
{
	int ret = if_is_up(ifp);
	if (ret)
		ret |= if_is_running(ifp);
	return ret;
}
/* 802.1 */
int lldp_port_vlan_id(struct interface *ifp, struct tlv_vlan *head)
{
	struct lldp_interface *lifp = (struct lldp_interface *)ifp->info;
	memset(head, 0, sizeof(struct tlv_vlan));
	head->vid = htons(23);
	//head->flag = 1;
	return sizeof(struct tlv_vlan);
}
int lldp_port_vlan_name(struct interface *ifp, struct tlv_vlan_name *head)
{
	struct lldp_interface *lifp = (struct lldp_interface *)ifp->info;
	memset(head, 0, sizeof(struct tlv_vlan_name));
	head->vid = htons(23);
	head->len = strlen("vlan23"); /* */
	sprintf((char *restrict)head->vlan_name, "%s", "vlan23");
	return (head->len + 2 + 1);
}
int lldp_port_vlan_protocol(struct interface *ifp, struct tlv_vlan_proto *head)
{
	struct lldp_interface *lifp = (struct lldp_interface *)ifp->info;
	memset(head, 0, sizeof(struct tlv_vlan_proto));
	head->vid = htons(23);
	head->flag = 1;
	return sizeof(struct tlv_vlan_proto);
}
int lldp_port_protocol(struct interface *ifp, struct tlv_proto *head)
{
	struct lldp_interface *lifp = (struct lldp_interface *)ifp->info;
	memset(head, 0, sizeof(struct tlv_proto));
	head->len = 0; /* */
	//head->value
	return 1; //TLV_SUB_HDR(*head);
}

/* 802.3 */
int lldp_port_frame_size(struct interface *ifp, unsigned short *size)
{
	if (size) {
		*size = ifp->mtu;
		return 2;
	}
	return 0;
}
int lldp_port_phy_status(struct interface *ifp, struct tlv_phy_status *phy)
{
	struct lldp_interface *lifp = (struct lldp_interface *)ifp->info;
	memset(phy, 0, sizeof(struct tlv_phy_status));
	phy->negotiation = 0x03;       /* */
	phy->pmd_capa = htons(0x6c00); /* 数据 */
	phy->mau_type = htons(0x0010); /* 数据 */
	return sizeof(struct tlv_phy_status);
}
