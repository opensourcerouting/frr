/*
 * lldp_db.h
 *
 *  Created on: Oct 30, 2016
 *      Author: zhurish
 */

#ifndef LLDPD_LLDP_DB_H_
#define LLDPD_LLDP_DB_H_


/*
#define LLDP_PORT_ID_MAX_LEN 255
#define LLDP_PORT_DESCR_MAX_LEN 255
#define LLDP_SYSTEM_NAME_MAX_LEN 255
#define LLDP_SYSTEM_DESCR_MAX_LEN 255
#define LLDP_MAN_ADDR_STR_MAX_LEN 31



#define LLDP_UNKNOWN_TLV_BUF_MAX_LEN 1486
#define LLDP_UNKNOWN_TLV_INFO_MAX_LEN 511
#define LLDP_TIMER_TASK_PRI 151
#define LLDP_PROCESS_TASK_PRI 150
*/

enum {
	LDDP_END,	       /* End Of LLDPPDU */
	LLDP_CHASSIS_ID,       /* Chassis ID */
	LLDP_PORT_ID,	       /* Port ID */
	LLDP_TTL_ID,	       /* Time To Live */
	LLDP_PORT_DESC_ID,     /* Port Description */
	LLDP_SYSTEM_NAME_ID,   /* System Name */
	LLDP_SYSTEM_DESC_ID,   /* System Description */
	LLDP_SYSTEM_CAPA_ID,   /* System Capabilities */
	LLDP_MGT_ADDR_ID,      /* Management Address */
	LLDP_ORG_TLV_ID = 127, /* Organizationally Specific TLVs */
};
/* Chassis SUB ID */
enum {
	LLDP_SUB_CHASSIS_COM_ID = 1, /* Chassis ID */
	LLDP_SUB_IF_ALIAS_ID,
	LLDP_SUB_PORT_COM_ID,
	LLDP_SUB_MAC_ADDR_ID,
	LLDP_SUB_NET_ADDR_ID,
	LLDP_SUB_IF_NAME_ID,
	LLDP_SUB_LOCALLY_ASSI_ID,
};
/* PORT SUB ID */
enum {
	LLDP_SUB_PORT_IF_ALIAS_ID = 1,
	LLDP_SUB_PORT_PORT_COM_ID,
	LLDP_SUB_PORT_MAC_ADDR_ID,
	LLDP_SUB_PORT_NET_ADDR_ID,
	LLDP_SUB_PORT_IF_NAME_ID,
	LLDP_SUB_PORT_AGENT_CIRCUIT_ID,
	LLDP_SUB_PORT_LOCALLY_ASSI_ID,
};

enum {
	LLDP_8021_ORG = 0, /*IEEE 802.1组织*/
	LLDP_8023_ORG = 1, /*IEEE 802.3 组织*/
	LLDP_TIA_TR41 = 2,
	LLDP_ORG_NULL = 255 /*无组织*/
};

/* IEEE 组织特定TLV 类型*/
enum {
	/* 802.1 */
	LLDP_PVID_TYPE = 1,		/*端口VLAN ID*/
	LLDP_PPVID_TYPE = 2,		/*端口和协议VLAN ID*/
	LLDP_VLAN_NAME_TYPE = 3,	/*VLAN名称*/
	LLDP_PROTOCOL_ID_TYPE = 4,	/*协议ID*/
					/* 802.3 */
	LLDP_MAC_PHY_TYPE = 1,		/*端口MAC/PHY 配置，状态״̬*/
	LLDP_POWER_VIA_MDI_TYPE = 2,	/*ͨ端口MDI功率*/
	LLDP_LINK_AGGREGATION_TYPE = 3, /*链路汇聚*/
	LLDP_MAX_FRAME_SIZE_TYPE = 4,	/*最大数据帧*/

	LLDP_ORG_TYPE_NULL = 255 /*无特定组织TLV 类型*/
};


#pragma pack(1)

struct mgt_address {
	unsigned char addr_len;				/*管理地址长度*/
	unsigned char subtype;				/*管理地址子类型*/
	unsigned char value[LLDP_MAN_ADDR_STR_MAX_LEN]; /*管理地址*/
	unsigned char ifsubtype;			/*管理地址接口子类型*/
	unsigned int idindex;				/*管理地址接口索引*/
	unsigned char oidlen;
	unsigned char oid[LLDP_OID_MAX_LEN]; /*OID*/
};

struct system_capability {
	unsigned short CapSupported; /* 系统性能 */
	unsigned short CapEnabled;   /* 生效的系统性能*/
};
/* 802.1 */
struct tlv_vlan {
	unsigned short vid; /* */
};
struct tlv_vlan_name {
	unsigned short vid;				 /* */
	unsigned char len;				 /* */
	unsigned char vlan_name[LLDP_VLAN_NAME_MAX_LEN]; /* */
};
struct tlv_vlan_proto {
	unsigned char flag; /* */
	unsigned short vid; /* */
};
struct tlv_proto {
	unsigned char len;				   /* */
	unsigned char value[LLDP_PROTOCOL_ID_MAX_LEN + 1]; /* 数据 */
};

/* 802.3 */
struct tlv_phy_status {
	unsigned char negotiation; /* */
	unsigned short pmd_capa;   /* 数据 */
	unsigned short mau_type;   /* 数据 */
};


struct tlv_sub_head {
	unsigned char subtype;				   /* 子类型*/
	unsigned char value[LLDP_SUB_TLV_STR_MAX_LEN + 1]; /* 数据 */
};
#define TLV_SUB_HDR(n) (strlen((const char *)(n).value) + 1)
#pragma pack(0)


extern const char *lldp_ststem_name(void);
extern const char *lldp_ststem_description(void);
extern int lldp_system_caability(struct system_capability *head);
extern int lldp_ststem_mgt_address(struct mgt_address *mgt);

extern int lldp_chassis_id(struct tlv_sub_head *head);

extern int lldp_port_id(struct interface *ifp, struct tlv_sub_head *head);
extern int lldp_port_link(struct interface *ifp);

/* 802.3 */
extern int lldp_port_vlan_id(struct interface *ifp, struct tlv_vlan *head);
extern int lldp_port_vlan_name(struct interface *ifp, struct tlv_vlan_name *head);
extern int lldp_port_vlan_protocol(struct interface *ifp, struct tlv_vlan_proto *head);
extern int lldp_port_protocol(struct interface *ifp, struct tlv_proto *head);

/* 802.3 */
extern int lldp_port_frame_size(struct interface *ifp, unsigned short *size);


#endif /* LLDPD_LLDP_DB_H_ */
