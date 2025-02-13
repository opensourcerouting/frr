/*
 * lldp_neighbor.h
 *
 *  Created on: Oct 31, 2016
 *      Author: zhurish
 */

#ifndef LLDPD_LLDP_NEIGHBOR_H_
#define LLDPD_LLDP_NEIGHBOR_H_


#define TLV_DB_CHECK_TIME 10

struct tlv_db_head {
	unsigned char type;
	unsigned char subtype; /* 子TLV 类型*/
	unsigned int len;      /* 数据长度 */
	unsigned char *value;  /* 数据*/
};

#define LLDP_TLV_HDR_TYPE(n) ((((n)[0]) & 0xFE) >> 1)
#define LLDP_TLV_HDR_LEN(n)  ((((n)[0]) & 0x01) << 8) | (((n)[1]) & 0xff)

struct tlv_db_id {
	unsigned char chassis_type;			       /* 子TLV 类型*/
	unsigned int chassis_len;			       /* 数据长度 */
	unsigned char chassis_value[LLDP_SUB_TLV_STR_MAX_LEN]; /* 数据*/
	unsigned char port_id_type;			       /* 子TLV 类型*/
	unsigned int port_id_len;			       /* 数据长度 */
	unsigned char port_id_value[LLDP_SUB_TLV_STR_MAX_LEN]; /* 数据*/
};

#include "lldp_db.h"

//远端设备信息缓存数据结构
struct tlv_db {
	struct tlv_db_id id;
	int time_interval;	    //邻居失效时间
	int ifindex;		    //接收该邻居信息的接口索引
				    //邻居保存的数据
	unsigned char *system_name; /* 系统名称 */
	unsigned char *system_desc; /* 系统描述 */
	unsigned int holdtime;	    /* LLDPPDU 生存时间 */
	//struct tlv_db_head chassis_id;  /* 设备 ID */
	//struct tlv_db_head port_id;  /* 端口ID */
	unsigned char *port_desc;	      /* 端口描述 */
	struct system_capability *capability; /* 系统性能 */
	struct mgt_address *mgt_address;      /* 管理地址 */

	struct list *org_list;
	//struct list *unknown_list;
	int unknown_count;

	//struct tlv_db_head UnknownTLV[LLDP_UNKNOWN_TLV_MAX_COUNT];  /* 未识别TLV */
	//struct tlv_db_head lldpOrgTLV[LLDP_ORG_COUNT];  /*组织特定TLV */
};

struct tlv_local_db {
	int db_init;					       //是否初始化完毕
	unsigned char chassis_type;			       /* 子TLV 类型*/
	unsigned int chassis_len;			       /* 数据长度 */
	unsigned char chassis_value[LLDP_SUB_TLV_STR_MAX_LEN]; /* 数据*/
							       //邻居保存的数据
	unsigned char *system_name;			       /* 系统名称 */
	unsigned char *system_desc;			       /* 系统描述 */
	struct system_capability *capability;		       /* 系统性能 */
	struct mgt_address *mgt_address;		       /* 管理地址 */
							       //struct list *org_list;
};
struct lldp_neighbor {
	struct tlv_local_db *tlv_local;
	struct list *tlv_neighbor_list;
	//	struct list *tlv_extern_list;
	int lldp_db_interval;
	struct thread *t_ckeck_time;
};


extern int lldp_neighbor_init(void);
extern struct tlv_db *lldp_neighbor_new(struct tlv_db_id *id);
extern int lldp_neighbor_free(struct tlv_db *db);
extern struct tlv_db *lldp_neighbor_lookup(struct tlv_db_id *id);
extern struct tlv_db *lldp_neighbor_get(struct tlv_db_id *id);


extern int lldp_local_db_init(void);


#endif /* LLDPD_LLDP_NEIGHBOR_H_ */
