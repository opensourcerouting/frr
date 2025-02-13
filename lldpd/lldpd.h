/*
 * lldpd.h
 *
 *  Created on: Oct 25, 2016
 *      Author: zhurish
 */

#ifndef LLDPD_LLDPD_H_
#define LLDPD_LLDPD_H_

#define LLDP_DEBUG
//#define LLDP_DEBUG_TEST
//#define LLDP_PROTOCOL_DEBUG

#define LLDP_VTY_PORT	    2617
#define LLDP_DEFAULT_CONFIG "lldpd.conf"


#define LLDP_NEIGHBORS_MAX_COUNT   128 /* 系统邻居最大数量 */
#define LLDP_MAN_ADDR_MAX_COUNT	   25  /* 系统管理地址最大数量 */
#define LLDP_UNKNOWN_TLV_MAX_COUNT 118 /* 系统最大未识别TLV数量 */
#define LLDP_ORG_COUNT		   2   /* 特定组织数量 802.1 802.3*/

#define LLDP_SYSTEM_DESCR_MAX_LEN 255
#define LLDP_TLV_STR_MAX_LEN	  511 /* TLV最大长度 */
#define LLDP_SUB_TLV_STR_MAX_LEN  255 /* 子TLV最大长度 */
#define LLDP_MAN_ADDR_STR_MAX_LEN 31
#define LLDP_OID_MAX_LEN	  128
#define LLDP_VLAN_NAME_MAX_LEN	  32
#define LLDP_PROTOCOL_ID_MAX_LEN  255


#define LLDP_HELLO_TIME_DEFAULT	 5 //60
#define LLDP_HOLD_TIME_DEFAULT	 120
#define LLDP_REINIT_TIME_DEFAULT 120

#define LLDP_CHECK_TIME_DEFAULT 5
#define LLDP_FAST_COUNT_DEFAULT 6

#define LLDP_VERSION 1

#define LLDP_PACKET_MAX_SIZE 1500

#define LLDP_STR "lldp config\n"


struct lldpd {
	int lldp_enable;
	int version;
	int lldp_tlv_select;	 //TLV选择
	int lldp_check_interval; //本地检测周期，检测本地信息是否发生变化

	struct thread *t_ckeck_time;
	//struct thread *t_reinit_time;
	//struct lldp_neighbor *tlv_db;
};
extern struct thread_master *master;
extern struct lldpd *lldpd_config;


//lldp_zebra.c
extern void lldp_zclient_init(void);

//lldpd.c
extern int lldp_config_init(void);
extern int lldp_interface_enable(struct interface *ifp);
extern int lldp_interface_disable(struct interface *ifp);
extern int lldp_interface_transmit_enable(struct interface *ifp);
extern int lldp_interface_receive_enable(struct interface *ifp);
extern int lldp_check_timer(struct thread *thread);
extern int lldp_change_event(void);
//extern int lldp_reinit_timer(struct thread *thread);
//lldp_write.c
extern int lldp_write(struct thread *thread);
extern int lldp_timer(struct thread *thread);
//lldp_read.c
extern int lldp_read(struct thread *thread);


#ifdef LLDP_DEBUG
#define LLDP_DEBUG_LOG(format, args...)                                                            \
	fprintf(stderr, "%s:", __func__);                                                          \
	fprintf(stderr, format, ##args);                                                           \
	fprintf(stderr, "\n");
#else
#define LLDP_DEBUG_LOG(format, args...)
#endif


#endif /* LLDPD_LLDPD_H_ */
