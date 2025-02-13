/*
 * lldp_interface.h
 *
 *  Created on: Oct 24, 2016
 *      Author: zhurish
 */

#ifndef LLDPD_LLDP_INTERFACE_H_
#define LLDPD_LLDP_INTERFACE_H_


#define LLDP_MAX_PACKET_SIZE 2048

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* mode */
#define LLDP_DISABLE	0 //
#define LLDP_ENABLE	1 //
#define LLDP_READ_MODE	2 //接收
#define LLDP_WRITE_MODE 4 //发送
#define LLDP_MED_MODE	8 //

#ifdef LLDP_PROTOCOL_DEBUG
/* protocol */
#define LLDP_CDP_TYPE	 0x0001 /* Cisco Discovery Protocol */
#define LLDP_EDP_TYPE	 0x0002 /* Extreme Discovery Protocol */
#define LLDP_FDP_TYPE	 0x0004 /* Foundry Discovery Protocol */
#define LLDP_DOT1_TYPE	 0x0008 /* Dot1 extension (VLAN stuff) */
#define LLDP_DOT3_TYPE	 0x0010 /* Dot3 extension (PHY stuff) */
#define LLDP_SONMP_TYPE	 0x0011 /*  */
#define LLDP_MED_TYPE	 0x0012 /* LLDP-MED extension */
#define LLDP_CUSTOM_TYPE 0x0014 /* Custom TLV support */
#endif
/* frame */
#define LLDP_FRAME_TYPE 1
#define SNAP_FRAME_TYPE 2


struct lldp_interface {
	int mode; /* 使能状态 */
#ifdef LLDP_PROTOCOL_DEBUG
	int protocol; /* 兼容协议 */
#endif
	int states;  /* 接口状态 */
	int frame;   /* LLDP 帧封装格式 */
	int Changed; /* 本地信息发生变动 */
	//unsigned short lldp_ttl;/* 报文TTL */
	unsigned short capabilities; /*  */

	int lldp_timer;		      /* 定时时间 */
	unsigned short lldp_holdtime; /* 生存时间 */
	int lldp_reinit;	      /* 重新初始化时间 */
	int lldp_fast_count;	      /* 快速发送计数 */
	//int lldp_tlv_select;//TLV选择
	//int lldp_check_interval;//本地检测周期，检测本地信息是否发生变化

	unsigned char own_mac[ETH_ALEN];
	unsigned char dst_mac[ETH_ALEN];

	struct lldpd *lldpd;
	/* Interface data from zebra. */
	struct interface *ifp;

	/* Output socket. */
	int sock;
	struct stream *ibuf;
	struct stream *obuf;
	//unsigned char *outbuf;
	/* Threads. */
	struct thread *t_read;	/* read to output socket. */
	struct thread *t_write; /* Write to output socket. */
	struct thread *t_time;	/* Write to output socket. */

	int sen_pkts;
	int rcv_pkts;
	int err_pkts;
};

enum {
	LLDP_DST_MAC1,
	LLDP_DST_MAC2,
	LLDP_DST_MAC3,
	LLDP_DST_MAC4,
	LLDP_DST_MAC_MAX,
};
extern unsigned char lldp_dst_mac[LLDP_DST_MAC_MAX][ETH_ALEN];

/*lldp_interface.c*/
extern int lldp_interface_init(void);

//lldp tlv-select basic-tlv (all|port-description|system-capability|system-description|system-name)
//lldp tlv-select dot1-tlv (all|port-vlan-id|protocol-vlan-id|vlan-name)
//lldp tlv-select dot3-tlv (all|link-aggregation|mac-physic|max-framc-size|power)
//							链路聚合，端口硬件速率模式等 最大帧，端口供电能力
//lldp tlv-select med-tlv (all|capability|location-id|elin-address PHONE)
//							LLDP-MED 能力，连接位置信息，电话号码
//lldp tlv-select network-policy 端口的VLAN-ID 支持的应用，应用的优先级，策了
//lldp tlv-select power-via-mdi 设备供电能力
//lldp tlv-select inventory 设备软硬件版本信息等
#endif /* LLDPD_LLDP_INTERFACE_H_ */
