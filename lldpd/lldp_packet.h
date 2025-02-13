/*
 * lldp_packet.h
 *
 *  Created on: Oct 25, 2016
 *      Author: zhurish
 */

#ifndef LLDPD_LLDP_PACKET_H_
#define LLDPD_LLDP_PACKET_H_


/*
 * LLDP TLV
 * 1 端口描述
 * 2 系统名称
 * 3 系统描述
 * 4 系统性能
 * 5 管理地址
 * 6 端口VLAN ID （IEEE 802.1）
 * 7 MAC/PHY配置状态 （IEEE 802.3）
 */

/*
 * LLDP-MED TLV
 * 1 LLDP-MED 性能
 * 2 网络策略
 * 3 电源管理
 * 4 清单管理
 * 5 位置
 * 6 端口VLAN ID （IEEE 802.1）
 * 7 MAC/PHY配置状态 （IEEE 802.3）
 */

#define LLDP_TLV_HDR(n, t, l)                                                                      \
	(n)->hdr[0] = (((t) & 0x7f) << 1) | (((l) & 0x0100) >> 8);                                 \
	(n)->hdr[1] = ((l) & 0xff);
//#define LLDP_TLV_HDR(n,t,l)	(n)->type = (((t)&0x7f)); (n)->len = ((l)&0x1ff);
#pragma pack(1)
struct lldp_tlv {
	unsigned char hdr[2];
};

struct lldp_exp_tlv {
	unsigned char hdr[2];
	unsigned char identifer[3];
	unsigned char subtype;
	//unsigned char *value;
};

#define LLDP_SUB_TLV_HDR(n) (strlen((const char *)(n).value) + 1)
struct lldp_sub_head {
	unsigned char subtype;				   /* 子类型*/
	unsigned char value[LLDP_SUB_TLV_STR_MAX_LEN + 1]; /* 数据 */
};


/* 管理地址数据 */
struct lldp_mgt_address {
	unsigned char addr_len;				/* 管理地址长度 */
	unsigned char subtype;				/* 管理地址子类型 */
	unsigned char value[LLDP_MAN_ADDR_STR_MAX_LEN]; /* 管理地址 */
};
/* 管理地址接口数据 */
struct lldp_mgt_if {
	unsigned char ifsubtype;	     /* 管理地址接口类型 */
	unsigned int idindex;		     /* 管理地址接口索引 */
	unsigned char oidlen;		     /* OID 长度 */
	unsigned char oid[LLDP_OID_MAX_LEN]; /* OID */
};

#pragma pack(0)


extern int lldp_head_format(struct interface *ifp, struct stream *obuf);
extern int lldp_make_lldp_pdu(struct interface *ifp);


#endif /* LLDPD_LLDP_PACKET_H_ */
