// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2025, Donatas Abraitis <donatas@opensourcerouting.org>
 */

#ifndef _FRR_BGP_NHC_H
#define _FRR_BGP_NHC_H

struct bgp_nhc_tlv {
	struct bgp_nhc_tlv *next;
	uint16_t code;
	uint16_t length;
	uint8_t *value;
};

struct bgp_nhc {
	unsigned long refcnt;
	uint16_t afi;
	uint8_t safi;
	uint8_t nh_length;
	struct in_addr nh_ipv4;
	struct in6_addr nh_ipv6_global;
	struct in6_addr nh_ipv6_local;
	uint16_t tlvs_length;
	struct bgp_nhc_tlv *tlvs;
};

/* 4 => Characteristic Code + Characteristic Length */
#define BGP_NHC_TLV_MIN_LEN 4
/* 
 * 12 => if using IPv4 next-hop
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Address Family Identifier   |     SAFI      | Next Hop Len  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~             Network Address of Next Hop (variable)            ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Characteristic Code      |      Characteristic Length    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                Characteristic Value (variable)                ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define BGP_NHC_MIN_LEN 12

/* TLV values: */
/* draft-wang-idr-next-next-hop-nodes */
#define BGP_ATTR_NHC_TLV_NNHN 2

extern struct bgp_nhc_tlv *bgp_nhc_tlv_encode_nnhn(struct bgp_path_info *bpi);
extern void bgp_nhc_tlv_add(struct attr *attr, struct bgp_nhc_tlv *tlv);
extern struct bgp_nhc_tlv *bgp_nhc_tlv_find(struct attr *attr, uint16_t code);
extern void bgp_nhc_tlv_free(struct bgp_nhc_tlv *tlv);
extern void bgp_nhc_tlvs_free(struct bgp_nhc_tlv *tlv);
extern void bgp_nhc_free(struct bgp_nhc *bnc);
extern void bgp_packet_nhc(struct stream *s, struct peer *peer, afi_t afi, safi_t safi,
			   struct attr *attr);

#endif /* _FRR_BGP_NHC_H */
