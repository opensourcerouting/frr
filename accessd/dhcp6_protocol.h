/*
 * Copyright (C) 1998 and 1999 WIDE Project.
 * All rights reserved.
 *
 * Imported and adapted for FRRouting
 * 2021 David Lamparter
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __DHCP6_H_DEFINED
#define __DHCP6_H_DEFINED

#include <stdint.h>

enum dhcp6_msgtype {
#define DH6MSG(name, val)			DH6MSG_##name = val,
#include "dhcp6_constants.h"
};

enum dhcp6_opttype {
#define DH6OPT(name, val, oro, singleton)	DH6OPT_##name = val,
#include "dhcp6_constants.h"
};

enum dhcp6_status {
#define DH6ST(name, val)			DH6ST_##name = val,
#include "dhcp6_constants.h"
};

enum dhcp6_duidtype {
#define DUID(name, val)				DUIDT_##name = val,
#include "dhcp6_constants.h"
};


#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%dDHMT" (int)
#pragma FRR printfrr_ext "%dDHMT" (uint8_t)

#pragma FRR printfrr_ext "%dDOPT" (int)
#pragma FRR printfrr_ext "%dDOPT" (uint16_t)

#pragma FRR printfrr_ext "%dDHST" (int)
#endif /* _FRR_ATTRIBUTE_PRINTFRR */

#define DH6OPT_PREF_UNDEF -1
#define DH6OPT_PREF_MAX 255

#define DH6OPT_REFRESHTIME_UNDEF -1

#define DH6OPT_ELAPSED_TIME_UNDEF -1

#define DH6OPT_AUTH_PROTO_DELAYED 2
#define DH6OPT_AUTH_RRECONFIGURE 3

#define DH6OPT_AUTH_ALG_HMACMD5 1

/* Predefined addresses */
#define DH6ADDR_ALLAGENT "ff02::1:2"
#define DH6ADDR_ALLSERVER "ff05::1:3"
#define DH6PORT_DOWNSTREAM "546"
#define DH6PORT_UPSTREAM "547"

/* Protocol constants */

/* timer parameters (msec, unless explicitly commented) */
#define SOL_MAX_DELAY 1000
#define SOL_TIMEOUT 1000
#define SOL_MAX_RT 120000
#define INF_TIMEOUT 1000
#define INF_MAX_RT 120000
#define REQ_TIMEOUT 1000
#define REQ_MAX_RT 30000
#define REQ_MAX_RC 10	  /* Max Request retry attempts */
#define REN_TIMEOUT 10000 /* 10secs */
#define REN_MAX_RT 600000 /* 600secs */
#define REB_TIMEOUT 10000 /* 10secs */
#define REB_MAX_RT 600000 /* 600secs */
#define REL_TIMEOUT 1000  /* 1 sec */
#define REL_MAX_RC 5

#define DHCP6_DURATION_INFINITE 0xffffffff
#define DHCP6_DURATION_MIN 30

#define DHCP6_RELAY_MULTICAST_HOPS 32
#define DHCP6_RELAY_HOP_COUNT_LIMIT 32

#define DHCP6_IRT_DEFAULT 86400 /* 1 day */
#define DHCP6_IRT_MINIMUM 600

/* DUID: DHCP unique Identifier */
struct duid {
	size_t duid_len; /* length */
	char *duid_id;	 /* variable length ID value (must be opaque) */
};

struct dhcp6_vbuf { /* generic variable length buffer */
	int dv_len;
	caddr_t dv_buf;
};

/* option information */
struct dhcp6_ia { /* identity association */
	u_int32_t iaid;
	u_int32_t t1;
	u_int32_t t2;
};

struct dhcp6_prefix { /* IA_PA */
	u_int32_t pltime;
	u_int32_t vltime;
	struct in6_addr addr;
	int plen;
};

struct dhcp6_statefuladdr { /* IA_NA */
	u_int32_t pltime;
	u_int32_t vltime;
	struct in6_addr addr;
};

/* DHCP6 base packet format */
struct dhcp6 {
	union {
		u_int8_t m;
		u_int32_t x;
	} dh6_msgtypexid;
	/* options follow */
} __attribute__((__packed__));
#define dh6_msgtype dh6_msgtypexid.m
#define dh6_xid dh6_msgtypexid.x
#define DH6_XIDMASK 0x00ffffff

/* DHCPv6 relay messages */
struct dhcp6_relay {
	u_int8_t dh6relay_msgtype;
	u_int8_t dh6relay_hcnt;
	struct in6_addr dh6relay_linkaddr; /* XXX: badly aligned */
	struct in6_addr dh6relay_peeraddr; /* ditto */
					   /* options follow */
} __attribute__((__packed__));

/* The followings are KAME specific. */

struct dhcp6opt {
	u_int16_t dh6opt_type;
	u_int16_t dh6opt_len;
	/* type-dependent data follows */
} __attribute__((__packed__));

/* DUID type 1 */
struct dhcp6opt_duid_type1 {
	u_int16_t dh6_duid1_type;
	u_int16_t dh6_duid1_hwtype;
	u_int32_t dh6_duid1_time;
	/* link-layer address follows */
} __attribute__((__packed__));

/* Status Code */
struct dhcp6opt_stcode {
	u_int16_t dh6_stcode_type;
	u_int16_t dh6_stcode_len;
	u_int16_t dh6_stcode_code;
} __attribute__((__packed__));

/*
 * General format of Identity Association.
 * This format applies to Prefix Delegation (IA_PD) and Non-temporary Addresses
 * (IA_NA)
 */
struct dhcp6opt_ia {
	u_int16_t dh6_ia_type;
	u_int16_t dh6_ia_len;
	u_int32_t dh6_ia_iaid;
	u_int32_t dh6_ia_t1;
	u_int32_t dh6_ia_t2;
	/* sub options follow */
} __attribute__((__packed__));

/* IA Addr */
struct dhcp6opt_ia_addr {
	u_int16_t dh6_ia_addr_type;
	u_int16_t dh6_ia_addr_len;
	struct in6_addr dh6_ia_addr_addr;
	u_int32_t dh6_ia_addr_preferred_time;
	u_int32_t dh6_ia_addr_valid_time;
} __attribute__((__packed__));

/* IA_PD Prefix */
struct dhcp6opt_ia_pd_prefix {
	u_int16_t dh6_iapd_prefix_type;
	u_int16_t dh6_iapd_prefix_len;
	u_int32_t dh6_iapd_prefix_preferred_time;
	u_int32_t dh6_iapd_prefix_valid_time;
	u_int8_t dh6_iapd_prefix_prefix_len;
	struct in6_addr dh6_iapd_prefix_prefix_addr;
} __attribute__((__packed__));

/* Authentication */
struct dhcp6opt_auth {
	u_int16_t dh6_auth_type;
	u_int16_t dh6_auth_len;
	u_int8_t dh6_auth_proto;
	u_int8_t dh6_auth_alg;
	u_int8_t dh6_auth_rdm;
	u_int8_t dh6_auth_rdinfo[8];
	/* authentication information follows */
} __attribute__((__packed__));

enum {
	DHCP6_AUTHPROTO_UNDEF = -1,
	DHCP6_AUTHPROTO_DELAYED = 2,
	DHCP6_AUTHPROTO_RECONFIG = 3
};
enum { DHCP6_AUTHALG_UNDEF = -1, DHCP6_AUTHALG_HMACMD5 = 1 };
enum { DHCP6_AUTHRDM_UNDEF = -1, DHCP6_AUTHRDM_MONOCOUNTER = 0 };

#endif /*__DHCP6_H_DEFINED*/
