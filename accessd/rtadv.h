/*
 * Copyright (C) 2022 David Lamparter
 * Copyright (C) 2005 6WIND <jean-mickael.guerin@6wind.com>
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ACCESSD_RTADV_H
#define _ACCESSD_RTADV_H

#include "lib/prefix.h"
#include "lib/typesafe.h"

struct event;
struct accessd_iface;

struct rtadv_vrf {
	size_t refcnt;

	int sock;

	struct event *t_read;
};

PREDECL_RBTREE_UNIQ(rtadv_prefixes);
PREDECL_HASH(rtadv_lladdrs);
PREDECL_DLIST(rtadv_ll_prefixes);

enum {
	RTADV_MTU_NOINCLUDE = 0,
	RTADV_MTU_AUTO = 1,
};

PREDECL_RBTREE_UNIQ(rtadv_rdnss);

struct rtadv_rdnss {
	struct rtadv_rdnss_item itm;

	/* Address of recursive DNS server to advertise */
	struct in6_addr addr;

	/*
	 * Lifetime in seconds; all-ones means infinity, zero
	 * stop using it.
	 */
	uint32_t lifetime;

	/* If lifetime not set, use a default of 3*MaxRtrAdvInterval */
	int lifetime_set;
};

struct rtadv_iface_cfg {
	bool enable : 1;

	bool managed_config : 1;
	bool other_config : 1;
	bool include_adv_interval : 1;

	uint32_t interval_msec;
	uint16_t lifetime_sec;

	uint32_t reachable_ms;
	uint32_t retrans_ms;
	uint8_t hoplimit;
	uint32_t link_mtu;

	struct rtadv_rdnss_head rdnss[1];
};

extern struct rtadv_iface_cfg rtadv_ifp_defaults;

struct rtadv_iface {
	struct rtadv_iface_cfg cfg;

	struct rtadv_prefixes_head prefixes[1];
	struct rtadv_lladdrs_head lladdrs[1];

	struct event *t_periodic;
};

struct rtadv_prefix_cfg {
	uint32_t valid_sec;
	uint32_t preferred_sec;

	bool onlink : 1;
	bool autonomous : 1;
	bool router_addr : 1;
	bool prefer_pd : 1;

	bool make_addr : 1;
};

struct rtadv_lladdr {
	struct rtadv_lladdrs_item item;

	struct in6_addr ll_addr;
	struct rtadv_ll_prefixes_head prefixes[1];
};

struct rtadv_prefix {
	struct rtadv_prefixes_item item;
	struct rtadv_ll_prefixes_item llitem;

	struct prefix_ipv6 prefix;
	struct rtadv_prefix_cfg cfg;

	struct rtadv_lladdr *ll_addr;
	struct event *t_periodic;
};

extern struct rtadv_iface *rtadv_ifp_get(struct accessd_iface *acif);
extern void rtadv_ifp_reconfig(struct interface *ifp);

extern void rtadv_lladdr_addref(struct accessd_iface *acif,
				struct rtadv_prefix *ra_prefix);
extern void rtadv_lladdr_delref(struct accessd_iface *acif,
				struct rtadv_prefix *ra_prefix);

extern void rtadv_cli_init(void);

struct rtadv_rdnss *rtadv_rdnss_get(struct rtadv_iface *ra_if,
				    struct in6_addr addr);

#endif /* _ACCESSD_RTADV_H */
