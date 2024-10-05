// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Interface's address and mask.
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_CONNECTED_H
#define _ZEBRA_CONNECTED_H

#include <zebra.h>
#include <stdint.h>

#include "lib/if.h"
#include "lib/prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

/* an address can be in 2 and a half states:
 *  - requested by daemon over zserv API
 *    .t_holdover = NULL
 *    .ifaitem = on struct zserv->if_addrs
 *  - in holdover after daemon disconnects (graceful restart ish)
 *    .t_holdover = running (ZAPI_ADDR_HOLDOVER_ZAPI_DISCONNECT)
 *    .ifaitem = not on list
 *    Addresses do NOT go into this state if the daemon deletes them!
 *  - in holdover after zebra starts and we read it from the kernel[*]
 *    .t_holdover = running (ZAPI_ADDR_HOLDOVER_ZEBRA_START)
 *    .ifaitem = not on list
 *
 * The last one can only happen if we recognize an address as installed by FRR
 * due to its rt_addrproto value.
 */

#define ZAPI_ADDR_HOLDOVER_ZAPI_DISCONNECT	60
#define ZAPI_ADDR_HOLDOVER_ZEBRA_START		300

enum zserv_if_addr_proto {
	ZSERV_IFAPROT_INVALID = 0,

	ZSERV_IFAPROT_RA_LL_PER_PREFIX,
};

PREDECL_HASH(zserv_if_addrs);

struct zserv_if_addr {
	/* struct connected -> this, always valid */
	struct connected_reqs_item critem;
	/* daemon / zserv connection -> this; ONLY if t_holdover == NULL! */
	struct zserv_if_addrs_item ifaitem;

	/* struct zserv * backlink not currently needed, but can be added */
	struct interface *ifp;
	struct connected *ifc;

	enum zserv_if_addr_proto proto;
	struct event *t_holdover;
};

DECLARE_DLIST(connected_reqs, struct zserv_if_addr, critem);

extern struct connected *connected_check(struct interface *ifp,
					 union prefixconstptr p);
extern struct connected *connected_check_ptp(struct interface *ifp,
					     union prefixconstptr p,
					     union prefixconstptr d);

extern void connected_add_ipv4(struct interface *ifp, int flags,
			       const struct in_addr *addr, uint16_t prefixlen,
			       const struct in_addr *dest, const char *label,
			       uint32_t metric);

extern void connected_delete_ipv4(struct interface *ifp, int flags,
				  const struct in_addr *addr,
				  uint16_t prefixlen,
				  const struct in_addr *dest);

extern void connected_delete_ipv4_unnumbered(struct connected *ifc);

extern void connected_up(struct interface *ifp, struct connected *ifc);
extern void connected_down(struct interface *ifp, struct connected *ifc);

extern void connected_add_ipv6(struct interface *ifp, int flags,
			       const struct in6_addr *address,
			       const struct in6_addr *dest, uint16_t prefixlen,
			       const char *label, uint32_t metric);
extern void connected_delete_ipv6(struct interface *ifp,
				  const struct in6_addr *address,
				  const struct in6_addr *dest,
				  uint16_t prefixlen);

extern int connected_is_unnumbered(struct interface *ifp);

#ifdef __cplusplus
}
#endif
#endif /*_ZEBRA_CONNECTED_H */
