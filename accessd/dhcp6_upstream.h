/*
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

#ifndef _FRR_DHCP6_UPSTREAM_H
#define _FRR_DHCP6_UPSTREAM_H

#include "lib/typesafe.h"
#include "lib/qobj.h"

struct zbuf;
struct dhcp6r_iface;
struct dhcp6;

PREDECL_RBTREE_UNIQ(dhcp6_ugroups);
PREDECL_DLIST(dhcp6_ust_member);
PREDECL_DLIST(dhcp6_ust_groups);

struct dhcp6_ugroup {
	struct dhcp6_ugroups_item item;
	struct dhcp6_ust_member_head members[1];

	QOBJ_FIELDS;

	/* config */

	char *name;

	/* state */
};

DECLARE_QOBJ_TYPE(dhcp6_ugroup);

struct dhcp6_upstream;

struct dhcp6_ust_member {
	struct dhcp6_ust_member_item member;
	struct dhcp6_ust_groups_item groups;

	struct dhcp6_ugroup *ug;
	struct dhcp6_upstream *us;
};

enum dhcp6_upstream_state {
	DHCP6_USST_UNDEF = 0,
	DHCP6_USST_CONNECTING,
	DHCP6_USST_OPERATIONAL,
	DHCP6_USST_ERROR,
};
enum dhcp6_lq_state {
	DHCP6_LQ_DISABLED = 0,
	DHCP6_LQ_INIT,
	DHCP6_LQ_CONNECTING,
	DHCP6_LQ_IDLE,
};

PREDECL_RBTREE_UNIQ(dhcp6_upstreams);

struct dhcp6_upstream {
	struct dhcp6_upstreams_item item;
	struct dhcp6_ust_groups_head groups[1];

	QOBJ_FIELDS;

	/* config */

	struct sockaddr_in6 addr;
	vrf_id_t vrf;

	/* state */

	enum dhcp6_upstream_state state;
	int sock;
	int last_err;
	unsigned err_count;
	struct thread *t_rcv;
	struct thread *t_timeout;

	/* leasequery */

	enum dhcp6_lq_state lq_state;
	int lq_sock;
	struct thread *t_lq_rcv, *t_lq_snd;

	unsigned retry_place;
};

DECLARE_QOBJ_TYPE(dhcp6_upstream);


extern void dhcp6_ugroup_relay(const char *upstream, struct dhcp6r_iface *ifp,
			       struct sockaddr_in6 *host, struct dhcp6 *dh6,
			       size_t size);

extern void dhcp6r_snoop(struct dhcp6r_iface *drif, struct sockaddr_in6 *host,
			 struct zbuf *zb);

extern void dhcp6_ra_self_rcv(struct dhcp6r_iface *drif, struct zbuf *zb);

#endif /* _FRR_DHCP6_UPSTREAM_H */
