#ifndef _ACCESSD_PERSIST_H
#define _ACCESSD_PERSIST_H

#include "typesafe.h"

/* DHCPv6 binding storage */

struct vrf;
struct persist_target;

struct dhcp6_binding;
struct dhcp6_duid;

struct persist_ops {
	/* just for show, no function */
	const char *name;

	/* DHCPv6 lease storage */

	/* necessary ops:
	 * - iterate at startup to restore routes
	 * - iterate for interface on iface create
	 * - lookup by DUID/IAID on updates from server
	 * - ageout expiring IAs
	 * - clear by user command
	 */

	/* read ops */
	struct dhcp6_binding *(*dhcp6_id_first)(struct persist_target *tgt);
	struct dhcp6_binding *(*dhcp6_id_next)(struct persist_target *tgt,
					       struct dhcp6_binding *prev);
	struct dhcp6_binding *(*dhcp6_expy_first)(struct persist_target *tgt);
	struct dhcp6_binding *(*dhcp6_expy_next)(struct persist_target *tgt,
						 struct dhcp6_binding *prev);

	bool (*dhcp6_fill)(struct persist_target *tgt,
			   struct dhcp6_binding *bnd);

	/* write ops */
	void (*dhcp6_update)(struct persist_target *tgt,
			     struct dhcp6_binding *bnd);
	void (*dhcp6_expire)(struct persist_target *tgt,
			     struct dhcp6_binding *bnd);
};

PREDECL_SORTLIST_NONUNIQ(persist_targets);

struct persist_target {
	struct persist_targets_item itm;

	const struct persist_ops *ops;

	/* for lookup, try backends with lower prio first. */
	int priority;
};

static inline int persist_target_cmp(const struct persist_target *a,
				     const struct persist_target *b)
{
	return numcmp(a->priority, b->priority);
}

DECLARE_SORTLIST_NONUNIQ(persist_targets, struct persist_target, itm,
			 persist_target_cmp);

/* FIXME: backends are currently global, needs to move to VRF */

extern struct persist_targets_head *ps_backends(struct vrf *vrf);

extern void ps_backend_add(struct vrf *vrf, struct persist_target *tgt);
extern void ps_backend_del(struct vrf *vrf, struct persist_target *tgt);

#endif /* _ACCESSD_PERSIST_H */
