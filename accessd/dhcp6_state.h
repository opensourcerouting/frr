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

#ifndef _FRR_DHCP6_STATE_H
#define _FRR_DHCP6_STATE_H

#include "lib/typesafe.h"
#include "lib/thread.h"
#include "lib/prefix.h"

#include "dhcp6_parse.h"

struct dhcp6_binding;

PREDECL_SORTLIST_UNIQ(dhcp6_pds);
struct dhcp6_pdprefix {
	struct dhcp6_pds_item item;
	struct dhcp6_binding *binding;

	struct prefix_ipv6 prefix;
	struct timeval t_pref, t_valid, last_seen;

	bool valid : 1;
	bool in_zebra : 1;
	bool seen : 1;
};

static int dhcp6_pdp_cmp(const struct dhcp6_pdprefix *a,
			 const struct dhcp6_pdprefix *b)
{
	return prefix_cmp(&a->prefix, &b->prefix);
}

DECLARE_SORTLIST_UNIQ(dhcp6_pds, struct dhcp6_pdprefix, item, dhcp6_pdp_cmp);

PREDECL_HASH(dhcp6_bindings);
struct dhcp6_binding {
	struct dhcp6_bindings_item item;
	size_t refcount;

	struct vrf *vrf;

	/* key */
	int hash_begin[0];

	uint32_t ia_id;
	uint16_t ia_type;
	struct dhcp6_duid duid;

	int hash_end[0];

	/* freshly allocated, does not contain proper data */
	bool invalid : 1;

	/* generic bits */
	struct interface *ifp;
	struct in6_addr client;
	struct timeval t0, t1, last_seen;

	struct thread *t_age;

	/* PD data */
	struct dhcp6_pds_head pds[1];
};

/* upper API */

struct dhcp6_id_iter;

extern struct dhcp6_id_iter *dhcp6_bnd_id_begin(struct vrf *vrf);
extern struct dhcp6_binding *dhcp6_bnd_id_next(struct dhcp6_id_iter *iter);
extern void dhcp6_bnd_id_end(struct dhcp6_id_iter *iter);

struct dhcp6_expy_iter;

extern struct dhcp6_expy_iter *dhcp6_bnd_expy_begin(struct vrf *vrf);
extern struct dhcp6_binding *dhcp6_bnd_expy_next(struct dhcp6_expy_iter *iter);
extern void dhcp6_bnd_expy_end(struct dhcp6_expy_iter *iter);

extern struct dhcp6_binding *dhcp6_bnd_get(struct vrf *vrf,
					   const struct dhcp6_duid *duid,
					   uint16_t ia_type, uint32_t ia_id);

extern void dhcp6_bnd_update(struct dhcp6_binding *bnd);
extern void dhcp6_bnd_expire(struct dhcp6_binding *bnd);

/* IA-PD */

extern struct dhcp6_pdprefix *dhcp6_bnd_pd_get(struct dhcp6_binding *bnd,
					       union prefixconstptr pu);
extern void dhcp6_bnd_pd_drop(struct dhcp6_pdprefix *pdp);

/* low-level handling */

/* this should only be called by persistent backends */
extern struct dhcp6_binding *dhcp6_bnd_alloc(struct vrf *vrf,
					     const struct dhcp6_duid *duid,
					     uint16_t ia_type, uint32_t ia_id);
/* only for dhcp6_bnd_unref */
extern void dhcp6_bnd_free(struct dhcp6_binding *bnd);

static inline struct dhcp6_binding *dhcp6_bnd_ref(struct dhcp6_binding *bnd)
{
	assertf(!bnd->invalid, "duid=%pDUID ia_type=%u ia_id=%u refcount=%zu",
		&bnd->duid, bnd->ia_type, bnd->ia_id, bnd->refcount);

	bnd->refcount++;
	return bnd;
}

static inline void dhcp6_bnd_unref(struct dhcp6_binding **bnd)
{
	if (!*bnd)
		return;
	if (!--(*bnd)->refcount)
		dhcp6_bnd_free(*bnd);
	*bnd = NULL;
}

#endif /* _FRR_DHCP6_STATE_H */
