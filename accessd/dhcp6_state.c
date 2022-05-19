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

#include <zebra.h>

#include "command.h"
#include "if.h"
#include "jhash.h"
#include "memory.h"
#include "network.h"
#include "printfrr.h"
#include "prefix.h"
#include "privs.h"
#include "sockopt.h"
#include "thread.h"
#include "vrf.h"

#include "accessd.h"

#include "dhcp6_protocol.h"

#include "dhcp6_upstream.h"
#include "dhcp6_state.h"
#include "dhcp6_iface.h"
#include "dhcp6_zebra.h"

#include "persist.h"

DEFINE_MTYPE_STATIC(DHCP6, DHCP6_BINDING,    "DHCPv6 binding");
DEFINE_MTYPE_STATIC(DHCP6, DHCP6_BINDING_PD, "DHCPv6 binding PD prefix");
DEFINE_MTYPE_STATIC(DHCP6, DHCP6_ITER,       "DHCPv6 binding iterator");

int duid_compare(const struct dhcp6_duid *a, const struct dhcp6_duid *b)
{
	if (a->type < b->type)
		return -1;
	if (a->type > b->type)
		return 1;

	if (a->size < b->size)
		return -1;
	if (a->size > b->size)
		return 1;

	return memcmp(a->raw, b->raw, a->size);
}

static int dhcp6_binding_cmp(const struct dhcp6_binding *a,
			     const struct dhcp6_binding *b)
{
	int rv;

	rv = duid_compare(&a->duid, &b->duid);
	if (rv)
		return rv;

	if (a->ia_type < b->ia_type)
		return -1;
	if (a->ia_type > b->ia_type)
		return 1;

	if (a->ia_id < b->ia_id)
		return -1;
	if (a->ia_id > b->ia_id)
		return 1;

	return 0;
}

static uint32_t dhcp6_binding_hash(const struct dhcp6_binding *a)
{
	return jhash(&a->hash_begin, offsetof(struct dhcp6_binding, hash_end)
		     - offsetof(struct dhcp6_binding, hash_begin), 0xb942a5c7);
}

DECLARE_HASH(dhcp6_bindings, struct dhcp6_binding, item, dhcp6_binding_cmp,
	     dhcp6_binding_hash);

static struct dhcp6_bindings_head bindings[1];

struct dhcp6_binding *dhcp6_bnd_alloc(struct vrf *vrf,
				      const struct dhcp6_duid *duid,
				      uint16_t ia_type, uint32_t ia_id)
{
	struct dhcp6_binding *ret, ref;

	assert(duid->size < sizeof(duid->raw));

	memset(&ref, 0, sizeof(ref));
	ref.duid.size = duid->size;
	ref.duid.type = duid->type;
	memcpy(ref.duid.raw, duid->raw, duid->size);
	ref.ia_type = ia_type;
	ref.ia_id = ia_id;

	ret = dhcp6_bindings_find(bindings, &ref);
	if (ret)
		return dhcp6_bnd_ref(ret);

	ret = XMALLOC(MTYPE_DHCP6_BINDING, sizeof(*ret));
	memcpy(ret, &ref, sizeof(*ret));
	dhcp6_pds_init(ret->pds);
	dhcp6_bindings_add(bindings, ret);

	/* dhcp6_bnd_ref() asserts on bnd->invalid */
	ret->invalid = true;
	ret->refcount = 1;
	return ret;
}

void dhcp6_bnd_free(struct dhcp6_binding *bnd)
{
	struct dhcp6_pdprefix *pd;

	dhcp6_bindings_del(bindings, bnd);
	while ((pd = dhcp6_pds_pop(bnd->pds)))
		XFREE(MTYPE_DHCP6_BINDING_PD, pd);

	XFREE(MTYPE_DHCP6_BINDING, bnd);
}

/* backend iterators are required to return results in the proper order, so
 * iteration works by lockstepping all backends.  This is easy for ID-order
 * iteration but not so much for expiry since data might be out of sync in
 * a backend.
 */

/* NB: tgts[i]->next holds a reference on the binding. best_next does NOT.
 * but when clearing tgts[i]->next, that reference needs to be dropped!
 */
struct dhcp6_iter_pertgt {
	struct persist_target *target;
	struct dhcp6_binding *next;
};

struct dhcp6_iter {
	size_t ntargets;
	struct dhcp6_binding *best_next;
	struct dhcp6_iter_pertgt tgts[0];
};

/* just safety wrappers */
struct dhcp6_id_iter {
	struct dhcp6_iter v;
};

struct dhcp6_expy_iter {
	struct dhcp6_iter v;
};

static void dhcp6_bnd_end(struct dhcp6_iter *iter)
{
	size_t i;

	for (i = 0; i < iter->ntargets; i++)
		dhcp6_bnd_unref(&iter->tgts[i].next);

	XFREE(MTYPE_DHCP6_ITER, iter);
}


struct dhcp6_id_iter *dhcp6_bnd_id_begin(struct vrf *vrf)
{
	struct persist_targets_head *tgts = ps_backends(vrf);
	struct persist_target *target;
	size_t ntargets = persist_targets_count(tgts);
	struct dhcp6_id_iter *iter;
	size_t i = 0;

	iter = XCALLOC(MTYPE_DHCP6_ITER, sizeof(*iter) +
		       ntargets * sizeof(struct dhcp6_iter_pertgt *));
	iter->v.ntargets = ntargets;

	frr_each (persist_targets, tgts, target) {
		struct dhcp6_binding *this_next;

		this_next = target->ops->dhcp6_id_first(target);

		if (!iter->v.best_next
		    || (this_next && dhcp6_binding_cmp(this_next,
						       iter->v.best_next) < 0))
			iter->v.best_next = this_next;

		assert(i < ntargets);
		iter->v.tgts[i].next = this_next;
		iter->v.tgts[i].target = target;

		i++;
	}
	return iter;
}

struct dhcp6_binding *dhcp6_bnd_id_next(struct dhcp6_id_iter *iter)
{
	struct dhcp6_iter_pertgt *now, *end;
	struct dhcp6_binding *next;

	if (!iter->v.best_next)
		return NULL;

	/* next has a reference held because it's also in at least one of the
	 * tgt[i]->next fields.  But we're dropping that below.  So this is
	 * the reference that gets returned which the caller gets to own.
	 */
	next = dhcp6_bnd_ref(iter->v.best_next);
	iter->v.best_next = NULL;

	now = &iter->v.tgts[0];
	end = now + iter->v.ntargets;

	for (; now < end; now++) {
		struct persist_target *target = now->target;

		if (now->next == next) {
			dhcp6_bnd_unref(&now->next);
			now->next = target->ops->dhcp6_id_next(target, next);
		}
		if (!now->next)
			continue;

		if (!iter->v.best_next
		    || (now->next && dhcp6_binding_cmp(now->next,
						       iter->v.best_next) < 0))
			iter->v.best_next = now->next;
	}

	return next;
}

void dhcp6_bnd_id_end(struct dhcp6_id_iter *iter)
{
	dhcp6_bnd_end(&iter->v);
}

#if 0
struct dhcp6_expy_iter *dhcp6_bnd_expy_begin(struct vrf *vrf)
{
}

struct dhcp6_binding *dhcp6_bnd_expy_next(struct dhcp6_expy_iter *iter);
{
}

void dhcp6_bnd_expy_end(struct dhcp6_expy_iter *iter)
{
	dhcp6_bnd_end(&iter->v);
}
#endif

struct dhcp6_binding *dhcp6_bnd_get(struct vrf *vrf,
				    const struct dhcp6_duid *duid,
				    uint16_t ia_type, uint32_t ia_id)
{
	struct persist_targets_head *tgts;
	struct persist_target *target;
	struct dhcp6_binding *bnd;

	bnd = dhcp6_bnd_alloc(vrf, duid, ia_type, ia_id);
	if (!bnd->invalid)
		return bnd;

	tgts = ps_backends(bnd->vrf);
	frr_each (persist_targets, tgts, target)
		if (target->ops->dhcp6_fill)
			target->ops->dhcp6_fill(target, bnd);

	if (bnd->invalid) {
		dhcp6_bnd_unref(&bnd);
		assert(!bnd);
	}
	return bnd;
}


void dhcp6_bnd_update(struct dhcp6_binding *bnd)
{
	struct persist_targets_head *tgts = ps_backends(bnd->vrf);
	struct persist_target *target;

	frr_each (persist_targets, tgts, target)
		if (target->ops->dhcp6_update)
			target->ops->dhcp6_update(target, bnd);
}

void dhcp6_bnd_expire(struct dhcp6_binding *bnd)
{
	struct persist_targets_head *tgts = ps_backends(bnd->vrf);
	struct persist_target *target;

	frr_each (persist_targets, tgts, target)
		if (target->ops->dhcp6_expire)
			target->ops->dhcp6_expire(target, bnd);
}

void dhcp6_bnd_pd_drop(struct dhcp6_pdprefix *pdp)
{
	dhcp6_pds_del(pdp->binding->pds, pdp);
	XFREE(MTYPE_DHCP6_BINDING_PD, pdp);
}

struct dhcp6_pdprefix *dhcp6_bnd_pd_get(struct dhcp6_binding *bnd,
					union prefixconstptr pu)
{
	struct dhcp6_pdprefix *ret, ref;

	ref.prefix = *pu.p6;
	ret = dhcp6_pds_find(bnd->pds, &ref);
	if (ret)
		return ret;

	ret = XCALLOC(MTYPE_DHCP6_BINDING_PD, sizeof(*ret));
	ret->binding = bnd;
	ret->prefix = *pu.p6;
	dhcp6_pds_add(bnd->pds, ret);
	return ret;
}

#if 0
static int dhcp6_binding_age(struct thread *t);

extern struct thread_master *master;

void dhcp6_bnd_update(struct dhcp6_binding *bnd)
{
	struct timeval now, delta;
	struct dhcp6_pdprefix *pdp, *earliest = NULL;

	monotime(&now);
	thread_cancel(&bnd->t_age);

	zlog_info("update %pDUID type %u ID %u",
		  &bnd->duid, bnd->ia_type, bnd->ia_id);

	frr_each_safe (dhcp6_pds, bnd->pds, pdp) {
		bool valid;

		timersub(&pdp->t_valid, &now, &delta);
		valid = delta.tv_sec >= 0;

		if (valid && (!earliest || timercmp(&pdp->t_valid,
						    &earliest->t_valid, <)))
			earliest = pdp;

		if (valid == pdp->valid)
			continue;

		if (!valid) {
			if (pdp->in_zebra)
				dhcp6r_zebra_ipv6_del(bnd, pdp);

			dhcp6_bnd_pd_drop(pdp);
			continue;
		}

		pdp->valid = valid;
		if (!pdp->in_zebra)
			dhcp6r_zebra_ipv6_add(bnd, pdp);
	}

	if (!earliest) {
		dhcp6_bnd_drop(bnd);
		return;
	}

	timersub(&earliest->t_valid, &now, &delta);

	thread_add_timer_tv(master, dhcp6_binding_age, bnd, &delta,
			    &bnd->t_age);
}

static int dhcp6_binding_age(struct thread *t)
{
	struct dhcp6_binding *bnd = THREAD_ARG(t);

	dhcp6_bnd_update(bnd);
	return 0;
}
#endif

/* CLI */

#define DHCP_STR "Dynamic Host Configuration Protocol\n"

DEFUN (show_dhcp6_bindings,
       show_dhcp6_bindings_cmd,
       "show ipv6 dhcp bindings",
       SHOW_STR
       IPV6_STR
       DHCP_STR
       "Display binding table\n")
{
	struct dhcp6_binding *bnd;
	struct dhcp6_pdprefix *pdp;

	vty_out(vty, "Binding table:\n\n");
	frr_each (dhcp6_bindings, bindings, bnd) {
		vty_out(vty, "%pDUID type %u ID %u:\n",
			&bnd->duid, bnd->ia_type, bnd->ia_id);

		if (bnd->t_age)
			vty_out(vty, "  ageing timer triggering in %.2fs\n",
				thread_timer_remain_msec(bnd->t_age) * 0.001);

/*		vty_out(vty, "  T1: %.2fs, T2: %.2fs\n",
			monotime_until( */

		frr_each (dhcp6_pds, bnd->pds, pdp) {
			vty_out(vty, "  PD %pFX:  preferred %.2fs, valid %.2fs\n",
				&pdp->prefix,
				monotime_until(&pdp->t_pref, NULL) * 0.000001f,
				monotime_until(&pdp->t_valid, NULL) * 0.000001f);
		}
	}

	return CMD_SUCCESS;
}

void dhcp6_state_init(void)
{
	dhcp6_bindings_init(bindings);

	install_element(VIEW_NODE, &show_dhcp6_bindings_cmd);
}
