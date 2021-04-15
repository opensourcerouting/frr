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

DEFINE_MTYPE_STATIC(DHCP6, DHCP6_BINDING,    "DHCPv6 binding");
DEFINE_MTYPE_STATIC(DHCP6, DHCP6_BINDING_PD, "DHCPv6 binding PD prefix");

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
extern struct thread_master *master;

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

void dhcp6_bnd_drop(struct dhcp6_binding *bnd)
{
	struct dhcp6_pdprefix *pd;

	dhcp6_bindings_del(bindings, bnd);
	while ((pd = dhcp6_pds_pop(bnd->pds)))
		XFREE(MTYPE_DHCP6_BINDING_PD, pd);

	XFREE(MTYPE_DHCP6_BINDING, bnd);
}

struct dhcp6_binding *dhcp6_bnd_get(struct dhcp6_duid *duid,
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
		return ret;

	ret = XMALLOC(MTYPE_DHCP6_BINDING, sizeof(*ret));
	memcpy(ret, &ref, sizeof(*ret));
	dhcp6_pds_init(ret->pds);
	dhcp6_bindings_add(bindings, ret);

	return ret;
}

static int dhcp6_binding_age(struct thread *t);

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
