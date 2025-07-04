// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IP MSDP for Quagga
 * Copyright (C) 2016 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include <lib/hash.h>
#include <lib/jhash.h>
#include <lib/log.h>
#include <lib/prefix.h>
#include <lib/sockunion.h>
#include <lib/stream.h>
#include <frrevent.h>
#include <lib/vty.h>
#include <lib/plist.h>
#include <lib/lib_errors.h>

#include "pimd.h"
#include "pim_memory.h"
#include "pim_instance.h"
#include "pim_iface.h"
#include "pim_rp.h"
#include "pim_str.h"
#include "pim_time.h"
#include "pim_upstream.h"
#include "pim_oil.h"
#include "pim_nht.h"

#include "pim_msdp.h"
#include "pim_msdp_packet.h"
#include "pim_msdp_socket.h"

static void pim_msdp_peer_listen(struct pim_msdp_peer *mp);
static void pim_msdp_peer_cr_timer_setup(struct pim_msdp_peer *mp, bool start);
static void pim_msdp_peer_ka_timer_setup(struct pim_msdp_peer *mp, bool start);
static void pim_msdp_peer_hold_timer_setup(struct pim_msdp_peer *mp,
					   bool start);
static void pim_msdp_peer_free(struct pim_msdp_peer *mp);
static void pim_msdp_enable(struct pim_instance *pim);
static void pim_msdp_sa_adv_timer_setup(struct pim_instance *pim, bool start);
static void pim_msdp_sa_deref(struct pim_msdp_sa *sa,
			      enum pim_msdp_sa_flags flags);
static int pim_msdp_mg_mbr_comp(const void *p1, const void *p2);
static void pim_msdp_mg_mbr_free(struct pim_msdp_mg_mbr *mbr);

void pim_msdp_originator_id(struct pim_instance *pim, const struct prefix *group,
			    struct in_addr *originator_id)
{
	struct rp_info *rp_info;

	originator_id->s_addr = INADDR_ANY;

	/* Originator ID was configured, use it. */
	if (pim->msdp.originator_id.s_addr != INADDR_ANY) {
		*originator_id = pim->msdp.originator_id;
		return;
	}

	rp_info = pim_rp_find_match_group(pim, group);
	if (rp_info) {
		*originator_id = rp_info->rp.rpf_addr;
		return;
	}
}

uint32_t pim_msdp_sa_asn(const struct pim_msdp_sa *sa)
{
	struct pim_msdp_peer *peer = pim_msdp_peer_find(sa->pim, sa->peer);

	if (peer == NULL)
		return 0;

	return peer->asn;
}

/************************ SA cache management ******************************/
/* RFC-3618:Sec-5.1 - global active source advertisement timer */
static void pim_msdp_sa_adv_timer_cb(struct event *t)
{
	struct pim_instance *pim = EVENT_ARG(t);

	if (pim_msdp_log_sa_events(pim))
		zlog_info("MSDP SA advertisement timer expired");

	pim_msdp_sa_adv_timer_setup(pim, true /* start */);
	pim_msdp_pkt_sa_tx(pim);
}

static void pim_msdp_sa_adv_timer_setup(struct pim_instance *pim, bool start)
{
	event_cancel(&pim->msdp.sa_adv_timer);
	if (start) {
		event_add_timer(pim->msdp.master, pim_msdp_sa_adv_timer_cb, pim,
				PIM_MSDP_SA_ADVERTISMENT_TIME,
				&pim->msdp.sa_adv_timer);
	}
}

/* RFC-3618:Sec-5.3 - SA cache state timer */
static void pim_msdp_sa_state_timer_cb(struct event *t)
{
	struct pim_msdp_sa *sa;

	sa = EVENT_ARG(t);

	if (pim_msdp_log_sa_events(sa->pim))
		zlog_info("MSDP SA %s state timer expired", sa->sg_str);

	pim_msdp_sa_deref(sa, PIM_MSDP_SAF_PEER);
}

static void pim_msdp_sa_state_timer_setup(struct pim_msdp_sa *sa, bool start)
{
	event_cancel(&sa->sa_state_timer);
	if (start) {
		event_add_timer(sa->pim->msdp.master,
				pim_msdp_sa_state_timer_cb, sa,
				PIM_MSDP_SA_HOLD_TIME, &sa->sa_state_timer);
	}
}

static void pim_msdp_sa_upstream_del(struct pim_msdp_sa *sa)
{
	struct pim_upstream *up = sa->up;
	if (!up) {
		return;
	}

	sa->up = NULL;
	if (PIM_UPSTREAM_FLAG_TEST_SRC_MSDP(up->flags)) {
		PIM_UPSTREAM_FLAG_UNSET_SRC_MSDP(up->flags);
		sa->flags |= PIM_MSDP_SAF_UP_DEL_IN_PROG;
		up = pim_upstream_del(sa->pim, up, __func__);
		/* re-eval joinDesired; clearing peer-msdp-sa flag can
		 * cause JD to change
		 */
		if (up)
			pim_upstream_update_join_desired(sa->pim, up);
		sa->flags &= ~PIM_MSDP_SAF_UP_DEL_IN_PROG;
	}

	if (pim_msdp_log_sa_events(sa->pim))
		zlog_info("MSDP SA %s de-referenced SPT", sa->sg_str);
}

static bool pim_msdp_sa_upstream_add_ok(struct pim_msdp_sa *sa,
					struct pim_upstream *xg_up)
{
	if (!(sa->flags & PIM_MSDP_SAF_PEER)) {
		/* SA should have been rxed from a peer */
		return false;
	}
	/* check if we are RP */
	if (!I_am_RP(sa->pim, sa->sg.grp)) {
		return false;
	}

	/* check if we have a (*, G) with a non-empty immediate OIL */
	if (!xg_up) {
		pim_sgaddr sg;

		memset(&sg, 0, sizeof(sg));
		sg.grp = sa->sg.grp;

		xg_up = pim_upstream_find(sa->pim, &sg);
	}
	if (!xg_up || (xg_up->join_state != PIM_UPSTREAM_JOINED)) {
		/* join desired will be true for such (*, G) entries so we will
		 * just look at join_state and let the PIM state machine do the
		 * rest of
		 * the magic */
		return false;
	}

	return true;
}

/* Upstream add evaluation needs to happen everytime -
 * 1. Peer reference is added or removed.
 * 2. The RP for a group changes.
 * 3. joinDesired for the associated (*, G) changes
 * 4. associated (*, G) is removed - this seems like a bit redundant
 *    (considering #4); but just in case an entry gets nuked without
 *    upstream state transition
 *    */
static void pim_msdp_sa_upstream_update(struct pim_msdp_sa *sa,
					struct pim_upstream *xg_up,
					const char *ctx)
{
	struct pim_upstream *up;

	if (!pim_msdp_sa_upstream_add_ok(sa, xg_up)) {
		pim_msdp_sa_upstream_del(sa);
		return;
	}

	if (sa->up) {
		/* nothing to do */
		return;
	}

	up = pim_upstream_find(sa->pim, &sa->sg);
	if (up && (PIM_UPSTREAM_FLAG_TEST_SRC_MSDP(up->flags))) {
		/* somehow we lost track of the upstream ptr? best log it */
		sa->up = up;
		if (pim_msdp_log_sa_events(sa->pim))
			zlog_info("MSDP SA %s SPT reference missing", sa->sg_str);
		return;
	}

	/* RFC3618: "RP triggers a (S, G) join event towards the data source
	 * as if a JP message was rxed addressed to the RP itself." */
	up = pim_upstream_add(sa->pim, &sa->sg, NULL /* iif */,
			      PIM_UPSTREAM_FLAG_MASK_SRC_MSDP, __func__, NULL);

	sa->up = up;
	if (up) {
		/* update inherited oil */
		pim_upstream_inherited_olist(sa->pim, up);
		/* should we also start the kat in parallel? we will need it
		 * when the
		 * SA ages out */
		if (pim_msdp_log_sa_events(sa->pim))
			zlog_info("MSDP SA %s referenced SPT", sa->sg_str);
	} else {
		if (pim_msdp_log_sa_events(sa->pim))
			zlog_info("MSDP SA %s SPT reference failed", sa->sg_str);
	}
}

/* release all mem associated with a sa */
static void pim_msdp_sa_free(struct pim_msdp_sa *sa)
{
	pim_msdp_sa_state_timer_setup(sa, false);

	XFREE(MTYPE_PIM_MSDP_SA, sa);
}

static struct pim_msdp_sa *pim_msdp_sa_new(struct pim_instance *pim,
					   pim_sgaddr *sg, struct in_addr rp)
{
	struct pim_msdp_sa *sa;

	sa = XCALLOC(MTYPE_PIM_MSDP_SA, sizeof(*sa));

	sa->pim = pim;
	sa->sg = *sg;
	snprintfrr(sa->sg_str, sizeof(sa->sg_str), "%pSG", sg);
	sa->rp = rp;
	sa->uptime = pim_time_monotonic_sec();

	/* insert into misc tables for easy access */
	sa = hash_get(pim->msdp.sa_hash, sa, hash_alloc_intern);
	listnode_add_sort(pim->msdp.sa_list, sa);

	if (pim_msdp_log_sa_events(pim))
		zlog_info("MSDP SA %s created", sa->sg_str);

	return sa;
}

static struct pim_msdp_sa *pim_msdp_sa_find(struct pim_instance *pim,
					    pim_sgaddr *sg)
{
	struct pim_msdp_sa lookup;

	lookup.sg = *sg;
	return hash_lookup(pim->msdp.sa_hash, &lookup);
}

static struct pim_msdp_sa *pim_msdp_sa_add(struct pim_instance *pim,
					   pim_sgaddr *sg, struct in_addr rp)
{
	struct pim_msdp_sa *sa;

	sa = pim_msdp_sa_find(pim, sg);
	if (sa) {
		return sa;
	}

	return pim_msdp_sa_new(pim, sg, rp);
}

static void pim_msdp_sa_del(struct pim_msdp_sa *sa)
{
	/* this is somewhat redundant - still want to be careful not to leave
	 * stale upstream references */
	pim_msdp_sa_upstream_del(sa);

	/* stop timers */
	pim_msdp_sa_state_timer_setup(sa, false /* start */);

	/* remove the entry from various tables */
	listnode_delete(sa->pim->msdp.sa_list, sa);
	hash_release(sa->pim->msdp.sa_hash, sa);

	if (pim_msdp_log_sa_events(sa->pim))
		zlog_info("MSDP SA %s deleted", sa->sg_str);

	/* free up any associated memory */
	pim_msdp_sa_free(sa);
}

static void pim_msdp_sa_peer_ip_set(struct pim_msdp_sa *sa,
				    struct pim_msdp_peer *mp, struct in_addr rp)
{
	struct pim_msdp_peer *old_mp;

	/* optimize the "no change" case as it will happen
	 * frequently/periodically */
	if (mp && (sa->peer.s_addr == mp->peer.s_addr)) {
		return;
	}

	/* any time the peer ip changes also update the rp address */
	if (sa->peer.s_addr != INADDR_ANY) {
		old_mp = pim_msdp_peer_find(sa->pim, sa->peer);
		if (old_mp && old_mp->sa_cnt) {
			--old_mp->sa_cnt;
		}
	}

	if (mp) {
		++mp->sa_cnt;
		sa->peer = mp->peer;
	} else {
		sa->peer.s_addr = PIM_NET_INADDR_ANY;
	}
	sa->rp = rp;
}

/* When a local active-source is removed there is no way to withdraw the
 * source from peers. We will simply remove it from the SA cache so it will
 * not be sent in supsequent SA updates. Peers will consequently timeout the
 * SA.
 * Similarly a "peer-added" SA is never explicitly deleted. It is simply
 * aged out overtime if not seen in the SA updates from the peers.
 * XXX: should we provide a knob to drop entries learnt from a peer when the
 * peer goes down? */
static void pim_msdp_sa_deref(struct pim_msdp_sa *sa,
			      enum pim_msdp_sa_flags flags)
{
	bool update_up = false;

	if ((sa->flags & PIM_MSDP_SAF_LOCAL)) {
		if (flags & PIM_MSDP_SAF_LOCAL) {
			if (pim_msdp_log_sa_events(sa->pim))
				zlog_info("MSDP SA %s local reference removed", sa->sg_str);

			if (sa->pim->msdp.local_cnt)
				--sa->pim->msdp.local_cnt;
		}
	}

	if ((sa->flags & PIM_MSDP_SAF_PEER)) {
		if (flags & PIM_MSDP_SAF_PEER) {
			struct in_addr rp;

			if (pim_msdp_log_sa_events(sa->pim))
				zlog_info("MSDP SA %s peer reference removed", sa->sg_str);

			pim_msdp_sa_state_timer_setup(sa, false /* start */);
			rp.s_addr = INADDR_ANY;
			pim_msdp_sa_peer_ip_set(sa, NULL /* mp */, rp);
			/* if peer ref was removed we need to remove the msdp
			 * reference on the
			 * msdp entry */
			update_up = true;
		}
	}

	sa->flags &= ~flags;
	if (update_up) {
		pim_msdp_sa_upstream_update(sa, NULL /* xg_up */, "sa-deref");
	}

	if (!(sa->flags & PIM_MSDP_SAF_REF)) {
		pim_msdp_sa_del(sa);
	}
}

void pim_msdp_sa_ref(struct pim_instance *pim, struct pim_msdp_peer *mp,
		     pim_sgaddr *sg, struct in_addr rp)
{
	struct pim_msdp_sa *sa;
	struct prefix grp;

	/* Check peer SA limit. */
	if (mp && mp->sa_limit && mp->sa_cnt >= mp->sa_limit) {
		if (pim_msdp_log_sa_events(pim))
			zlog_debug("MSDP peer %pI4 reject SA (%pI4, %pI4): SA limit %u of %u",
				   &mp->peer, &sg->src, &sg->grp, mp->sa_cnt, mp->sa_limit);

		return;
	}

	sa = pim_msdp_sa_add(pim, sg, rp);
	if (!sa) {
		return;
	}

	/* reference it */
	if (mp) {
		if (!(sa->flags & PIM_MSDP_SAF_PEER)) {
			sa->flags |= PIM_MSDP_SAF_PEER;
			if (pim_msdp_log_sa_events(pim))
				zlog_info("MSDP SA %s added by peer", sa->sg_str);
		}
		pim_msdp_sa_peer_ip_set(sa, mp, rp);
		/* start/re-start the state timer to prevent cache expiry */
		pim_msdp_sa_state_timer_setup(sa, true /* start */);
		/* We re-evaluate SA "SPT-trigger" everytime we hear abt it from
		 * a
		 * peer. XXX: If this becomes too much of a periodic overhead we
		 * can make it event based */
		pim_msdp_sa_upstream_update(sa, NULL /* xg_up */, "peer-ref");
	} else {
		if (!(sa->flags & PIM_MSDP_SAF_LOCAL)) {
			sa->flags |= PIM_MSDP_SAF_LOCAL;
			++sa->pim->msdp.local_cnt;
			if (pim_msdp_log_sa_events(pim))
				zlog_info("MSDP SA %s added locally", sa->sg_str);

			/* send an immediate SA update to peers */
			pim_addr_to_prefix(&grp, sa->sg.grp);
			pim_msdp_originator_id(pim, &grp, &sa->rp);
			pim_msdp_pkt_sa_tx_one(sa);
		}
		sa->flags &= ~PIM_MSDP_SAF_STALE;
	}
}

/* The following criteria must be met to originate an SA from the MSDP
 * speaker -
 * 1. KAT must be running i.e. source is active.
 * 2. We must be RP for the group.
 * 3. Source must be registrable to the RP (this is where the RFC is vague
 *    and especially ambiguous in CLOS networks; with anycast RP all sources
 *    are potentially registrable to all RPs in the domain). We assume #3 is
 *    satisfied if -
 *    a. We are also the FHR-DR for the source (OR)
 *    b. We rxed a pim register (null or data encapsulated) within the last
 *       (3 * (1.5 * register_suppression_timer))).
 */
static bool pim_msdp_sa_local_add_ok(struct pim_upstream *up)
{
	struct pim_instance *pim = up->channel_oil->pim;

	if (!(pim->msdp.flags & PIM_MSDPF_ENABLE)) {
		return false;
	}

	if (!pim_upstream_is_kat_running(up))
		/* stream is not active */
		return false;

	if (!I_am_RP(pim, up->sg.grp)) {
		/* we are not RP for the group */
		return false;
	}

	/* we are the FHR-DR for this stream  or we are RP and have seen
	 * registers
	 * from a FHR for this source */
	if (PIM_UPSTREAM_FLAG_TEST_FHR(up->flags) || up->t_msdp_reg_timer) {
		return true;
	}

	return false;
}

static void pim_msdp_sa_local_add(struct pim_instance *pim, pim_sgaddr *sg)
{
	struct in_addr rp;
	rp.s_addr = INADDR_ANY;
	pim_msdp_sa_ref(pim, NULL /* mp */, sg, rp);
}

void pim_msdp_sa_local_del(struct pim_instance *pim, pim_sgaddr *sg)
{
	struct pim_msdp_sa *sa;

	sa = pim_msdp_sa_find(pim, sg);
	if (sa) {
		pim_msdp_sa_deref(sa, PIM_MSDP_SAF_LOCAL);
	}
}

/* we need to be very cautious with this API as SA del too can trigger an
 * upstream del and we will get stuck in a simple loop */
static void pim_msdp_sa_local_del_on_up_del(struct pim_instance *pim,
					    pim_sgaddr *sg)
{
	struct pim_msdp_sa *sa;

	sa = pim_msdp_sa_find(pim, sg);
	if (sa) {
		if (PIM_DEBUG_MSDP_INTERNAL) {
			zlog_debug("MSDP local sa %s del on up del",
				   sa->sg_str);
		}

		/* if there is no local reference escape */
		if (!(sa->flags & PIM_MSDP_SAF_LOCAL)) {
			if (PIM_DEBUG_MSDP_INTERNAL) {
				zlog_debug("MSDP local sa %s del; no local ref",
					   sa->sg_str);
			}
			return;
		}

		if (sa->flags & PIM_MSDP_SAF_UP_DEL_IN_PROG) {
			/* MSDP is the one that triggered the upstream del. if
			 * this happens
			 * we most certainly have a bug in the PIM upstream
			 * state machine. We
			 * will not have a local reference unless the KAT is
			 * running. And if the
			 * KAT is running there MUST be an additional
			 * source-stream reference to
			 * the flow. Accounting for such cases requires lot of
			 * changes; perhaps
			 * address this in the next release? - XXX  */
			flog_err(
				EC_LIB_DEVELOPMENT,
				"MSDP sa %s SPT teardown is causing the local entry to be removed",
				sa->sg_str);
			return;
		}

		/* we are dropping the sa on upstream del we should not have an
		 * upstream reference */
		if (sa->up) {
			if (PIM_DEBUG_MSDP_INTERNAL) {
				zlog_debug("MSDP local sa %s del; up non-NULL",
					   sa->sg_str);
			}
			sa->up = NULL;
		}
		pim_msdp_sa_deref(sa, PIM_MSDP_SAF_LOCAL);
	}
}

/* Local SA qualification needs to be re-evaluated when -
 * 1. KAT is started or stopped
 * 2. on RP changes
 * 3. Whenever FHR status changes for a (S,G) - XXX - currently there
 *    is no clear path to transition an entry out of "MASK_FHR" need
 *    to discuss this with Donald. May result in some strangeness if the
 *    FHR is also the RP.
 * 4. When msdp_reg timer is started or stopped
 */
void pim_msdp_sa_local_update(struct pim_upstream *up)
{
	struct pim_instance *pim = up->channel_oil->pim;

	if (pim_msdp_sa_local_add_ok(up)) {
		pim_msdp_sa_local_add(pim, &up->sg);
	} else {
		pim_msdp_sa_local_del(pim, &up->sg);
	}
}

static void pim_msdp_sa_local_setup(struct pim_instance *pim)
{
	struct pim_upstream *up;

	frr_each (rb_pim_upstream, &pim->upstream_head, up)
		pim_msdp_sa_local_update(up);
}

/* whenever the RP changes we need to re-evaluate the "local" SA-cache */
/* XXX: needs to be tested */
void pim_msdp_i_am_rp_changed(struct pim_instance *pim)
{
	struct listnode *sanode;
	struct listnode *nextnode;
	struct pim_msdp_sa *sa;

	if (!(pim->msdp.flags & PIM_MSDPF_ENABLE)) {
		/* if the feature is not enabled do nothing */
		return;
	}

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP i_am_rp changed");
	}

	/* mark all local entries as stale */
	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		if (sa->flags & PIM_MSDP_SAF_LOCAL) {
			sa->flags |= PIM_MSDP_SAF_STALE;
		}
	}

	/* re-setup local SA entries */
	pim_msdp_sa_local_setup(pim);

	for (ALL_LIST_ELEMENTS(pim->msdp.sa_list, sanode, nextnode, sa)) {
		/* purge stale SA entries */
		if (sa->flags & PIM_MSDP_SAF_STALE) {
			/* clear the stale flag; the entry may be kept even
			 * after
			 * "local-deref" */
			sa->flags &= ~PIM_MSDP_SAF_STALE;
			/* sa_deref can end up freeing the sa; so don't access
			 * contents after */
			pim_msdp_sa_deref(sa, PIM_MSDP_SAF_LOCAL);
		} else {
			/* if the souce is still active check if we can
			 * influence SPT */
			pim_msdp_sa_upstream_update(sa, NULL /* xg_up */,
						    "rp-change");
		}
	}
}

/* We track the join state of (*, G) entries. If G has sources in the SA-cache
 * we need to setup or teardown SPT when the JoinDesired status changes for
 * (*, G) */
void pim_msdp_up_join_state_changed(struct pim_instance *pim,
				    struct pim_upstream *xg_up)
{
	struct listnode *sanode;
	struct pim_msdp_sa *sa;

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP join state changed for %s", xg_up->sg_str);
	}

	/* If this is not really an XG entry just move on */
	if (!pim_addr_is_any(xg_up->sg.src) || pim_addr_is_any(xg_up->sg.grp)) {
		return;
	}

	/* XXX: Need to maintain SAs per-group to avoid all this unnecessary
	 * walking */
	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		if (pim_addr_cmp(sa->sg.grp, xg_up->sg.grp)) {
			continue;
		}
		pim_msdp_sa_upstream_update(sa, xg_up, "up-jp-change");
	}
}

static void pim_msdp_up_xg_del(struct pim_instance *pim, pim_sgaddr *sg)
{
	struct listnode *sanode;
	struct pim_msdp_sa *sa;

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP %pSG del", sg);
	}

	/* If this is not really an XG entry just move on */
	if (!pim_addr_is_any(sg->src) || pim_addr_is_any(sg->grp)) {
		return;
	}

	/* XXX: Need to maintain SAs per-group to avoid all this unnecessary
	 * walking */
	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		if (pim_addr_cmp(sa->sg.grp, sg->grp)) {
			continue;
		}
		pim_msdp_sa_upstream_update(sa, NULL /* xg */, "up-jp-change");
	}
}

void pim_msdp_up_del(struct pim_instance *pim, pim_sgaddr *sg)
{
	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP up %pSG del", sg);
	}
	if (pim_addr_is_any(sg->src)) {
		pim_msdp_up_xg_del(pim, sg);
	} else {
		pim_msdp_sa_local_del_on_up_del(pim, sg);
	}
}

/* sa hash and peer list helpers */
static unsigned int pim_msdp_sa_hash_key_make(const void *p)
{
	const struct pim_msdp_sa *sa = p;

	return pim_sgaddr_hash(sa->sg, 0);
}

static bool pim_msdp_sa_hash_eq(const void *p1, const void *p2)
{
	const struct pim_msdp_sa *sa1 = p1;
	const struct pim_msdp_sa *sa2 = p2;

	return !pim_sgaddr_cmp(sa1->sg, sa2->sg);
}

static int pim_msdp_sa_comp(const void *p1, const void *p2)
{
	const struct pim_msdp_sa *sa1 = p1;
	const struct pim_msdp_sa *sa2 = p2;

	return pim_sgaddr_cmp(sa1->sg, sa2->sg);
}

DEFINE_MTYPE_STATIC(PIMD, MSDP_RP_CACHE, "MSDP RP cache entry");

struct msdp_rp_cache {
	struct msdp_rp_cache_item item;

	struct in_addr rp_addr;
	struct in_addr nexthop_addr;
	uint32_t nexthop_asn;
	struct in_addr selected_msdp;

	struct pim_instance *pim;
	struct timeval lastuse;
	struct event *refresh;
};

static int msdp_rp_cache_cmp(const struct msdp_rp_cache *a, const struct msdp_rp_cache *b)
{
	return IPV4_ADDR_CMP(&a->rp_addr, &b->rp_addr);
}

static uint32_t msdp_rp_cache_hash(const struct msdp_rp_cache *a)
{
	return jhash_1word(a->rp_addr.s_addr, 0x4e622350);
}

DECLARE_HASH(msdp_rp_cache, struct msdp_rp_cache, item, msdp_rp_cache_cmp, msdp_rp_cache_hash);

static void msdp_rp_cache_update(struct msdp_rp_cache *ent)
{
	struct pim_nexthop nexthop = {};
	uint32_t asn = 0;
	struct pim_msdp_peer *mp;
	unsigned int best_preference = ~0U;
	const char *rule = "nothing found";
	struct in_addr best_addr = {};
	struct listnode *node;

	if (!pim_bgp_nht_lookup(ent->pim, &nexthop, ent->rp_addr, PIMADDR_ANY, &asn)) {
		ent->nexthop_addr.s_addr = INADDR_ANY;
		ent->nexthop_asn = 0;
		return;
	}

	if (PIM_DEBUG_ZEBRA && (IPV4_ADDR_CMP(&ent->nexthop_addr, &nexthop.mrib_nexthop_addr) ||
				ent->nexthop_asn != asn)) {
		zlog_debug("MSDP RP %pI4: nexthop changed to %pI4 [AS%u] (was %pI4 [AS%u])",
			   &ent->rp_addr, &nexthop.mrib_nexthop_addr, asn, &ent->nexthop_addr,
			   ent->nexthop_asn);
	}

	ent->nexthop_addr = nexthop.mrib_nexthop_addr;
	ent->nexthop_asn = asn;

	for (ALL_LIST_ELEMENTS_RO(ent->pim->msdp.peer_list, node, mp)) {
		if (mp->state != PIM_MSDP_ESTABLISHED)
			continue;

		/* N == R */
		if (!IPV4_ADDR_CMP(&mp->peer, &ent->rp_addr)) {
			best_addr = mp->peer;
			rule = "(i) MSDP peer is RP";
			if (IPV4_ADDR_CMP(&mp->peer, &ent->nexthop_addr))
				rule = "(i) MSDP peer is RP [NOTE: RPF mismatch]";
			/* no point in looking further */
			break;
		}

		/* is nexthop */
		if (!IPV4_ADDR_CMP(&mp->peer, &ent->nexthop_addr) && best_preference > 3) {
			best_preference = 3;
			best_addr = mp->peer;
			rule = "(ii/iii) MSDP peer is nexthop to RP";
		}

		if (best_preference == 3)
			continue;

		if (ent->nexthop_asn == mp->asn &&
		    (best_preference > 4 || IPV4_ADDR_CMP(&best_addr, &mp->peer) > 0)) {
			best_preference = 4;
			best_addr = mp->peer;
			rule = "(iv) MSDP peer is in closest AS to RP";
		}

		if (best_preference == 4)
			continue;

		/* 5 - static peer - not supported */
	}

	if (PIM_DEBUG_ZEBRA && IPV4_ADDR_CMP(&ent->selected_msdp, &best_addr))
		zlog_debug("MSDP RP %pI4: best MSDP peer changed to %pI4 [%s] (was %pI4)",
			   &ent->rp_addr, &best_addr, rule, &ent->selected_msdp);

	ent->selected_msdp = best_addr;
}

static void msdp_rp_cache_timer(struct event *e)
{
	struct msdp_rp_cache *ent = EVENT_ARG(e);
	int64_t us_since;

	us_since = monotime_since(&ent->lastuse, NULL);
	if (us_since > 135 * 1000 * 1000) {
		if (PIM_DEBUG_ZEBRA)
			zlog_debug("MSDP RP %pI4: expired, dropping", &ent->rp_addr);

		msdp_rp_cache_del(ent->pim->msdp.rp_cache, ent);
		XFREE(MTYPE_MSDP_RP_CACHE, ent);
		return;
	}

	msdp_rp_cache_update(ent);

	event_add_timer_msec(ent->pim->msdp.master, msdp_rp_cache_timer, ent, 60000, &ent->refresh);
}

static struct msdp_rp_cache *msdp_rp_cache_get(struct pim_instance *pim, struct in_addr addr)
{
	struct msdp_rp_cache *ent, ref = { .rp_addr = addr };

	ent = msdp_rp_cache_find(pim->msdp.rp_cache, &ref);
	if (!ent) {
		ent = XCALLOC(MTYPE_MSDP_RP_CACHE, sizeof(*ent));
		ent->rp_addr = addr;
		ent->pim = pim;

		msdp_rp_cache_add(pim->msdp.rp_cache, ent);
		msdp_rp_cache_update(ent);
		event_add_timer_msec(pim->msdp.master, msdp_rp_cache_timer, ent, 59000,
				     &ent->refresh);
	}

	monotime(&ent->lastuse);
	return ent;
}

static void msdp_rp_cache_clear(struct pim_instance *pim)
{
	struct msdp_rp_cache *ent;

	while ((ent = msdp_rp_cache_pop(pim->msdp.rp_cache))) {
		event_cancel(&ent->refresh);
		XFREE(MTYPE_MSDP_RP_CACHE, ent);
	}

	msdp_rp_cache_fini(pim->msdp.rp_cache);
}

/* RFC-3618:Sec-10.1.3 - Peer-RPF forwarding */
/* XXX: this can use a bit of refining and extensions */
bool pim_msdp_peer_rpf_check(struct pim_msdp_peer *mp, struct in_addr rp)
{
	struct msdp_rp_cache *ent;

	ent = msdp_rp_cache_get(mp->pim, rp);
	if (ent->selected_msdp.s_addr == mp->peer.s_addr)
		return true;

	if (pim_msdp_log_sa_events(mp->pim))
		zlog_info("MSDP peer %pI4 is not RPF for %pI4", &mp->peer, &rp);

	mp->rpf_lookup_failure_count++;
	return false;
}

/************************ Peer session management **************************/
char *pim_msdp_state_dump(enum pim_msdp_peer_state state, char *buf,
			  int buf_size)
{
	switch (state) {
	case PIM_MSDP_DISABLED:
		snprintf(buf, buf_size, "%s", "disabled");
		break;
	case PIM_MSDP_INACTIVE:
		snprintf(buf, buf_size, "%s", "inactive");
		break;
	case PIM_MSDP_LISTEN:
		snprintf(buf, buf_size, "%s", "listen");
		break;
	case PIM_MSDP_CONNECTING:
		snprintf(buf, buf_size, "%s", "connecting");
		break;
	case PIM_MSDP_ESTABLISHED:
		snprintf(buf, buf_size, "%s", "established");
		break;
	default:
		snprintf(buf, buf_size, "unk-%d", state);
	}
	return buf;
}

static void pim_msdp_peer_state_chg_log(struct pim_msdp_peer *mp)
{
	char state_str[PIM_MSDP_STATE_STRLEN];

	pim_msdp_state_dump(mp->state, state_str, sizeof(state_str));
	zlog_info("MSDP peer %s state changed to %s", mp->key_str, state_str);
}

/* MSDP Connection State Machine actions (defined in RFC-3618:Sec-11.2) */
/* 11.2.A2: active peer - start connect retry timer; when the timer fires
 * a tcp connection will be made */
static void pim_msdp_peer_connect(struct pim_msdp_peer *mp)
{
	/* Stop here if we are shutdown. */
	if (mp->pim->msdp.shutdown)
		return;

	mp->state = PIM_MSDP_CONNECTING;
	if (pim_msdp_log_neighbor_events(mp->pim))
		pim_msdp_peer_state_chg_log(mp);

	pim_msdp_peer_cr_timer_setup(mp, true /* start */);
}

/* 11.2.A3: passive peer - just listen for connections */
static void pim_msdp_peer_listen(struct pim_msdp_peer *mp)
{
	/* Stop here if we are shutdown. */
	if (mp->pim->msdp.shutdown)
		return;

	mp->state = PIM_MSDP_LISTEN;
	if (pim_msdp_log_neighbor_events(mp->pim))
		pim_msdp_peer_state_chg_log(mp);

	/* this is interntionally asymmetric i.e. we set up listen-socket when
	* the
	* first listening peer is configured; but don't bother tearing it down
	* when
	* all the peers go down */
	if (mp->auth_type == MSDP_AUTH_NONE)
		pim_msdp_sock_listen(mp->pim);
	else
		pim_msdp_sock_auth_listen(mp);
}

/* 11.2.A4 and 11.2.A5: transition active or passive peer to
 * established state */
void pim_msdp_peer_established(struct pim_msdp_peer *mp)
{
	if (mp->state != PIM_MSDP_ESTABLISHED) {
		++mp->est_flaps;
	}

	mp->state = PIM_MSDP_ESTABLISHED;
	mp->uptime = pim_time_monotonic_sec();

	if (pim_msdp_log_neighbor_events(mp->pim))
		pim_msdp_peer_state_chg_log(mp);

	/* stop retry timer on active peers */
	pim_msdp_peer_cr_timer_setup(mp, false /* start */);

	/* send KA; start KA and hold timers */
	pim_msdp_pkt_ka_tx(mp);
	pim_msdp_peer_ka_timer_setup(mp, true /* start */);
	pim_msdp_peer_hold_timer_setup(mp, true /* start */);

	pim_msdp_pkt_sa_tx_to_one_peer(mp);

	PIM_MSDP_PEER_WRITE_ON(mp);
	PIM_MSDP_PEER_READ_ON(mp);
}

/* 11.2.A6, 11.2.A7 and 11.2.A8: shutdown the peer tcp connection */
void pim_msdp_peer_stop_tcp_conn(struct pim_msdp_peer *mp, bool chg_state)
{
	if (chg_state) {
		if (mp->state == PIM_MSDP_ESTABLISHED) {
			++mp->est_flaps;
		}
		mp->state = PIM_MSDP_INACTIVE;

		if (pim_msdp_log_neighbor_events(mp->pim))
			pim_msdp_peer_state_chg_log(mp);
	}

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s pim_msdp_peer_stop_tcp_conn",
			   mp->key_str);
	}
	/* stop read and write threads */
	PIM_MSDP_PEER_READ_OFF(mp);
	PIM_MSDP_PEER_WRITE_OFF(mp);

	/* reset buffers */
	mp->packet_size = 0;
	if (mp->ibuf)
		stream_reset(mp->ibuf);
	if (mp->obuf)
		stream_fifo_clean(mp->obuf);

	/* stop all peer timers */
	pim_msdp_peer_ka_timer_setup(mp, false /* start */);
	pim_msdp_peer_cr_timer_setup(mp, false /* start */);
	pim_msdp_peer_hold_timer_setup(mp, false /* start */);

	/* close connection */
	if (mp->fd >= 0) {
		close(mp->fd);
		mp->fd = -1;
	}
}

/* RFC-3618:Sec-5.6 - stop the peer tcp connection and startover */
void pim_msdp_peer_reset_tcp_conn(struct pim_msdp_peer *mp, const char *rc_str)
{
	if (pim_msdp_log_neighbor_events(mp->pim))
		zlog_info("MSDP peer %s tcp reset %s", mp->key_str, rc_str);

	snprintf(mp->last_reset, sizeof(mp->last_reset), "%s", rc_str);

	/* close the connection and transition to listening or connecting */
	pim_msdp_peer_stop_tcp_conn(mp, true /* chg_state */);
	if (PIM_MSDP_PEER_IS_LISTENER(mp)) {
		pim_msdp_peer_listen(mp);
	} else {
		pim_msdp_peer_connect(mp);
	}
}

/* RFC-3618:Sec-5.4 - peer hold timer */
static void pim_msdp_peer_hold_timer_cb(struct event *t)
{
	struct pim_msdp_peer *mp;

	mp = EVENT_ARG(t);

	if (pim_msdp_log_neighbor_events(mp->pim))
		zlog_info("MSDP peer %s hold timer expired", mp->key_str);

	if (mp->state != PIM_MSDP_ESTABLISHED) {
		return;
	}

	if (pim_msdp_log_neighbor_events(mp->pim))
		pim_msdp_peer_state_chg_log(mp);

	pim_msdp_peer_reset_tcp_conn(mp, "ht-expired");
}

static void pim_msdp_peer_hold_timer_setup(struct pim_msdp_peer *mp, bool start)
{
	struct pim_instance *pim = mp->pim;
	event_cancel(&mp->hold_timer);
	if (start) {
		event_add_timer(pim->msdp.master, pim_msdp_peer_hold_timer_cb,
				mp, pim->msdp.hold_time, &mp->hold_timer);
	}
}


/* RFC-3618:Sec-5.5 - peer keepalive timer */
static void pim_msdp_peer_ka_timer_cb(struct event *t)
{
	struct pim_msdp_peer *mp;

	mp = EVENT_ARG(t);

	if (pim_msdp_log_neighbor_events(mp->pim))
		zlog_info("MSDP peer %s keep alive timer expired", mp->key_str);

	pim_msdp_pkt_ka_tx(mp);
	pim_msdp_peer_ka_timer_setup(mp, true /* start */);
}

static void pim_msdp_peer_ka_timer_setup(struct pim_msdp_peer *mp, bool start)
{
	event_cancel(&mp->ka_timer);
	if (start) {
		event_add_timer(mp->pim->msdp.master, pim_msdp_peer_ka_timer_cb,
				mp, mp->pim->msdp.keep_alive, &mp->ka_timer);
	}
}

static void pim_msdp_peer_active_connect(struct pim_msdp_peer *mp)
{
	int rc;
	++mp->conn_attempts;
	rc = pim_msdp_sock_connect(mp);

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s pim_msdp_peer_active_connect: %d",
			   mp->key_str, rc);
	}

	switch (rc) {
	case connect_error:
	case -1:
		/* connect failed restart the connect-retry timer */
		pim_msdp_peer_cr_timer_setup(mp, true /* start */);
		break;

	case connect_success:
		/* connect was sucessful move to established */
		pim_msdp_peer_established(mp);
		break;

	case connect_in_progress:
		/* for NB content we need to wait till sock is readable or
		 * writeable */
		PIM_MSDP_PEER_WRITE_ON(mp);
		PIM_MSDP_PEER_READ_ON(mp);
		/* also restart connect-retry timer to reset the socket if
		 * connect is
		 * not sucessful */
		pim_msdp_peer_cr_timer_setup(mp, true /* start */);
		break;
	}
}

/* RFC-3618:Sec-5.6 - connection retry on active peer */
static void pim_msdp_peer_cr_timer_cb(struct event *t)
{
	struct pim_msdp_peer *mp;

	mp = EVENT_ARG(t);

	if (pim_msdp_log_neighbor_events(mp->pim))
		zlog_info("MSDP peer %s connection retry timer expired", mp->key_str);

	if (mp->state != PIM_MSDP_CONNECTING || PIM_MSDP_PEER_IS_LISTENER(mp)) {
		return;
	}

	pim_msdp_peer_active_connect(mp);
}

static void pim_msdp_peer_cr_timer_setup(struct pim_msdp_peer *mp, bool start)
{
	event_cancel(&mp->cr_timer);
	if (start) {
		event_add_timer(mp->pim->msdp.master, pim_msdp_peer_cr_timer_cb,
				mp, mp->pim->msdp.connection_retry,
				&mp->cr_timer);
	}
}

/* if a valid packet is rxed from the peer we can restart hold timer */
void pim_msdp_peer_pkt_rxed(struct pim_msdp_peer *mp)
{
	if (mp->state == PIM_MSDP_ESTABLISHED) {
		pim_msdp_peer_hold_timer_setup(mp, true /* start */);
	}
}

/* if a valid packet is txed to the peer we can restart ka timer and avoid
 * unnecessary ka noise in the network */
void pim_msdp_peer_pkt_txed(struct pim_msdp_peer *mp)
{
	if (mp->state == PIM_MSDP_ESTABLISHED) {
		pim_msdp_peer_ka_timer_setup(mp, true /* start */);
		if (PIM_DEBUG_MSDP_INTERNAL) {
			zlog_debug("MSDP ka timer restart on pkt tx to %s",
				   mp->key_str);
		}
	}
}

/* 11.2.A1: create a new peer and transition state to listen or connecting */
struct pim_msdp_peer *pim_msdp_peer_add(struct pim_instance *pim,
					const struct in_addr *peer,
					const struct in_addr *local,
					const char *mesh_group_name)
{
	struct pim_msdp_peer *mp;

	pim_msdp_enable(pim);

	mp = XCALLOC(MTYPE_PIM_MSDP_PEER, sizeof(*mp));

	mp->pim = pim;
	mp->peer = *peer;
	pim_inet4_dump("<peer?>", mp->peer, mp->key_str, sizeof(mp->key_str));
	mp->local = *local;
	if (mesh_group_name) {
		mp->mesh_group_name =
			XSTRDUP(MTYPE_PIM_MSDP_MG_NAME, mesh_group_name);
		SET_FLAG(mp->flags, PIM_MSDP_PEERF_IN_GROUP);
	}
	mp->state = PIM_MSDP_INACTIVE;
	mp->fd = -1;
	mp->auth_listen_sock = -1;
	strlcpy(mp->last_reset, "-", sizeof(mp->last_reset));
	/* higher IP address is listener */
	if (ntohl(mp->local.s_addr) > ntohl(mp->peer.s_addr)) {
		mp->flags |= PIM_MSDP_PEERF_LISTENER;
	}

	/* setup packet buffers */
	mp->ibuf = stream_new(PIM_MSDP_MAX_PACKET_SIZE);
	mp->obuf = stream_fifo_new();

	/* insert into misc tables for easy access */
	mp = hash_get(pim->msdp.peer_hash, mp, hash_alloc_intern);
	listnode_add_sort(pim->msdp.peer_list, mp);

	if (pim_msdp_log_neighbor_events(pim)) {
		zlog_info("MSDP peer %s created", mp->key_str);

		pim_msdp_peer_state_chg_log(mp);
	}

	/* fireup the connect state machine */
	if (PIM_MSDP_PEER_IS_LISTENER(mp)) {
		pim_msdp_peer_listen(mp);
	} else {
		pim_msdp_peer_connect(mp);
	}
	return mp;
}

struct pim_msdp_peer *pim_msdp_peer_find(const struct pim_instance *pim, struct in_addr peer_addr)
{
	struct pim_msdp_peer lookup;

	lookup.peer = peer_addr;
	return hash_lookup(pim->msdp.peer_hash, &lookup);
}

/* release all mem associated with a peer */
static void pim_msdp_peer_free(struct pim_msdp_peer *mp)
{
	/*
	 * Let's make sure we are not running when we delete
	 * the underlying data structure
	 */
	pim_msdp_peer_stop_tcp_conn(mp, false);

	if (mp->ibuf) {
		stream_free(mp->ibuf);
	}

	if (mp->obuf) {
		stream_fifo_free(mp->obuf);
	}

	/* Free authentication data. */
	event_cancel(&mp->auth_listen_ev);
	XFREE(MTYPE_PIM_MSDP_AUTH_KEY, mp->auth_key);
	if (mp->auth_listen_sock != -1)
		close(mp->auth_listen_sock);

	XFREE(MTYPE_PIM_MSDP_FILTER_NAME, mp->acl_in);
	XFREE(MTYPE_PIM_MSDP_FILTER_NAME, mp->acl_out);
	XFREE(MTYPE_PIM_MSDP_MG_NAME, mp->mesh_group_name);

	mp->pim = NULL;
	XFREE(MTYPE_PIM_MSDP_PEER, mp);
}

/* delete the peer config */
void pim_msdp_peer_del(struct pim_msdp_peer **mp)
{
	if (*mp == NULL)
		return;

	/* stop the tcp connection and shutdown all timers */
	pim_msdp_peer_stop_tcp_conn(*mp, true /* chg_state */);

	/* remove the session from various tables */
	listnode_delete((*mp)->pim->msdp.peer_list, *mp);
	hash_release((*mp)->pim->msdp.peer_hash, *mp);

	if (pim_msdp_log_neighbor_events((*mp)->pim))
		zlog_info("MSDP peer %s deleted", (*mp)->key_str);

	/* free up any associated memory */
	pim_msdp_peer_free(*mp);
	*mp = NULL;
}

void pim_msdp_peer_restart(struct pim_msdp_peer *mp)
{
	/* Stop auth listening socket if any. */
	event_cancel(&mp->auth_listen_ev);
	if (mp->auth_listen_sock != -1) {
		close(mp->auth_listen_sock);
		mp->auth_listen_sock = -1;
	}

	/* Stop previously running connection. */
	pim_msdp_peer_stop_tcp_conn(mp, true);

	/* Start connection again. */
	if (PIM_MSDP_PEER_IS_LISTENER(mp))
		pim_msdp_peer_listen(mp);
	else
		pim_msdp_peer_connect(mp);
}

void pim_msdp_peer_change_source(struct pim_msdp_peer *mp,
				 const struct in_addr *addr)
{
	mp->local = *addr;
	pim_msdp_peer_restart(mp);
}

/* peer hash and peer list helpers */
static unsigned int pim_msdp_peer_hash_key_make(const void *p)
{
	const struct pim_msdp_peer *mp = p;
	return (jhash_1word(mp->peer.s_addr, 0));
}

static bool pim_msdp_peer_hash_eq(const void *p1, const void *p2)
{
	const struct pim_msdp_peer *mp1 = p1;
	const struct pim_msdp_peer *mp2 = p2;

	return (mp1->peer.s_addr == mp2->peer.s_addr);
}

static int pim_msdp_peer_comp(const void *p1, const void *p2)
{
	const struct pim_msdp_peer *mp1 = p1;
	const struct pim_msdp_peer *mp2 = p2;

	if (ntohl(mp1->peer.s_addr) < ntohl(mp2->peer.s_addr))
		return -1;

	if (ntohl(mp1->peer.s_addr) > ntohl(mp2->peer.s_addr))
		return 1;

	return 0;
}

/************************** Mesh group management **************************/
void pim_msdp_mg_free(struct pim_instance *pim, struct pim_msdp_mg **mgp)
{
	struct pim_msdp_mg_mbr *mbr;
	struct listnode *n, *nn;

	if (*mgp == NULL)
		return;

	/* SIP is being removed - tear down all active peer sessions */
	for (ALL_LIST_ELEMENTS((*mgp)->mbr_list, n, nn, mbr))
		pim_msdp_mg_mbr_del((*mgp), mbr);

	if (pim_msdp_log_neighbor_events(pim))
		zlog_info("MSDP mesh-group %s deleted", (*mgp)->mesh_group_name);

	XFREE(MTYPE_PIM_MSDP_MG_NAME, (*mgp)->mesh_group_name);

	if ((*mgp)->mbr_list)
		list_delete(&(*mgp)->mbr_list);

	SLIST_REMOVE(&pim->msdp.mglist, (*mgp), pim_msdp_mg, mg_entry);
	XFREE(MTYPE_PIM_MSDP_MG, (*mgp));
}

struct pim_msdp_mg *pim_msdp_mg_new(struct pim_instance *pim,
				    const char *mesh_group_name)
{
	struct pim_msdp_mg *mg;

	mg = XCALLOC(MTYPE_PIM_MSDP_MG, sizeof(*mg));
	mg->pim = pim;
	mg->mesh_group_name = XSTRDUP(MTYPE_PIM_MSDP_MG_NAME, mesh_group_name);
	mg->mbr_list = list_new();
	mg->mbr_list->del = (void (*)(void *))pim_msdp_mg_mbr_free;
	mg->mbr_list->cmp = (int (*)(void *, void *))pim_msdp_mg_mbr_comp;

	if (pim_msdp_log_neighbor_events(pim))
		zlog_info("MSDP mesh-group %s created", mg->mesh_group_name);

	SLIST_INSERT_HEAD(&pim->msdp.mglist, mg, mg_entry);

	return mg;
}

static int pim_msdp_mg_mbr_comp(const void *p1, const void *p2)
{
	const struct pim_msdp_mg_mbr *mbr1 = p1;
	const struct pim_msdp_mg_mbr *mbr2 = p2;

	if (ntohl(mbr1->mbr_ip.s_addr) < ntohl(mbr2->mbr_ip.s_addr))
		return -1;

	if (ntohl(mbr1->mbr_ip.s_addr) > ntohl(mbr2->mbr_ip.s_addr))
		return 1;

	return 0;
}

static void pim_msdp_mg_mbr_free(struct pim_msdp_mg_mbr *mbr)
{
	XFREE(MTYPE_PIM_MSDP_MG_MBR, mbr);
}

void pim_msdp_mg_mbr_del(struct pim_msdp_mg *mg, struct pim_msdp_mg_mbr *mbr)
{
	/* Delete active peer session if any */
	if (mbr->mp) {
		pim_msdp_peer_del(&mbr->mp);
	}

	listnode_delete(mg->mbr_list, mbr);
	if (pim_msdp_log_neighbor_events(mg->pim))
		zlog_info("MSDP mesh-group %s neighbor %pI4 deleted", mg->mesh_group_name,
			  &mbr->mbr_ip);

	pim_msdp_mg_mbr_free(mbr);
	if (mg->mbr_cnt) {
		--mg->mbr_cnt;
	}
}

static void pim_msdp_src_del(struct pim_msdp_mg *mg)
{
	struct pim_msdp_mg_mbr *mbr;
	struct listnode *mbr_node;

	/* SIP is being removed - tear down all active peer sessions */
	for (ALL_LIST_ELEMENTS_RO(mg->mbr_list, mbr_node, mbr)) {
		if (mbr->mp)
			pim_msdp_peer_del(&mbr->mp);
	}

	if (pim_msdp_log_neighbor_events(mg->pim))
		zlog_info("MSDP mesh-group %s source cleared", mg->mesh_group_name);
}

/*********************** MSDP feature APIs *********************************/
int pim_msdp_config_write(struct pim_instance *pim, struct vty *vty)
{
	struct pim_msdp_mg *mg;
	struct listnode *mbrnode;
	struct pim_msdp_mg_mbr *mbr;
	char src_str[INET_ADDRSTRLEN];
	int count = 0;

	if (pim->msdp.hold_time != PIM_MSDP_PEER_HOLD_TIME ||
	    pim->msdp.keep_alive != PIM_MSDP_PEER_KA_TIME ||
	    pim->msdp.connection_retry != PIM_MSDP_PEER_CONNECT_RETRY_TIME) {
		vty_out(vty, " msdp timers %u %u", pim->msdp.hold_time, pim->msdp.keep_alive);
		if (pim->msdp.connection_retry != PIM_MSDP_PEER_CONNECT_RETRY_TIME)
			vty_out(vty, " %u", pim->msdp.connection_retry);
		vty_out(vty, "\n");
	}

	if (pim_msdp_log_neighbor_events(pim))
		vty_out(vty, " msdp log neighbor-events\n");
	if (pim_msdp_log_sa_events(pim))
		vty_out(vty, " msdp log sa-events\n");
	if (pim->msdp.shutdown)
		vty_out(vty, " msdp shutdown\n");

	if (SLIST_EMPTY(&pim->msdp.mglist))
		return count;

	SLIST_FOREACH (mg, &pim->msdp.mglist, mg_entry) {
		if (mg->src_ip.s_addr != INADDR_ANY) {
			pim_inet4_dump("<src?>", mg->src_ip, src_str,
				       sizeof(src_str));
			vty_out(vty, " msdp mesh-group %s source %s\n",
				mg->mesh_group_name, src_str);
			++count;
		}

		for (ALL_LIST_ELEMENTS_RO(mg->mbr_list, mbrnode, mbr)) {
			vty_out(vty, " msdp mesh-group %s member %pI4\n",
				mg->mesh_group_name, &mbr->mbr_ip);
			++count;
		}
	}

	return count;
}

bool pim_msdp_peer_config_write(struct vty *vty, struct pim_instance *pim)
{
	struct pim_msdp_peer *mp;
	struct listnode *node;
	bool written = false;

	for (ALL_LIST_ELEMENTS_RO(pim->msdp.peer_list, node, mp)) {
		/* Skip meshed group peers. */
		if (mp->flags & PIM_MSDP_PEERF_IN_GROUP)
			continue;

		vty_out(vty, " msdp peer %pI4 source %pI4", &mp->peer, &mp->local);
		if (mp->asn)
			vty_out(vty, " as %u", mp->asn);
		vty_out(vty, "\n");

		if (mp->auth_type == MSDP_AUTH_MD5)
			vty_out(vty, " msdp peer %pI4 password %s\n", &mp->peer,
				mp->auth_key);

		if (mp->acl_in)
			vty_out(vty, " msdp peer %pI4 sa-filter %s in\n",
				&mp->peer, mp->acl_in);

		if (mp->acl_out)
			vty_out(vty, " msdp peer %pI4 sa-filter %s out\n",
				&mp->peer, mp->acl_out);

		if (mp->sa_limit)
			vty_out(vty, " msdp peer %pI4 sa-limit %u\n", &mp->peer, mp->sa_limit);

		written = true;
	}

	if (pim->msdp.originator_id.s_addr != INADDR_ANY)
		vty_out(vty, " msdp originator-id %pI4\n", &pim->msdp.originator_id);

	if (pim->msdp.shutdown)
		vty_out(vty, " msdp shutdown\n");

	return written;
}

/* Enable feature including active/periodic timers etc. on the first peer
 * config. Till then MSDP should just stay quiet. */
static void pim_msdp_enable(struct pim_instance *pim)
{
	if (pim->msdp.flags & PIM_MSDPF_ENABLE) {
		/* feature is already enabled */
		return;
	}
	pim->msdp.flags |= PIM_MSDPF_ENABLE;
	pim->msdp.work_obuf = stream_new(PIM_MSDP_MAX_PACKET_SIZE);
	pim_msdp_sa_adv_timer_setup(pim, true /* start */);
	/* setup sa cache based on local sources */
	pim_msdp_sa_local_setup(pim);
}

/* MSDP init */
void pim_msdp_init(struct pim_instance *pim, struct event_loop *master)
{
	pim->msdp.master = master;
	char hash_name[64];

	snprintf(hash_name, sizeof(hash_name), "PIM %s MSDP Peer Hash",
		 pim->vrf->name);
	pim->msdp.peer_hash = hash_create(pim_msdp_peer_hash_key_make,
					  pim_msdp_peer_hash_eq, hash_name);
	pim->msdp.peer_list = list_new();
	pim->msdp.peer_list->del = (void (*)(void *))pim_msdp_peer_free;
	pim->msdp.peer_list->cmp = (int (*)(void *, void *))pim_msdp_peer_comp;

	snprintf(hash_name, sizeof(hash_name), "PIM %s MSDP SA Hash",
		 pim->vrf->name);
	pim->msdp.sa_hash = hash_create(pim_msdp_sa_hash_key_make,
					pim_msdp_sa_hash_eq, hash_name);
	pim->msdp.sa_list = list_new();
	pim->msdp.sa_list->del = (void (*)(void *))pim_msdp_sa_free;
	pim->msdp.sa_list->cmp = (int (*)(void *, void *))pim_msdp_sa_comp;

	/* MSDP global timer defaults. */
	pim->msdp.hold_time = PIM_MSDP_PEER_HOLD_TIME;
	pim->msdp.keep_alive = PIM_MSDP_PEER_KA_TIME;
	pim->msdp.connection_retry = PIM_MSDP_PEER_CONNECT_RETRY_TIME;

	msdp_rp_cache_init(pim->msdp.rp_cache);
}

/* counterpart to MSDP init; XXX: unused currently */
void pim_msdp_exit(struct pim_instance *pim)
{
	struct pim_msdp_mg *mg;

	msdp_rp_cache_clear(pim);

	pim_msdp_sa_adv_timer_setup(pim, false);

	/* Stop listener and delete all peer sessions */
	while ((mg = SLIST_FIRST(&pim->msdp.mglist)) != NULL)
		pim_msdp_mg_free(pim, &mg);

	hash_clean_and_free(&pim->msdp.peer_hash, NULL);

	if (pim->msdp.peer_list) {
		list_delete(&pim->msdp.peer_list);
	}

	hash_clean_and_free(&pim->msdp.sa_hash, NULL);

	if (pim->msdp.sa_list) {
		list_delete(&pim->msdp.sa_list);
	}

	if (pim->msdp.work_obuf)
		stream_free(pim->msdp.work_obuf);
	pim->msdp.work_obuf = NULL;
}

void pim_msdp_mg_src_add(struct pim_instance *pim, struct pim_msdp_mg *mg,
			 struct in_addr *ai)
{
	struct pim_msdp_mg_mbr *mbr;
	struct listnode *mbr_node;

	/* Stop all connections and remove data structures. */
	pim_msdp_src_del(mg);

	/* Set new address. */
	mg->src_ip = *ai;

	/* No new address, disable everyone. */
	if (ai->s_addr == INADDR_ANY) {
		if (pim_msdp_log_neighbor_events(pim))
			zlog_info("MSDP mesh-group %s source unset", mg->mesh_group_name);
		return;
	}

	/* Create data structures and start TCP connection. */
	for (ALL_LIST_ELEMENTS_RO(mg->mbr_list, mbr_node, mbr))
		mbr->mp = pim_msdp_peer_add(pim, &mbr->mbr_ip, &mg->src_ip,
					    mg->mesh_group_name);

	if (pim_msdp_log_neighbor_events(pim))
		zlog_info("MSDP mesh-group %s source %pI4 set", mg->mesh_group_name, &mg->src_ip);
}

struct pim_msdp_mg_mbr *pim_msdp_mg_mbr_add(struct pim_instance *pim,
					    struct pim_msdp_mg *mg,
					    struct in_addr *ia)
{
	struct pim_msdp_mg_mbr *mbr;

	mbr = XCALLOC(MTYPE_PIM_MSDP_MG_MBR, sizeof(*mbr));
	mbr->mbr_ip = *ia;
	listnode_add_sort(mg->mbr_list, mbr);

	/* if valid SIP has been configured add peer session */
	if (mg->src_ip.s_addr != INADDR_ANY)
		mbr->mp = pim_msdp_peer_add(pim, &mbr->mbr_ip, &mg->src_ip,
					    mg->mesh_group_name);

	if (pim_msdp_log_neighbor_events(pim))
		zlog_info("MSDP mesh-group %s neighbor %pI4 created", mg->mesh_group_name,
			  &mbr->mbr_ip);

	++mg->mbr_cnt;

	return mbr;
}

/* MSDP on RP needs to know if a source is registerable to this RP */
static void pim_upstream_msdp_reg_timer(struct event *t)
{
	struct pim_upstream *up = EVENT_ARG(t);
	struct pim_instance *pim = up->channel_oil->pim;

	/* source is no longer active - pull the SA from MSDP's cache */
	pim_msdp_sa_local_del(pim, &up->sg);
}

void pim_upstream_msdp_reg_timer_start(struct pim_upstream *up)
{
	event_cancel(&up->t_msdp_reg_timer);
	event_add_timer(router->master, pim_upstream_msdp_reg_timer, up, PIM_MSDP_REG_RXED_PERIOD,
			&up->t_msdp_reg_timer);

	pim_msdp_sa_local_update(up);
}

void pim_msdp_shutdown(struct pim_instance *pim, bool state)
{
	struct pim_msdp_peer *peer;
	struct listnode *node;

	/* Same value nothing to do. */
	if (pim->msdp.shutdown == state)
		return;

	if (state) {
		pim->msdp.shutdown = true;

		for (ALL_LIST_ELEMENTS_RO(pim->msdp.peer_list, node, peer)) {
			/* Stop the tcp connection and shutdown all timers */
			pim_msdp_peer_stop_tcp_conn(peer, true);

			/* Stop listening socket if any. */
			event_cancel(&peer->auth_listen_ev);
			if (peer->auth_listen_sock != -1)
				close(peer->auth_listen_sock);

			/* Disable and remove listener flag. */
			UNSET_FLAG(pim->msdp.flags, PIM_MSDPF_ENABLE | PIM_MSDPF_LISTENER);
		}

		msdp_rp_cache_clear(pim);
	} else {
		pim->msdp.shutdown = false;

		for (ALL_LIST_ELEMENTS_RO(pim->msdp.peer_list, node, peer)) {
			/* Start connection again. */
			if (PIM_MSDP_PEER_IS_LISTENER(peer))
				pim_msdp_peer_listen(peer);
			else
				pim_msdp_peer_connect(peer);

			SET_FLAG(pim->msdp.flags, PIM_MSDPF_ENABLE);
		}
	}
}
