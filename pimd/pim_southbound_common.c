// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM southbound implementation.
 *
 * Copyright (C) 2021-2026 Network Education Foundation
 *                         Rafael Zalamena
 */

#include "lib/libfrr.h"
#include "lib/zlog.h"

#include "pim_iface.h"
#include "pim_instance.h"
#include "pim_join.h"
#include "pim_neighbor.h"
#include "pim_register.h"
#include "pim_southbound_common.h"
#include "pim_time.h"

/*
 * PIM southbound.
 */
enum multicast_event_type {
	MRT_EVENT_DATA_START,
	MRT_EVENT_DATA_STOP,
	MRT_EVENT_WRONG_IF,
	MRT_EVENT_JOIN_SPT,
	MRT_EVENT_DATA_PACKET,
};

/** PIM southbound message version. */
#define MRE_VERSION_V1 0x01

struct mroute_event_header {
	/** Protocol message version. */
	uint8_t version;
	/** Multicast route event. \see enum multicast_event_type. */
	uint8_t type;
	/** Message length. */
	uint16_t length;
};

struct mroute_event {
	/** Event header. */
	struct mroute_event_header header;
	/** Event flags. \see MRE_FLAG_* definitions. */
	uint32_t flags;
	/** Input interface index. */
	int32_t iif_idx;
	/** Source address. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} source;
	/** Group address. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} group;
};

static struct zclient *zclient;
static pim_addr pim_addr_any = PIMADDR_ANY;

/*
 * FPM handling.
 */
/** Tell data plane that SPT switch over is allowed. */
#define MRT_FLAG_JOIN_SPT_ALLOWED 0x0001
/** Ask data plane to tell us when the data flow stops. */
#define MRT_FLAG_RESTART_DL_TIMER 0x0002
/** Flag IPv6 addresses for the data plane. */
#define MRT_FLAG_ADDR_TYPE_V6 0x0008
/** Blackhole multicast packets. */
#define MRT_FLAG_DUMMY 0x0020
/** Used with dummy to remove blackhole after a time. */
#define MRT_FLAG_DL_TIMER 0x0040

/** Get interface of the best path to source. */
static void pimsb_set_input_interface(const struct rp_info *rp, struct channel_oil *oil,
				      bool i_am_rp)
{
	struct pim_upstream *upstream = oil->up;
	struct interface *interface;
	int32_t rp_if = 0;
	bool has_rp_if = false;
	bool star_source = false;
	bool use_notifif = false;
	struct prefix p = {};
	struct pim_nexthop pn = {};

	/* Figure out what part of the topology we are. */
	star_source = pim_addr_is_any(oil->source);

	/* Figure out RP information. */
	pim_addr_to_prefix(&p, oil->group);
	if (rp && rp->rp.source_nexthop.interface) {
		has_rp_if = true;
		rp_if = rp->rp.source_nexthop.interface->ifindex;
	}

	/*
	 * Set input interface:
	 * 1. Use special index when `pimreg`.
	 * 2. `MAXVIFS` means no interface.
	 * 3. If PIM decided to use its own RP interface and we are RP, then
	 *    use `pimreg` (also see item (1)).
	 * 4. Otherwise use what PIM decided.
	 */
	if (oil->iif.index == PIM_OIF_PIM_REGISTER_VIF)
		oil->iif.index = PIM_REG_IF_IDX;
	else if (oil->iif.index == southbound.interface_max)
		oil->iif.index = 0;
	else {
		interface = pim_if_find_by_vif_index(oil->pim, oil->iif.index);
		oil->iif.index = interface ? interface->ifindex : PIM_REG_IF_IDX;
	}

	/*
	 * Handle simple case first (non-RP)
	 */
	if (!i_am_rp) {
		/*
		 * Notification interface must be used when we want to know
		 * that we are receiving multicast data on the specified
		 * interface.
		 *
		 * SG(*,G) does not need to watch for multicast data.
		 */
		if (!star_source && has_rp_if && (oil->iif.index == 0 || rp_if == oil->iif.index)) {
			/* Figure out the SPT path. */
			if (pim_nht_lookup(oil->pim, &pn, oil->source, oil->group, 0) &&
			    oil->iif.index != pn.interface->ifindex)
				oil->notifif.index = pn.interface->ifindex;
			else
				oil->notifif.index = 0;

		} else
			oil->notifif.index = 0;

		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: SG(%pPA, %pPA) IAmNotRP RPIF:%d iif:%d notifif:%d",
				   __func__, &oil->source, &oil->group, rp_if, oil->iif.index,
				   oil->notifif.index);
		return;
	}

	/*
	 * Handle the RP case
	 */
	if (star_source)
		oil->iif.index = PIM_REG_IF_IDX;
	else {
		interface = pim_if_find_by_vif_index(oil->pim, oil->iif.index);
		oil->iif.index = interface ? interface->ifindex : PIM_REG_IF_IDX;
		if (has_rp_if && rp_if == oil->iif.index)
			oil->iif.index = PIM_REG_IF_IDX;
	}

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: SG(%pPA, %pPA) IAmRP iif:%d RPIF:%d use_notifif:%s upstream:%s",
			   __func__, &oil->source, &oil->group, oil->iif.index, rp_if,
			   use_notifif ? "yes" : "no", upstream ? "yes" : "no");

	/* We need upstream information to proceed */
	if (!upstream)
		return;

	/*
	 * If no traffic has been seen yet, then set notification
	 * interface instead of input interface.
	 */
	if (!(upstream->flags & PIM_UPSTREAM_FLAG_MASK_DATA_START) &&
	    oil->iif.index != PIM_REG_IF_IDX) {
		oil->notifif.index = oil->iif.index;
		oil->iif.index = 0;
		return;
	}

	/* Figure out the SPT path. */
	if (pim_nht_lookup(oil->pim, &pn, oil->source, oil->group, 0))
		oil->notifif.index = pn.interface->ifindex;
	else
		oil->notifif.index = 0;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s:   notifif:%d iif:%d", __func__, oil->notifif.index, oil->iif.index);
}

static void pimsb_debug_oil(struct channel_oil *oil)
{
	struct channel_oif *oif;
	struct interface *ifp;
	char line[128];
	char buf[512];

	zlog_debug("OIL[installed:%d rescan:%d size:%zu refcount:%d]", oil->installed,
		   oil->oil_inherited_rescan, channel_oif_list_count(&oil->oif_list),
		   oil->oil_ref_count);
	frr_each (channel_oif_list, &oil->oif_list, oif) {
		ifp = pim_if_find_by_vif_index(oil->pim, oif->index);
		if (!ifp)
			snprintf(buf, sizeof(buf), "  IF[index:%d flags:", oif->index);
		else
			snprintf(buf, sizeof(buf), "  IF[index:%d name:%s flags:", oif->index,
				 ifp->name);

		if (oif->flags & PIM_OIF_FLAG_PROTO_GM)
			strlcat(buf, " GM", sizeof(buf));
		if (oif->flags & PIM_OIF_FLAG_PROTO_PIM)
			strlcat(buf, " PIM", sizeof(buf));
		if (oif->flags & PIM_OIF_FLAG_PROTO_STAR)
			strlcat(buf, " STAR", sizeof(buf));
		if (oif->flags & PIM_OIF_FLAG_PROTO_VXLAN)
			strlcat(buf, " VXLAN", sizeof(buf));
		strlcat(buf, "]", sizeof(buf));
		zlog_debug("%s", buf);
	}

	snprintfrr(buf, sizeof(buf), "  MFC(%pPA,%pPA)[iif:%d,", &oil->source, &oil->group,
		   oil->iif.index);
	frr_each (channel_oif_list, &oil->oif_list, oif) {
		ifp = pim_if_find_by_vif_index(oil->pim, oif->index);
		if (!ifp)
			snprintf(line, sizeof(line), "X(%d:X),", oif->index);
		else
			snprintf(line, sizeof(line), "%s(%d,%d),", ifp->name, oif->index,
				 ifp->ifindex);

		strlcat(buf, line, sizeof(buf));
	}
	zlog_debug("%s]", buf);
}

static void pimsb_debug_upstream(const struct pim_upstream *up)
{
	struct pim_ifchannel *ch;
	struct listnode *node;
	char buf[1024];

	snprintfrr(buf, sizeof(buf), "UP[up:%pPA register:%pPA sg:%s join:%d reg:%d spt:%d flags:",
		   &up->upstream_addr, &up->upstream_register, up->sg_str, up->join_state,
		   up->reg_state, up->sptbit);

#define PRINT_FLAG(flag, str)                                                                     \
	do {                                                                                      \
		if (up->flags & (flag))                                                           \
			strlcat(buf, str ",", sizeof(buf));                                       \
	} while (0)
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED, "DR_JOIN_DESIRED");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED, "DR_JOIN_DESIRED_UPDATED");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_FHR, "FHR");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_IGMP, "SRC_IGMP");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_PIM, "SRC_PIM");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_STREAM, "SRC_STREAM");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_MSDP, "SRC_MSDP");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SEND_SG_RPT_PRUNE, "SEND_SG_RPT_PRUNE");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_LHR, "SRC_LHR");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_STATIC_IIF, "STATIC_IIF");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_ALLOW_IIF_IN_OIL, "ALLOW_IIF_IN_OIL");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_NO_PIMREG_DATA, "NO_PIMREG_DATA");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_FORCE_PIMREG, "FORCE_PIMREG");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG, "SRC_VXLAN_ORIG");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM, "SRC_VXLAN_TERM");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_MLAG_VXLAN, "MLAG_VXLAN");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_MLAG_NON_DF, "MLAG_NON_DF");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_MLAG_PEER, "MLAG_PEER");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE, "SRC_NOCACHE");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_USE_RPT, "USE_RPT");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE, "MLAG_INTERFACE");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED, "SPT_DESIRED");
	PRINT_FLAG(PIM_UPSTREAM_FLAG_MASK_DATA_START, "DATA_START");
	zlog_debug("%s]", buf);
	zlog_debug("  RPF[if:%s nh:%pPA rpf_addr:%pPA]",
		   up->rpf.source_nexthop.interface != NULL ? up->rpf.source_nexthop.interface->name
							    : "unknown",
		   &up->rpf.source_nexthop.mrib_nexthop_addr, &up->rpf.rpf_addr);

	for (ALL_LIST_ELEMENTS_RO(up->ifchannels, node, ch)) {
		buf[0] = 0;
		PRINT_FLAG(PIM_IF_FLAG_MASK_COULD_ASSERT, "COULD_ASSERT");
		PRINT_FLAG(PIM_IF_FLAG_MASK_ASSERT_TRACKING_DESIRED, "ASSERT_TRACKING_DESIRED");
		PRINT_FLAG(PIM_IF_FLAG_MASK_PROTO_PIM, "PROTO_PIM");
		PRINT_FLAG(PIM_IF_FLAG_MASK_PROTO_IGMP, "PROTO_IGMP");
		zlog_debug("  SOURCE[sg:%s if:%s join:%d assert:%d winner:%pI4 flags:%s]",
			   ch->sg_str, ch->interface ? ch->interface->name : "unknown",
			   ch->ifjoin_state, ch->ifassert_state, &ch->ifassert_winner, buf);
	}
#undef PRINT_FLAG

	if (PIM_UPSTREAM_FLAG_TEST_USE_RPT(up->flags)) {
		if (up->parent)
			pimsb_debug_upstream(up->parent);
		else
			zlog_debug("%s:  no upstream parent, but USE_RPT set", __func__);
	}
}

static void pimsb_debug_route_flags(uint32_t flags)
{
	char buf[128] = {};

	if (CHECK_FLAG(flags, MRT_FLAG_JOIN_SPT_ALLOWED))
		strlcat(buf, "JOIN_SPT_ALLOWED ", sizeof(buf));
	if (CHECK_FLAG(flags, MRT_FLAG_RESTART_DL_TIMER))
		strlcat(buf, "RESTART_DL_TIMER ", sizeof(buf));
	if (CHECK_FLAG(flags, MRT_FLAG_ADDR_TYPE_V6))
		strlcat(buf, "ADDR_TYPE_V6 ", sizeof(buf));
	if (CHECK_FLAG(flags, MRT_FLAG_DUMMY))
		strlcat(buf, "DUMMY ", sizeof(buf));
	if (CHECK_FLAG(flags, MRT_FLAG_DL_TIMER))
		strlcat(buf, "DL_TIMER ", sizeof(buf));

	zlog_debug("route_flags: %s", buf);
}

#if PIM_IPV == 6
static void pimsb_interface_ipv6_get(const struct pim_interface *pim_interface, pim_addr *address)
{
	struct pim_secondary_addr *sec_addr;
	struct listnode *node;

	memset(address, 0, sizeof(*address));

	if (!IN6_IS_ADDR_LINKLOCAL(&pim_interface->primary_address)) {
		*address = pim_interface->primary_address;
		return;
	}

	if (!pim_interface->sec_addr_list) {
		return;
	}

	for (ALL_LIST_ELEMENTS_RO(pim_interface->sec_addr_list, node, sec_addr)) {
		pim_addr next_address = pim_addr_from_prefix(&sec_addr->addr);
		if (IN6_IS_ADDR_LINKLOCAL(&next_address))
			continue;

		*address = next_address;
		return;
	}
}
#endif /* PIM_IPV == 6 */

static void pimsb_mroute_do(struct channel_oil *oil, bool install)
{
	struct pim_upstream *upstream = oil->up;
	struct pim_interface *pim_ifp;
	struct channel_oif *oif;
	struct interface *ifp;
	struct rp_info *rp;
	struct stream *s;
	size_t oif_count_pos;
	size_t oif_count;
	bool i_am_rp = false;
	bool i_am_fhr = false;
	bool i_am_lhr = false;
	bool i_am_mhr = false;
	bool has_rp_if = false;
	bool is_static = false;
	bool has_pimreg = false;
	bool star_source = false;
	uint32_t route_flags = 0;
	uint32_t spt_threshold = 0;
	pim_addr source_encap;
	struct prefix p = {};
	char intf[128];
	char oifs[2048];

	if (PIM_DEBUG_MROUTE) {
		zlog_backtrace(LOG_DEBUG);
		pimsb_debug_oil(oil);
		if (upstream)
			pimsb_debug_upstream(upstream);
	}

	/* Treat IGMP joined routes as static. */
	if (upstream != NULL && (upstream->flags & PIM_UPSTREAM_FLAG_MASK_SRC_IGMP))
		is_static = true;

	/* Figure out what part of the topology we are. */
	star_source = pim_addr_is_any(oil->source);
	i_am_rp = pim_rp_i_am_rp(oil->pim, oil->group);
	if (upstream) {
		i_am_lhr = !!(upstream->flags & (PIM_UPSTREAM_FLAG_MASK_SRC_LHR |
						 PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED));
		i_am_fhr = PIM_UPSTREAM_FLAG_TEST_FHR(upstream->flags);
	}

	i_am_mhr = !i_am_lhr && !i_am_rp && !i_am_fhr;

	/* Figure out RP information. */
	pim_addr_to_prefix(&p, oil->group);
	rp = pim_rp_find_match_group(oil->pim, &p);
	if (rp != NULL && rp->rp.source_nexthop.interface != NULL &&
	    rp->rp.source_nexthop.interface->info != NULL)
		has_rp_if = true;

	/* Update input interface */
	pimsb_set_input_interface(rp, oil, i_am_rp);

	/* Generate flags based on detected information. */
	if (!is_static && !star_source && !i_am_mhr)
		route_flags |= MRT_FLAG_RESTART_DL_TIMER;

	/*
	 * SPT only matters for LHR (the router which receives the IGMP join),
	 * however since we don't know about LHR status in star route until
	 * it is too late we'll check for not FHR and not RP.
	 *
	 * Intermediary routers do not create star route so it shouldn't be
	 * a problem.
	 */
	if (!i_am_fhr && !i_am_rp && star_source && oil->spt_threshold < PIM_SPT_THRESH_NEVER) {
		route_flags |= MRT_FLAG_JOIN_SPT_ALLOWED;
		spt_threshold = oil->spt_threshold;
	}
	if (!is_static && (channel_oif_list_count(&oil->oif_list) == 0 || oil->filtered))
		route_flags |= MRT_FLAG_DUMMY | MRT_FLAG_DL_TIMER;

	/*
	 * Disable data plane notification to remove dummy route if no
	 * input interface is configured.
	 */
	if (oil->iif.index == 0)
		route_flags &= ~MRT_FLAG_DL_TIMER;

	/*
	 * Handle special case: RP and FHR.
	 *
	 * If there is a upstream to send traffic but it has not yet joined
	 * the stream then don't attempt to send any traffic.
	 */
	if (i_am_rp && i_am_fhr) {
		route_flags &= ~(MRT_FLAG_RESTART_DL_TIMER | MRT_FLAG_DUMMY);
		route_flags |= MRT_FLAG_DL_TIMER;
	}

#if PIM_IPV == 6
	/* Flag all multicast routes coming from us to be IPv6. */
	route_flags |= MRT_FLAG_ADDR_TYPE_V6;
#endif /* PIM_IPV == 6 */

	if (PIM_DEBUG_MROUTE)
		pimsb_debug_route_flags(route_flags);

	/*
	 * Multicast route internal communication format:
	 *  - 2 bytes: Action (0: install, 1: delete).
	 *  - 2 bytes: address family.
	 *  - X bytes: IP(v4|v6) source address.
	 *  - X bytes: IP(v4|v6) group address.
	 *  - 4 bytes: input interface.
	 *  - 4 bytes: RPF interface.
	 *  - 2 byte: flags.
	 *  - 2 bytes: output interface amount.
	 *  - 4 * X bytes: output interface array.
	 *  - 4 bytes: SPT threshould.
	 *  - X bytes: IP(v4|v6) local address.
	 *  - X bytes: IP(v4|v6) remote address.
	 */
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_MROUTE_EVENT, oil->pim->vrf->vrf_id);
	stream_putw(s, install ? 0 : 1);
	stream_putw(s, PIM_AF);
	stream_put(s, &oil->source, sizeof(pim_addr));
	stream_put(s, &oil->group, sizeof(pim_addr));

	/* Input interface. */
	stream_putl(s, oil->iif.index);
	/* Notification interface. */
	stream_putl(s, oil->notifif.index);

	/* Multicast route flags. */
	stream_putw(s, route_flags);

	/* Output interface amount. */
	oif_count_pos = stream_get_endp(s);
	stream_putw(s, 0);

	/* Output interfaces. */
	oif_count = 0;
	if (!oil->filtered) {
		frr_each (channel_oif_list, &oil->oif_list, oif) {
			if (oif->index == PIM_REG_IF_IDX)
				has_pimreg = true;

			stream_putl(s, oif->index);
			oif_count++;
		}
	}

	stream_putw_at(s, oif_count_pos, oif_count);

	/* SPT threshold. */
	stream_putl(s, spt_threshold);

	/* Interface address in the way to the RP. */
	if (has_pimreg && has_rp_if) {
		pim_ifp = rp->rp.source_nexthop.interface->info;

		/* Interface address in the way to the RP. */
#if PIM_IPV == 6
		pimsb_interface_ipv6_get(pim_ifp, &source_encap);
#else
		source_encap = pim_ifp->primary_address;
#endif
		stream_put(s, &source_encap, sizeof(pim_addr));
	} else
		stream_put(s, &pim_addr_any, sizeof(pim_addr));

	/* Remote RP address. */
	if (has_pimreg && has_rp_if) {
		stream_put(s, &rp->rp.rpf_addr, sizeof(pim_addr));
		upstream->sb_register_to = rp->rp.rpf_addr;
	} else {
		stream_put(s, &pim_addr_any, sizeof(pim_addr));
		upstream->sb_register_to = pim_addr_any;
	}

	stream_putw_at(s, 0, (uint16_t)stream_get_endp(s));
	zclient_send_message(zclient);

	if (PIM_DEBUG_MROUTE) {
		oifs[0] = 0;
		frr_each (channel_oif_list, &oil->oif_list, oif) {
			if (oif->index == PIM_REG_IF_IDX) {
				snprintf(intf, sizeof(intf), PIMREG "(%d),", oif->index);
				strlcat(oifs, intf, sizeof(oifs));
				continue;
			}

			ifp = if_lookup_by_index(oif->index, oil->pim->vrf->vrf_id);
			snprintf(intf, sizeof(intf), "%s(%d),", ifp ? ifp->name : "?", oif->index);
			strlcat(oifs, intf, sizeof(oifs));
		}
		if (oifs[0])
			oifs[strlen(oifs) - 1] = 0;

		zlog_debug("%s: %s SG(%pPAs, %pPAs) iif:%d notifif:%d flags:0x%04x OIFS_AMOUNT:%zu OIF:[%s] encap:(local:%pPAs, rp:%pPAs) rp:%s fhr:%s lhr:%s",
			   __func__, install ? "INSTALL" : "DELETE", &oil->source, &oil->group,
			   oil->iif.index, oil->notifif.index, route_flags, oif_count, oifs,
			   has_pimreg && has_rp_if ? &pim_ifp->primary_address : &pim_addr_any,
			   has_pimreg && has_rp_if ? &rp->rp.rpf_addr : &pim_addr_any,
			   i_am_rp ? "yes" : "no", i_am_fhr ? "yes" : "no",
			   i_am_lhr ? "yes" : "no");
	}

	/* Update route installation status.  */
	if (install) {
		if (!oil->installed)
			oil->mroute_creation = pim_time_monotonic_sec();

		oil->installed = 1;
	} else
		oil->installed = 0;
}

static int pimsb_mroute_add(struct channel_oil *c_oil, const char *name)
{
	struct pim_instance *pim = c_oil->pim;
	int err = 0;

	pim->mroute_add_last = pim_time_monotonic_sec();
	++pim->mroute_add_events;

	/* Copy the oil to a temporary structure to fixup (without need to
	 * later restore) before sending the mroute add to the dataplane
	 */

	pimsb_mroute_do(c_oil, true);

	if (err) {
		zlog_warn("%s %s: failure: setsockopt(fd=%d,IPPROTO_IP,MRT_ADD_MFC): errno=%d: %s",
			  __FILE__, __func__, pim->mroute_socket, errno, safe_strerror(errno));
		return -2;
	}

	if (PIM_DEBUG_MROUTE) {
		char buf[2048];
		zlog_debug("%s(%s), vrf %s Added Route: %s", __func__, name, pim->vrf->name,
			   pim_channel_oil_dump(c_oil, buf, sizeof(buf)));
	}

	return 0;
}

static int pimsb_mroute_del(struct channel_oil *c_oil, const char *name)
{
	struct pim_instance *pim = c_oil->pim;

	pim->mroute_del_last = pim_time_monotonic_sec();
	++pim->mroute_del_events;

	if (!c_oil->installed) {
		if (PIM_DEBUG_MROUTE) {
			char buffer[2048];
			zlog_debug("%s %s: vifi %d for route is %s not installed, do not need to send del req. ",
				   __FILE__, __func__, c_oil->iif.index,
				   pim_channel_oil_dump(c_oil, buffer, sizeof(buffer)));
		}
		return -2;
	}

	pimsb_mroute_do(c_oil, false);

	if (PIM_DEBUG_MROUTE) {
		char buffer[2048];

		zlog_debug("%s(%s), vrf %s Deleted Route: %s", __func__, name, pim->vrf->name,
			   pim_channel_oil_dump(c_oil, buffer, sizeof(buffer)));
	}

	return 0;
}

/*
 * Southbound callbacks
 */
static int pimsb_interface_enable(struct interface *ifp, pim_addr ifaddr, unsigned char flags)
{
	struct pim_interface *pim_ifp = ifp->info;

	/*
	 * In southbound we do 1:1 mapping interface index and
	 * multicast interface index.
	 */
	pim_ifp->mroute_vif_index = ifp->ifindex;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: Add Vif %d (%s[%s])", __func__, pim_ifp->mroute_vif_index,
			   ifp->name, pim_ifp->pim->vrf->name);

	return 0;
}

static void pimsb_interface_disable(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: Del Vif %d (%s[%s])", __func__, pim_ifp->mroute_vif_index,
			   ifp->name, pim_ifp->pim->vrf->name);
}

void pimsb_configure(void)
{
	southbound = (struct pim_sb_cbs){
		.interface_max = PIMSB_MAX_MULTICAST_IFS,
		.mroute_enable = pimsb_mroute_socket_enable,
		.mroute_disable = pimsb_mroute_socket_disable,
		.mroute_install = pimsb_mroute_add,
		.mroute_uninstall = pimsb_mroute_del,
		.interface_enable = pimsb_interface_enable,
		.interface_disable = pimsb_interface_disable,
		.interface_join = pimsb_interface_join,
		.interface_leave = pimsb_interface_leave,
	};
}


/*
 * Southbound connection handling
 */

/** PIM southbound client for server mode. */
struct pimsb_client {
	/** Peer socket. */
	int sock;
	/** Input events. */
	struct event *in_ev;
	/** Output events. */
	struct event *out_ev;
	/** Connection start event. */
	struct event *connstart_ev;

	/** Peer message buffer. */
	char msgbuf[256];
	/** Bytes available. */
	size_t msgbuf_available;
};

/** PIM southbound server information for client mode */
struct pimsb_server {
	/** Listening socket for server mode. */
	int listening_socket;
	/** Listening event. */
	struct event *listening_ev;
	/** Reuse PIM client context for server. */
	struct pimsb_client client;
};

/** PIM southbound context information. */
struct pimsb_ctx {
	/*
	 * PIM southbound can operate in two ways:
	 *  - Client mode (connects to a server)
	 *  - Server mode (accepts only one connection a time)
	 */
	union {
		struct pimsb_client client;
		struct pimsb_server server;
	};
	/** Client/server indicator. */
	bool is_server;
	/** Listening/connect address. */
	struct sockaddr_storage ss;
	/** Address length. */
	socklen_t sslen;
};

static struct pimsb_ctx pimsb_ctx;

static void pimsb_client_start_connection_cb(struct event *t);

static void pimsb_client_stop(struct pimsb_client *client)
{
	if (client->sock != -1) {
		close(client->sock);
		client->sock = -1;
	}

	client->msgbuf_available = 0;
	event_cancel(&client->in_ev);
	event_cancel(&client->out_ev);
	event_cancel(&client->connstart_ev);
}

static void pimsb_client_restart(struct pimsb_client *client)
{
	pimsb_client_stop(client);

	/* If server then wait for the next accepted connection. */
	if (pimsb_ctx.is_server)
		return;

	/* If client then try to connect again. */
	event_add_timer(router->master, pimsb_client_start_connection_cb, client, 3,
			&client->connstart_ev);
}

static void pimsb_client_data_start(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	int32_t input_index = ntohl(me->iif_idx);
	pim_sgaddr sg_p = {
#if PIM_IPV == 4
		.src = me->source.v4,
		.grp = me->group.v4,
#else
		.src = me->source.v6,
		.grp = me->group.v6,
#endif
	};

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(input_index, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (!ifp) {
		zlog_err("%s: DATA_START %pSG interface %d not found", __func__, &sg_p,
			 ntohl(me->iif_idx));
		return;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		zlog_err("%s: DATA_START %pSG interface %s(%d) disabled", __func__, &sg_p,
			 ifp->name, ifp->ifindex);
		return;
	}

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: DATA_START %pSG interface %s(%d)", __func__, &sg_p, ifp->name,
			   ifp->ifindex);

#if PIM_IPV == 6
	pim_addr embedded_rp;

	if (pim_ifp->pim->embedded_rp.enable && pim_embedded_rp_extract(&sg_p.grp, &embedded_rp) &&
	    !pim_embedded_rp_filter_match(pim_ifp->pim, &sg_p.grp))
		pim_embedded_rp_new(pim_ifp->pim, &sg_p.grp, &embedded_rp);
#endif /* PIM_IPV == 6 */

	/* Handle simplest case first. */
	if (pim_if_connected_to_source(ifp, sg_p.src)) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: source connected (%s, %pPA)", __func__, ifp->name,
				   &sg_p.src);

		if (!(PIM_I_am_DR(pim_ifp))) {
			if (PIM_DEBUG_MROUTE_DETAIL)
				zlog_debug("%s: '%s' is not the DR for %pSG", __func__, ifp->name,
					   &sg_p);

			up = pim_upstream_find_or_add(&sg_p, ifp,
						      PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE, __func__);
			pim_upstream_mroute_add(up->channel_oil, __func__);
			return;
		}

		up = pim_upstream_find(pim_ifp->pim, &sg_p);
		if (!up)
			up = pim_upstream_add(pim_ifp->pim, &sg_p, ifp, PIM_UPSTREAM_FLAG_MASK_FHR,
					      __func__, NULL);

		PIM_UPSTREAM_FLAG_SET_SRC_STREAM(up->flags);
		up->flags |= PIM_UPSTREAM_FLAG_MASK_DATA_START;
		pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);

		up->channel_oil->cc.pktcnt++;
		if (up->rpf.source_nexthop.interface != NULL &&
		    up->channel_oil->iif.index >= southbound.interface_max)
			pim_upstream_mroute_iif_update(up->channel_oil, __func__);

		pim_register_join(up);
		pim_upstream_inherited_olist_decide(pim_ifp->pim, up);
		pimsb_mroute_do(up->channel_oil, true);
		return;
	}

	/* Figure out what case this is by looking at upstream. */
	up = pim_upstream_find(pim_ifp->pim, &sg_p);
	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: unconnected source (%s, %pPA) %s", __func__, ifp->name, &sg_p.src,
			   up ? (up->flags & PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED)
					   ? "upstream switch"
					   : "upstream no switch"
			      : "no upstream");

	if (up && (up->flags & PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED)) {
		struct pim_neighbor *nbr = NULL;

		/* SPT_DESIRED is holding 1 ref, "transfer" that to SRC_LHR */
		up->flags &= ~PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED;
		up->flags |= PIM_UPSTREAM_FLAG_MASK_SRC_LHR;
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%pSG4: -SPT_DESIRED +SRC_LHR rc=%d", &up->sg, up->ref_count);

		pim_upstream_set_sptbit(up, ifp);
		pim_upstream_update_use_rpt(up, true);
		pim_upstream_inherited_olist_decide(pim_ifp->pim, up);
		pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);

		/*
		 * Generate the prune message immediately for SG(*,G)
		 * so we only receive traffic from SG(S,G).
		 */
		if (up->parent && up->parent->rpf.source_nexthop.interface) {
			nbr = pim_neighbor_find(up->parent->rpf.source_nexthop.interface,
						up->parent->rpf.rpf_addr, true);
			if (nbr) {
				struct pim_rpf rpf = {};

				rpf.source_nexthop.interface = nbr->interface;
				rpf.rpf_addr = nbr->source_addr;
				pim_joinprune_send(&rpf, nbr->upstream_jp_agg);
			}
		}
		return;
	}

	if (up && (up->flags & PIM_UPSTREAM_FLAG_MASK_SRC_LHR)) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%pSG4: extra DATA_START after SPT switch", &up->sg);
		if (up->sptbit != PIM_UPSTREAM_SPTBIT_TRUE)
			zlog_warn("%pSG4: LHR DATA_START without SPT_DESIRED, and we're not on SPT?",
				  &up->sg);
		return;
	}

	if (!up)
		up = pim_upstream_add(pim_ifp->pim, &sg_p, ifp, PIM_UPSTREAM_FLAG_MASK_SRC_PIM,
				      __func__, NULL);
	if (!up)
		return;

	up->flags |= PIM_UPSTREAM_FLAG_MASK_DATA_START;
	up->flags |= PIM_UPSTREAM_FLAG_MASK_USE_RPT;
	pimsb_mroute_do(up->channel_oil, true);
}

static void pimsb_client_data_stop(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	pim_sgaddr sg = {
#if PIM_IPV == 4
		.src = me->source.v4,
		.grp = me->group.v4,
#else
		.src = me->source.v6,
		.grp = me->group.v6,
#endif
	};

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(ntohl(me->iif_idx), vrf->vrf_id);
		if (ifp)
			break;
	}
	if (!ifp) {
		zlog_err("%s: DATA_STOP %pSG interface %d not found", __func__, &sg,
			 ntohl(me->iif_idx));
		return;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		zlog_err("%s: DATA_STOP %pSG interface %s(%d) disabled", __func__, &sg, ifp->name,
			 ifp->ifindex);
		return;
	}

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: DATA_STOP %pSG interface %s(%d)", __func__, &sg, ifp->name,
			   ifp->ifindex);

	up = pim_upstream_find(pim_ifp->pim, &sg);
	if (!up) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s:   upstream %pSG not found", __func__, &sg);
		return;
	}

	/* Don't remove routes created by IGMP joins. */
	if (up->flags & PIM_UPSTREAM_FLAG_MASK_SRC_IGMP) {
		zlog_debug("%s:  route not removed due to IGMP join", __func__);
		return;
	}

	/* HACK: make sure reference count is low so it gets deleted. */
	up->ref_count = 1;

	pim_upstream_del(pim_ifp->pim, up, __func__);
}

static void pimsb_client_wrong_if(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	int32_t input_index = ntohl(me->iif_idx);
	kernmsg im = {};
	pim_sgaddr sg = {
#if PIM_IPV == 4
		.src = me->source.v4,
		.grp = me->group.v4,
#else
		.src = me->source.v6,
		.grp = me->group.v6,
#endif
	};

#if PIM_IPV == 4
	im.im_msgtype = IGMPMSG_WRONGVIF;
	im.im_src = me->source.v4;
	im.im_dst = me->group.v4;
	im.im_vif = input_index;
#else
	im.im6_msgtype = MRT6MSG_WRONGMIF;
	im.im6_src = me->source.v6;
	im.im6_dst = me->group.v6;
	im.im6_mif = input_index;
#endif

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(input_index, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (!ifp) {
		zlog_err("%s: WRONG_IF %pSG interface %d not found", __func__, &sg,
			 ntohl(me->iif_idx));
		return;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		zlog_err("%s: WRONG_IF %pSG interface %s(%d) disabled", __func__, &sg, ifp->name,
			 ifp->ifindex);
		return;
	}

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: WRONG_IF %pSG interface %s(%d)", __func__, &sg, ifp->name,
			   ifp->ifindex);

	if (pim_ifp)
		pim_mroute_msg_wrongvif(pim_ifp->pim->mroute_socket, ifp, &im);
}

static void pimsb_client_spt_join(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	pim_sgaddr sg_p = {
#if PIM_IPV == 4
		.src = me->source.v4,
		.grp = me->group.v4,
#else
		.src = me->source.v6,
		.grp = me->group.v6,
#endif
	};

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(ntohl(me->iif_idx), vrf->vrf_id);
		if (ifp)
			break;
	}
	if (!ifp) {
		zlog_err("%s: SPT_JOIN %pSG interface %d not found", __func__, &sg_p,
			 ntohl(me->iif_idx));
		return;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		zlog_err("%s: SPT_JOIN %pSG interface %s(%d) disabled", __func__, &sg_p, ifp->name,
			 ifp->ifindex);
		return;
	}

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: SPT_JOIN %pSG interface %s(%d)", __func__, &sg_p, ifp->name,
			   ifp->ifindex);

	up = pim_upstream_add(pim_ifp->pim, &sg_p, NULL, PIM_UPSTREAM_FLAG_MASK_SRC_PIM, __func__,
			      NULL);
	if (!up)
		return;

	/*
	 * pim_upstream_add unconditionally added a ref above.  but the ref
	 * we track here is bound to the SPT_DESIRED/SRC_LHR flag (otherwise
	 * we leak later)
	 */
	if (up->flags & (PIM_UPSTREAM_FLAG_MASK_SPT_DESIRED | PIM_UPSTREAM_FLAG_MASK_SRC_LHR)) {
		assert(up->ref_count >= 2);
		pim_upstream_del(pim_ifp->pim, up, __func__);
	} else {
		/*
		 * Once the data plane switches this flow over to the SPT it
		 * is handled entirely in hardware, so a follow-up DATA_START
		 * (which is what normally moves SPT_DESIRED to SRC_LHR) may
		 * never show up.  Mark this as SRC_LHR right away instead of
		 * waiting on that event, otherwise nothing ever keeps this
		 * upstream's keepalive timer running and the SPT silently
		 * reverts back to the RPT once it expires.
		 */
		up->flags |= PIM_UPSTREAM_FLAG_MASK_SRC_LHR;
	}

	pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);
	pim_upstream_inherited_olist(pim_ifp->pim, up);
}

/** Parses message buffer and returns whether it can be called again. */
static bool pimsb_client_msg_parse(struct pimsb_client *client)
{
	const struct mroute_event_header *meheader;
	size_t msglen;

	/* Check for minimum amount of data. */
	if (client->msgbuf_available < sizeof(*meheader)) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: header incomplete (%zu of %zu bytes)", __func__,
				   sizeof(*meheader), client->msgbuf_available);
		return false;
	}

	/* Basic header length check. */
	meheader = (const struct mroute_event_header *)client->msgbuf;
	msglen = ntohs(meheader->length);
	if (msglen < sizeof(*meheader)) {
		zlog_err("%s: invalid length %zu", __func__, msglen);
		/*
		 * We've got an invalid message length so all other messages
		 * in this stream will be unaligned or wrong.
		 */
		pimsb_client_restart(client);
		return false;
	}

	/* Check if we've downloaded the whole message. */
	if (msglen > client->msgbuf_available) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: message incomplete (%zu of %zu bytes)", __func__, msglen,
				   client->msgbuf_available);
		return false;
	}

	/* Basic version check. */
	if (meheader->version != MRE_VERSION_V1) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: invalid version %d (skipping message)", __func__,
				   meheader->version);
		goto prepare_next_message;
	}

	switch (meheader->type) {
	case MRT_EVENT_DATA_START:
		pimsb_client_data_start((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_DATA_STOP:
		pimsb_client_data_stop((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_WRONG_IF:
		pimsb_client_wrong_if((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_JOIN_SPT:
		pimsb_client_spt_join((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_DATA_PACKET:
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: DATA_PACKET: not implemented", __func__);
		break;

	default:
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: unhandled type %d", __func__, meheader->type);
		break;
	}

prepare_next_message:
	/* Move data to the beginning of the buffer and account it. */
	if ((client->msgbuf_available - msglen) > 0)
		memmove(client->msgbuf, client->msgbuf + msglen, client->msgbuf_available - msglen);

	client->msgbuf_available -= msglen;
	return client->msgbuf_available > 0;
}

static void pimsb_client_read_cb(struct event *t)
{
	struct pimsb_client *client = EVENT_ARG(t);
	ssize_t bytes_read;

	bytes_read = read(client->sock, client->msgbuf + client->msgbuf_available,
			  sizeof(client->msgbuf) - client->msgbuf_available);
	if (bytes_read == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			goto schedule_and_return;

		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: read: %s", __func__, strerror(errno));

		/* Fatal connection error, don't schedule anymore. */
		pimsb_client_restart(client);
		return;
	}
	if (bytes_read == 0) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: read: connection closed", __func__);

		/* Connection closed, don't schedule anymore. */
		pimsb_client_restart(client);
		return;
	}

	client->msgbuf_available += bytes_read;

	/* Handle data. */
	while (pimsb_client_msg_parse(client))
		/* NOTHING */;

	/* If client closed then don't attempt to reschedule. */
	if (client->sock == -1)
		return;

schedule_and_return:
	event_add_read(router->master, pimsb_client_read_cb, client, client->sock, &client->in_ev);
}

static void pimsb_client_connect_cb(struct event *t)
{
	struct pimsb_client *client = EVENT_ARG(t);
	int rv = 0;
	socklen_t rvlen = sizeof(rv);

	/* Make sure `errno` is reset, then test `getsockopt` success. */
	errno = 0;
	if (getsockopt(client->sock, SOL_SOCKET, SO_ERROR, &rv, &rvlen) == -1)
		rv = -1;

	/* Connection successful. */
	if (rv == 0) {
		if (!client->in_ev)
			event_add_read(router->master, pimsb_client_read_cb, client, client->sock,
				       &client->in_ev);
		return;
	}

	switch (rv) {
	case EINTR:
	case EAGAIN:
	case EALREADY:
	case EINPROGRESS:
		/* non error, wait more. */
		if (!client->out_ev)
			event_add_write(router->master, pimsb_client_connect_cb, client,
					client->sock, &client->out_ev);
		return;

	default:
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: connection failed: %s", __func__, strerror(rv));

		pimsb_client_restart(client);
		return;
	}
}

static void pimsb_client_start_connection_cb(struct event *t)
{
	struct pimsb_client *client = EVENT_ARG(t);
	int rv;

	client->sock = socket(pimsb_ctx.ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (client->sock == -1) {
		zlog_err("%s: socket: %s", __func__, strerror(errno));
		event_add_timer(router->master, pimsb_client_start_connection_cb, client, 3,
				&client->connstart_ev);
		return;
	}

	/* Set 'no delay' (disables nagle algorithm) for IPv4/IPv6. */
	rv = 1;
	if (pimsb_ctx.ss.ss_family != AF_UNIX &&
	    setsockopt(client->sock, IPPROTO_TCP, TCP_NODELAY, &rv, sizeof(rv)) == -1)
		zlog_warn("%s: setsockopt(TCP_NODELAY): %s", __func__, strerror(errno));

	rv = connect(client->sock, (struct sockaddr *)&pimsb_ctx.ss, pimsb_ctx.sslen);
	/* Connection successful, just schedule read. */
	if (rv == 0) {
		event_add_read(router->master, pimsb_client_read_cb, client, client->sock,
			       &client->in_ev);
		return;
	}

	/* Connect failed, handle it according to the failure. */
	if (errno == EAGAIN || errno == EALREADY || errno == EINPROGRESS) {
		event_add_write(router->master, pimsb_client_connect_cb, client, client->sock,
				&client->out_ev);
		return;
	}

	close(client->sock);
	client->sock = -1;

	/* Try again later, maybe the server will be available. */
	event_add_timer(router->master, pimsb_client_start_connection_cb, client, 3,
			&client->connstart_ev);
}

static void pimsb_server_wait_cb(struct event *t)
{
	int sock = EVENT_FD(t);
	int fd;

	/* Accept new connection. */
	fd = accept(sock, NULL, NULL);
	if (fd == -1) {
		zlog_err("%s: accept: %s", __func__, strerror(errno));
		goto schedule_and_return;
	}

	/* Only one client supported at the moment. */
	if (pimsb_ctx.server.client.sock != -1) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: client already connected", __func__);

		close(fd);
		goto schedule_and_return;
	}

	/* Schedule new client read events. */
	pimsb_ctx.server.client.sock = fd;
	event_add_read(router->master, pimsb_client_read_cb, &pimsb_ctx.server.client, fd,
		       &pimsb_ctx.server.client.in_ev);

schedule_and_return:
	/* Re-schedule accept connection. */
	event_add_read(router->master, pimsb_server_wait_cb, NULL, sock,
		       &pimsb_ctx.server.listening_ev);
}

void pimsb_socket_init(const struct sockaddr_storage *ss, socklen_t sslen, bool client)
{
	int sock;

	pimsb_ctx.ss = *ss;
	pimsb_ctx.sslen = sslen;

	if (client) {
		/* Start client socket. */
		zlog_info("initializing PIM southbound (client mode)");
		event_add_timer(router->master, pimsb_client_start_connection_cb,
				&pimsb_ctx.client, 0, &pimsb_ctx.client.connstart_ev);
		return;
	}

	zlog_info("initializing PIM southbound (server mode)");

	/* Start server socket. */
	sock = socket(ss->ss_family, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_err("%s: socket: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (bind(sock, (struct sockaddr *)ss, sslen) == -1) {
		zlog_err("%s: bind: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (listen(sock, 1) == -1) {
		zlog_err("%s: listen: %s", __func__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Reset server's client data socket value. */
	pimsb_ctx.server.client.sock = -1;

	/* Schedule listening events. */
	event_add_read(router->master, pimsb_server_wait_cb, NULL, sock,
		       &pimsb_ctx.server.listening_ev);

	pimsb_ctx.is_server = true;
}

void pimsb_socket_stop(void)
{
	if (pimsb_ctx.is_server) {
		event_cancel(&pimsb_ctx.server.listening_ev);
		close(pimsb_ctx.server.listening_socket);
		pimsb_ctx.server.listening_socket = -1;
		pimsb_client_stop(&pimsb_ctx.server.client);
	} else
		pimsb_client_stop(&pimsb_ctx.client);
}
