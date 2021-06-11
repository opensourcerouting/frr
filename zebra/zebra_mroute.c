// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra_mroute code
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This file is part of Quagga
 */

#include <zebra.h>

#include "stream.h"
#include "prefix.h"
#include "vrf.h"
#include "rib.h"

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mroute.h"
#include "zebra/rt.h"
#include "zebra/debug.h"

void zebra_ipmr_route_stats(ZAPI_HANDLER_ARGS)
{
	struct mcast_route_data mroute;
	struct stream *s;
	int suc = -1;

	memset(&mroute, 0, sizeof(mroute));
	STREAM_GETL(msg, mroute.family);

	switch (mroute.family) {
	case AF_INET:
		SET_IPADDR_V4(&mroute.src);
		SET_IPADDR_V4(&mroute.grp);
		STREAM_GET(&mroute.src.ipaddr_v4, msg,
			   sizeof(mroute.src.ipaddr_v4));
		STREAM_GET(&mroute.grp.ipaddr_v4, msg,
			   sizeof(mroute.grp.ipaddr_v4));
		break;
	case AF_INET6:
		SET_IPADDR_V6(&mroute.src);
		SET_IPADDR_V6(&mroute.grp);
		STREAM_GET(&mroute.src.ipaddr_v6, msg,
			   sizeof(mroute.src.ipaddr_v6));
		STREAM_GET(&mroute.grp.ipaddr_v6, msg,
			   sizeof(mroute.grp.ipaddr_v6));
		break;
	default:
		zlog_warn("%s: Invalid address family received while parsing",
			  __func__);
		return;
	}

	STREAM_GETL(msg, mroute.ifindex);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Asking for (%pIA,%pIA)[%s(%u)] mroute information",
			   &mroute.src, &mroute.grp, zvrf->vrf->name,
			   zvrf->vrf->vrf_id);

	suc = kernel_get_ipmr_sg_stats(zvrf, &mroute);

stream_failure:
	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);

	stream_reset(s);

	zclient_create_header(s, ZEBRA_IPMR_ROUTE_STATS, zvrf_id(zvrf));

	if (mroute.family == AF_INET) {
		stream_write(s, &mroute.src.ipaddr_v4,
			     sizeof(mroute.src.ipaddr_v4));
		stream_write(s, &mroute.grp.ipaddr_v4,
			     sizeof(mroute.grp.ipaddr_v4));
	} else {
		stream_write(s, &mroute.src.ipaddr_v6,
			     sizeof(mroute.src.ipaddr_v6));
		stream_write(s, &mroute.grp.ipaddr_v6,
			     sizeof(mroute.grp.ipaddr_v6));
	}

	stream_put(s, &mroute.lastused, sizeof(mroute.lastused));
	stream_putl(s, (uint32_t)suc);

	stream_putw_at(s, 0, stream_get_endp(s));
	zserv_send_message(client, s);
}

struct mroute_oif_arg *mroute_oif_arg_new(struct mroute_oif_list *oif_list)
{
	struct mroute_oif_arg *oif;

	oif = XCALLOC(MTYPE_TMP, sizeof(*oif));
	SLIST_INSERT_HEAD(oif_list, oif, entry);

	return oif;
}

void mroute_oif_arg_free(struct mroute_oif_list *oif_list, struct mroute_oif_arg **oif)
{
	if (*oif == NULL)
		return;

	SLIST_REMOVE(oif_list, (*oif), mroute_oif_arg, entry);
	XFREE(MTYPE_TMP, (*oif));
}

void mroute_oif_list_free_all(struct mroute_oif_list *oif_list)
{
	while (!SLIST_EMPTY(oif_list)) {
		struct mroute_oif_arg *oif = SLIST_FIRST(oif_list);
		mroute_oif_arg_free(oif_list, &oif);
	}
}

void zmroute_event(ZAPI_HANDLER_ARGS)
{
	size_t output_idx;
	uint16_t family;
	uint16_t type;
	struct ipaddr ipa = {};
	struct mroute_args args = {};

	STREAM_GETW(msg, type);
	if (type == 0)
		args.mroute_op = DPLANE_OP_MROUTE_INSTALL;
	else
		args.mroute_op = DPLANE_OP_MROUTE_DELETE;

	STREAM_GETW(msg, family);
	if (family == AF_INET) {
		ipa.ipa_type = AF_INET;
		STREAM_GETL(msg, ipa.ipaddr_v4.s_addr);
		args.source = ipa;

		STREAM_GETL(msg, ipa.ipaddr_v4.s_addr);
		args.group = ipa;
	}

	STREAM_GETL(msg, args.input);
	STREAM_GETL(msg, args.notif_idx);
	STREAM_GETW(msg, args.flags);
	STREAM_GETW(msg, args.output_amount);
	if (args.output_amount > MAXVIFS) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: invalid amount of interfaces %zu, truncating to %d",
				   __func__, args.output_amount, MAXVIFS);

		args.output_amount = MAXVIFS;
	}
	for (output_idx = 0; output_idx < args.output_amount; output_idx++) {
		struct mroute_oif_arg *oif = mroute_oif_arg_new(&args.oif_list);
		ifindex_t index;

		STREAM_GETL(msg, index);
		oif->index = index;
	}

	STREAM_GETL(msg, args.spt_threshold);

	STREAM_GETL(msg, ipa.ipaddr_v4.s_addr);
	args.local = ipa;
	STREAM_GETL(msg, ipa.ipaddr_v4.s_addr);
	args.remote = ipa;

	dplane_mroute_enqueue(&args);
	mroute_oif_list_free_all(&args.oif_list);
	return;

stream_failure:
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: message parse failure", __func__);
	return;
}
