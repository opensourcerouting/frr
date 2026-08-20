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
	/** Packet read buffer */
	char *pktbuf;
	/** Packet read buffer size */
	size_t pktbuflen;
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
	if (ifp == NULL) {
		zlog_err("%s: DATA_START %pSG interface %d not found", __func__, &sg_p,
			 ntohl(me->iif_idx));
		return;
	}

	pim_ifp = ifp->info;
	if (pim_ifp == NULL) {
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
		if (up == NULL)
			up = pim_upstream_add(pim_ifp->pim, &sg_p, ifp, PIM_UPSTREAM_FLAG_MASK_FHR,
					      __func__, NULL);

		PIM_UPSTREAM_FLAG_SET_SRC_STREAM(up->flags);
		up->flags |= PIM_UPSTREAM_FLAG_MASK_DATA_START;
		pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);

		up->channel_oil->cc.pktcnt++;
		if (up->rpf.source_nexthop.interface != NULL &&
		    *oil_incoming_vif(up->channel_oil) >= system_maxvifs())
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
	if (ifp == NULL) {
		zlog_err("%s: DATA_STOP %pSG interface %d not found", __func__, &sg,
			 ntohl(me->iif_idx));
		return;
	}

	pim_ifp = ifp->info;
	if (pim_ifp == NULL) {
		zlog_err("%s: DATA_STOP %pSG interface %s(%d) disabled", __func__, &sg, ifp->name,
			 ifp->ifindex);
		return;
	}

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: DATA_STOP %pSG interface %s(%d)", __func__, &sg, ifp->name,
			   ifp->ifindex);

	up = pim_upstream_find(pim_ifp->pim, &sg);
	if (up == NULL) {
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
	if (ifp == NULL) {
		zlog_err("%s: WRONG_IF %pSG interface %d not found", __func__, &sg,
			 ntohl(me->iif_idx));
		return;
	}

	pim_ifp = ifp->info;
	if (pim_ifp == NULL) {
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
	if (ifp == NULL) {
		zlog_err("%s: SPT_JOIN %pSG interface %d not found", __func__, &sg_p,
			 ntohl(me->iif_idx));
		return;
	}

	pim_ifp = ifp->info;
	if (pim_ifp == NULL) {
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
		if (client->in_ev == NULL)
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
		if (client->out_ev == NULL)
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
