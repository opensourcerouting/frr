// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM southbound implementation.
 *
 * Copyright (C) 2021-2026 Network Education Foundation
 *                         Rafael Zalamena
 */

#ifdef HAVE_CONFIG_H
#include "config.h" /* Include this explicitly */
#endif

#include "lib/lib_errors.h"
#include "lib/libfrr.h"
#include "lib/network.h"
#include "lib/sockopt.h"

#include "pimd/pim_iface.h"
#include "pimd/pim_instance.h"
#include "pimd/pim_neighbor.h"
#include "pimd/pim_pim.h"
#include "pimd/pim_southbound_common.h"
#include "pimd/pim6_mld_protocol.h"
#include "pimd/pimd.h"

struct pimsb_ctx {
	/** IGMP socket */
	int mld_fd;
	/** IGMP socket read event */
	struct event *mld_read_ev;

	/** PIM socket */
	int pim_fd;
	/** PIM socket read event */
	struct event *pim_read_ev;

	/** PIM unicast socket */
	int pim_unicast_fd;
	/** PIM unicast read event */
	struct event *pim_unicast_read_ev;

	/** PIM southbound connection data */
	struct network_address address;

	/** Packet receive buffer */
	uint8_t *packet;
	/** Packet receiver buffer size */
	size_t packet_size;
};

static struct pimsb_ctx ctx = {
	.mld_fd = -1,
	.pim_fd = -1,
};

#if 0
/*
 * MLD socket.
 */
static bool pimsb_mld_parse_hopopts(const uint8_t *hopopt,
				    const size_t hopopt_len, uint8_t **data,
				    size_t *data_len)
{
	size_t hopopt_end;

	*data = (uint8_t *)(size_t)hopopt;
	*data_len = hopopt_len;
	if (hopopt_len <= 8)
		return false;

	hopopt_end = (size_t)(hopopt[1] + 1) * 8;
	if (hopopt_len <= hopopt_end)
		return false;

	*data = (uint8_t *)(size_t)(hopopt + hopopt_end);
	*data_len = hopopt_len - hopopt_end;
	return hopopt[0] == IPPROTO_ICMPV6 &&
	       ip6_check_hopopts_ra(hopopt, hopopt_end, IP6_ALERT_MLD);
}

void pimsb_msg_send_frame(const pim_addr *src, const pim_addr *dst,
			  const struct interface *ifp, struct iovec *iov,
			  int fd)
{
	struct in6_pktinfo ipi6;
	struct cmsghdr *cmsg;
	ssize_t bytes;
	uint32_t ifindex;
	struct msghdr msg;
	struct sockaddr_in6 dest;
	char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
		     CMSG_SPACE(sizeof(uint32_t))];

	memset(&dest, 0, sizeof(dest));
	dest.sin6_family = AF_INET6;
#ifdef SIN6_LEN
	dest.sin6_len = sizeof(struct sockaddr_in6);
#endif /*SIN6_LEN*/
	dest.sin6_addr = *dst;
	if (ifp != NULL) {
		if (ifp->vif_index)
			dest.sin6_scope_id = ifp->vif_index;
		else
			dest.sin6_scope_id = ifp->ifindex;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &dest;
	msg.msg_namelen = sizeof(dest);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if (ifp != NULL) {
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		memset(&ipi6, 0, sizeof(ipi6));
		ipi6.ipi6_addr = *src;
		ipi6.ipi6_ifindex = dest.sin6_scope_id;
		memcpy(CMSG_DATA(cmsg), &ipi6, sizeof(ipi6));

		cmsg = CMSG_NXTHDR(&msg, cmsg);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_FLOWINFO;
		cmsg->cmsg_len = CMSG_SPACE(sizeof(uint32_t));
		ifindex = htonl((uint32_t)ifp->ifindex);
		memcpy(CMSG_DATA(cmsg), &ifindex, sizeof(uint32_t));

		fd = pim_fd;
	}

	bytes = sendmsg(fd, &msg, 0);
	if (bytes == -1)
		zlog_warn("%s: sendmsg: (%d) %s", __func__, errno,
			  strerror(errno));
}

struct pimsb_loopback_packet {
	const struct gm_if *gm_if;
	struct sockaddr_in6 src;
	pim_addr dst;
	int proto;

	size_t data_len;
	uint8_t data[];
};

static void pimsb_recv_loopback(struct thread *t)
{
	struct pimsb_loopback_packet *packet = THREAD_ARG(t);
	gm_rx_process((struct gm_if *)packet->gm_if, &packet->src, &packet->dst,
		      packet->proto, packet->data, packet->data_len);
	XFREE(MTYPE_TMP, packet);
}

static void pimsb_send_loopback(const struct gm_if *gm_if,
				const struct msghdr *msg)
{
	const struct ipv6_ph *ipv6 =
		(const struct ipv6_ph *)msg->msg_iov[-1].iov_base;
	struct pimsb_loopback_packet *packet;
	size_t packet_len;

	if (msg->msg_iovlen == 1)
		packet_len = msg->msg_iov[0].iov_len;
	else
		packet_len = msg->msg_iov[0].iov_len + msg->msg_iov[1].iov_len;

	packet = XCALLOC(MTYPE_TMP, sizeof(*packet) + packet_len);
	packet->gm_if = gm_if;
	packet->src = (struct sockaddr_in6){
		.sin6_family = AF_INET6,
		.sin6_addr = ipv6->src,
	};
	packet->dst = ipv6->dst;
	packet->proto = ipv6->next_hdr;

	packet->data_len = packet_len;
	memcpy(packet->data, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len);
	if (msg->msg_iovlen == 2)
		memcpy(packet->data + msg->msg_iov[0].iov_len,
		       msg->msg_iov[1].iov_base, msg->msg_iov[1].iov_len);

	thread_add_timer(router->master, pimsb_recv_loopback, packet, 0, NULL);
}

int pimsb_send_query(const struct gm_if *gm_ifp, struct msghdr *msg,
		     struct in6_pktinfo *ipi6, int proto)
{
	const struct interface *ifp = gm_ifp->ifp;
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
	struct sockaddr_in6 *dst;
	int32_t ifindex;
	int32_t vifindex;

	pimsb_send_loopback(gm_ifp, msg);

	ifindex = htonl(ifp->ifindex);
	vifindex = ifp->vif_index ? ifp->vif_index : ifp->ifindex;

	/* Configure virtual interface to output packet. */
	dst = (struct sockaddr_in6 *)msg->msg_name;
	dst->sin6_scope_id = vifindex;
	ipi6->ipi6_ifindex = vifindex;

	/* Skip IPV6_HOPOPTS */
	cmsg = CMSG_NXTHDR(msg, cmsg);
	/* Skip IPV6_PKTINFO */
	cmsg = CMSG_NXTHDR(msg, cmsg);
	/* Configure flow with real interface id. */
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_FLOWINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
	memcpy(CMSG_DATA(cmsg), &ifindex, sizeof(uint32_t));

	switch (proto) {
	case PIM_IPV6_ENCAP_MLD:
		return (int)sendmsg(mld_fd, msg, 0);

	default:
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: unhandled protocol %d", __func__,
				   proto);
		/* FALL THROUGH */

	case IPPROTO_ICMPV6:
		return (int)sendmsg(gm_ifp->pim->gm_socket, msg, 0);
	}
}

static void pimsb_mld_send(const struct interface *interface, bool join,
			   const pim_addr *source, const pim_addr *group)
{
	struct pim_interface *pim_interface = interface->info;
	struct mld_packet_list *packet_list;
	struct mld_packet *packet;
	struct cmsghdr *cmsg;
	uint8_t *dp;
	struct iovec iov[2];
	struct msghdr msg;
	struct in6_pktinfo ipi6;
	struct sockaddr_in6 sin6_src;
	struct sockaddr_in6 sin6_dst;
	char cmsgbuf[CMSG_SPACE(8) + CMSG_SPACE(sizeof(struct in6_pktinfo)) +
		     CMSG_SPACE(sizeof(uint32_t))];

	packet_list = mld_generate_packet_list(interface, join, source, group);

	/* MLD static join was called, but no groups configured. */
	if (packet_list == NULL)
		return;

	memset(&sin6_src, 0, sizeof(sin6_src));
	sin6_src.sin6_family = AF_INET6;
	memset(&sin6_dst, 0, sizeof(sin6_dst));
	sin6_dst.sin6_family = AF_INET6;

	memset(&ipi6, 0, sizeof(ipi6));
	ipi6.ipi6_ifindex = (unsigned int)interface->ifindex;

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_iov = &iov[1];
	msg.msg_iovlen = 1;
	msg.msg_name = &sin6_dst;
	msg.msg_namelen = sizeof(sin6_dst);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_HOPOPTS;
	cmsg->cmsg_len = CMSG_LEN(8);
	dp = CMSG_DATA(cmsg);
	*dp++ = 0;		     /* next header */
	*dp++ = 0;		     /* length (8-byte blocks, minus 1) */
	*dp++ = IP6OPT_ROUTER_ALERT; /* router alert */
	*dp++ = 2;		     /* length */
	*dp++ = 0;		     /* value (2 bytes) */
	*dp++ = 0;		     /* value (2 bytes) (0 = MLD) */
	*dp++ = 0;		     /* pad0 */
	*dp++ = 0;		     /* pad0 */

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

	SLIST_FOREACH (packet, packet_list, entry) {
		ipi6.ipi6_addr = packet->ip6->src;
		sin6_src.sin6_addr = packet->ip6->src;
		sin6_dst.sin6_addr = packet->ip6->dst;
		iov[0].iov_base = packet->ip6;
		iov[0].iov_len = sizeof(packet->ip6);
		iov[1].iov_base = packet->icmp6;
		iov[1].iov_len = packet->size;

		frr_with_privs (&pimd_privs) {
			pimsb_send_query(pim_interface->mld, &msg, &ipi6,
					 PIM_IPV6_ENCAP_MLD);
		}
	}

	mld_free_packet_list(packet_list);
}
#endif

static void pimsb_mld_read(struct thread *t __attribute__((unused)))
{
	struct pim_interface *pim_ifp;
	struct interface *ifp;
	struct vrf *vrf;
	struct cmsghdr *cmsg;
	uint8_t *pktbuf;
	bool has_router_alert;
	size_t pktbuf_len;
	ssize_t brecv;
	uint32_t flowinfo;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_in6 src;
	struct in6_pktinfo ipi6;
	char cmsgbuf[
		CMSG_SPACE(sizeof(struct in6_pktinfo)) +
		CMSG_SPACE(sizeof(uint32_t))
	];

	thread_add_read(router->master, pimsb_mld_read, NULL, ctx.mld_fd, &ctx.mld_read_ev);

	iov.iov_base = ctx.packet;
	iov.iov_len = ctx.packet_size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	brecv = recvmsg(ctx.mld_fd, &msg, 0);
	if (brecv == -1) {
		zlog_warn("%s: recvmsg: %s", __func__, strerror(errno));
		return;
	}
	if (brecv == 0) {
		zlog_warn("%s: recvmsg: EOF", __func__);
		return;
	}

	flowinfo = 0;
	memset(&ipi6, 0, sizeof(ipi6));
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;

		switch (cmsg->cmsg_type) {
		case IPV6_FLOWINFO:
			memcpy(&flowinfo, CMSG_DATA(cmsg), sizeof(flowinfo));
			flowinfo = ntohl(flowinfo) & 0x0FFFFF;
			break;
		case IPV6_PKTINFO:
			memcpy(&ipi6, CMSG_DATA(cmsg), sizeof(ipi6));
			break;
		}
	}

	ifp = NULL;
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(flowinfo, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: could not find interface %d", __func__,
				   flowinfo);
		return;
	}

	pim_ifp = ifp->info;
	if (pim_ifp == NULL || pim_ifp->mld == NULL) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: interface %s has MLD disabled",
				   __func__, ifp->name);
		return;
	}

	has_router_alert =
		pimsb_mld_parse_hopopts((uint8_t *)ctx.packet,
					(size_t)brecv, &pktbuf, &pktbuf_len);

	if (pktbuf_len < sizeof(struct icmp6_plain_hdr)) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug(
				"%s: %s: packet too small (%zd expected %zu)",
				__func__, ifp->name, brecv,
				sizeof(struct icmp6_plain_hdr));
		return;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&src.sin6_addr)) {
		/*
		 * reports from :: happen in normal operation for DAD, so
		 * don't spam log messages about this
		 */
		return;
	}

	if (!IN6_IS_ADDR_LINKLOCAL(&src.sin6_addr)) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: %s: invalid source %pI6", __func__,
				   ifp->name, &src.sin6_addr);
		return;
	}

	/* Ignore multicast packets, its impossible when using data plane. */
	if (IN6_IS_ADDR_MULTICAST(&ipi6.ipi6_addr))
		return;

	if (PIM_DEBUG_GM_PACKETS)
		zlog_debug("%s: [%pI6]->[%pI6] (%s vif %d if %d) router alert %s",
			   __func__, &src.sin6_addr, &ipi6.ipi6_addr, ifp->name,
			   ifp->vif_index, ifp->ifindex,
			   has_router_alert ? "yes" : "no");

	if (pim_ifp->gmp_require_ra && !has_router_alert) {
		zlog_err(
			"[MLD %s:%s %pI6] packet without IPv6 Router Alert MLD option",
			ifp->vrf->name, ifp->name, &src.sin6_addr);
		return;
	}

	gm_rx_process(pim_ifp->mld, &src, &ipi6.ipi6_addr, PIM_IPV6_ENCAP_MLD,
		      pktbuf, pktbuf_len);
}

static void pimsb_pim_packet_read(struct event *event __attribute__((unused)))
{
	uint8_t *pim_msg = (uint8_t *)ctx.packet;
	struct pim_interface *pim_ifp;
	struct pim_msg_header *header;
	struct pim_neighbor *neigh;
	struct interface *ifp;
	struct cmsghdr *cmsg;
	struct vrf *vrf;
	uint32_t pim_msg_len = 0;
	ssize_t brecv;
	pim_sgaddr sg;
	uint32_t flowinfo;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_in6 src;
	struct in6_pktinfo ipi6;
	char cmsgbuf[
		CMSG_SPACE(sizeof(struct in6_pktinfo)) +
		CMSG_SPACE(sizeof(uint32_t))
	];

	event_add_read(router->master, pimsb_pim_packet_read, NULL, ctx.pim_fd, &ctx.pim_read_ev);

	iov.iov_base = ctx.packet;
	iov.iov_len = ctx.packet_size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	brecv = recvmsg(ctx.pim_fd, &msg, 0);
	if (brecv == -1) {
		zlog_warn("%s: recvmsg: %s", __func__, strerror(errno));
		return;
	}
	if (brecv == 0) {
		zlog_warn("%s: recvmsg: EOF", __func__);
		return;
	}

	flowinfo = 0;
	memset(&ipi6, 0, sizeof(ipi6));
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;

		switch (cmsg->cmsg_type) {
		case IPV6_FLOWINFO:
			memcpy(&flowinfo, CMSG_DATA(cmsg), sizeof(flowinfo));
			flowinfo = ntohl(flowinfo) & 0x0FFFFF;
			break;
		case IPV6_PKTINFO:
			memcpy(&ipi6, CMSG_DATA(cmsg), sizeof(ipi6));
			break;
		}
	}

	ifp = NULL;
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(flowinfo, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: could not find interface %d", __func__,
				   flowinfo);
		return;
	}

	pim_ifp = ifp->info;
	if (pim_ifp == NULL || !pim_ifp->pim_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: interface %s has PIM disabled",
				   __func__, ifp->name);
		return;
	}

	if ((size_t)brecv < PIM_PIM_MIN_LEN) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: %s: packet too small (%zd expected %d)",
				   __func__, ifp->name, brecv, PIM_PIM_MIN_LEN);
		return;
	}

	pim_msg_len = (uint32_t)brecv;
	header = (struct pim_msg_header *)iov.iov_base;
	if (header->ver != PIM_PROTO_VERSION) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"Ignoring PIM pkt from %s with unsupported version: %d",
				ifp->name, header->ver);
		return;
	}

	/* Ignore multicast packets, its impossible when using data plane. */
	if (IN6_IS_ADDR_MULTICAST(&ipi6.ipi6_addr))
		return;

	if (PIM_DEBUG_PIM_PACKETS) {
		zlog_debug(
			"Recv PIM %s packet from %pPA to %pPA on %s: pim_version=%d pim_msg_size=%d checksum=%x",
			pim_pim_msgtype2str(header->type), &src.sin6_addr,
			&ipi6.ipi6_addr, ifp->name, header->ver, pim_msg_len,
			header->checksum);
		if (PIM_DEBUG_PIM_PACKETDUMP_RECV)
			pim_pkt_dump(__func__, pim_msg, pim_msg_len);
	}

	if (if_address_is_local(&src.sin6_addr, AF_INET6, ifp->vrf->vrf_id)) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: incoming packet from myself", __func__);
		return;
	}

	if (pim_hello_filter(ifp, &src.sin6_addr, (uint8_t *)ctx.packet, (size_t)brecv))
		return;

	switch (header->type) {
	case PIM_MSG_TYPE_HELLO:
		pim_hello_recv(ifp, src.sin6_addr, pim_msg + PIM_MSG_HEADER_LEN,
			       pim_msg_len - PIM_MSG_HEADER_LEN);
		return;
	case PIM_MSG_TYPE_REGISTER:
		pim_register_recv(ifp, ipi6.ipi6_addr, src.sin6_addr,
				  pim_msg + PIM_MSG_HEADER_LEN,
				  pim_msg_len - PIM_MSG_HEADER_LEN);
		return;
	case PIM_MSG_TYPE_REG_STOP:
		pim_register_stop_recv(ifp, pim_msg + PIM_MSG_HEADER_LEN,
				       pim_msg_len - PIM_MSG_HEADER_LEN);
		return;
	case PIM_MSG_TYPE_JOIN_PRUNE:
		neigh = pim_neighbor_find(ifp, src.sin6_addr, true);
		if (!neigh) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"%s %s: non-hello PIM message type=%d from non-neighbor %pPA on %s",
					__FILE__, __func__, header->type,
					&src.sin6_addr, ifp->name);
			return;
		}
		pim_neighbor_timer_reset(neigh, neigh->holdtime);
		pim_joinprune_recv(ifp, neigh, src.sin6_addr,
				   pim_msg + PIM_MSG_HEADER_LEN,
				   pim_msg_len - PIM_MSG_HEADER_LEN);
		return;
	case PIM_MSG_TYPE_ASSERT:
		neigh = pim_neighbor_find(ifp, src.sin6_addr, true);
		if (!neigh) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"%s %s: non-hello PIM message type=%d from non-neighbor %pPA on %s",
					__FILE__, __func__, header->type,
					&src.sin6_addr, ifp->name);
			return;
		}
		pim_neighbor_timer_reset(neigh, neigh->holdtime);
		pim_assert_recv(ifp, neigh, src.sin6_addr,
				pim_msg + PIM_MSG_HEADER_LEN,
				pim_msg_len - PIM_MSG_HEADER_LEN);
		return;
	case PIM_MSG_TYPE_BOOTSTRAP:
		sg.src = src.sin6_addr;
		sg.grp = qpim_all_pim_routers_addr;
		pim_bsm_process(ifp, &sg, pim_msg, pim_msg_len, header->Nbit);
		return;

	default:
		if (PIM_DEBUG_PIM_PACKETS) {
			zlog_debug(
				"Recv PIM packet type %d which is not currently understood",
				header->type);
		}
		return;
	}
}

static void pimsb_pim_unicast_read(struct event *event __attribute__((unused)))
{
	uint8_t *pim_msg = (uint8_t *)ctx.packet;
	struct pim_interface *pim_ifp;
	struct pim_msg_header *header;
	struct pim_neighbor *neigh;
	struct interface *ifp;
	struct cmsghdr *cmsg;
	struct vrf *vrf;
	uint32_t pim_msg_len = 0;
	ssize_t brecv;
	pim_sgaddr sg;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_in6 src;
	struct in6_pktinfo ipi6;
	char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];

	event_add_read(router->master, pimsb_pim_unicast_read, NULL, ctx.pim_unicast_fd,
		       &ctx.pim_unicast_read_ev);

	iov.iov_base = ctx.packet;
	iov.iov_len = ctx.packet_size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	brecv = recvmsg(ctx.pim_unicast_fd, &msg, 0);
	if (brecv == -1) {
		zlog_warn("%s: recvmsg: %s", __func__, strerror(errno));
		return;
	}
	if (brecv == 0) {
		zlog_warn("%s: recvmsg: EOF", __func__);
		return;
	}

	memset(&ipi6, 0, sizeof(ipi6));
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;

		switch (cmsg->cmsg_type) {
		case IPV6_PKTINFO:
			memcpy(&ipi6, CMSG_DATA(cmsg), sizeof(ipi6));
			break;
		}
	}

	ifp = NULL;
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_address_local(&ipi6.ipi6_addr, AF_INET6,
					      vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"%s: could not find interface for address %pI6",
				__func__, &ipi6.ipi6_addr);
		return;
	}

	pim_ifp = ifp->info;
	if (pim_ifp == NULL || !pim_ifp->pim_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: interface %s has PIM disabled",
				   __func__, ifp->name);
		return;
	}

	if ((size_t)brecv < PIM_PIM_MIN_LEN) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: %s: packet too small (%zd expected %d)",
				   __func__, ifp->name, brecv, PIM_PIM_MIN_LEN);
		return;
	}

	pim_msg_len = (uint32_t)brecv;
	header = (struct pim_msg_header *)iov.iov_base;
	if (header->ver != PIM_PROTO_VERSION) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"Ignoring PIM pkt from %s with unsupported version: %d",
				ifp->name, header->ver);
		return;
	}

	/* Ignore multicast packets, its impossible when using data plane. */
	if (IN6_IS_ADDR_MULTICAST(&ipi6.ipi6_addr))
		return;

	if (PIM_DEBUG_PIM_PACKETS) {
		zlog_debug(
			"Recv PIM %s packet from %pPA to %pPA on %s: pim_version=%d pim_msg_size=%d checksum=%x",
			pim_pim_msgtype2str(header->type), &src.sin6_addr,
			&ipi6.ipi6_addr, ifp->name, header->ver, pim_msg_len,
			header->checksum);
		if (PIM_DEBUG_PIM_PACKETDUMP_RECV)
			pim_pkt_dump(__func__, pim_msg, pim_msg_len);
	}

	if (pim_hello_filter(ifp, &src.sin6_addr, (uint8_t *)ctx.packet, (size_t)brecv))
		return;

	switch (header->type) {
	case PIM_MSG_TYPE_HELLO:
		pim_hello_recv(ifp, src.sin6_addr, pim_msg + PIM_MSG_HEADER_LEN,
			       pim_msg_len - PIM_MSG_HEADER_LEN);
		return;
	case PIM_MSG_TYPE_REGISTER:
		pim_register_recv(ifp, ipi6.ipi6_addr, src.sin6_addr,
				  pim_msg + PIM_MSG_HEADER_LEN,
				  pim_msg_len - PIM_MSG_HEADER_LEN);
		return;
	case PIM_MSG_TYPE_REG_STOP:
		pim_register_stop_recv(ifp, pim_msg + PIM_MSG_HEADER_LEN,
				       pim_msg_len - PIM_MSG_HEADER_LEN);
		return;
	case PIM_MSG_TYPE_JOIN_PRUNE:
		neigh = pim_neighbor_find(ifp, src.sin6_addr, true);
		if (!neigh) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"%s %s: non-hello PIM message type=%d from non-neighbor %pPA on %s",
					__FILE__, __func__, header->type,
					&src.sin6_addr, ifp->name);
			return;
		}
		pim_neighbor_timer_reset(neigh, neigh->holdtime);
		pim_joinprune_recv(ifp, neigh, src.sin6_addr,
				   pim_msg + PIM_MSG_HEADER_LEN,
				   pim_msg_len - PIM_MSG_HEADER_LEN);
		return;
	case PIM_MSG_TYPE_ASSERT:
		neigh = pim_neighbor_find(ifp, src.sin6_addr, true);
		if (!neigh) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"%s %s: non-hello PIM message type=%d from non-neighbor %pPA on %s",
					__FILE__, __func__, header->type,
					&src.sin6_addr, ifp->name);
			return;
		}
		pim_neighbor_timer_reset(neigh, neigh->holdtime);
		pim_assert_recv(ifp, neigh, src.sin6_addr,
				pim_msg + PIM_MSG_HEADER_LEN,
				pim_msg_len - PIM_MSG_HEADER_LEN);
		return;
	case PIM_MSG_TYPE_BOOTSTRAP:
		sg.src = src.sin6_addr;
		sg.grp = qpim_all_pim_routers_addr;
		pim_bsm_process(ifp, &sg, pim_msg, pim_msg_len, header->Nbit);
		return;

	default:
		if (PIM_DEBUG_PIM_PACKETS) {
			zlog_debug(
				"Recv PIM packet type %d which is not currently understood",
				header->type);
		}
		return;
	}
}

static void pimsb_mld_join(const struct interface *interface)
{
	struct pim_interface *pim_interface = interface->info;

	/* Check if MLD is active */
	if (pim_interface->mld == NULL)
		return;

	pimsb_mld_send(interface, true, NULL, NULL);
}

static void pimsb_mld_leave(const struct interface *interface,
			    const pim_addr *source, const pim_addr *group)
{
	struct pim_interface *pim_interface = interface->info;

	/* Check if MLD is active */
	if (pim_interface->mld == NULL)
		return;

	pimsb_mld_send(interface, false, source, group);
}

static void pimsb_init_pim(void)
{
	int fd;
	int on = 1;

	frr_with_privs (&pimd_privs) {
		fd = socket(PIM_AF, SOCK_RAW, PIM_IP_ENCAP_PIM);
		if (fd == -1) {
			zlog_err("%s: socket: %s", __func__, strerror(errno));
			return;
		}

		if (setsockopt_ipv6_tclass(fd, IPTOS_PREC_INTERNETCONTROL))
			zlog_warn("can't set sockopt IPV6_TOS to socket %d: %m",
				  fd);

		if (setsockopt_ipv6_pktinfo(fd, 1) == -1) {
			flog_err(
				EC_LIB_SOCKET,
				"Can't set IPV6_RECVPKTINFO option for fd %d: %s",
				fd, safe_strerror(errno));
			close(fd);
			return;
		}

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWINFO, &on,
		    sizeof(on)) == -1) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IPV6_FLOWINFO option for fd %d: %s",
				 fd, safe_strerror(errno));
			close(fd);
			return;
		}

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on,
		    sizeof(on)) == -1) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IPV6_FLOWINFO_SEND option for fd %d: %s",
				 fd, safe_strerror(errno));
			close(fd);
			return;
		}

		if (set_nonblocking(fd) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set non blocking fd %d: %s", fd,
				 safe_strerror(errno));
			close(fd);
			exit(1);
		}
	}

	setsockopt_so_sendbuf(fd, 1024 * 1024);
	setsockopt_so_recvbuf(fd, 1024 * 1024);

	ctx.pim_fd = fd;
	event_add_read(router->master, pimsb_pim_packet_read, NULL, ctx.pim_fd, &ctx.pim_read_ev);

	frr_with_privs (&pimd_privs) {
		fd = socket(PIM_AF, SOCK_RAW, IPPROTO_PIM);

		sockopt_reuseaddr(fd);
		setsockopt_ipv6_pktinfo(fd, 1);

		if (set_nonblocking(fd) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set non blocking fd %d: %s", fd,
				 safe_strerror(errno));
			close(fd);
			exit(1);
		}
	}

	setsockopt_so_recvbuf(fd, 8 * 1024 * 1024);
	ctx.pim_unicast_fd = fd;
	event_add_read(router->master, pimsb_pim_unicast_read, NULL, ctx.pim_unicast_fd,
		       &ctx.pim_unicast_read_ev);
}

static void pimsb_init_mld(void)
{
	int fd;

	frr_with_privs (&pimd_privs) {
		fd = socket(AF_INET6, SOCK_RAW, PIM_IPV6_ENCAP_MLD);
		if (fd == -1) {
			zlog_err("%s: socket: %s", __func__, strerror(errno));
			close(fd);
			return;
		}

		if (setsockopt_ipv6_flowinfo(fd, 1) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set IPV6_FLOWINFO option for fd %d: %s", fd,
				 safe_strerror(errno));
			close(fd);
			return;
		}

		if (setsockopt_ipv6_flowinfo(fd, 1) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set IPV6_FLOWINFO_SEND option for fd %d: %s",
				 fd, safe_strerror(errno));
			close(fd);
			return;
		}

		if (setsockopt_ipv6_pktinfo(fd, 1) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set IPV6_RECVPKTINFO option for fd %d: %s",
				 fd, safe_strerror(errno));
			close(fd);
			return;
		}

		if (set_nonblocking(fd) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set non blocking fd %d: %s", fd,
				 safe_strerror(errno));
			close(fd);
			exit(1);
		}
	}

	setsockopt_so_sendbuf(fd, 1024 * 1024);
	setsockopt_so_recvbuf(fd, 1024 * 1024);

	ctx.mld_fd = fd;
	thread_add_read(router->master, pimsb_mld_read, NULL, ctx.mld_fd, &ctx.mld_read_ev);
}


/*
 * PIM southbound callbacks
 */
void pimsb_mroute_socket_enable(struct pim_instance *pim)
{
	pim->mroute_socket = ctx.mld_fd;
	pim->mroute_socket_creation = pim_time_monotonic_sec();
}

void pimsb_mroute_socket_disable(struct pim_instance *pim)
{
	pim->mroute_socket = -1;
}

void pimsb_interface_join(struct interface *interface)
{
	/* Multicast not enabled */
	if (!interface->info)
		return;

	pimsb_mld_join(interface);
}

void pimsb_interface_leave(struct interface *interface, const pim_addr *source,
			   const pim_addr *group)
{
	/* Multicast not enabled */
	if (!interface->info)
		return;

	pimsb_mld_leave(interface, source, group);
}

ssize_t pimsb_send(const char *interface_name, const pim_addr *source, const pim_addr *destination,
		   uint8_t protocol, uint8_t ttl, const void *data, size_t data_length)
{
}


/*
 * PIM southbound module functions
 */
DEFINE_MTYPE_STATIC(PIMD, PIM6_PACKET_BUFFER, "PIMv6 packet buffer");

static int pim6_southbound_stop(void)
{
	pimsb_socket_stop();

	event_cancel(&ctx.mld_read_ev);
	event_cancel(&ctx.pim_read_ev);
	event_cancel(&ctx.pim_unicast_read_ev);

	if (ctx.mld_fd != -1) {
		close(ctx.mld_fd);
		ctx.mld_fd = -1;
	}
	if (ctx.pim_fd != -1) {
		close(ctx.pim_fd);
		ctx.pim_fd = -1;
	}
	if (ctx.pim_unicast_fd != -1) {
		close(ctx.pim_unicast_fd);
		ctx.pim_unicast_fd = -1;
	}

	XFREE(MTYPE_PIM6_PACKET_BUFFER, ctx.packet);

	return 0;
}

static int pim6_southbound_start(struct event_loop *event_loop)
{
	/* Initialize IP handler */
	ip_fragmentation_handler_init(event_loop);

	/* Alocate big buffer to read incoming packets */
	ctx.packet_size = IPV4_MAXIMUM_PACKET_SIZE;
	ctx.packet = XCALLOC(MTYPE_PIM6_PACKET_BUFFER, ctx.packet_size);

	/* Initialize IGMP packets handler */
	pimsb_init_mld();

	/* Initialize PIM packets handler */
	pimsb_init_pim();

	/* Initialize PIM data plane listening socket */
	pimsb_socket_init(&ctx.address.address, (socklen_t)ctx.address.address_size,
			  !ctx.address.listen);

	/* Register callback to stop southbound on shutdown */
	hook_register(frr_fini, pim6_southbound_stop);

	return 0;
}

static int pim6_southbound_init(void)
{
	if (!network_address_parse(THIS_MODULE->load_args, &ctx.address, PIMSB_DEFAULT_PORT)) {
		zlog_err("PIM southbound initialization: %s", ctx.address.error);
		return -1;
	}

	pimsb_configure();

	hook_register(frr_late_init, pim6_southbound_start);

	return 0;
}

/* clang-format off */
FRR_MODULE_SETUP(
	.name = "pim6_southbound",
	.version = "0.0.1",
	.description = "Data plane plugin for PIMv6.",
	.init = pim6_southbound_init,
);
/* clang-format on */
