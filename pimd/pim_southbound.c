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

#include "lib/libfrr.h"
#if 0
#include "lib/zebra.h"

#include <linux/mroute.h>
#include <netinet/ip6.h>
#include <sys/un.h>

#include <err.h>
#include <stdbool.h>

#include "lib/checksum.h"
#include "lib/lib_errors.h"
#include "lib/printfrr.h"
#endif
#include "lib/network.h"
#if 0
#include "lib/sockopt.h"
#include "lib/stream.h"
#include "lib/zclient.h"
#include "lib/zlog.h"
#include "pimd/pimd.h"
#include "pimd/pim_errors.h"
#include "pimd/pim_iface.h"
#include "pimd/pim_hello.h"
#include "pimd/pim_igmp.h"
#include "pimd/pim_igmp_packet.h"
#include "pimd/pim_igmpv3.h"
#include "pimd/pim_instance.h"
#include "pimd/pim_neighbor.h"
#include "pimd/pim_join.h"
#include "pimd/pim_pim.h"
#include "pimd/pim_register.h"
#include "pimd/pim_sock.h"
#endif
#include "pimd/pim_southbound_common.h"
#if 0
#include "pimd/pim_ssm.h"
#include "pimd/pim_static.h"
#include "pimd/pim_util.h"
#include "pimd/pim_time.h"
#include "pimd/pim_nht.h"
#include "pimd/pim6_mld.h"
#include "pimd/pim6_mld_packet.h"
#include "pimd/pim6_mld_protocol.h"

#if PIM_IPV == 4
/* IGMP global data. */
static int igmp_fd = -1;
static struct thread *igmp_read_ev;
#else
/* MLD global data. */
static int mld_fd = -1;
static struct thread *mld_read_ev;
#endif

/* PIM global data. */
static int pim_fd = -1;
static struct thread *pim_read_ev;

#if PIM_IPV == 6
static int pim_unicast_fd = -1;
static struct thread *pim_unicast_read_ev;
#endif

#if PIM_IPV == 4
/*
 * IGMP socket.
 */
static void pimsb_igmp_read_cb(struct thread *t);

static void pimsb_igmp_add_read(void)
{
	thread_add_read(router->master, pimsb_igmp_read_cb, NULL, igmp_fd,
			&igmp_read_ev);
}

static bool ipv4_has_router_alert(const uint8_t *packet, size_t packet_length)
{
	const struct ipv4_header *ipv4 = (const struct ipv4_header *)packet;
	size_t header_length = ipv4_header_length(ipv4);

	/* No additional options or packet too short. */
	if ((header_length < 24) || (packet_length < header_length))
		return false;

	/* Check for router alert signature in option. */
	if (packet[20] == 0x94)
		return true;

	return false;
}

void pimsb_packet_read(int sock)
{
	enum ip_encap_packet_assemble_result erv;
	enum ip_packet_assemble_result rv;
	struct pim_interface *pim_ifp;
	struct interface *ifp = NULL;
	const uint8_t *packet;
	struct vrf *vrf;
	size_t packet_length;
	ssize_t bytes_read;
	struct ipv4_encap_result encap_result;
	uint8_t buf[2048];

	/* Attempt to read a whole packet. */
	bytes_read = read(sock, buf, sizeof(buf));
	if (bytes_read == -1) {
		zlog_warn("%s: read: %s", __func__, strerror(errno));
		return;
	}
	if (bytes_read == 0) {
		zlog_warn("%s: read: EOF", __func__);
		return;
	}

	/* Parse the encapsulation. */
	erv = ipv4_encap_parse(buf, bytes_read, &encap_result);
	if (erv != IEPA_OK)
		return;

	/* Skip packets to data plane. */
	if (encap_result.destination == htonl(IPV4_ENCAP_DST))
		return;

	/* Find interface to figure out which VRF it belongs. */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(encap_result.ifindex, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: could not find interface %d", __func__,
				   encap_result.ifindex);
		return;
	}

	/* Reassemble the packet (if fragmented) and pass it along. */
	rv = ipv4_packet_assemble(&buf[encap_result.encap_length],
				  bytes_read - encap_result.encap_length,
				  &packet, &packet_length);
	switch (rv) {
	case IPA_NOT_FRAGMENTED:
	case IPA_OK:
		break;

	default:
		/* Assembly failed, just quit. */
		return;
	}

	/* Packet assembled, get VRF information and call PIM code. */
	pim_ifp = ifp->info;
	if (pim_ifp)
		(void)pim_mroute_msg(
			pim_ifp->pim, (char *)packet, packet_length,
			encap_result.ifindex,
			ipv4_has_router_alert(packet, packet_length));
	else if (PIM_DEBUG_GM_PACKETS)
		zlog_debug("%s: received packet on disabled interface (%d) %s",
			   __func__, ifp->ifindex, ifp->name);
}

static void pimsb_igmp_read_cb(struct thread *t)
{
	pimsb_packet_read(THREAD_FD(t));
	pimsb_igmp_add_read();
}

static void pimsb_init_igmp(void)
{
	int sock;
	int on = 1;

	frr_with_privs (&pimd_privs) {
		sock = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK,
			      PIM_IP_ENCAP_IGMP);
		if (sock == -1) {
			zlog_err("%s: socket: %s", __func__, strerror(errno));
			return;
		}

		/* Include IP header. */
		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) ==
		    -1) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IP_HDRINCL option for fd %d: %s",
				 sock, safe_strerror(errno));
			close(sock);
			return;
		}
	}

	setsockopt_so_sendbuf(sock, 1024 * 1024);
	setsockopt_so_recvbuf(sock, 1024 * 1024);

	igmp_fd = sock;
	pimsb_igmp_add_read();
}
#else
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

	thread_add_read(router->master, pimsb_mld_read, NULL, mld_fd,
			&mld_read_ev);

	iov.iov_base = pimsb_ctx.pktbuf;
	iov.iov_len = pimsb_ctx.pktbuflen;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	brecv = recvmsg(mld_fd, &msg, 0);
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
		pimsb_mld_parse_hopopts((uint8_t *)pimsb_ctx.pktbuf,
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
		pim_ifp->mld->stats.rx_drop_ra++;
		return;
	}

	gm_rx_process(pim_ifp->mld, &src, &ipi6.ipi6_addr, PIM_IPV6_ENCAP_MLD,
		      pktbuf, pktbuf_len);
}

static void pimsb_init_mld(void)
{
	int fd;
	int on = 1;

	frr_with_privs (&pimd_privs) {
		fd = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK,
			    PIM_IPV6_ENCAP_MLD);
		if (fd == -1) {
			zlog_err("%s: socket: %s", __func__, strerror(errno));
			close(fd);
			return;
		}

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWINFO, &on,
			       sizeof(on)) == -1)
			zlog_warn("%s: failed to request IPV6_FLOWINFO",
				  __func__);
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on,
			       sizeof(on)) == -1)
			zlog_warn(
				"%s: failed to request IPV6_FLOWINFO_SENDINFO",
				__func__);
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
			       sizeof(on)) == -1)
			zlog_warn("%s: setsockopt(IPV6_RECVPKTINFO): %s",
				  __func__, strerror(errno));
	}

	setsockopt_so_sendbuf(fd, 1024 * 1024);
	setsockopt_so_recvbuf(fd, 1024 * 1024);

	mld_fd = fd;
	thread_add_read(router->master, pimsb_mld_read, NULL, mld_fd,
			&mld_read_ev);
}
#endif /* IPV == 6 */

/*
 * PIM socket.
 */
#if PIM_IPV == 4
static void pimsb_pim_packet_read(int sock)
{
	enum ip_encap_packet_assemble_result erv;
	enum ip_packet_assemble_result rv;
	const struct ipv4_header *ipv4;
	struct pim_interface *pim_ifp;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	const uint8_t *packet;
	size_t packet_length;
	ssize_t bytes_read;
	struct ipv4_encap_result encap_result;
	pim_sgaddr addr = {};
	uint8_t buf[2048];

	/* Attempt to read a whole packet. */
	bytes_read = read(sock, buf, sizeof(buf));
	if (bytes_read == -1) {
		zlog_warn("%s: read: %s", __func__, strerror(errno));
		return;
	}
	if (bytes_read == 0) {
		zlog_warn("%s: read: EOF", __func__);
		return;
	}

	/* Parse the encapsulation. */
	erv = ipv4_encap_parse(buf, bytes_read, &encap_result);
	if (erv != IEPA_OK)
		return;

	/* Skip packets to data plane. */
	if (encap_result.destination == htonl(IPV4_ENCAP_DST))
		return;

	/* Reassemble the packet (if fragmented) and pass it along. */
	rv = ipv4_packet_assemble(&buf[encap_result.encap_length],
				  bytes_read - encap_result.encap_length,
				  &packet, &packet_length);
	switch (rv) {
	case IPA_NOT_FRAGMENTED:
	case IPA_OK:
		break;

	default:
		/* Assembly failed, just quit. */
		return;
	}

	/* Find interface to figure out which VRF it belongs. */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(encap_result.ifindex, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"%s: incoming packet on unknown interface %d",
				__func__, encap_result.ifindex);
		return;
	}

	/* Packet assembled, get VRF information and call PIM code. */
	pim_ifp = ifp->info;

	if (PIM_DEBUG_PIM_PACKETS)
		zlog_debug("%s: incoming pim packet on %s(%d)", __func__,
			   ifp ? ifp->name : "unknown", encap_result.ifindex);

	ipv4 = (const struct ipv4_header *)packet;
	if (if_address_is_local(&ipv4->source, AF_INET, ifp->vrf->vrf_id)) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: incoming packet from myself", __func__);
		return;
	}

	addr.src.s_addr = ipv4->source;
	addr.grp.s_addr = ipv4->destination;
	if (pim_ifp)
		pim_pim_packet(ifp, (uint8_t *)(size_t)packet, packet_length,
			       addr);
}
#else
static void pimsb_pim_packet_read(int pim_fd)
{
	uint8_t *pim_msg = (uint8_t *)pimsb_ctx.pktbuf;
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

	iov.iov_base = pimsb_ctx.pktbuf;
	iov.iov_len = pimsb_ctx.pktbuflen;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	brecv = recvmsg(pim_fd, &msg, 0);
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

	if (pim_hello_filter(ifp, &src.sin6_addr, (uint8_t *)pimsb_ctx.pktbuf,
			     (size_t)brecv))
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
#endif

static void pimsb_pim_add_read(void);

static void pimsb_pim_read_cb(struct thread *t)
{
	pimsb_pim_packet_read(THREAD_FD(t));
	pimsb_pim_add_read();
}

static void pimsb_pim_add_read(void)
{
	thread_add_read(router->master, pimsb_pim_read_cb, NULL, pim_fd,
			&pim_read_ev);
}

#if PIM_IPV == 6
static void pimsb_pim_unicast_read(struct thread *thread);

static inline void pimsb_pim_unicast_add_read(void)
{
	thread_add_read(router->master, pimsb_pim_unicast_read, NULL,
			pim_unicast_fd, &pim_unicast_read_ev);
}

static void pimsb_pim_unicast_read(struct thread *thread
				   __attribute__((unused)))
{
	uint8_t *pim_msg = (uint8_t *)pimsb_ctx.pktbuf;
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

	pimsb_pim_unicast_add_read();

	iov.iov_base = pimsb_ctx.pktbuf;
	iov.iov_len = pimsb_ctx.pktbuflen;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	brecv = recvmsg(pim_unicast_fd, &msg, 0);
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

	if (pim_hello_filter(ifp, &src.sin6_addr, (uint8_t *)pimsb_ctx.pktbuf,
			     (size_t)brecv))
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
#endif

static void pimsb_init_pim(void)
{
	int sock;
	int on = 1;

	frr_with_privs (&pimd_privs) {
		sock = socket(PIM_AF, SOCK_RAW | SOCK_NONBLOCK,
			      PIM_IP_ENCAP_PIM);
		if (sock == -1) {
			zlog_err("%s: socket: %s", __func__, strerror(errno));
			return;
		}

#if PIM_IPV == 4
		/* Include IP header. */
		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) ==
		    -1) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IP_HDRINCL option for fd %d: %s",
				 sock, safe_strerror(errno));
			close(sock);
			return;
		}

		if (setsockopt_ipv4_tos(sock, IPTOS_PREC_INTERNETCONTROL))
			zlog_warn("can't set sockopt IP_TOS to socket %d: %m",
				  sock);
#endif

#if PIM_IPV == 6
		if (setsockopt_ipv6_tclass(sock, IPTOS_PREC_INTERNETCONTROL))
			zlog_warn("can't set sockopt IPV6_TOS to socket %d: %m",
				  sock);

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
			       sizeof(on)) == -1) {
			flog_err(
				EC_LIB_SOCKET,
				"Can't set IPV6_RECVPKTINFO option for fd %d: %s",
				sock, safe_strerror(errno));
			close(sock);
			return;
		}

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWINFO, &on,
		    sizeof(on)) == -1) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IPV6_FLOWINFO option for fd %d: %s",
				 sock, safe_strerror(errno));
			close(sock);
			return;
		}

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on,
		    sizeof(on)) == -1) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IPV6_FLOWINFO_SEND option for fd %d: %s",
				 sock, safe_strerror(errno));
			close(sock);
			return;
		}
#endif
	}

	setsockopt_so_sendbuf(sock, 1024 * 1024);
	setsockopt_so_recvbuf(sock, 1024 * 1024);

	pim_fd = sock;
	pimsb_pim_add_read();

#if PIM_IPV == 6
	frr_with_privs (&pimd_privs) {
		sock = socket(PIM_AF, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_PIM);

		sockopt_reuseaddr(sock);
		setsockopt_ipv6_pktinfo(sock, 1);
	}

	setsockopt_so_recvbuf(sock, 8 * 1024 * 1024);
	pim_unicast_fd = sock;
	pimsb_pim_unicast_add_read();
#endif
}

/*
 * Exported functions.
 */
void pimsb_init(struct zclient *zc)
{
	/* Keep pointer to zebra client context. */
	zclient = zc;

	pimsb_ctx.pktbuflen = 65535;
	pimsb_ctx.pktbuf = XMALLOC(MTYPE_TMP, pimsb_ctx.pktbuflen);

#if PIM_IPV == 4
	pimsb_init_igmp();
#else
	pimsb_init_mld();
#endif
	pimsb_init_pim();
}

void pimsb_shutdown(void)
{
	if (pimsb_ctx.is_server) {
		THREAD_OFF(pimsb_ctx.server.listening_ev);
		close(pimsb_ctx.server.listening_socket);
		pimsb_ctx.server.listening_socket = -1;
		pimsb_client_stop(&pimsb_ctx.server.client);
	} else
		pimsb_client_stop(&pimsb_ctx.client);

#if PIM_IPV == 4
	THREAD_OFF(igmp_read_ev);
	close(igmp_fd);
	igmp_fd = -1;
#else
	THREAD_OFF(mld_read_ev);
	close(mld_fd);
	mld_fd = -1;
#endif

	THREAD_OFF(pim_read_ev);
	close(pim_fd);
	pim_fd = -1;

#if PIM_IPV == 6
	thread_cancel(&pim_unicast_read_ev);
	close(pim_unicast_fd);
	pim_unicast_fd = -1;
#endif
}

#if PIM_IPV == 4
ssize_t pimsb_igmp_sendto(const char *ifname, const void *data, size_t datalen,
			  struct sockaddr *sa, socklen_t salen)
{
	struct sockaddr_in *dsin = (struct sockaddr_in *)sa;
	struct pim_interface *pim_ifp;
	struct interface *ifp = NULL;
	struct vrf *vrf;
	ssize_t bytes_sent;
	struct ipv4_encap_params encap_params;
	struct sockaddr_in sin = {};
	struct msghdr msg = {};
	struct iovec iov[3] = {};
	uint8_t ipv4_encap[IPV4_ENCAP_DATA_SIZE] = {};
	struct {
		struct ipv4_header ipv4;
		uint8_t ipv4_options[4];
	} ipv4_data = {};

	/* Get output interface. */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_name(ifname, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: no interface %s found", __func__,
				   ifname);

		errno = ENOENT;
		return -1;
	}

	/* Generate the IPv4 encapsulation header. */
	pim_ifp = ifp->info;
	encap_params.source = pim_ifp->primary_address.s_addr;
	encap_params.ifindex = ifp->ifindex;
	ipv4_encap_output(&encap_params, &ipv4_encap, datalen);

	/* Generate the IPv4 header. */
	ipv4_set_version(&ipv4_data.ipv4);
	ipv4_set_header_length(&ipv4_data.ipv4, sizeof(ipv4_data));
	ipv4_data.ipv4.tos = 0xC0;
	ipv4_data.ipv4.total_length = htons(sizeof(ipv4_data) + datalen);
	ipv4_data.ipv4.ttl = 1;
	ipv4_data.ipv4.protocol = 2;
	ipv4_data.ipv4.source = pim_ifp->primary_address.s_addr;
	ipv4_data.ipv4.destination = dsin->sin_addr.s_addr;
	ipv4_data.ipv4_options[0] = 148;
	ipv4_data.ipv4_options[1] = 4;
	ipv4_data.ipv4_options[2] = 0;
	ipv4_data.ipv4_options[3] = 0;
	ipv4_data.ipv4.checksum = in_cksum(&ipv4_data, sizeof(ipv4_data));

	/* Send to data plane in loopback. */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(IPV4_ENCAP_DST);

	msg.msg_name = &sin;
	msg.msg_namelen = sizeof(sin);
	msg.msg_iov = iov;
	msg.msg_iovlen = 3;
	iov[0].iov_base = &ipv4_encap;
	iov[0].iov_len = sizeof(ipv4_encap);
	iov[1].iov_base = &ipv4_data;
	iov[1].iov_len = sizeof(ipv4_data);
	iov[2].iov_base = (void *)(size_t)data;
	iov[2].iov_len = datalen;

	bytes_sent = sendmsg(igmp_fd, &msg, 0);
	if (bytes_sent == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return -1;

		zlog_err("%s: sendmsg: (%d) %s", __func__, errno,
			 strerror(errno));
		return -1;
	} else if (bytes_sent == 0) {
		zlog_err("%s: sendmsg: connection closed", __func__);
		return 0;
	}

	if (PIM_DEBUG_GM_PACKETS)
		zlog_debug("%s: [sent %zd bytes (of %ld) via interface %d]",
			   __func__, bytes_sent,
			   sizeof(ipv4_encap) + sizeof(ipv4_data) + datalen,
			   ifp->ifindex);

	return datalen;
}

/**
 * IGMP join callback: when timer expires it injects an IGMP join packet
 * into the IGMP input path to simulate a local membership to source/group.
 *
 * This callback is called on `pimsb_igmp_join` or when a IGMP general query
 * is sent.
 */
static void pimsb_igmp_join_cb(struct thread *thread)
{
	struct gm_sock *igmp_socket = THREAD_ARG(thread);
	const struct igmp_packet *packet;
	struct igmp_packet_list *packets;
	struct igmp_packet_params *params;

	params = pim_interface_generate_igmp_static_params(
		igmp_socket->interface, true, NULL, NULL);
	packets = igmp_generate_packets(params);
	igmp_join_params_free(params);

	/* IGMP static join was called, but no groups configured. */
	if (packets == NULL)
		return;

	SLIST_FOREACH (packet, packets, entry) {
		const struct ipv4_header *ip =
			(const struct ipv4_header *)packet->data;
		struct sockaddr_in sin = {
			.sin_addr.s_addr = ip->destination,
		};

		pimsb_igmp_sendto(igmp_socket->interface->name,
				  packet->data + ipv4_header_length(ip),
				  packet->size - ipv4_header_length(ip),
				  (struct sockaddr *)&sin, sizeof(sin));

		pim_igmp_packet(igmp_socket, (char *)packet->data, packet->size,
				true);
	}

	igmp_packet_list_free(packets);
}

static void pimsb_igmp_join(const struct pim_interface *pim_interface)
{
	struct gm_sock *igmp_socket = pim_igmp_sock_lookup_ifaddr(
		pim_interface->gm_socket_list, pim_interface->primary_address);

	/* This is possible if interface is not multicast enabled. */
	if (igmp_socket == NULL)
		return;

	thread_cancel(&igmp_socket->join_event);
	thread_add_timer(router->master, pimsb_igmp_join_cb, igmp_socket, 0,
			 &igmp_socket->join_event);
}

static void pimsb_igmp_leave(const struct pim_interface *pim_interface,
			     const struct in_addr *source,
			     const struct in_addr *group)
{
	struct gm_sock *igmp_socket = pim_igmp_sock_lookup_ifaddr(
		pim_interface->gm_socket_list, pim_interface->primary_address);
	const struct igmp_packet *packet;
	struct igmp_packet_list *packets;
	struct igmp_packet_params *params;

	/* This is possible if interface is not multicast enabled. */
	if (igmp_socket == NULL)
		return;

	params = pim_interface_generate_igmp_static_params(
		igmp_socket->interface, false, source, group);
	packets = igmp_generate_packets(params);
	igmp_join_params_free(params);

	/* IGMP static join was called, but no groups configured. */
	if (packets == NULL)
		return;

	SLIST_FOREACH (packet, packets, entry)
		pim_igmp_packet(igmp_socket, (char *)packet->data, packet->size,
				true);

	igmp_packet_list_free(packets);
}
#endif /* PIM_IPV == 4 */

int pimsb_socket_bind(int fd, pim_addr address)
{
#if PIM_IPV == 4
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr = address,
	};

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		zlog_warn("%s: bind(%pI4): %s", __func__, &address,
			  safe_strerror(errno));
		return -1;
	}

	return 0;
#else
	struct sockaddr_in6 sin6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = address,
	};

	if (bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) == -1) {
		zlog_warn("%s: bind(%pI6): %s", __func__, &address,
			  safe_strerror(errno));
		return -1;
	}

	return 0;
#endif
}

int pim_socket_get(void)
{
	return pim_fd;
}

int pimsb_mroute_socket_enable(struct pim_instance *pim)
{
#if PIM_IPV == 4
	pim->mroute_socket = igmp_fd;
#endif
	pim->mroute_socket_creation = pim_time_monotonic_sec();
	return 0;
}

#if PIM_IPV == 4
void pimsb_msg_send_frame(const struct interface *ifp, const struct ip *ip,
			  const void *msg, const size_t msglen)
{
	struct ipv4_output_params params = {
		.destination = ip->ip_dst.s_addr,
		.source = ip->ip_src.s_addr,
		.protocol = ip->ip_p,
		.tos = ip->ip_tos,
		.socket = pim_socket_get(),
		.ttl = ip->ip_ttl,
		.mtu = ifp ? ifp->mtu : 1500,
		.encap.ifindex = ifp ? ifp->ifindex : 0,
		.encap.source = ip->ip_src.s_addr,
	};

	ipv4_output(&params, msg, msglen);
}
#else
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
#endif /* PIM_IPV == 6 */

void pimsb_gm_join(const struct interface *interface)
{
	if (interface->info == NULL)
		return;

#if PIM_IPV == 4
	pimsb_igmp_join(interface->info);
#else
	pimsb_mld_join(interface);
#endif /* PIM_IPV == 6 */
}

void pimsb_gm_leave(const struct interface *interface, const pim_addr *source,
		    const pim_addr *group)
{
	if (interface->info == NULL)
		return;

#if PIM_IPV == 4
	pimsb_igmp_leave(interface->info, source, group);
#else
	pimsb_mld_leave(interface, source, group);
#endif /* PIM_IPV == 6 */
}

#endif

static int pim_southbound_init(void)
{
	const char *args = THIS_MODULE->load_args;
	struct network_address address;

	if (!network_address_parse(args, &address, PIMSB_DEFAULT_PORT)) {
		zlog_err("PIM southbound initialization: %s", address.error);
		return -1;
	}

#if 0
#if PIM_IPV == 4
	/* Initialize IP handler. */
	ip_fragmentation_handler_init(router->master);
#endif
#endif

	/* Initialize BFD data plane listening socket. */
	pimsb_socket_init(&address.address, (socklen_t)address.address_size, !address.listen);

	return 0;
}

/* clang-format off */
FRR_MODULE_SETUP(
	.name = "pim_southbound",
	.version = "0.0.1",
	.description = "Data plane plugin for PIM.",
	.init = pim_southbound_init,
);
/* clang-format on */
