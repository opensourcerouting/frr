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
#include "lib/zlog.h"

#include "pimd/pim_iface.h"
#include "pimd/pim_igmp_packet.h"
#include "pimd/pim_instance.h"
#include "pimd/pim_pim.h"
#include "pimd/pim_southbound_common.h"
#include "pimd/pim_time.h"
#include "pimd/pimd.h"

/*
 * PIM southbound
 */
struct pimsb_ctx {
	/** IGMP socket */
	int igmp_fd;
	/** IGMP socket read event */
	struct event *igmp_read_ev;

	/** PIM socket */
	int pim_fd;
	/** PIM socket read event */
	struct event *pim_read_ev;

	/** PIM southbound connection data */
	struct network_address address;

	/** Packet receive buffer */
	uint8_t *packet;
	/** Packet receiver buffer size */
	size_t packet_size;
};

static struct pimsb_ctx ctx = {
	.igmp_fd = -1,
	.pim_fd = -1,
};

static void pimsb_igmp_read(void)
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

	/* Attempt to read a whole packet. */
	bytes_read = read(ctx.igmp_fd, ctx.packet, ctx.packet_size);
	if (bytes_read == -1) {
		zlog_warn("%s: read: %s", __func__, strerror(errno));
		return;
	}
	if (bytes_read == 0) {
		zlog_warn("%s: read: EOF", __func__);
		return;
	}

	/* Parse the encapsulation. */
	erv = ipv4_encap_parse(ctx.packet, bytes_read, &encap_result);
	if (erv != IEPA_OK)
		return;

	/* Skip packets to data plane. */
	if (encap_result.destination.s_addr == htonl(IPV4_ENCAP_DST))
		return;

	/* Find interface to figure out which VRF it belongs. */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(encap_result.ifindex, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (!ifp) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: could not find interface %d", __func__,
				   encap_result.ifindex);
		return;
	}

	/* Reassemble the packet (if fragmented) and pass it along. */
	rv = ipv4_packet_assemble(&ctx.packet[encap_result.encap_length],
				  bytes_read - encap_result.encap_length, &packet, &packet_length);
	if (rv != IPA_NOT_FRAGMENTED && rv != IPA_OK)
		/* Assembly failed, just quit. */
		return;

	/* Packet assembled, get VRF information and call PIM code. */
	pim_ifp = ifp->info;
	if (pim_ifp)
		pim_mroute_msg(pim_ifp->pim, (char *)packet, packet_length, encap_result.ifindex);
	else if (PIM_DEBUG_GM_PACKETS)
		zlog_debug("%s: received packet on disabled interface (%d) %s", __func__,
			   ifp->ifindex, ifp->name);
}

static void pimsb_igmp_read_cb(struct event *ev __attribute__((unused)))
{
	pimsb_igmp_read();
	event_add_read(router->master, pimsb_igmp_read_cb, NULL, ctx.igmp_fd, &ctx.igmp_read_ev);
}

static void pimsb_init_igmp(void)
{
	int fd;
	int on = 1;

	frr_with_privs (&pimd_privs) {
		fd = socket(AF_INET, SOCK_RAW, PIM_IP_ENCAP_IGMP);
		if (fd == -1) {
			zlog_err("%s: socket: %s", __func__, strerror(errno));
			return;
		}

		if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set IP_HDRINCL option for fd %d: %s", fd,
				 safe_strerror(errno));
			close(fd);
			return;
		}

		set_nonblocking(fd);
	}

	setsockopt_so_sendbuf(fd, 1024 * 1024);
	setsockopt_so_recvbuf(fd, 1024 * 1024);

	ctx.igmp_fd = fd;

	event_add_read(router->master, pimsb_igmp_read_cb, NULL, ctx.igmp_fd, &ctx.igmp_read_ev);
}

static void pimsb_pim_packet_read(void)
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

	/* Attempt to read a whole packet. */
	bytes_read = read(ctx.pim_fd, ctx.packet, ctx.packet_size);
	if (bytes_read == -1) {
		zlog_warn("%s: read: %s", __func__, strerror(errno));
		return;
	}
	if (bytes_read == 0) {
		zlog_warn("%s: read: EOF", __func__);
		return;
	}

	/* Parse the encapsulation. */
	erv = ipv4_encap_parse(ctx.packet, bytes_read, &encap_result);
	if (erv != IEPA_OK)
		return;

	/* Skip packets to data plane. */
	if (encap_result.destination.s_addr == htonl(IPV4_ENCAP_DST))
		return;

	/* Reassemble the packet (if fragmented) and pass it along. */
	rv = ipv4_packet_assemble(&ctx.packet[encap_result.encap_length],
				  bytes_read - encap_result.encap_length, &packet, &packet_length);
	if (rv != IPA_NOT_FRAGMENTED || rv != IPA_OK)
		/* Assembly failed, just quit. */
		return;

	/* Find interface to figure out which VRF it belongs. */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(encap_result.ifindex, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (!ifp) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: incoming packet on unknown interface %d", __func__,
				   encap_result.ifindex);
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

	addr.src = ipv4->source;
	addr.grp = ipv4->destination;
	if (pim_ifp)
		pim_pim_packet(ifp, (uint8_t *)(size_t)packet, packet_length, addr,
			       IN_CLASSD(ntohl(ipv4->destination.s_addr)));
	else if (PIM_DEBUG_PIM_PACKETS)
		zlog_debug("%s: received packet on disabled interface (%d) %s", __func__,
			   ifp->ifindex, ifp->name);
}

static void pimsb_pim_read_cb(struct event *e __attribute__((unused)))
{
	pimsb_pim_packet_read();
	event_add_read(router->master, pimsb_pim_read_cb, NULL, ctx.pim_fd, &ctx.pim_read_ev);
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

		/* Include IP header. */
		if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set IP_HDRINCL option for fd %d: %s", fd,
				 safe_strerror(errno));
			close(fd);
			return;
		}

		if (setsockopt_ipv4_tos(fd, IPTOS_PREC_INTERNETCONTROL))
			zlog_warn("can't set sockopt IP_TOS to socket %d: %m", fd);

		set_nonblocking(fd);
	}

	setsockopt_so_sendbuf(fd, 1024 * 1024);
	setsockopt_so_recvbuf(fd, 1024 * 1024);

	ctx.pim_fd = fd;

	event_add_read(router->master, pimsb_pim_read_cb, NULL, ctx.pim_fd, &ctx.pim_read_ev);
}

/**
 * IGMP join callback: when timer expires it injects an IGMP join packet
 * into the IGMP input path to simulate a local membership to source/group.
 *
 * This callback is called on `pimsb_igmp_join` or when a IGMP general query
 * is sent.
 */
static void pimsb_igmp_join_cb(struct event *e)
{
	struct gm_sock *igmp_socket = EVENT_ARG(e);
	const struct igmp_packet *packet;
	struct igmp_packet_list *packets;
	struct igmp_packet_params *params;

	params = pim_interface_generate_igmp_static_params(igmp_socket->interface, true, NULL,
							   NULL);
	packets = igmp_generate_packets(params);
	igmp_join_params_free(params);

	/* IGMP static join was called, but no groups configured. */
	if (!packets)
		return;

	SLIST_FOREACH (packet, packets, entry) {
		const struct ipv4_header *ip = (const struct ipv4_header *)packet->data;

		pimsb_send(igmp_socket->interface->name, (struct in_addr *)&ip->source,
			   (struct in_addr *)&ip->destination, ip->protocol, ip->ttl,
			   packet->data + ipv4_header_length(ip),
			   packet->size - ipv4_header_length(ip));

		pim_igmp_packet(igmp_socket, (char *)packet->data, packet->size);
	}

	igmp_packet_list_free(packets);
}

static void pimsb_igmp_join(const struct pim_interface *pim_interface)
{
	struct gm_sock *igmp_socket = pim_igmp_sock_lookup_ifaddr(pim_interface->gm_socket_list,
								  pim_interface->primary_address);

	/* This is possible if interface is not multicast enabled. */
	if (!igmp_socket)
		return;

	event_cancel(&igmp_socket->join_event);
	event_add_timer(router->master, pimsb_igmp_join_cb, igmp_socket, 0,
			&igmp_socket->join_event);
}

static void pimsb_igmp_leave(const struct pim_interface *pim_interface,
			     const struct in_addr *source, const struct in_addr *group)
{
	struct gm_sock *igmp_socket = pim_igmp_sock_lookup_ifaddr(pim_interface->gm_socket_list,
								  pim_interface->primary_address);
	const struct igmp_packet *packet;
	struct igmp_packet_list *packets;
	struct igmp_packet_params *params;

	/* This is possible if interface is not multicast enabled. */
	if (!igmp_socket)
		return;

	params = pim_interface_generate_igmp_static_params(igmp_socket->interface, false, source,
							   group);
	packets = igmp_generate_packets(params);
	igmp_join_params_free(params);

	/* IGMP static join was called, but no groups configured. */
	if (!packets)
		return;

	SLIST_FOREACH (packet, packets, entry)
		pim_igmp_packet(igmp_socket, (char *)packet->data, packet->size);

	igmp_packet_list_free(packets);
}


/*
 * PIM southbound callbacks
 */
void pimsb_mroute_socket_enable(struct pim_instance *pim)
{
	pim->mroute_socket = ctx.igmp_fd;
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

	pimsb_igmp_join(interface->info);
}

void pimsb_interface_leave(struct interface *interface, const pim_addr *source,
			   const pim_addr *group)
{
	/* Multicast not enabled */
	if (!interface->info)
		return;

	pimsb_igmp_leave(interface->info, source, group);
}

ssize_t pimsb_send(const char *interface_name, const pim_addr *source, const pim_addr *destination,
		   uint8_t protocol, uint8_t ttl, const void *data, size_t data_length)
{
	struct pim_interface *pim_interface = NULL;
	struct interface *interface = NULL;
	struct vrf *vrf;
	struct in_addr source_address;
	struct ipv4_output_params params;

	if (interface_name) {
		RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
			interface = if_lookup_by_name(interface_name, vrf->vrf_id);
			if (interface)
				break;
		}
		if (!interface) {
			if (PIM_DEBUG_PACKETS)
				zlog_debug("%s: no interface %s found", __func__, interface_name);

			errno = ENOENT;
			return -1;
		}

		pim_interface = interface->info;
	}

	assert((interface && pim_interface) || source);

	if (source)
		source_address = *source;
	else
		source_address = pim_interface->primary_address;

	params = (struct ipv4_output_params){
		.destination = *destination,
		.source = source_address,
		.protocol = protocol,
		.tos = IPTOS_PREC_INTERNETCONTROL,
		.socket = (protocol == PIM_IP_PROTO_PIM) ? ctx.pim_fd : ctx.igmp_fd,
		.ttl = ttl,
		.mtu = interface ? interface->mtu : 1500,
		.encap.ifindex = interface ? interface->ifindex : 0,
		.encap.source = source_address,
	};

	return ipv4_output(&params, data, data_length);
}


/*
 * PIM southbound module functions
 */
DEFINE_MTYPE_STATIC(PIMD, PIM_PACKET_BUFFER, "PIM packet buffer");

static int pim_southbound_stop(void)
{
	pimsb_socket_stop();

	event_cancel(&ctx.igmp_read_ev);
	event_cancel(&ctx.pim_read_ev);
	close(ctx.igmp_fd);
	close(ctx.pim_fd);

	XFREE(MTYPE_PIM_PACKET_BUFFER, ctx.packet);

	ip_fragmentation_handler_stop();

	return 0;
}

static int pim_southbound_start(void)
{
	/* Initialize IP handler */
	ip_fragmentation_handler_init(router->master);

	/* Alocate big buffer to read incoming packets */
	ctx.packet_size = IPV4_MAXIMUM_PACKET_SIZE;
	ctx.packet = XCALLOC(MTYPE_PIM_PACKET_BUFFER, ctx.packet_size);

	/* Initialize IGMP packets handler */
	pimsb_init_igmp();

	/* Initialize PIM packets handler */
	pimsb_init_pim();

	/* Initialize PIM data plane listening socket */
	pimsb_socket_init(&ctx.address.address, (socklen_t)ctx.address.address_size,
			  !ctx.address.listen);

	/* Register callback to stop southbound on shutdown */
	hook_register(frr_fini, pim_southbound_stop);

	pimsb_configure();
}

static int pim_southbound_init(void)
{
	if (!network_address_parse(THIS_MODULE->load_args, &ctx.address, PIMSB_DEFAULT_PORT)) {
		zlog_err("PIM southbound initialization: %s", ctx.address.error);
		return -1;
	}

	hook_register(frr_late_init, pim_southbound_start);

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
