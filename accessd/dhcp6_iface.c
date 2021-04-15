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

#include "lib/command.h"
#include "lib/if.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/prefix.h"
#include "lib/privs.h"
#include "lib/sockopt.h"
#include "lib/thread.h"
#include "lib/vrf.h"

#include "nhrpd/zbuf.h"

#include "accessd.h"

#include "dhcp6_protocol.h"

#include "dhcp6_parse.h"
#include "dhcp6_state.h"
#include "dhcp6_iface.h"
#include "dhcp6_upstream.h"
#include "dhcp6_zebra.h"

extern struct zebra_privs_t accessd_privs;
extern struct thread_master *master;

DEFINE_MTYPE_STATIC(DHCP6, DHCP6R_IF, "DHCPv6 relay interface information");
DEFINE_MTYPE_STATIC(DHCP6, DHCP6_RA_SELF_PKT, "DHCPv6 ra-self packet");

static void dhcp6r_if_setup_rcv(struct dhcp6r_iface *drif);

static int dhcp6r_if_new_hook(struct interface *ifp)
{
	struct dhcp6r_iface *drif;

	drif = XCALLOC(MTYPE_DHCP6R_IF, sizeof(*drif));
	drif->ifp = ifp;
	drif->sock = -1;

	ifp->info = drif;
	return 0;
}

static int dhcp6r_if_del_hook(struct interface *ifp)
{
	XFREE(MTYPE_DHCP6R_IF, ifp->info);
	return 0;
}

static void dhcp6r_if_stop(struct dhcp6r_iface *drif, const char *reason,
			   bool forcewarn)
{
	if (forcewarn && !drif->running)
		zlog_info("%s: cannot start DHCPv6 relay (%s)", drif->ifp->name,
			  reason);

	if (!drif->running)
		return;

	thread_cancel(&drif->rcv);

	zlog_info("%s: stopping DHCPv6 relay (%s)", drif->ifp->name, reason);
}

static void dhcp6r_if_start(struct dhcp6r_iface *drif,
			    struct connected *best_global)
{
	int rv;

	drif->best_global = best_global;

	if (drif->running) {
		return;
	}

	drif->sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (drif->sock < 0) {
		zlog_err("socket(): %m");
		return;
	}

	set_nonblocking(drif->sock);
	sockopt_reuseport(drif->sock);
	sockopt_v6only(AF_INET6, drif->sock);
	setsockopt_ipv6_pktinfo(drif->sock, 1);
	setsockopt_ipv6_multicast_hops(drif->sock, 1);
	setsockopt_ipv6_multicast_loop(drif->sock, 0);

	struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6 };

	sin6.sin6_port = htons(547);
	sin6.sin6_scope_id = drif->ifp->ifindex;

	frr_with_privs (&accessd_privs) {
		setsockopt_ipv6_tclass(drif->sock, IPTOS_PREC_INTERNETCONTROL);

		vrf_bind(VRF_DEFAULT, drif->sock, drif->ifp->name);

		rv = bind(drif->sock, (struct sockaddr *)&sin6, sizeof(sin6));
	}

	if (rv) {
		zlog_err("%s: bind(): %m", drif->ifp->name);

		close(drif->sock);
		drif->sock = -1;
		return;
	}

	struct ipv6_mreq mr6;
	memset(&mr6, 0, sizeof(mr6));
	inet_pton(AF_INET6, DH6ADDR_ALLAGENT, &mr6.ipv6mr_multiaddr);

	mr6.ipv6mr_interface = drif->ifp->ifindex;

	frr_with_privs (&accessd_privs) {
		rv = setsockopt(drif->sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mr6,
			       sizeof(mr6));
	}

	if (rv) {
		zlog_err("%s: setsockopt(IPV6_JOIN_GROUP): %m",
			 drif->ifp->name);

		close(drif->sock);
		drif->sock = -1;
		return;
	}

	drif->running = true;
	dhcp6r_if_setup_rcv(drif);
}

static void dhcp6r_if_rcv(struct thread *t)
{
	struct dhcp6r_iface *drif = THREAD_ARG(t);
	ssize_t retval;
	size_t size;
	struct msghdr mh[1];
	struct sockaddr_storage from[1];
	struct iovec iov[1];
	struct cmsghdr *cmh;
	uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	struct in6_pktinfo *pktinfo;
	char buf[16384];

	dhcp6r_if_setup_rcv(drif);

	cmh = (struct cmsghdr *)cmsgbuf;
	cmh->cmsg_level = IPPROTO_IPV6;
	cmh->cmsg_type = IPV6_PKTINFO;
	cmh->cmsg_len = CMSG_LEN(sizeof(*pktinfo));
	pktinfo = (struct in6_pktinfo *)(CMSG_DATA(cmh));

	memset(from, 0, sizeof(from));
	memset(mh, 0, sizeof(mh));

	iov->iov_base = buf;
	iov->iov_len = sizeof(buf);
	mh->msg_iov = iov;
	mh->msg_iovlen = array_size(iov);
	mh->msg_name = from;
	mh->msg_namelen = sizeof(from);
	mh->msg_control = (caddr_t)cmsgbuf;
	mh->msg_controllen = sizeof(cmsgbuf);

	retval = recvmsg(drif->sock, mh, 0);
	if (retval < 0) {
		zlog_warn("recvmsg failed: %m");
		return;
	} else if (retval == sizeof(buf)) {
		zlog_warn("recvmsg read full buffer size: %zd", retval);
		return;
	}
	size = retval;

	if ((ifindex_t)pktinfo->ipi6_ifindex != drif->ifp->ifindex) {
		zlog_warn("received packet for other interface?");
		return;
	}

	struct dhcp6 *dh6;
	struct zbuf zb[1];

	zbuf_init(zb, buf, size, size);

	dh6 = zbuf_pull(zb, struct dhcp6);
	if (!dh6)
		goto out_malformed;

	zlog_debug("%s: %pSU: %dDHMT", drif->ifp->name, from,
		   dh6->dh6_msgtype);

	switch (dh6->dh6_msgtype) {
	case DH6MSG_RELAY_REPL:
		/*
		 * The server may send a relay reply to the client
		 * port.
		 * XXX: need to clarify the port issue
		 */
		/*relay_to_client((struct dhcp6_relay *)dh6, len,
				(struct sockaddr *)&from);*/
		return;

	case DH6MSG_SOLICIT:
	case DH6MSG_REQUEST:
	case DH6MSG_CONFIRM:
	case DH6MSG_RENEW:
	case DH6MSG_REBIND:
	case DH6MSG_RELEASE:
	case DH6MSG_DECLINE:
	case DH6MSG_INFORMATION_REQUEST:
	case DH6MSG_RELAY_FORW:
		break;

	default:
		zlog_info("%s: %pSU: forwarding unexpected message type %dDHMT",
			  drif->ifp->name, from, dh6->dh6_msgtype);
		break;
	}

	if (!drif->ugroup_name) {
		zlog_info("%s: %pSU: dropping request, no server group set",
			  drif->ifp->name, from);
		return;
	}

	dhcp6_ugroup_relay(drif->ugroup_name, drif,
			   (struct sockaddr_in6 *)&from, dh6, size);
	return;

out_malformed:
	zlog_info("%s: %pSU: malformed packet (%zu bytes)", drif->ifp->name,
		  from, size);
	return;
}

static void dhcp6r_if_setup_rcv(struct dhcp6r_iface *drif)
{
	thread_add_read(master, dhcp6r_if_rcv, drif, drif->sock, &drif->rcv);
}

static void dhcp6r_snoop_ia_pd(struct dhcp6r_iface *drif,
			       struct sockaddr_in6 *host,
			       struct dhcp6_duid *duid,
			       struct dh6p_option *ia_pd)
{
	struct dh6p_option buf[128], *opt;
	struct dh6p_optspec opts[] = {
		[DH6OPT_IAPREFIX] = { .want = true, },
	};
	const char *perr;

	struct dhcp6_binding *bnd;
	struct dhcp6_pdprefix *pdp;

	uint16_t iatype = ia_pd->type;
	uint32_t iaid, t1, t2;

	iaid = zbuf_get_be32(ia_pd->zb);
	t1 = zbuf_get_be32(ia_pd->zb);
	t2 = zbuf_get_be32(ia_pd->zb);

	if (ia_pd->zb->error) {
		zlog_err("IA_PD parse error");
		return;
	}

	if (!dhcp6_parse_opts(ia_pd->zb, opts, array_size(opts), buf,
			      array_size(buf), &perr)) {
		zlog_warn("%s: %pSU: snoop parse failed: %s", drif->ifp->name,
			  host, perr);
		return;
	}

	zlog_info("%s: %pSU %pDUID: IA_PD %08x T1=%u T2=%u", drif->ifp->name,
		  host, duid, iaid, t1, t2);

	bnd = dhcp6_bnd_get(duid, iatype, iaid);
	bnd->ifp = drif->ifp;
	bnd->client = host->sin6_addr;
	monotime(&bnd->last_seen);

	frr_each (dhcp6_pds, bnd->pds, pdp)
		pdp->seen = false;

	frr_each (dh6p_optlist, opts[DH6OPT_IAPREFIX].list, opt) {
		struct prefix pfx = { .family = AF_INET6 };
		uint32_t pref, valid;
		void *p;

		pref = zbuf_get_be32(opt->zb);
		valid = zbuf_get_be32(opt->zb);

		pfx.prefixlen = zbuf_get8(opt->zb);
		p = zbuf_pulln(opt->zb, sizeof(pfx.u.prefix6));

		if (opt->zb->error || !p) {
			zlog_warn("malformed IAPREFIX");
			continue;
		}
		memcpy(&pfx.u.prefix6, p, sizeof(pfx.u.prefix6));
		apply_mask(&pfx);

		pdp = dhcp6_bnd_pd_get(bnd, &pfx);
		monotime(&pdp->last_seen);
		pdp->t_pref = pdp->last_seen;
		pdp->t_pref.tv_sec += pref;
		pdp->t_valid = pdp->last_seen;
		pdp->t_valid.tv_sec += valid;
		pdp->seen = true;

		zlog_info("%s: %pSU:   %pFX pref=%u valid=%u",
			  drif->ifp->name, host, &pfx, pref, valid);
	}

	frr_each (dhcp6_pds, bnd->pds, pdp) {
		if (pdp->seen)
			continue;

		zlog_info("%s: %pSU:   %pFX removed from IA",
			  drif->ifp->name, host, &pdp->prefix);

		pdp->t_valid.tv_sec = 0;
		pdp->t_valid.tv_usec = 0;
	}

	dhcp6_bnd_update(bnd);
}

void dhcp6r_snoop(struct dhcp6r_iface *drif, struct sockaddr_in6 *host,
		  struct zbuf *zb)
{
	struct dh6p_option client_id_opt[1];
	struct dh6p_option buf[128], *ia_opt;
	struct dh6p_optspec opts[] = {
		[DH6OPT_CLIENTID] = { .single = client_id_opt, },
		[DH6OPT_IA_PD] = { .want = true, },
	};
	const char *perr;
	struct dhcp6_duid client_id;

	if (!dhcp6_parse_msg(zb, opts, array_size(opts), buf, array_size(buf),
			     &perr, NULL, NULL)) {
		zlog_warn("%s: %pSU: snoop parse failed: %s", drif->ifp->name,
			  host, perr);
		return;
	}

	dhcp6_parse_duid(client_id_opt->zb, &client_id);
	if (client_id_opt->zb->error) {
		zlog_warn("%s: %pSU: malformed DUID", drif->ifp->name, host);
		return;
	}

	zlog_info("%s: %pSU: snoop on reply for %pDUID", drif->ifp->name, host,
		  &client_id);

	frr_each (dh6p_optlist, opts[DH6OPT_IA_PD].list, ia_opt)
		dhcp6r_snoop_ia_pd(drif, host, &client_id, ia_opt);
}

static inline bool in6_uc_routable(const struct in6_addr *addr)
{
	uint32_t beginning = ntohl(addr->s6_addr32[0]);

	return (beginning & 0xe0000000) == 0x20000000
		|| (beginning & 0xfe000000) == 0xfc000000;
}

static unsigned dhcp6_timer_adj(unsigned *curp, unsigned init, unsigned max)
{
	unsigned cur = *curp;
	int64_t mult = (int16_t)(frr_weak_random() & 0xffff);
	int64_t adj;

	if (cur && cur <= max / 2) {
		adj = cur;
		cur *= 2;
	} else if (cur > max / 2) {
		adj = max;
		cur = max;
	} else {
		adj = init;
		cur = init;
	}

	adj *= mult;
	adj >>= 18;	/* +- 0.125 */

	cur += adj;
	*curp = cur;
	return cur;
}

static void dhcp6_ra_self_solicit_tmr(struct thread *t)
{
	struct dhcp6r_iface *drif = THREAD_ARG(t);
	char buf[4096];
	struct zbuf zb[1];

	assert(drif->ra_self_state == DHCP6_CS_SOLICIT);

	if (drif->ra_self_state != DHCP6_CS_SOLICIT)
		return;

	zbuf_init(zb, buf, sizeof(buf), 0);

	zbuf_put8(zb, DH6MSG_SOLICIT);
	zbuf_put8(zb, drif->ra_self_xid >> 16);
	zbuf_put_be16(zb, drif->ra_self_xid & 0xffff);

	zbuf_put_be16(zb, DH6OPT_ELAPSED_TIME);
	zbuf_put_be16(zb, 2);
	zbuf_put_be16(zb, MIN(drif->ra_self_elapsed, 0xffff));

	uint16_t req[] = { DH6OPT_DNS_SERVERS, DH6OPT_DOMAIN_LIST };

	zbuf_put_be16(zb, DH6OPT_ORO);
	zbuf_put_be16(zb, sizeof(req));
	for (size_t i = 0; i < array_size(req); i++)
		zbuf_put_be16(zb, req[i]);

	dhcp6_put_duidopt(zb, DH6OPT_CLIENTID, &drif->ra_self_duid);

	zbuf_put_be16(zb, DH6OPT_IA_PD);
	zbuf_put_be16(zb, 12 + 4 + 25);
	zbuf_put_be32(zb, 1); /* IAID */
	zbuf_put_be32(zb, 0); /* T1 */
	zbuf_put_be32(zb, 0); /* T2 */

	zbuf_put_be16(zb, DH6OPT_IAPREFIX);
	zbuf_put_be16(zb, 25);
	zbuf_put_be32(zb, 0);	/* preferred */
	zbuf_put_be32(zb, 0);	/* valid */
	zbuf_put8(zb, 64);	/* /64 */
	zbuf_put_be32(zb, 0);	/* prefix */
	zbuf_put_be32(zb, 0);
	zbuf_put_be32(zb, 0);
	zbuf_put_be32(zb, 0);

	dhcp6_timer_adj(&drif->ra_self_sol_delay, SOL_MAX_DELAY, SOL_MAX_RT);
	thread_add_timer_msec(master, dhcp6_ra_self_solicit_tmr, drif,
			      drif->ra_self_sol_delay, &drif->t_ra_self);
	drif->ra_self_elapsed += drif->ra_self_sol_delay;

	zlog_info("SOLICIT for %s, xid %#06x, retry now %u", drif->ifp->name,
		  drif->ra_self_xid, drif->ra_self_sol_delay);

	struct sockaddr_in6 from;

	from.sin6_family = AF_INET6;
	from.sin6_port = ntohs(546);
	from.sin6_addr.s6_addr32[0] = htonl(0xfe800000);
	from.sin6_addr.s6_addr32[1] = 0;
	from.sin6_addr.s6_addr32[2] = 0;
	from.sin6_addr.s6_addr32[3] = 0;

	dhcp6_ugroup_relay(drif->ugroup_name, drif, &from,
			   (struct dhcp6 *)zb->buf, zb->tail - zb->buf);
}

void dhcp6_ra_self_rcv(struct dhcp6r_iface *drif, struct zbuf *zb)
{
	struct zbuf tmp = *zb;
	uint8_t msg_type = zbuf_get8(&tmp);
	uint32_t xid;

	xid = (zbuf_get8(&tmp) << 16) | zbuf_get_be16(&tmp);
	if (xid != drif->ra_self_xid) {
		zlog_info("%s: %dDHMT for ra-self XID mismatch (got %#06x, expected %#06x)",
			  drif->ifp->name, msg_type, xid, drif->ra_self_xid);
		return;
	}

	zlog_info("%s: %dDHMT for ra-self", drif->ifp->name, msg_type);

#define MAY .optional = true,
	struct dh6p_option server_id_opt[1], client_id_opt[1];
	struct dh6p_option sol_max_rt_opt[1], pref_opt[1];
	struct dh6p_option buf[128], *ia_pd;
	struct dh6p_optspec opts[] = {
		[DH6OPT_CLIENTID] = { .single = client_id_opt, },
		[DH6OPT_SERVERID] = { .single = server_id_opt, },
		[DH6OPT_PREFERENCE] = { .single = pref_opt, MAY },
		[DH6OPT_SOL_MAX_RT] = { .single = sol_max_rt_opt, MAY },
		[DH6OPT_IA_PD] = { .want = true, },
	};
	const char *perr;

	if (!dhcp6_parse_msg(zb, opts, array_size(opts), buf, array_size(buf),
			     &perr, NULL, NULL)) {
		zlog_warn("%s: ra-self parse failed: %s", drif->ifp->name,
			  perr);
		return;
	}

	struct dhcp6_duid client_id, server_id;

	dhcp6_parse_duid(client_id_opt->zb, &client_id);
	dhcp6_parse_duid(server_id_opt->zb, &server_id);

	if (duid_compare(&client_id, &drif->ra_self_duid)) {
		zlog_warn("%s: ignoring ADVERTISE for another client %pDUID",
			  drif->ifp->name, &client_id);
		return;
	}

	if (dh6p_optlist_count(opts[DH6OPT_IA_PD].list) == 0) {
		zlog_warn("%s: ignoring ADVERTISE without IA_PD",
			  drif->ifp->name);
		return;
	}

	frr_each (dh6p_optlist, opts[DH6OPT_IA_PD].list, ia_pd) {
		struct dh6p_option subbuf[128], *iapfx;
		struct dh6p_optspec subopts[] = {
			[DH6OPT_IAPREFIX] = { .want = true, },
		};

		uint32_t iaid, t1, t2;

		iaid = zbuf_get_be32(ia_pd->zb);
		t1 = zbuf_get_be32(ia_pd->zb);
		t2 = zbuf_get_be32(ia_pd->zb);

		if (ia_pd->zb->error) {
			zlog_err("IA_PD parse error");
			return;
		}

		if (!dhcp6_parse_opts(ia_pd->zb, subopts, array_size(subopts),
				      subbuf, array_size(subbuf), &perr)) {
			zlog_warn("%s: IAPREFIX parse failed: %s",
				  drif->ifp->name, perr);
			return;
		}
		(void)iaid;
		(void)t1;
		(void)t2;

		frr_each (dh6p_optlist, subopts[DH6OPT_IAPREFIX].list, iapfx) {
			struct prefix pfx = { .family = AF_INET6 };
			uint32_t pref, valid;
			void *p;

			pref = zbuf_get_be32(iapfx->zb);
			valid = zbuf_get_be32(iapfx->zb);

			pfx.prefixlen = zbuf_get8(iapfx->zb);
			p = zbuf_pulln(iapfx->zb, sizeof(pfx.u.prefix6));

			if (iapfx->zb->error || !p) {
				zlog_warn("malformed IAPREFIX");
				continue;
			}
			memcpy(&pfx.u.prefix6, p, sizeof(pfx.u.prefix6));
			apply_mask(&pfx);

			if (pfx.prefixlen > 64) {
				zlog_debug("ignoring %pFX, >/64", &pfx);
				continue;
			}
			zlog_debug("ra-self adv %pFX pref %u valid %u", &pfx,
				   pref, valid);
		}
	}
}

static void dhcp6_ra_self_solicit(struct dhcp6r_iface *drif)
{
	thread_cancel(&drif->t_ra_self);

	drif->ra_self_state = DHCP6_CS_SOLICIT;
	drif->ra_self_sol_delay = 0;
	drif->ra_self_xid = frr_weak_random() & 0xffffff;
	drif->ra_self_elapsed = 0;

	dhcp6_timer_adj(&drif->ra_self_sol_delay, SOL_MAX_DELAY, SOL_MAX_RT);
	thread_add_timer_msec(master, dhcp6_ra_self_solicit_tmr, drif,
			      drif->ra_self_sol_delay, &drif->t_ra_self);

}

static void dhcp6_ra_self_if_refresh(struct interface *ifp, bool forcewarn)
{
	struct dhcp6r_iface *drif = ifp->info;

	if (!drif->ra_self_enabled) {
		return;
	}

	if (!if_is_up(ifp)) {
		return;
	}

	if (drif->ra_self_state == DHCP6_CS_DISABLED) {
		dhcp6_ra_self_solicit(drif);
	}
}

void dhcp6r_if_refresh(struct interface *ifp, bool forcewarn)
{
	struct dhcp6r_iface *drif = ifp->info;
	struct listnode *node;
	struct connected *linklocal = NULL;
	struct connected *best_global = NULL;
	struct connected *connected;

	dhcp6_ra_self_if_refresh(ifp, forcewarn);

	if (!drif->relay_enabled) {
		dhcp6r_if_stop(drif, "disabled", forcewarn);
		return;
	}

	if (!if_is_up(ifp)) {
		dhcp6r_if_stop(drif, "interface is down", forcewarn);
		return;
	}

	linklocal = connected_get_linklocal(ifp);
	if (!linklocal) {
		dhcp6r_if_stop(drif, "no link-local IPv6 address", forcewarn);
		return;
	}

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
		if (!linklocal)
			zlog_info("%s addr: %pFX", drif->ifp->name,
				  connected->address);
		if (connected->address->family != AF_INET6)
			continue;
		if (!in6_uc_routable(&connected->address->u.prefix6))
			continue;
		if (!best_global
		    || IPV6_ADDR_CMP(&best_global->address->u.prefix6,
				     &connected->address->u.prefix6) < 0)
			best_global = connected;
	}

	if (!best_global)
		zlog_warn("%s: enabling DHCPv6 relay without global address",
			  ifp->name);
	else if (best_global != drif->best_global)
		zlog_info("%s: enabling DHCPv6 relay using %pFX as identifier",
			  ifp->name, best_global->address);

	dhcp6r_if_start(drif, best_global);
}

/* ZAPI callbacks */

static int dhcp6r_ifp_create(struct interface *ifp)
{
	return 0;
}

static int dhcp6r_ifp_destroy(struct interface *ifp)
{
	return 0;
}

static int dhcp6r_ifp_up(struct interface *ifp)
{
	dhcp6r_if_refresh(ifp, false);
	return 0;
}

static int dhcp6r_ifp_down(struct interface *ifp)
{
	dhcp6r_if_refresh(ifp, false);
	return 0;
}

/* CLI */

#ifndef VTYSH_EXTRACT_PL
#include "dhcp6_iface_clippy.c"
#endif

#define DHCP_STR "Dynamic Host Configuration Protocol\n"

DEFPY (dhcp6r_relay,
       dhcp6r_relay_cmd,
       "[no] ipv6 dhcp relay-agent enable",
       NO_STR
       IPV6_STR
       DHCP_STR
       "Relay DHCPv6 requests from/to clients this interface\n"
       "Enable relaying requests from clients\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct dhcp6r_iface *drif = ifp->info;

	drif->relay_enabled = !no;
	dhcp6r_if_refresh(ifp, true);

	return CMD_SUCCESS;
}

DEFPY (dhcp6r_relay_ugroup,
       dhcp6r_relay_ugroup_cmd,
       "[no] ipv6 dhcp relay-agent server-group WORD",
       NO_STR
       IPV6_STR
       DHCP_STR
       "Relay DHCPv6 requests from/to clients this interface\n"
       "Configure server group to relay requests to\n"
       "Server group name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct dhcp6r_iface *drif = ifp->info;

	XFREE(MTYPE_TMP, drif->ugroup_name);

	if (no)
		return CMD_SUCCESS;

	drif->ugroup_name = XSTRDUP(MTYPE_TMP, server_group);
	return CMD_SUCCESS;
}

DEFPY (dhcp6_ra_self,
       dhcp6_ra_self_cmd,
       "[no] ipv6 dhcp relay-agent self-delegate",
       NO_STR
       IPV6_STR
       DHCP_STR
       "Relay DHCPv6 requests from/to clients this interface\n"
       "Request /64 prefix delegation for assignment to interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct dhcp6r_iface *drif = ifp->info;

	drif->ra_self_duid.type = DUIDT_EN;

	uint32_t iana_en = htonl(50145);

	memcpy(drif->ra_self_duid.raw + 0, &iana_en, sizeof(iana_en));
	drif->ra_self_duid.raw[4] = 0xde;
	drif->ra_self_duid.raw[5] = 0xad;
	drif->ra_self_duid.raw[6] = 0xbe;
	drif->ra_self_duid.raw[7] = 0xef;
	drif->ra_self_duid.size = 8;

	drif->ra_self_enabled = !no;
	dhcp6_ra_self_if_refresh(ifp, true);

	return CMD_SUCCESS;
}

DEFPY (dhcp6r_show_iface,
       dhcp6r_show_iface_cmd,
       "show ipv6 dhcp interface [IFNAME]",
       SHOW_STR
       IPV6_STR
       DHCP_STR
       "Interface information\n"
       "Interface to show\n")
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	FOR_ALL_INTERFACES(vrf, ifp) {
		vty_out(vty, "Interface %s:\n", ifp->name);
		if (!if_is_up(ifp)) {
			vty_out(vty, "  Interface is down.\n\n");
			continue;
		}
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

static int dhcp6r_if_config_write(struct vty *vty)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	int ctr = 0;

	FOR_ALL_INTERFACES(vrf, ifp) {
		struct dhcp6r_iface *drif = ifp->info;

		vty_frame(vty, "interface %s\n",ifp->name);

		if (ifp->desc)
			vty_out(vty, " description %s\n", ifp->desc);

		if (drif->relay_enabled)
			vty_out(vty, " ipv6 dhcp relay-agent enable\n");
		if (drif->ugroup_name)
			vty_out(vty, " ipv6 dhcp relay-agent server-group %s\n",
				drif->ugroup_name);

		vty_endframe (vty, "!\n");
		ctr++;
	}
	return ctr;
}

void dhcp6r_if_init(void)
{
	hook_register_prio(if_add, 0, dhcp6r_if_new_hook);
	hook_register_prio(if_del, 0, dhcp6r_if_del_hook);

	if_cmd_init(dhcp6r_if_config_write);

	install_element(VIEW_NODE, &dhcp6r_show_iface_cmd);

	install_element(INTERFACE_NODE, &dhcp6r_relay_cmd);
	install_element(INTERFACE_NODE, &dhcp6r_relay_ugroup_cmd);
	install_element(INTERFACE_NODE, &dhcp6_ra_self_cmd);

	if_zapi_callbacks(dhcp6r_ifp_create, dhcp6r_ifp_up,
			  dhcp6r_ifp_down, dhcp6r_ifp_destroy);
}
