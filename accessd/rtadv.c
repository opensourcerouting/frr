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

#include "lib/zebra.h"
#include <netinet/icmp6.h>

#include "rtadv.h"
#include "rtadv_protocol.h"

#include "accessd.h"
#include "accessd_vrf.h"
#include "accessd_iface.h"

#include "nhrpd/zbuf.h"
#include "lib/vrf.h"
#include "lib/sockopt.h"

DEFINE_MTYPE_STATIC(ACCESSD, RTADV_VRF, "IPv6 RA VRF state");
DEFINE_MTYPE_STATIC(ACCESSD, RTADV_IF, "IPv6 RA interface");

static const struct in6_addr all_nodes = {
	.s6_addr = {
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
};

static int rtadv_prefix_cmp(const struct rtadv_prefix *a,
			    const struct rtadv_prefix *b)
{
	return prefix_cmp(&a->prefix, &b->prefix);
}

DECLARE_RBTREE_UNIQ(rtadv_prefixes, struct rtadv_prefix, item,
		    rtadv_prefix_cmp);

static inline struct accessd_vrf *accessd_if_to_vrf(struct accessd_iface *acif)
{
	struct vrf *vrf = acif->ifp->vrf;

	assertf(vrf, "acif->ifp->name=%s", acif->ifp->name);
	return vrf->info;
}

static struct rtadv_vrf *rtadv_vrf_getref(struct accessd_vrf *acvrf)
{
	struct rtadv_vrf *ravrf;
	int sock;
	int ret;
	struct icmp6_filter filter;

	if (acvrf->rtadv_vrf) {
		acvrf->rtadv_vrf->refcnt++;
		return acvrf->rtadv_vrf;
	}

	frr_with_privs (&accessd_privs) {
		sock = vrf_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6,
				  acvrf->vrf->vrf_id, acvrf->vrf->name);
	}

	if (sock < 0) {
		zlog_err("rtadv socket: %m");
		return NULL;
	}

	ret = setsockopt_ipv6_pktinfo(sock, 1);
	if (ret < 0) {
		close(sock);
		return NULL;
	}
	ret = setsockopt_ipv6_multicast_loop(sock, 0);
	if (ret < 0) {
		close(sock);
		return NULL;
	}
#if 0
	ret = setsockopt_ipv6_unicast_hops(sock, 255);
	if (ret < 0) {
		close(sock);
		return NULL;
	}
	ret = setsockopt_ipv6_multicast_hops(sock, 255);
	if (ret < 0) {
		close(sock);
		return NULL;
	}
	ret = setsockopt_ipv6_hoplimit(sock, 1);
	if (ret < 0) {
		close(sock);
		return ret;
	}
#endif

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);

	ret = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
			 sizeof(struct icmp6_filter));
	if (ret < 0)
		zlog_warn("failed to set ICMP6_FILTER: %m");

	ravrf = XCALLOC(MTYPE_RTADV_VRF, sizeof(*ravrf));
	ravrf->refcnt = 1;
	ravrf->sock = sock;
	// t_read

	acvrf->rtadv_vrf = ravrf;
	return ravrf;
}

static void rtadv_vrf_decref(struct accessd_vrf *acvrf)
{
	struct rtadv_vrf *ravrf = acvrf->rtadv_vrf;

	assertf(ravrf, "acvrf->vrf->name=%s", acvrf->vrf->name);

	if (--ravrf->refcnt)
		return;

	EVENT_OFF(ravrf->t_read);
	close(ravrf->sock);

	XFREE(MTYPE_RTADV_VRF, acvrf->rtadv_vrf);
}

struct rtadv_iface *rtadv_ifp_get(struct accessd_iface *acif)
{
	if (acif->rtadv)
		return acif->rtadv;

	acif->rtadv = XCALLOC(MTYPE_RTADV_IF, sizeof(*acif->rtadv));
	acif->rtadv->cfg = rtadv_ifp_defaults;
	return acif->rtadv;
}

static void rtadv_ra_header(struct rtadv_iface *raif, struct zbuf *zb)
{
	struct nd_router_advert *rtadv;
	unsigned int lifetime;

	rtadv = zbuf_push(zb, struct nd_router_advert);
	assert(rtadv);
	memset(rtadv, 0, sizeof(*rtadv));

	rtadv->nd_ra_type = ND_ROUTER_ADVERT;
	rtadv->nd_ra_code = 0;
	rtadv->nd_ra_cksum = 0;

	rtadv->nd_ra_curhoplimit = raif->cfg.hoplimit;
#if 0
	if (raif->cfg.lifetime_sec)
		/* RFC4191: Default Router Preference is 0 if Router Lifetime is 0. */
	rtadv->nd_ra_flags_reserved = zif->rtadv.AdvDefaultLifetime == 0
					      ? 0
					      : zif->rtadv.DefaultPreference;
	rtadv->nd_ra_flags_reserved <<= 3;
#endif

	if (raif->cfg.managed_config)
		rtadv->nd_ra_flags_reserved |= ND_RA_FLAG_MANAGED;
	if (raif->cfg.other_config)
		rtadv->nd_ra_flags_reserved |= ND_RA_FLAG_OTHER;
#if 0
	if (zif->rtadv.AdvHomeAgentFlag)
		rtadv->nd_ra_flags_reserved |= ND_RA_FLAG_HOME_AGENT;
#endif
	if (raif->cfg.lifetime_sec)
		lifetime = raif->cfg.lifetime_sec;
	else
		lifetime = (raif->cfg.interval_msec * 3 + 999) / 1000;

	rtadv->nd_ra_router_lifetime = htons(lifetime);
	rtadv->nd_ra_reachable = htonl(raif->cfg.reachable_ms);
	rtadv->nd_ra_retransmit = htonl(raif->cfg.retrans_ms);
}

static void rtadv_option_interval(struct rtadv_iface *raif, struct zbuf *zb)
{
	struct nd_opt_adv_interval *ndopt_adv;

	if (!raif->cfg.include_adv_interval)
		return;

	ndopt_adv = zbuf_push(zb, struct nd_opt_adv_interval);
	assert(ndopt_adv);
	memset(ndopt_adv, 0, sizeof(*ndopt_adv));

	ndopt_adv->nd_opt_ai_type = ND_OPT_ADV_INTERVAL;
	ndopt_adv->nd_opt_ai_len = 1;
	ndopt_adv->nd_opt_ai_reserved = 0;
	ndopt_adv->nd_opt_ai_interval = htonl(raif->cfg.interval_msec);
}

static void rtadv_option_lladdr(struct accessd_iface *acif, struct zbuf *zb)
{
	struct interface *ifp = acif->ifp;
	struct nd_opt_hdr *hdr;
	unsigned int total_len_8b; /* in units of 8 bytes */
	uint8_t *lladdr;

	if (!ifp->hw_addr_len)
		return;

	total_len_8b = (ifp->hw_addr_len + sizeof(*hdr) + 7U) / 8U;

	hdr = zbuf_push(zb, struct nd_opt_hdr);
	hdr->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	hdr->nd_opt_len = total_len_8b;

	lladdr = zbuf_pushn(zb, total_len_8b * 8U - 2);
	memset(lladdr, 0, total_len_8b * 8U - 2);
	memcpy(lladdr, ifp->hw_addr, ifp->hw_addr_len);
}

static void rtadv_option_mtu(struct accessd_iface *acif, struct zbuf *zb)
{
	struct rtadv_iface *raif = acif->rtadv;
	struct interface *ifp = acif->ifp;
	unsigned int mtu;
	struct nd_opt_mtu *ndopt_mtu;

	switch (raif->cfg.link_mtu) {
	case RTADV_MTU_NOINCLUDE:
		return;
	case RTADV_MTU_AUTO:
		mtu = ifp->mtu6;
		break;
	default:
		mtu = raif->cfg.link_mtu;
		break;
	}

	ndopt_mtu = zbuf_push(zb, struct nd_opt_mtu);
	assert(ndopt_mtu);
	memset(ndopt_mtu, 0, sizeof(*ndopt_mtu));

	ndopt_mtu->nd_opt_mtu_type = ND_OPT_MTU;
	ndopt_mtu->nd_opt_mtu_len = 1;
	ndopt_mtu->nd_opt_mtu_reserved = 0;
	ndopt_mtu->nd_opt_mtu_mtu = htonl(mtu);
}

static void rtadv_option_prefix(struct accessd_iface *acif,
				struct rtadv_prefix *ra_prefix,
				struct zbuf *zb)
{
}

static void rtadv_send_ip6(struct accessd_iface *acif,
			   const struct in6_addr *dst,
			   struct zbuf *zb)
{
	struct accessd_vrf *acvrf = accessd_if_to_vrf(acif);
	struct msghdr mh[1] = {};
	struct iovec iov[1] = {};
	struct cmsghdr *cmh;
	struct in6_pktinfo *pktinfo;
	union {
		char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
		struct cmsghdr align;
	} cmsgbuf = {};
	struct sockaddr_in6 sa_dst = {
		.sin6_family = AF_INET6,
#ifdef SIN6_LEN
		.sin6_len = sizeof(struct sockaddr_in6),
#endif
		.sin6_port = htons(IPPROTO_ICMPV6),
	};
	ssize_t ret;

	if (dst)
		sa_dst.sin6_addr = *dst;
	else
		sa_dst.sin6_addr = all_nodes;

	mh->msg_name = (struct sockaddr *)&sa_dst;
	mh->msg_namelen = sizeof(sa_dst);
	mh->msg_iov = iov;
	mh->msg_iovlen = array_size(iov);
	mh->msg_control = (void *)&cmsgbuf;
	mh->msg_controllen = sizeof(cmsgbuf.buf);
	mh->msg_flags = 0;

	iov->iov_base = zb->head;
	iov->iov_len = zbuf_used(zb);

	cmh = CMSG_FIRSTHDR(mh);
	cmh->cmsg_len = CMSG_LEN(sizeof(*pktinfo));
	cmh->cmsg_level = IPPROTO_IPV6;
	cmh->cmsg_type = IPV6_PKTINFO;

	pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmh);
	pktinfo->ipi6_ifindex = acif->ifp->ifindex;

	ret = sendmsg(acvrf->rtadv_vrf->sock, mh, 0);
	if (ret < 0)
		zlog_err("%s: RA send failed: %m", acif->ifp->name);
}

static void rtadv_ra_send(struct accessd_iface *acif,
			  struct rtadv_prefix *ra_prefix,
			  const struct in6_addr *dst,
			  const struct ethaddr *ethdst)
{
	struct rtadv_iface *raif = acif->rtadv;
	struct zbuf *zb = zbuf_alloc(1280);

	assert(raif);

	rtadv_ra_header(raif, zb);

	rtadv_option_interval(raif, zb);
	rtadv_option_lladdr(acif, zb);
	rtadv_option_mtu(acif, zb);

	if (ra_prefix)
		rtadv_option_prefix(acif, ra_prefix, zb);
	else
		frr_each (rtadv_prefixes, raif->prefixes, ra_prefix)
			if (!ra_prefix->cfg.make_addr)
				rtadv_option_prefix(acif, ra_prefix, zb);

	if (!ethdst)
		rtadv_send_ip6(acif, dst, zb);
	/* else: send ETH */
}

#if 0
/* Send router advertisement packet. */
static void rtadv_send_packet(int sock, struct interface *ifp,
			      enum ipv6_nd_suppress_ra_status stop)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsgptr;
	struct in6_pktinfo *pkt;
	struct sockaddr_in6 addr;
	static void *adata = NULL;
	unsigned char buf[RTADV_MSG_SIZE];
	struct nd_router_advert *rtadv;
	int ret;
	int len = 0;
	struct zebra_if *zif;
	struct rtadv_prefix *rprefix;
	struct listnode *node;
	uint16_t pkt_RouterLifetime;

	/*
	 * Allocate control message bufffer.  This is dynamic because
	 * CMSG_SPACE is not guaranteed not to call a function.  Note that
	 * the size will be different on different architectures due to
	 * differing alignment rules.
	 */
	if (adata == NULL) {
		/* XXX Free on shutdown. */
		adata = calloc(1, CMSG_SPACE(sizeof(struct in6_pktinfo)));

		if (adata == NULL) {
			zlog_debug(
				"rtadv_send_packet: can't malloc control data");
			exit(-1);
		}
	}

	/* Logging of packet. */
	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("%s(%s:%u): Tx RA, socket %u", ifp->name,
			   ifp->vrf->name, ifp->ifindex, sock);

	/* Fetch interface information. */
	zif = ifp->info;

	/* If both the Home Agent Preference and Home Agent Lifetime are set to
	 * their default values specified above, this option SHOULD NOT be
	 * included in the Router Advertisement messages sent by this home
	 * agent. -- RFC6275, 7.4 */
	if (zif->rtadv.AdvHomeAgentFlag
	    && (zif->rtadv.HomeAgentPreference
		|| zif->rtadv.HomeAgentLifetime != -1)) {
		struct nd_opt_homeagent_info *ndopt_hai =
			(struct nd_opt_homeagent_info *)(buf + len);
		ndopt_hai->nd_opt_hai_type = ND_OPT_HA_INFORMATION;
		ndopt_hai->nd_opt_hai_len = 1;
		ndopt_hai->nd_opt_hai_reserved = 0;
		ndopt_hai->nd_opt_hai_preference =
			htons(zif->rtadv.HomeAgentPreference);
		/* 16-bit unsigned integer.  The lifetime associated with the
		 * home
		 * agent in units of seconds.  The default value is the same as
		 * the
		 * Router Lifetime, as specified in the main body of the Router
		 * Advertisement.  The maximum value corresponds to 18.2 hours.
		 * A
		 * value of 0 MUST NOT be used. -- RFC6275, 7.5 */
		ndopt_hai->nd_opt_hai_lifetime =
			htons(zif->rtadv.HomeAgentLifetime != -1
				      ? zif->rtadv.HomeAgentLifetime
				      : MAX(1, pkt_RouterLifetime) /* 0 is OK
								      for RL,
								      but not
								      for HAL*/
			      );
		len += sizeof(struct nd_opt_homeagent_info);
	}

	/* Fill in prefix. */
	frr_each (rtadv_prefixes, zif->rtadv.prefixes, rprefix) {
		struct nd_opt_prefix_info *pinfo;

		pinfo = (struct nd_opt_prefix_info *)(buf + len);

		pinfo->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		pinfo->nd_opt_pi_len = 4;
		pinfo->nd_opt_pi_prefix_len = rprefix->prefix.prefixlen;

		pinfo->nd_opt_pi_flags_reserved = 0;
		if (rprefix->AdvOnLinkFlag)
			pinfo->nd_opt_pi_flags_reserved |=
				ND_OPT_PI_FLAG_ONLINK;
		if (rprefix->AdvAutonomousFlag)
			pinfo->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
		if (rprefix->AdvRouterAddressFlag)
			pinfo->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_RADDR;

		pinfo->nd_opt_pi_valid_time = htonl(rprefix->AdvValidLifetime);
		pinfo->nd_opt_pi_preferred_time =
			htonl(rprefix->AdvPreferredLifetime);
		pinfo->nd_opt_pi_reserved2 = 0;

		IPV6_ADDR_COPY(&pinfo->nd_opt_pi_prefix,
			       &rprefix->prefix.prefix);

		len += sizeof(struct nd_opt_prefix_info);
	}

	/*
	 * There is no limit on the number of configurable recursive DNS
	 * servers or search list entries. We don't want the RA message
	 * to exceed the link's MTU (risking fragmentation) or even
	 * blow the stack buffer allocated for it.
	 */
	size_t max_len = MIN(ifp->mtu6 - 40, sizeof(buf));

	/* Recursive DNS servers */
	struct rtadv_rdnss *rdnss;

	for (ALL_LIST_ELEMENTS_RO(zif->rtadv.AdvRDNSSList, node, rdnss)) {
		size_t opt_len =
			sizeof(struct nd_opt_rdnss) + sizeof(struct in6_addr);

		if (len + opt_len > max_len) {
			zlog_warn(
				"%s(%s:%u): Tx RA: RDNSS option would exceed MTU, omitting it",
				ifp->name, ifp->vrf->name, ifp->ifindex);
			goto no_more_opts;
		}
		struct nd_opt_rdnss *opt = (struct nd_opt_rdnss *)(buf + len);

		opt->nd_opt_rdnss_type = ND_OPT_RDNSS;
		opt->nd_opt_rdnss_len = opt_len / 8;
		opt->nd_opt_rdnss_reserved = 0;
		opt->nd_opt_rdnss_lifetime = htonl(
			rdnss->lifetime_set
				? rdnss->lifetime
				: MAX(1, 0.003 * zif->rtadv.MaxRtrAdvInterval));

		len += sizeof(struct nd_opt_rdnss);

		IPV6_ADDR_COPY(buf + len, &rdnss->addr);
		len += sizeof(struct in6_addr);
	}

	/* DNS search list */
	struct rtadv_dnssl *dnssl;

	for (ALL_LIST_ELEMENTS_RO(zif->rtadv.AdvDNSSLList, node, dnssl)) {
		size_t opt_len = sizeof(struct nd_opt_dnssl)
				 + ((dnssl->encoded_len + 7) & ~7);

		if (len + opt_len > max_len) {
			zlog_warn(
				"%s(%u): Tx RA: DNSSL option would exceed MTU, omitting it",
				ifp->name, ifp->ifindex);
			goto no_more_opts;
		}
		struct nd_opt_dnssl *opt = (struct nd_opt_dnssl *)(buf + len);

		opt->nd_opt_dnssl_type = ND_OPT_DNSSL;
		opt->nd_opt_dnssl_len = opt_len / 8;
		opt->nd_opt_dnssl_reserved = 0;
		opt->nd_opt_dnssl_lifetime = htonl(
			dnssl->lifetime_set
				? dnssl->lifetime
				: MAX(1, 0.003 * zif->rtadv.MaxRtrAdvInterval));

		len += sizeof(struct nd_opt_dnssl);

		memcpy(buf + len, dnssl->encoded_name, dnssl->encoded_len);
		len += dnssl->encoded_len;

		/* Zero-pad to 8-octet boundary */
		while (len % 8)
			buf[len++] = '\0';
	}

no_more_opts:

	msg.msg_name = (void *)&addr;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *)adata;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
	msg.msg_flags = 0;
	iov.iov_base = buf;
	iov.iov_len = len;

	cmsgptr = CMSG_FIRSTHDR(&msg);
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;

	pkt = (struct in6_pktinfo *)CMSG_DATA(cmsgptr);
	memset(&pkt->ipi6_addr, 0, sizeof(struct in6_addr));
	pkt->ipi6_ifindex = ifp->ifindex;

	ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "%s(%u): Tx RA failed, socket %u error %d (%s)",
			     ifp->name, ifp->ifindex, sock, errno,
			     safe_strerror(errno));
	} else
		zif->ra_sent++;
}
#endif

static void rtadv_ifp_timer(struct event *ev)
{
	struct accessd_iface *acif = EVENT_ARG(ev);
	struct rtadv_iface *rtadv = acif->rtadv;

	event_add_timer_msec(master, rtadv_ifp_timer, acif,
			      rtadv->cfg.interval_msec, &rtadv->t_periodic);

	zlog_info("rtadv interface timer for %s, next %pTHD",
		  acif->ifp->name, rtadv->t_periodic);

	rtadv_ra_send(acif, NULL, &all_nodes, NULL);
}

static void rtadv_ifp_refresh(struct accessd_iface *acif)
{
	struct rtadv_iface *rtadv = acif->rtadv;

	if (rtadv->t_periodic && (!if_is_up(acif->ifp) || !rtadv->cfg.enable)) {
		EVENT_OFF(rtadv->t_periodic);
		rtadv_vrf_decref(accessd_if_to_vrf(acif));
		zlog_info("if %s disabled", acif->ifp->name);
		return;
	}

	if (rtadv->cfg.enable && if_is_up(acif->ifp) && !rtadv->t_periodic) {
		struct accessd_vrf *acvrf = accessd_if_to_vrf(acif);
		struct rtadv_vrf *ravrf;

		ravrf = rtadv_vrf_getref(acvrf);
		if (!ravrf) {
			zlog_warn("failed to enable rtadv");
			return;
		}

		event_add_timer_msec(master, rtadv_ifp_timer, acif, 0,
				      &rtadv->t_periodic);

		zlog_info("if %s enabled", acif->ifp->name);
	}
}

static int rtadv_ifp_up(struct interface *ifp)
{
	struct accessd_iface *acif = ifp->info;

	if (!acif || !acif->rtadv)
		return 0;

	rtadv_ifp_refresh(acif);
	return 0;
}

static int rtadv_ifp_down(struct interface *ifp)
{
	struct accessd_iface *acif = ifp->info;

	if (!acif || !acif->rtadv)
		return 0;

	rtadv_ifp_refresh(acif);
	return 0;
}

void rtadv_ifp_reconfig(struct interface *ifp)
{
	rtadv_ifp_refresh(ifp->info);
}

void rtadv_init(void)
{
	hook_register(if_up, rtadv_ifp_up);
	hook_register(if_down, rtadv_ifp_down);

	rtadv_cli_init();
}
