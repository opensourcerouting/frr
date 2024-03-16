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
#include "accessd_zebra.h"

#include "nhrpd/zbuf.h"
#include "lib/vrf.h"
#include "lib/sockopt.h"
#include "lib/jhash.h"
#include "lib/sha256.h"
#include "lib/checksum.h"

#include "pimd/pim6_mld_protocol.h"

DEFINE_MTYPE_STATIC(ACCESSD, RTADV_VRF, "IPv6 RA VRF state");
DEFINE_MTYPE_STATIC(ACCESSD, RTADV_IF, "IPv6 RA interface");
DEFINE_MTYPE_STATIC(ACCESSD, RTADV_LLADDR, "IPv6 prefix-DAD link-local");
DEFINE_MTYPE_STATIC(ACCESSD, RTADV_PACKET, "IPv6 RA packet");

static void rtadv_vrf_recv(struct event *ev);

static const struct in6_addr all_nodes = {
	.s6_addr = {
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
};

static const struct in6_addr all_routers = {
	.s6_addr = {
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
};

static int rtadv_prefix_cmp(const struct rtadv_prefix *a,
			    const struct rtadv_prefix *b)
{
	return prefix_cmp(&a->prefix, &b->prefix);
}

DECLARE_RBTREE_UNIQ(rtadv_prefixes, struct rtadv_prefix, item,
		    rtadv_prefix_cmp);

static int rtadv_lladdr_cmp(const struct rtadv_lladdr *a,
			    const struct rtadv_lladdr *b)
{
	return IPV6_ADDR_CMP(&a->ll_addr, &b->ll_addr);
}

static uint32_t rtadv_lladdr_hash(const struct rtadv_lladdr *a)
{
	return jhash(&a->ll_addr, sizeof(a->ll_addr), 0x6f458853);
}

DECLARE_HASH(rtadv_lladdrs, struct rtadv_lladdr, item, rtadv_lladdr_cmp,
	     rtadv_lladdr_hash);

DECLARE_DLIST(rtadv_ll_prefixes, struct rtadv_prefix, llitem);

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
	int intval;
	struct icmp6_filter filter;

	if (acvrf->rtadv_vrf) {
		acvrf->rtadv_vrf->refcnt++;
		return acvrf->rtadv_vrf;
	}

	frr_with_privs (&accessd_privs) {
		sock = vrf_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6,
				  acvrf->vrf->vrf_id, acvrf->vrf->name);
		ret = setsockopt_ipv6_multicast_hops(sock, 255);
		if (ret < 0)
			zlog_warn("failed to set hopcount: %m");
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
	intval = 1;
	ret = setsockopt(sock, SOL_IPV6, IPV6_RECVHOPLIMIT, &intval,
			 sizeof(intval));
	if (ret)
		zlog_err("(VRF %s) failed to set IPV6_RECVHOPLIMIT: %m",
			 acvrf->vrf->name);

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
	event_add_read(master, rtadv_vrf_recv, acvrf, ravrf->sock,
			&ravrf->t_read);

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

void rtadv_lladdr_addref(struct accessd_iface *acif,
			 struct rtadv_prefix *ra_prefix)
{
	struct rtadv_iface *ra_if = acif->rtadv;
	struct rtadv_lladdr *ll_addr, ref = {};
	SHA256_CTX sha[1];
	uint8_t sha_hash[32];

	SHA256_Init(sha);
	SHA256_Update(sha, &ra_prefix->prefix.prefix,
		      sizeof(ra_prefix->prefix.prefix));
	SHA256_Update(sha, acif->ifp->hw_addr, acif->ifp->hw_addr_len);
	SHA256_Final(sha_hash, sha);

	ref.ll_addr.s6_addr32[0] = htonl(0xfe800000);
	ref.ll_addr.s6_addr32[1] = 0;
	memcpy(&ref.ll_addr.s6_addr32[2], sha_hash, 8);
	ref.ll_addr.s6_addr[8] &= ~0x02; /* locally generated */
	ref.ll_addr.s6_addr[8] |= 0x01; /* avoid collisions */

	ll_addr = rtadv_lladdrs_find(ra_if->lladdrs, &ref);
	if (!ll_addr) {
		struct prefix_ipv6 pfx;

		ll_addr = XCALLOC(MTYPE_RTADV_LLADDR, sizeof(*ll_addr));
		ll_addr->ll_addr = ref.ll_addr;
		rtadv_ll_prefixes_init(ll_addr->prefixes);

		rtadv_lladdrs_add(ra_if->lladdrs, ll_addr);

		pfx.family = AF_INET6;
		pfx.prefixlen = 64;
		pfx.prefix = ll_addr->ll_addr;
		if_addr_install(acif->ifp, &pfx);
	}
	ra_prefix->ll_addr = ll_addr;
	rtadv_ll_prefixes_add_tail(ll_addr->prefixes, ra_prefix);
}

void rtadv_lladdr_delref(struct accessd_iface *acif,
			 struct rtadv_prefix *ra_prefix)
{
	CPP_NOTICE("STUB - IMPLEMENT THIS");
}

struct rtadv_iface *rtadv_ifp_get(struct accessd_iface *acif)
{
	if (acif->rtadv)
		return acif->rtadv;

	acif->rtadv = XCALLOC(MTYPE_RTADV_IF, sizeof(*acif->rtadv));
	acif->rtadv->cfg = rtadv_ifp_defaults;
	rtadv_prefixes_init(acif->rtadv->prefixes);
	rtadv_lladdrs_init(acif->rtadv->lladdrs);
	return acif->rtadv;
}

CPP_NOTICE("clean up acif->rtadv");

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
	struct nd_opt_prefix_info *ndopt_pi;

	ndopt_pi = zbuf_push(zb, struct nd_opt_prefix_info);
	assert(ndopt_pi);
	memset(ndopt_pi, 0, sizeof(*ndopt_pi));

	ndopt_pi->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	ndopt_pi->nd_opt_pi_len = 4;
	ndopt_pi->nd_opt_pi_prefix_len = ra_prefix->prefix.prefixlen;
	ndopt_pi->nd_opt_pi_flags_reserved = 0;

	if (ra_prefix->cfg.onlink)
		ndopt_pi->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_ONLINK;
	if (ra_prefix->cfg.autonomous)
		ndopt_pi->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
	if (ra_prefix->cfg.router_addr)
		ndopt_pi->nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_RADDR;

	ndopt_pi->nd_opt_pi_valid_time = htonl(ra_prefix->cfg.valid_sec);
	ndopt_pi->nd_opt_pi_preferred_time =
		htonl(ra_prefix->cfg.preferred_sec);
	ndopt_pi->nd_opt_pi_reserved2 = 0;
	ndopt_pi->nd_opt_pi_prefix = ra_prefix->prefix.prefix;
}

static void rtadv_send_ip6(struct accessd_iface *acif,
			   const struct in6_addr *src,
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
	if (src)
		pktinfo->ipi6_addr = *src;

	zlog_info("%s: RA send src=%pI6 len=%zd", acif->ifp->name, src, iov->iov_len);
	ret = sendmsg(acvrf->rtadv_vrf->sock, mh, 0);
	if (ret < 0)
		zlog_err("%s: RA send failed: %m", acif->ifp->name);
}

static void rtadv_ra_send(struct accessd_iface *acif,
			  struct rtadv_lladdr *ll_addr,
			  const struct in6_addr *dst,
			  const struct ethaddr *ethdst)
{
	struct rtadv_iface *raif = acif->rtadv;
	struct rtadv_prefix *ra_prefix;
	struct zbuf *zb = zbuf_alloc(1280);
	struct in6_addr realsrc;
	const struct in6_addr *src = NULL;

	assert(raif);

	rtadv_ra_header(raif, zb);

	rtadv_option_interval(raif, zb);
	rtadv_option_lladdr(acif, zb);
	rtadv_option_mtu(acif, zb);

	if (ll_addr) {
		src = &ll_addr->ll_addr;

		frr_each (rtadv_ll_prefixes, ll_addr->prefixes, ra_prefix)
			rtadv_option_prefix(acif, ra_prefix, zb);
	} else {
		struct connected *connected;

		memset(&realsrc, 0xff, sizeof(realsrc));

		frr_each (rtadv_prefixes, raif->prefixes, ra_prefix)
			if (!ra_prefix->ll_addr)
				rtadv_option_prefix(acif, ra_prefix, zb);

		frr_each (if_connected, acif->ifp->connected, connected) {
			if (connected->address->family != AF_INET6)
				continue;
			if (IPV6_ADDR_CMP(&connected->address->u.prefix6, &realsrc) < 0)
				realsrc = connected->address->u.prefix6;
		}

		src = &realsrc;
	}

	if (!ethdst)
		rtadv_send_ip6(acif, src, dst, zb);
	/* else: send ETH */
}

static void rtadv_ifp_timer(struct event *ev)
{
	struct accessd_iface *acif = EVENT_ARG(ev);
	struct rtadv_iface *rtadv = acif->rtadv;
	struct rtadv_lladdr *ll_addr;

	event_add_timer_msec(master, rtadv_ifp_timer, acif,
			      rtadv->cfg.interval_msec, &rtadv->t_periodic);

	zlog_info("rtadv interface timer for %s, next %pTHD",
		  acif->ifp->name, rtadv->t_periodic);

	rtadv_ra_send(acif, NULL, &all_nodes, NULL);

	frr_each (rtadv_lladdrs, rtadv->lladdrs, ll_addr)
		rtadv_ra_send(acif, ll_addr, &all_nodes, NULL);
}

/* shorthand for log messages */
#define log_ifp(msg)                                                           \
	"[RA %s:%s] " msg, acif->ifp->vrf->name, acif->ifp->name
#define log_pkt_src(msg)                                                       \
	"[RA %s:%s %pI6] " msg, acif->ifp->vrf->name, acif->ifp->name,         \
		&pkt_src->sin6_addr

static void rtadv_handle_advert(struct accessd_iface *acif,
				const struct sockaddr_in6 *pkt_src,
				const struct in6_addr *pkt_dst,
				void *data, size_t pktlen)
{
	zlog_info(log_pkt_src("RA received"));
}

static void rtadv_handle_solicit(struct accessd_iface *acif,
				 const struct sockaddr_in6 *pkt_src,
				 const struct in6_addr *pkt_dst,
				 void *data, size_t pktlen)
{
	zlog_info(log_pkt_src("RS received"));
}

static void rtadv_rx_process(struct accessd_iface *acif,
			     const struct sockaddr_in6 *pkt_src,
			     const struct in6_addr *pkt_dst,
			     void *data, size_t pktlen)
{
	struct icmp6_plain_hdr *icmp6 = data;
	uint16_t pkt_csum, ref_csum;
	struct ipv6_ph ph6 = {
		.src = pkt_src->sin6_addr,
		.dst = *pkt_dst,
		.ulpl = htons(pktlen),
		.next_hdr = IPPROTO_ICMPV6,
	};

	pkt_csum = icmp6->icmp6_cksum;
	icmp6->icmp6_cksum = 0;
	ref_csum = in_cksum_with_ph6(&ph6, data, pktlen);

	if (pkt_csum != ref_csum) {
		zlog_warn(
			log_pkt_src(
				"(dst %pI6) packet RX checksum failure, expected %04hx, got %04hx"),
			pkt_dst, pkt_csum, ref_csum);
		return;
	}

	data = (icmp6 + 1);
	pktlen -= sizeof(*icmp6);

	switch (icmp6->icmp6_type) {
	case ND_ROUTER_ADVERT:
		rtadv_handle_advert(acif, pkt_src, pkt_dst, data, pktlen);
		break;
	case ND_ROUTER_SOLICIT:
		rtadv_handle_solicit(acif, pkt_src, pkt_dst, data, pktlen);
		break;
	}
}

static void rtadv_vrf_recv(struct event *ev)
{
	struct accessd_vrf *acvrf = EVENT_ARG(ev);
	struct rtadv_vrf *ravrf = acvrf->rtadv_vrf;
	union {
		char buf[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
			 CMSG_SPACE(sizeof(int)) /* hopcount */];
		struct cmsghdr align;
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pktinfo = NULL;
	int *hoplimit = NULL;
	char rxbuf[2048];
	struct msghdr mh[1] = {};
	struct iovec iov[1];
	struct sockaddr_in6 pkt_src[1];
	ssize_t nread;
	size_t pktlen;

	event_add_read(master, rtadv_vrf_recv, acvrf, ravrf->sock,
			&ravrf->t_read);

	iov->iov_base = rxbuf;
	iov->iov_len = sizeof(rxbuf);

	mh->msg_name = pkt_src;
	mh->msg_namelen = sizeof(pkt_src);
	mh->msg_control = cmsgbuf.buf;
	mh->msg_controllen = sizeof(cmsgbuf.buf);
	mh->msg_iov = iov;
	mh->msg_iovlen = array_size(iov);
	mh->msg_flags = 0;

	nread = recvmsg(ravrf->sock, mh, MSG_PEEK | MSG_TRUNC);
	if (nread <= 0) {
		zlog_err("(VRF %s) RX error: %m", acvrf->vrf->name);
		return;
	}

	if ((size_t)nread > sizeof(rxbuf)) {
		iov->iov_base = XMALLOC(MTYPE_RTADV_PACKET, nread);
		iov->iov_len = nread;
	}
	nread = recvmsg(ravrf->sock, mh, 0);
	if (nread <= 0) {
		zlog_err("(VRF %s) RX error: %m", acvrf->vrf->name);
		goto out_free;
	}

	struct interface *ifp;

	ifp = if_lookup_by_index(pkt_src->sin6_scope_id, acvrf->vrf->vrf_id);
	if (!ifp || !ifp->info)
		goto out_free;

	struct accessd_iface *acif = ifp->info;
	struct rtadv_iface *raif = acif ? acif->rtadv : NULL;

	if (!raif)
		goto out_free;

	for (cmsg = CMSG_FIRSTHDR(mh); cmsg; cmsg = CMSG_NXTHDR(mh, cmsg)) {
		if (cmsg->cmsg_level != SOL_IPV6)
			continue;

		switch (cmsg->cmsg_type) {
		case IPV6_PKTINFO:
			pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			break;
		case IPV6_HOPLIMIT:
			hoplimit = (int *)CMSG_DATA(cmsg);
			break;
		}
	}

	if (!pktinfo || !hoplimit) {
		zlog_err(log_ifp("BUG: packet without IPV6_PKTINFO or IPV6_HOPLIMIT"));
		goto out_free;
	}

	if (*hoplimit != 255) {
		zlog_err(log_pkt_src("packet with hop limit != 255"));
		goto out_free;
	}

	if (!IN6_IS_ADDR_LINKLOCAL(&pkt_src->sin6_addr)) {
		zlog_warn(log_pkt_src("packet from invalid source address"));
		goto out_free;
	}

	pktlen = nread;
	if (pktlen < sizeof(struct icmp6_plain_hdr)) {
		zlog_warn(log_pkt_src("truncated packet"));
		goto out_free;
	}

	rtadv_rx_process(acif, pkt_src, &pktinfo->ipi6_addr, iov->iov_base,
			 pktlen);

out_free:
	if (iov->iov_base != rxbuf)
		XFREE(MTYPE_RTADV_PACKET, iov->iov_base);
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

		frr_with_privs (&accessd_privs) {
			struct ipv6_mreq mreq;
			int ret;

			mreq.ipv6mr_multiaddr = all_routers;
			mreq.ipv6mr_interface = acif->ifp->ifindex;
			ret = setsockopt(ravrf->sock, SOL_IPV6,
					 IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
			if (ret)
				zlog_err("(%s) failed to join ff02::2 (all-routers): %m",
					 acif->ifp->name);
		}

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
