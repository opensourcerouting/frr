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

#include "command.h"
#include "if.h"
#include "memory.h"
#include "network.h"
#include "prefix.h"
#include "privs.h"
#include "sockopt.h"
#include "thread.h"
#include "vrf.h"

#include "accessd.h"

#include "dhcp6_protocol.h"

#include "dhcp6_parse.h"
#include "dhcp6_state.h"
#include "dhcp6_zebra.h"
#include "dhcp6_iface.h"
#include "dhcp6_upstream.h"

DEFINE_MTYPE_STATIC(DHCP6, DHCP6_UPSTREAM_GROUP, "DHCPv6 server group");
DEFINE_MTYPE_STATIC(DHCP6, DHCP6_UPSTREAM,       "DHCPv6 server");

DEFINE_QOBJ_TYPE(dhcp6_ugroup);
DEFINE_QOBJ_TYPE(dhcp6_upstream);

DECLARE_DLIST(dhcp6_ust_member, struct dhcp6_ust_member, member);
DECLARE_DLIST(dhcp6_ust_groups, struct dhcp6_ust_member, groups);

static int dhcp6_ugroup_cmp(const struct dhcp6_ugroup *a,
			    const struct dhcp6_ugroup *b)
{
	return strcmp(a->name, b->name);
}

DECLARE_RBTREE_UNIQ(dhcp6_ugroups, struct dhcp6_ugroup, item, dhcp6_ugroup_cmp);

static int dhcp6_upstream_cmp(const struct dhcp6_upstream *a,
			      const struct dhcp6_upstream *b)
{
	return sockunion_cmp((const union sockunion *)&a->addr,
			     (const union sockunion *)&b->addr);
}

DECLARE_RBTREE_UNIQ(dhcp6_upstreams, struct dhcp6_upstream, item,
		    dhcp6_upstream_cmp);

static struct dhcp6_ugroups_head ugroups[1];
static struct dhcp6_upstreams_head upstreams[1];

static void dhcp6_ust_error(struct dhcp6_upstream *us, int err,
			    const char *what)
{
	us->err_count++;
	us->last_err = errno;

	zlog_warn("%pSU: error(%s): %m", &us->addr, what);

	if (us->err_count > 5) {
		zlog_warn("%pSU: marking server as down", &us->addr);
		us->state = DHCP6_USST_ERROR;
	}
}

static void dhcp6_us_rcv(struct thread *t)
{
	struct dhcp6_upstream *us = THREAD_ARG(t);
	struct interface *ifp;
	ssize_t retval;
	size_t size;
	struct msghdr mh[1];
	struct sockaddr_storage from[1];
	struct iovec iov[1];
	struct cmsghdr *cmh;
	uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	struct in6_pktinfo *pktinfo;
	char buf[16384];

	thread_add_read(master, dhcp6_us_rcv, us, us->sock, &us->t_rcv);

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

	retval = recvmsg(us->sock, mh, 0);
	if (us->state == DHCP6_USST_CONNECTING) {
		if (retval >= 0) {
			us->state = DHCP6_USST_OPERATIONAL;
		} else {
			zlog_warn("server %pSU unavailable: %m", &us->addr);
			us->state = DHCP6_USST_ERROR;

			return;
		}
	}

	if (retval < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			return;

		dhcp6_ust_error(us, errno, "recvmsg");
		return;
	} else if (retval == sizeof(buf)) {
		zlog_warn("recvmsg read full buffer size: %zd", retval);
		return;
	} else if (retval == 0) {
		zlog_warn("empty packet or EOF");
		return;
	}
	us->err_count = 0;
	us->state = DHCP6_USST_OPERATIONAL;
	thread_cancel(&us->t_timeout);

	size = retval;
	ifp = if_lookup_by_index(pktinfo->ipi6_ifindex, VRF_DEFAULT);

	struct zbuf zb[1];

	uint8_t msg_type;
	struct dhcp6 *dh6;
	struct dhcp6_relay *dh6r;
	struct dh6p_option relay_msg[1];
	struct dh6p_option relay_if_id[1];
	struct dh6p_optspec opts[] = {
		[DH6OPT_RELAY_MSG] = { .single = relay_msg, },
		[DH6OPT_INTERFACE_ID] = { .single = relay_if_id, },
	};
	const char *perr;

	zbuf_init(zb, buf, size, size);

	msg_type = dhcp6_parse_msg(zb, opts, array_size(opts), NULL, 0, &perr,
				   &dh6, &dh6r);

	if (!msg_type || perr) {
		zlog_debug("%s/relay: %pSU: %dDHMT parser error: %s",
			   ifp->name, from, msg_type, perr);
		return;
	}

	if (msg_type != DH6MSG_RELAY_REPL) {
		zlog_debug("%s/relay: %pSU: ignoring %dDHMT", ifp->name, from,
			   msg_type);
		return;
	}

	zlog_debug("%s/relay: %pSU: %dDHMT, size %zu", ifp->name, from,
		   msg_type, size);

	size_t ifnlen = zbuf_used(relay_if_id->zb);
	char *ifname = strndupa(zbuf_pulln(relay_if_id->zb, ifnlen), ifnlen);
	struct interface *ifp_out = if_lookup_by_name(ifname, VRF_DEFAULT);

	if (!ifp_out || !ifp_out->info) {
		zlog_warn("no OIF");
		return;
	}

	struct dhcp6r_iface *drif = ifp_out->info;
	struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6 };

	struct zbuf tmp = *relay_msg->zb;
	uint8_t inner_type = zbuf_get8(&tmp);
	struct zbuf inner = *relay_msg->zb;

	sin6.sin6_port = htons(546);
	memcpy(&sin6.sin6_addr, &dh6r->dh6relay_peeraddr,
	       sizeof(sin6.sin6_addr));

	if (sin6.sin6_addr.s6_addr32[0] == htonl(0xfe800000)
	    && !sin6.sin6_addr.s6_addr32[1] && !sin6.sin6_addr.s6_addr32[2]
	    && !sin6.sin6_addr.s6_addr32[3]) {
		dhcp6_ra_self_rcv(drif, &inner);
		return;
	}

	if (inner_type == DH6MSG_REPLY)
		dhcp6r_snoop(drif, &sin6, relay_msg->zb);

	iov->iov_base = inner.head;
	iov->iov_len = zbuf_used(&inner);

	memset(mh, 0, sizeof(mh));
	mh->msg_iov = iov;
	mh->msg_iovlen = 1;
	mh->msg_name = (struct sockaddr *)&sin6;
	mh->msg_namelen = sizeof(sin6);

	retval = sendmsg(drif->sock, mh, 0);
	if (retval < 0) {
		zlog_warn("%s: sendmsg to %pSU failed: %m", ifp_out->name,
			  &sin6);
		return;
	}
}

static void dhcp6_ust_timeout(struct thread *t)
{
	struct dhcp6_upstream *us = THREAD_ARG(t);

	dhcp6_ust_error(us, ETIMEDOUT, "timeout");
}

static void dhcp6_ust_expectreply(struct dhcp6_upstream *us)
{
	if (us->t_timeout)
		return;

	thread_add_timer(master, dhcp6_ust_timeout, us, 5, &us->t_timeout);
}

void dhcp6_ugroup_relay(const char *upstream_name, struct dhcp6r_iface *drif,
			struct sockaddr_in6 *from, struct dhcp6 *dh6,
			size_t len)
{
	struct dhcp6_ugroup *ug, ref;
	struct dhcp6_relay rhdr[1];
	struct dhcp6opt relaymsg_hdr[1];
	struct dhcp6opt ifid_hdr[1];
	struct {
		struct dhcp6opt hdr;
		uint16_t duid_type;
		uint8_t duid[128];
	} __attribute__((packed)) relayid[1];
#if 0
	struct {
		struct dhcp6opt hdr;
		uint32_t ifindex;
	} ifid[1];
#endif

	ref.name = (char *)upstream_name;
	ug = dhcp6_ugroups_find(ugroups, &ref);

	if (!ug) {
		zlog_warn("%s: %pSU: cannot relay packet, no server group",
			  drif->ifp->name, from);
		return;
	}
	if (!drif->best_global) {
		zlog_warn("%s: no global address to identify link, ditching",
			  drif->ifp->name);
		return;
	}

	rhdr->dh6relay_msgtype = DH6MSG_RELAY_FORW;
	rhdr->dh6relay_hcnt = 0;
	memcpy(&rhdr->dh6relay_peeraddr, &from->sin6_addr,
	       sizeof(rhdr->dh6relay_peeraddr));
	memcpy(&rhdr->dh6relay_linkaddr, &drif->best_global->address->u.prefix6,
	       sizeof(rhdr->dh6relay_linkaddr));

	if (dh6->dh6_msgtype == DH6MSG_RELAY_FORW) {
		struct dhcp6_relay *dh6relay0 = (struct dhcp6_relay *)dh6;

		/* Relaying a Message from a Relay Agent */

		/*
		 * If the hop-count in the message is greater than or equal to
		 * HOP_COUNT_LIMIT, the relay agent discards the received
		 * message.
		 * [RFC3315 Section 20.1.2]
		 */
		if (dh6relay0->dh6relay_hcnt >= DHCP6_RELAY_HOP_COUNT_LIMIT) {
			zlog_warn("too many relay forwardings");
			return;
		}

		rhdr->dh6relay_hcnt = dh6relay0->dh6relay_hcnt + 1;

		/*
		 * We can keep the link-address field 0, regardless of the
		 * scope of the source address, since we always include
		 * interface-ID option.
		 */
	}

	relaymsg_hdr->dh6opt_type = htons(DH6OPT_RELAY_MSG);
	relaymsg_hdr->dh6opt_len = htons(len);

	ifid_hdr->dh6opt_type = htons(DH6OPT_INTERFACE_ID);
	ifid_hdr->dh6opt_len = htons(strlen(drif->ifp->name));
#if 0
	ifid->hdr.dh6opt_type = htons(DH6OPT_INTERFACE_ID);
	ifid->hdr.dh6opt_len = htons(sizeof(ifid->ifindex));
	ifid->ifindex = htonl(drif->ifp->ifindex);
#endif

	uint32_t val;

	relayid->hdr.dh6opt_type = htons(DH6OPT_RELAY_ID);
	relayid->hdr.dh6opt_len = htons(10);
	relayid->duid_type = htons(DUIDT_EN);
	val = htonl(50145);
	memcpy(relayid->duid + 0, &val, sizeof(val));
	val = htonl(12345678);
	memcpy(relayid->duid + 4, &val, sizeof(val));

	ssize_t retval;
	struct msghdr mh[1];
	struct iovec iov[6], *iovp = iov;

	iovp->iov_base = rhdr;
	iovp->iov_len = sizeof(rhdr);
	iovp++;
	iovp->iov_base = relaymsg_hdr;
	iovp->iov_len = sizeof(relaymsg_hdr);
	iovp++;
	iovp->iov_base = dh6;
	iovp->iov_len = len;
	iovp++;
	iovp->iov_base = ifid_hdr;
	iovp->iov_len = sizeof(ifid_hdr);
	iovp++;
	iovp->iov_base = drif->ifp->name;
	iovp->iov_len = strlen(drif->ifp->name);
	iovp++;
	iovp->iov_base = relayid;
	iovp->iov_len = sizeof(relayid->hdr) + 10;
	iovp++;

	memset(mh, 0, sizeof(mh));
	mh->msg_iov = iov;
	mh->msg_iovlen = iovp - iov;

	struct dhcp6_upstream *fallback = NULL;
	struct dhcp6_ust_member *umemb;

	frr_each (dhcp6_ust_member, ug->members, umemb) {
		struct dhcp6_upstream *us = umemb->us;

		zlog_debug("try server %pSU state %u", &us->addr, us->state);
		if (us->state == DHCP6_USST_ERROR) {
			if (!fallback
			    || ((us->retry_place - fallback->retry_place)
				>= 0x80000000))
				fallback = us;
		}
		if (us->state != DHCP6_USST_OPERATIONAL)
			continue;

		mh->msg_name = (struct sockaddr *)&us->addr;
		mh->msg_namelen = sizeof(us->addr);

		retval = sendmsg(us->sock, mh, 0);
		if (retval > 0) {
			zlog_debug("%s: %pSU: relayed to %pSU", drif->ifp->name,
				   from, &us->addr);

			dhcp6_ust_expectreply(us);
			return;
		}

		dhcp6_ust_error(us, errno, "sendmsg");
	}

	if (!fallback) {
		zlog_warn("%s: no server available", ug->name);
		return;
	}
	fallback->retry_place += dhcp6_ust_member_count(ug->members);

	zlog_warn("%s: retrying failed server %pSU", ug->name, &fallback->addr);

	mh->msg_name = (struct sockaddr *)&fallback->addr;
	mh->msg_namelen = sizeof(fallback->addr);

	retval = sendmsg(fallback->sock, mh, 0);

	if (retval < 0) {
		zlog_warn("sendmsg to %pSU failed: %m", &fallback->addr);
		return;
	}
}


static void dhcp6_ust_start(struct dhcp6_upstream *us)
{
	if (us->sock != -1)
		close(us->sock);
	thread_cancel(&us->t_rcv);

	us->sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (us->sock < 0) {
		zlog_err("socket(): %m");
		return;
	}

	set_nonblocking(us->sock);
	sockopt_reuseport(us->sock);
	sockopt_v6only(AF_INET6, us->sock);
	setsockopt_ipv6_pktinfo(us->sock, 1);
	setsockopt_ipv6_multicast_hops(us->sock, 1);
	setsockopt_ipv6_multicast_loop(us->sock, 0);

	struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6 };
	int rv;

	sin6.sin6_port = htons(547); //htons(546);

	frr_with_privs (&accessd_privs) {
		setsockopt_ipv6_tclass(us->sock, IPTOS_PREC_INTERNETCONTROL);

		rv = bind(us->sock, (struct sockaddr *)&sin6, sizeof(sin6));
	}

	if (rv) {
		zlog_err("bind(): %m");

		close(us->sock);
		us->sock = -1;
		return;
	}

	rv = connect(us->sock, (struct sockaddr *)&us->addr, sizeof(us->addr));
	if (rv && errno != EINPROGRESS) {
		zlog_err("connect(): %m");

		close(us->sock);
		us->sock = -1;
		return;
	}

	us->state = rv ? DHCP6_USST_CONNECTING : DHCP6_USST_OPERATIONAL;
	thread_add_read(master, dhcp6_us_rcv, us, us->sock, &us->t_rcv);
}

static void dhcp6_server_lq_start(struct dhcp6_upstream *us);

static void dhcp6_lq_connect(struct thread *t)
{
	struct dhcp6_upstream *us = THREAD_ARG(t);

	dhcp6_server_lq_start(us);
}

static void dhcp6_lq_error(struct dhcp6_upstream *us)
{
	close(us->lq_sock);
	us->lq_sock = -1;

	if (us->lq_state == DHCP6_LQ_DISABLED)
		return;

	us->lq_state = DHCP6_LQ_INIT;
	thread_add_timer(master, dhcp6_lq_connect, us, 60, &us->t_lq_rcv);
}

static void dhcp6_lq_rcv(struct thread *t)
{
	struct dhcp6_upstream *us = THREAD_ARG(t);
	ssize_t retval;
	char buf[16384];

	retval = read(us->lq_sock, buf, sizeof(buf));

	if (retval <= 0) {
		zlog_warn("%pSUp: leasequery socket error: %m", &us->addr);
		dhcp6_lq_error(us);
		return;
	}

	thread_add_read(master, dhcp6_lq_rcv, us, us->lq_sock, &us->t_lq_rcv);
}

static void dhcp6_lq_snd(struct thread *t)
{
	struct dhcp6_upstream *us = THREAD_ARG(t);

	if (us->lq_state == DHCP6_LQ_CONNECTING) {
		int status = 0;
		int ret;

		socklen_t size = sizeof(status);

		ret = getsockopt(us->lq_sock, SOL_SOCKET, SO_ERROR, &status,
				 &size);

		if (ret) {
			zlog_warn("%pSUp: getopt failed: %m", &us->addr);
			dhcp6_lq_error(us);
			return;
		}

		if (status) {
			errno = status;
			zlog_warn("%pSUp: connection failed: %m", &us->addr);
			dhcp6_lq_error(us);
			return;
		}

		zlog_info("%pSUp: connected.", &us->addr);
		us->lq_state = DHCP6_LQ_IDLE;

		thread_add_read(master, dhcp6_lq_rcv, us, us->lq_sock,
				&us->t_lq_rcv);
		return;
	}
}

static void dhcp6_server_lq_start(struct dhcp6_upstream *us)
{
	int rv;

	if (us->lq_sock != -1)
		close(us->lq_sock);
	thread_cancel(&us->t_lq_rcv);
	thread_cancel(&us->t_lq_snd);

	us->lq_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (us->lq_sock < 0) {
		zlog_err("socket(): %m");
		return;
	}

	set_nonblocking(us->lq_sock);
	sockopt_v6only(AF_INET6, us->lq_sock);

	frr_with_privs (&accessd_privs) {
		setsockopt_ipv6_tclass(us->lq_sock, IPTOS_PREC_INTERNETCONTROL);
	}

	rv = connect(us->lq_sock, (struct sockaddr *)&us->addr,
		     sizeof(us->addr));
	if (rv && errno != EINPROGRESS) {
		zlog_err("leasequery connect(): %m");

		dhcp6_lq_error(us);
		return;
	}

	if (rv && errno == EINPROGRESS) {
		us->lq_state = DHCP6_LQ_CONNECTING;
		thread_add_write(master, dhcp6_lq_snd, us, us->lq_sock,
				 &us->t_lq_snd);
	} else {
		us->lq_state = DHCP6_LQ_IDLE;
		thread_add_read(master, dhcp6_lq_rcv, us, us->lq_sock,
				&us->t_lq_rcv);
	}
}

static void dhcp6_server_lq_poke(struct dhcp6_upstream *us)
{
	if (us->lq_state == DHCP6_LQ_DISABLED) {
		if (us->lq_sock != -1)
			close(us->lq_sock);

		us->lq_sock = -1;
		thread_cancel(&us->t_lq_snd);
		thread_cancel(&us->t_lq_rcv);
		return;
	}

	if (us->lq_state <= DHCP6_LQ_CONNECTING) {
		dhcp6_server_lq_start(us);
		return;
	}
}

/* CLI */

#ifndef VTYSH_EXTRACT_PL
#include "dhcp6_upstream_clippy.c"
#endif

static int dhcp6_up_config_write(struct vty *vty);

static struct cmd_node upstream_node = {
	.name = "dhcp6-upstream-server",
	.node = DHCP6_SERVER_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-dhcp6-server)# ",
};

static struct cmd_node ugroup_node = {
	.name = "dhcp6-upstream-server-group",
	.node = DHCP6_SERVER_GROUP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-dhcp6-server-group)# ",
	.config_write = dhcp6_up_config_write,
};

#define DHCP_STR "Dynamic Host Configuration Protocol\n"

DEFPY (dhcp6_server,
       dhcp6_server_cmd,
       "[no] ipv6 dhcp server X:X::X:X",
       NO_STR
       IPV6_STR
       DHCP_STR
       "Configure a DHCPv6 server\n"
       "DHCPv6 server address\n")
{
	struct dhcp6_upstream *us, ref;

	ref.addr.sin6_family = AF_INET6;
	ref.addr.sin6_port = htons(547);
	ref.addr.sin6_addr = server;

	us = dhcp6_upstreams_find(upstreams, &ref);

	if (no) {
		return CMD_SUCCESS;
	}
	if (!us) {
		us = XCALLOC(MTYPE_DHCP6_UPSTREAM, sizeof(*us));
		us->sock = -1;
		us->lq_sock = -1;
		us->addr.sin6_family = AF_INET6;
		us->addr.sin6_port = htons(547);
		us->addr.sin6_addr = server;
		dhcp6_ust_groups_init(us->groups);

		dhcp6_upstreams_add(upstreams, us);
		QOBJ_REG(us, dhcp6_upstream);
		dhcp6_ust_start(us);
	}

	VTY_PUSH_CONTEXT(DHCP6_SERVER_NODE, us);
	return CMD_SUCCESS;
}

DEFPY (dhcp6_server_lq,
       dhcp6_server_lq_cmd,
       "[no] dhcp leasequery",
       NO_STR
       DHCP_STR
       "Enable leasequery\n")
{
	VTY_DECLVAR_CONTEXT(dhcp6_upstream, us);

	us->lq_state = no ? DHCP6_LQ_DISABLED : DHCP6_LQ_INIT;
	dhcp6_server_lq_poke(us);

	return CMD_SUCCESS;
}


DEFPY (dhcp6_server_group,
       dhcp6_server_group_cmd,
       "[no] ipv6 dhcp server-group WORD",
       NO_STR
       IPV6_STR
       DHCP_STR
       "Create a DHCPv6 server group\n"
       "Name for the DHCPv6 server group\n")
{
	struct dhcp6_ugroup *ug, ref;

	ref.name = (char *)server_group;

	ug = dhcp6_ugroups_find(ugroups, &ref);
	if (!ug) {
		ug = XCALLOC(MTYPE_DHCP6_UPSTREAM_GROUP, sizeof(*ug));
		ug->name = XSTRDUP(MTYPE_TMP, server_group);
		dhcp6_ust_member_init(ug->members);

		QOBJ_REG(ug, dhcp6_ugroup);
		dhcp6_ugroups_add(ugroups, ug);
	}

	VTY_PUSH_CONTEXT(DHCP6_SERVER_GROUP_NODE, ug);
	return CMD_SUCCESS;
}

DEFPY (dhcp6_sg_server,
       dhcp6_sg_server_cmd,
       "[no] server X:X::X:X",
       NO_STR
       "Add a server\n"
       "Server address\n")
{
	VTY_DECLVAR_CONTEXT(dhcp6_ugroup, ug);

	struct dhcp6_ust_member *umemb;

	frr_each(dhcp6_ust_member, ug->members, umemb) {
		if (IPV6_ADDR_SAME(&server, &umemb->us->addr.sin6_addr))
			break;
	}

	if (!umemb) {
		struct dhcp6_upstream *us, ref;

		ref.addr.sin6_family = AF_INET6;
		ref.addr.sin6_port = htons(547);
		ref.addr.sin6_addr = server;

		us = dhcp6_upstreams_find(upstreams, &ref);
		if (!us) {
			us = XCALLOC(MTYPE_DHCP6_UPSTREAM, sizeof(*us));
			us->sock = -1;
			us->lq_sock = -1;
			us->addr.sin6_family = AF_INET6;
			us->addr.sin6_port = htons(547);
			us->addr.sin6_addr = server;
			dhcp6_ust_groups_init(us->groups);

			dhcp6_upstreams_add(upstreams, us);
			QOBJ_REG(us, dhcp6_upstream);
			dhcp6_ust_start(us);
		}

		umemb = XCALLOC(MTYPE_DHCP6_UPSTREAM, sizeof(*umemb));
		umemb->ug = ug;
		umemb->us = us;

		dhcp6_ust_member_add_tail(ug->members, umemb);
		dhcp6_ust_groups_add_tail(us->groups, umemb);
	}

	return CMD_SUCCESS;
}

static void dhcp6_show_server_one(struct vty *vty, struct dhcp6_upstream *us)
{
	vty_out(vty, "DHCPv6 server %pSUp:\n", &us->addr);

	switch (us->state) {
	case DHCP6_USST_UNDEF:
		vty_out(vty, "  state: initializing\n");
		break;
	case DHCP6_USST_CONNECTING:
		vty_out(vty, "  state: connecting\n");
		break;
	case DHCP6_USST_OPERATIONAL:
		vty_out(vty, "  state: operational\n");
		break;
	case DHCP6_USST_ERROR:
		vty_out(vty, "  state: failed\n");
		vty_out(vty, "  last error: %s\n", safe_strerror(us->last_err));
		break;
	}

	vty_out(vty, "  %u errors\n", us->err_count);
	vty_out(vty, "\n");

}

DEFPY (dhcp6_show_server,
       dhcp6_show_server_cmd,
       "show ipv6 dhcp server [X:X::X:X]",
       SHOW_STR
       IPV6_STR
       DHCP_STR
       "DHCPv6 servers\n"
       "Server address\n")
{
	struct dhcp6_upstream *us;

	if (server_str) {
		struct dhcp6_upstream ref;

		ref.addr.sin6_family = AF_INET6;
		ref.addr.sin6_port = htons(547);
		ref.addr.sin6_addr = server;

		us = dhcp6_upstreams_find(upstreams, &ref);
		if (!us) {
			vty_out(vty, "%% No DHCPv6 server with address %pI6\n",
				&server);
			return CMD_WARNING;
		}

		dhcp6_show_server_one(vty, us);
		return CMD_SUCCESS;
	}

	frr_each (dhcp6_upstreams, upstreams, us)
		dhcp6_show_server_one(vty, us);
	return CMD_SUCCESS;
}

static int dhcp6_up_config_write(struct vty *vty)
{
	int ctr = 0;
	struct dhcp6_ugroup *ug;
	struct dhcp6_upstream *us;
	struct dhcp6_ust_member *umemb;

	frr_each (dhcp6_upstreams, upstreams, us) {
		vty_out(vty, "ipv6 dhcp server %pI6\n", &us->addr.sin6_addr);
		vty_out(vty, "!\n");
		ctr++;
	}

	frr_each (dhcp6_ugroups, ugroups, ug) {
		vty_out(vty, "ipv6 dhcp server-group %s\n", ug->name);

		frr_each(dhcp6_ust_member, ug->members, umemb) {
			vty_out(vty, " server %pI6\n",
				&umemb->us->addr.sin6_addr);
		}
		vty_out(vty, "!\n");
		ctr++;
	}

	return ctr;
}

void dhcp6_upstream_init(void)
{
	dhcp6_ugroups_init(ugroups);
	dhcp6_upstreams_init(upstreams);

	install_node(&upstream_node);
	install_default(DHCP6_SERVER_NODE);
	install_element(CONFIG_NODE, &dhcp6_server_cmd);

	install_element(DHCP6_SERVER_NODE, &dhcp6_server_lq_cmd);

	install_node(&ugroup_node);
	install_default(DHCP6_SERVER_GROUP_NODE);
	install_element(CONFIG_NODE, &dhcp6_server_group_cmd);

	install_element(DHCP6_SERVER_GROUP_NODE, &dhcp6_sg_server_cmd);

	install_element(VIEW_NODE, &dhcp6_show_server_cmd);
}
