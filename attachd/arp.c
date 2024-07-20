#include "lib/zebra.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/tc_act/tc_punt.h>

#include <libmnl/libmnl.h>

#include "lib/typesafe.h"
#include "lib/jhash.h"
#include "lib/printfrr.h"
#include "lib/log.h"
#include "lib/privs.h"
#include "lib/frrevent.h"
#include "lib/network.h"
#include "lib/table.h"
#include "lib/prefix.h"
#include "lib/nexthop.h"
#include "lib/vty.h"
#include "lib/command.h"

#include "attachd.h"
#include "attachd_iface.h"

#define SOCK_PUNT 11

static void arp_read(struct event *ev)
{
	struct attachd_iface *acif = EVENT_ARG(ev);
	struct sockaddr_punt spunt;
	socklen_t slen = sizeof(spunt);
	uint8_t buf[65536], *bp, *end;
	ssize_t nread;
	int ret;

	event_add_read(master, arp_read, acif, acif->arp_fd, &acif->ev_arp);

	nread = recvfrom(acif->arp_fd, buf, sizeof(buf), 0,
			 (struct sockaddr *)&spunt, &slen);
	if (nread <= 0) {
		zlog_warn("read from %s failed (%zd): %m",
			  acif->ifp->name, nread);
		return;
	}
	end = buf + nread;
	bp = buf;

	if (nread < 14 || bp[12] != 0x08 || bp[13] != 0x06) {
		zlog_info("non-ARP packet (%zd) on %s",
			  nread, acif->ifp->name);
		return;
	}

	struct ether_header *ehdr = (struct ether_header *)bp;
	bp += sizeof(*ehdr);

	if (end - bp < (ssize_t)sizeof(struct arphdr)) {
		zlog_info("truncated ARP packet");
		return;
	}

	struct arphdr *ahdr = (struct arphdr *)bp;
	bp += sizeof(*ahdr);

	if (ahdr->ar_hln != 6 || ahdr->ar_pln != 4) {
		zlog_info("invalid ARP packet");
		return;
	}

	struct ethaddr *e_src = (struct ethaddr *)bp;
	struct ethaddr *e_dst = (struct ethaddr *)(bp + 10);
	struct in_addr *ip_src = (struct in_addr *)(bp + 6);
	struct in_addr *ip_dst = (struct in_addr *)(bp + 16);

	switch (ntohs(ahdr->ar_op)) {
	case ARPOP_REQUEST:
		zlog_info("ARP request %pI4(%pEA) -> %pI4(%pEA) on %s",
			  ip_src, e_src, ip_dst, e_dst, acif->ifp->name);
		break;
	case ARPOP_REPLY:
		zlog_info("ARP reply %pI4(%pEA) -> %pI4(%pEA) on %s",
			  ip_src, e_src, ip_dst, e_dst, acif->ifp->name);
		break;
	default:
		zlog_info("ARP unknown %04x (%zd) on %s",
			  ntohs(ahdr->ar_op), nread, acif->ifp->name);
		return;
	}

	struct sockaddr_ll sll;

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ARP);
	sll.sll_ifindex = acif->ifp->ifindex;
	sll.sll_hatype = ARPHRD_ETHER;
	sll.sll_pkttype = PACKET_RXINJECT;
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, buf, 6);

	ret = sendto(acif->arp_fd, buf, end - buf, 0, (struct sockaddr *)&sll,
		     sizeof(sll));
	if (ret <= 0)
		zlog_warn("sendto(arp): %m");
}

static inline struct nlattr *mnl_attr_nest_compat(struct nlmsghdr *nlh, uint16_t type)
{
	struct nlattr *start = mnl_nlmsg_get_payload_tail(nlh);

	/* set start->nla_len in mnl_attr_nest_end() */
	start->nla_type = type;
	nlh->nlmsg_len += MNL_ALIGN(sizeof(struct nlattr));

	return start;
}

static int arp_tc_filter(int ifindex)
{
	struct mnl_socket *nls;
	int prio = 100;
	char buf[4096];

	struct nlmsghdr *nlh;
	struct tcmsg *tch;
	struct nlattr *nest1, *nest2, *nest3, *nest4;

	nls = mnl_socket_open(NETLINK_ROUTE);
	if (!nls)
		return -1;
	if (mnl_socket_bind(nls, 0, 0)) {
		mnl_socket_close(nls);
		return -1;
	}

	memset(buf, 0, sizeof(buf));

	nlh = mnl_nlmsg_put_header(buf);
	tch = mnl_nlmsg_put_extra_header(nlh, sizeof(*tch));

	nlh->nlmsg_seq = 1;
	nlh->nlmsg_pid = getpid();
	//nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	nlh->nlmsg_type = RTM_NEWTFILTER;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;

	tch->tcm_family = AF_UNSPEC;
	tch->tcm_parent = 0xffff0000; //TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
	tch->tcm_info = TC_H_MAKE(prio<<16, htons(ETH_P_ARP));
	tch->tcm_ifindex = ifindex;

	mnl_attr_put_strz(nlh, TCA_KIND, "matchall");
	nest1 = mnl_attr_nest_compat(nlh, TCA_OPTIONS);
	nest2 = mnl_attr_nest_compat(nlh, TCA_BASIC_EMATCHES);

	nest3 = mnl_attr_nest_compat(nlh, 1 /* prio */);
	mnl_attr_put_strz(nlh, TCA_ACT_KIND, "punt");
	nest4 = mnl_attr_nest_start(nlh, TCA_ACT_OPTIONS);

	struct tc_punt sel = {};

	sel.action = TC_ACT_PIPE;
	sel.index = 100;
	sel.allow_steal = 1;
	mnl_attr_put(nlh, TCA_PUNT_PARMS, sizeof(sel), &sel);

	mnl_attr_nest_end(nlh, nest4);
	mnl_attr_nest_end(nlh, nest3);
	mnl_attr_nest_end(nlh, nest2);
	mnl_attr_nest_end(nlh, nest1);

	size_t len = mnl_nlmsg_size(mnl_nlmsg_get_payload_len(nlh));
	ssize_t ret;
	ret = mnl_socket_sendto(nls, buf, len);
	if (ret <= 0) {
		zlog_warn("NL sendto failed: %zd %m", ret);
		mnl_socket_close(nls);
		return -1;
	}

	ret = mnl_socket_recvfrom(nls, buf, sizeof(buf));
	if (ret <= 0) {
		zlog_warn("NL recvfrom failed: %zd %m", ret);
		mnl_socket_close(nls);
		return -1;
	}
	nlh = (struct nlmsghdr *)buf;

	if (nlh->nlmsg_type != NLMSG_ERROR) {
		zlog_warn("NL non-error response??");
		mnl_socket_close(nls);
		return -1;
	}
	struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
	if (err->error != 0) {
		zlog_warn("tc error: %s (%d)", strerror(-err->error), -err->error);
		mnl_socket_close(nls);
		return -1;
	}

	mnl_socket_close(nls);
	return 0;
}

void arp_snoop(struct attachd_iface *acif)
{
	int fd;

	if (acif->ifp->ifindex == IFINDEX_INTERNAL) {
		zlog_warn("cannot snoop %s - does not exist", acif->ifp->name);
		return;
	}
	if (acif->arp_fd != -1) {
		zlog_warn("already snooping %s", acif->ifp->name);
		return;
	}

	frr_with_privs (&attachd_privs) {
		int one = 1;
		struct sockaddr_punt spunt;

		fd = socket(PF_PACKET, SOCK_PUNT, htons(ETH_P_ARP));
		if (fd < 0) {
			zlog_warn("socket(PF_PACKET, SOCK_PUNT) failed: %m");
			return;
		}

		if (setsockopt(fd, SOL_PACKET, PACKET_PUNT_CONSUME, &one,
			       sizeof(one)))
			zlog_warn("failed to set PUNT_CONSUME: %m");

		memset(&spunt, 0, sizeof(spunt));
		spunt.spunt_family = AF_PACKET;
		spunt.spunt_protocol = htons(ETH_P_ALL);
		spunt.spunt_ifindex = acif->ifp->ifindex;
		spunt.spunt_hatype = ARPHRD_VOID;
		spunt.spunt_halen = 8;
		memcpy(spunt.spunt_location, "tca_punt", 8);

		if (bind(fd, (struct sockaddr *)(&spunt),
			 offsetof(struct sockaddr_punt, spunt_location) + 8)) {
			zlog_warn("bind(PF_PACKET) failed: %m");
			close(fd);
			return;
		}

		if (arp_tc_filter(acif->ifp->ifindex)) {
			zlog_warn("tc_setup failed");
			close(fd);
			return;
		}
	}
	set_nonblocking(fd);

	acif->arp_fd = fd;

	event_add_read(master, arp_read, acif, fd,
			&acif->ev_arp);
	zlog_info("iface %s arpfd %d", acif->ifp->name, fd);
}

#include "arp_clippy.c"

DEFPY (arp_snoop_cli,
       arp_snoop_cmd,
       "arp snoop",
       "ARP\n"
       "snooping\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct attachd_iface *acif = ifp->info;

	assert(acif);
	arp_snoop(acif);
	return CMD_SUCCESS;
}

void arp_snoop_init(void)
{
	install_element(INTERFACE_NODE, &arp_snoop_cmd);
}
