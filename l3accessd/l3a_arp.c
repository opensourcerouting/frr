#include "lib/zebra.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_vlan.h>
#include <linux/bpf.h>

#include <libmnl/libmnl.h>

#include "lib/typesafe.h"
#include "lib/jhash.h"
#include "lib/printfrr.h"
#include "lib/log.h"
#include "lib/privs.h"
#include "lib/thread.h"
#include "lib/network.h"
#include "lib/table.h"
#include "lib/prefix.h"
#include "lib/nexthop.h"
#include "lib/vty.h"

#include "l3a.h"

/* 'arp' */
static struct sock_filter arpfilter[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 1, 0x00000806 },
	{ 0x06, 0, 0, 0x00040000 },
	{ 0x06, 0, 0, 0x00000000 },
};

#if 0
static struct sock_fprog arpbpf = {
	.len = array_size(arpfilter),
	.filter = arpfilter,
};
#endif

extern struct zebra_privs_t l3a_privs;
extern struct thread_master *master;

static int l3a_arp_read(struct thread *t)
{
	struct l3a_if *l3a_if = THREAD_ARG(t);
	struct sockaddr_ll sll;
	socklen_t slen = sizeof(sll);
	uint8_t buf[65536], *bp, *end;
	ssize_t nread;

	thread_add_read(master, l3a_arp_read, l3a_if, l3a_if->arp_fd,
			&l3a_if->arp_thread);

	nread = recvfrom(l3a_if->arp_fd, buf, sizeof(buf), 0,
			 (struct sockaddr *)&sll, &slen);
	if (nread <= 0) {
		zlog_warn("read from %s failed (%zd): %m",
			  l3a_if->ifp->name, nread);
		return 0;
	}
	end = buf + nread;
	bp = buf;

	if (nread < 14 || bp[12] != 0x08 || bp[13] != 0x06) {
		zlog_info("non-ARP packet (%zd) on %s",
			  nread, l3a_if->ifp->name);
		return 0;
	}
	bp += 14;

	zlog_info("ARP packet (%zd) on %s", nread, l3a_if->ifp->name);

	return 0;

out_truncated:
	zlog_warn("DHCPv6 packet (%zd bytes) on %s is truncated",
		  nread, l3a_if->ifp->name);
	return 0;
}

static int arp_tc_filter(int ifindex, int fd)
{
	struct mnl_socket *nls;
	int prio = 0xe000;
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
	tch->tcm_info = TC_H_MAKE(prio<<16, htons(ETH_P_ALL));
	tch->tcm_ifindex = ifindex;

#if 0
	mnl_attr_put_strz(nlh, TCA_KIND, "basic");
	nest1 = mnl_attr_nest_start(nlh, TCA_OPTIONS);
	nest2 = mnl_attr_nest_start(nlh, TCA_BASIC_ACT);
#else
	mnl_attr_put_strz(nlh, TCA_KIND, "bpf");
	nest1 = mnl_attr_nest_start(nlh, TCA_OPTIONS);

	mnl_attr_put_u16(nlh, TCA_BPF_OPS_LEN, array_size(arpfilter));
	mnl_attr_put(nlh, TCA_BPF_OPS, sizeof(arpfilter), arpfilter);

	nest2 = mnl_attr_nest_start(nlh, TCA_BPF_ACT);
#endif
	nest3 = mnl_attr_nest_start(nlh, 1 /* prio */);
	mnl_attr_put_strz(nlh, TCA_ACT_KIND, "mirred");
	nest4 = mnl_attr_nest_start(nlh, TCA_ACT_OPTIONS);

	struct tc_mirred sel = {};
	sel.action = TC_ACT_PIPE;
	sel.eaction = TCA_INGRESS_REDIR;
	mnl_attr_put(nlh, TCA_MIRRED_PARMS, sizeof(sel), &sel);
	mnl_attr_put_u32(nlh, TCA_MIRRED_SOCK_FD, fd);

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

void l3a_arp_snoop(struct l3a_if *l3a_if)
{
	int fd;

	if (l3a_if->ifp->ifindex == IFINDEX_INTERNAL) {
		zlog_warn("cannot snoop %s - does not exist", l3a_if->ifp->name);
		return;
	}
	if (l3a_if->arp_fd != -1) {
		zlog_warn("already snooping %s", l3a_if->ifp->name);
		return;
	}

	frr_elevate_privs (&l3a_privs) {
		struct sockaddr_ll sll;

		fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
		if (fd < 0) {
			zlog_warn("socket(PF_PACKET) failed: %m");
			return;
		}

		memset(&sll, 0, sizeof(sll));
		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_LOOP);
		sll.sll_ifindex = 1; /* hak hak */

		if (bind(fd, (struct sockaddr *)(&sll), sizeof(sll))) {
			zlog_warn("bind(PF_PACKET) failed: %m");
			close(fd);
			return;
		}

		if (arp_tc_filter(l3a_if->ifp->ifindex, fd)) {
			zlog_warn("tc_setup failed");
			close(fd);
			return;
		}
	}
	set_nonblocking(fd);

	l3a_if->arp_fd = fd;

	thread_add_read(master, l3a_arp_read, l3a_if, fd,
			&l3a_if->arp_thread);
	zlog_info("iface %s arpfd %d", l3a_if->ifp->name, fd);
}
