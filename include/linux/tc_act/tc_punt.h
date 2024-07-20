/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_TC_PUNT_H
#define __LINUX_TC_PUNT_H

#include <linux/types.h>
#include <linux/pkt_cls.h>

struct tc_punt {
	tc_gen;

	/* if 1, standard tc action only happens when skb_punt() says noone
	 *       took the packet
	 * if 0, skb_punt() decision is ignored and standard tc action always
	 *       happens
	 */
	int allow_steal;
};

enum {
	TCA_PUNT_UNSPEC,
	TCA_PUNT_TM,
	TCA_PUNT_PARMS,
	TCA_PUNT_PAD,
	__TCA_PUNT_MAX
};
#define TCA_PUNT_MAX (__TCA_PUNT_MAX - 1)

/* extra info in struct sockaddr_punt */
struct tcf_punt_info {
	__u32 index;
};

#endif
