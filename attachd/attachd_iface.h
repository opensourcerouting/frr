// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _FRR_ATTACHD_IFACE_H
#define _FRR_ATTACHD_IFACE_H

#include "lib/hook.h"

struct interface;
struct rtadv_iface;
struct dhcp6r_iface;
struct vty;

struct attachd_iface {
	struct interface *ifp;

	struct dhcp6r_iface *dhcp6r;
	struct rtadv_iface *rtadv;

	int arp_fd;
	struct event *ev_arp;
};

extern int dhcp6r_if_config_write(struct vty *vty);
extern void arp_snoop(struct attachd_iface *acif);
extern void arp_snoop_init(void);

#endif /* _FRR_ATTACHD_IFACE_H */
