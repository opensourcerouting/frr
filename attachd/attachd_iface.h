// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _FRR_ATTACHD_IFACE_H
#define _FRR_ATTACHD_IFACE_H

#include "lib/hook.h"

struct interface;
struct rtadv_iface;

struct attachd_iface {
	struct interface *ifp;

	struct rtadv_iface *rtadv;
};

#endif /* _FRR_ATTACHD_IFACE_H */
