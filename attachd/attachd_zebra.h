// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _FRR_ATTACHD_ZEBRA_H
#define _FRR_ATTACHD_ZEBRA_H

#include "lib/hook.h"
#include "lib/prefix.h"

struct connected;
struct zclient;

extern struct zclient *attachd_zclient;

DECLARE_HOOK(attachd_if_addr_add, (struct connected *c), (c));
DECLARE_KOOH(attachd_if_addr_del, (struct connected *c), (c));

extern int if_addr_install(struct interface *ifp, union prefixconstptr pu);
extern int if_addr_uninstall(struct interface *ifp, union prefixconstptr pu);

#endif /* _FRR_ATTACHD_ZEBRA_H */
