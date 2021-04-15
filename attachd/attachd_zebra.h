// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _FRR_ATTACHD_ZEBRA_H
#define _FRR_ATTACHD_ZEBRA_H

#include "lib/hook.h"

struct connected;
struct zclient;

extern struct zclient *attachd_zclient;

DECLARE_HOOK(attachd_if_addr_add, (struct connected *c), (c));
DECLARE_KOOH(attachd_if_addr_del, (struct connected *c), (c));

#endif /* _FRR_ATTACHD_ZEBRA_H */
