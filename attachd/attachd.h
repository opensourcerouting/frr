// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _FRR_ATTACHD_H
#define _FRR_ATTACHD_H

#include "lib/memory.h"
#include "lib/privs.h"

DECLARE_MGROUP(ATTACHD);

struct event_loop;

extern struct event_loop *master;
extern struct zebra_privs_t attachd_privs;

#endif /* _FRR_ATTACHD_H */
