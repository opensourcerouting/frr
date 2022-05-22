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

#ifndef _FRR_ACCESSD_ZEBRA_H
#define _FRR_ACCESSD_ZEBRA_H

#include "lib/hook.h"
#include "lib/prefix.h"

struct connected;
struct zclient;

extern struct zclient *zclient;

DECLARE_HOOK(accessd_if_addr_add, (struct connected *c), (c));
DECLARE_KOOH(accessd_if_addr_del, (struct connected *c), (c));

extern int if_addr_install(struct interface *ifp, union prefixconstptr pu);
extern int if_addr_uninstall(struct interface *ifp, union prefixconstptr pu);

#endif /* _FRR_DHCP6_ZEBRA_H */
