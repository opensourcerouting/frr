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

#include "accessd_iface.h"

#include "accessd.h"

#include "lib/command.h"
#include "lib/if.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/prefix.h"
#include "lib/sockopt.h"
#include "lib/thread.h"
#include "lib/vrf.h"

DEFINE_MTYPE_STATIC(ACCESSD, ACCESSD_IF, "accessd interface information");

static int accessd_if_new_hook(struct interface *ifp)
{
	struct accessd_iface *acif;

	acif = XCALLOC(MTYPE_ACCESSD_IF, sizeof(*acif));
	acif->ifp = ifp;

	ifp->info = acif;
	return 0;
}

static int accessd_if_del_hook(struct interface *ifp)
{
	XFREE(MTYPE_ACCESSD_IF, ifp->info);
	return 0;
}

/* ZAPI callbacks */

static int accessd_ifp_create(struct interface *ifp)
{
	return 0;
}

static int accessd_ifp_destroy(struct interface *ifp)
{
	return 0;
}

static int accessd_ifp_up(struct interface *ifp)
{
	return 0;
}

static int accessd_ifp_down(struct interface *ifp)
{
	return 0;
}

static int accessd_if_config_write(struct vty *vty)
{
	return 0;
}

void accessd_if_init(void)
{
	hook_register_prio(if_add, 0, accessd_if_new_hook);
	hook_register_prio(if_del, 0, accessd_if_del_hook);

	if_cmd_init(accessd_if_config_write);

	if_zapi_callbacks(accessd_ifp_create, accessd_ifp_up,
			  accessd_ifp_down, accessd_ifp_destroy);
}
