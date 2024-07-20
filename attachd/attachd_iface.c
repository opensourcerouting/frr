// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>

#include "attachd_iface.h"

#include "attachd.h"

#include "lib/command.h"
#include "lib/if.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/prefix.h"
#include "lib/sockopt.h"
#include "lib/frrevent.h"
#include "lib/vrf.h"

DEFINE_MTYPE_STATIC(ATTACHD, ATTACHD_IF, "attachd interface information");

static int attachd_if_new_hook(struct interface *ifp)
{
	struct attachd_iface *acif;

	acif = XCALLOC(MTYPE_ATTACHD_IF, sizeof(*acif));
	acif->ifp = ifp;
	acif->arp_fd = -1;

	ifp->info = acif;
	return 0;
}

static int attachd_if_del_hook(struct interface *ifp)
{
	XFREE(MTYPE_ATTACHD_IF, ifp->info);
	return 0;
}

static int attachd_if_config_write(struct vty *vty)
{
	dhcp6r_if_config_write(vty);
	return 0;
}

void attachd_if_init(void)
{
	hook_register_prio(if_add, 0, attachd_if_new_hook);
	hook_register_prio(if_del, 0, attachd_if_del_hook);

	if_cmd_init(attachd_if_config_write);
}

void attachd_if_fini(void)
{
}
