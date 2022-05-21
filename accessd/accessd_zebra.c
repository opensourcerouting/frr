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

#include "accessd_zebra.h"

#include "accessd.h"

#include "command.h"
#include "memory.h"
#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "thread.h"
#include "zclient.h"

struct zclient *zclient = NULL;

extern struct thread_master *master;

extern struct zebra_privs_t accessd_privs;

static int accessd_if_addr_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	(void)c;

	return 0;
}

static int accessd_if_addr_del(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(&c);
	return 0;
}

static void accessd_zebra_connected(struct zclient *zclient)
{
	zlog_info("zebra connected");
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

static zclient_handler *const accessd_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD]    = accessd_if_addr_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = accessd_if_addr_del,
};

void accessd_zebra_init(void)
{
	struct zclient_options opt = { };

	zclient = zclient_new(master, &opt, accessd_handlers,
			      array_size(accessd_handlers));
	zclient_init(zclient, ZEBRA_ROUTE_ACCESSD, 0, &accessd_privs);
	zclient->zebra_connected = accessd_zebra_connected;
}
