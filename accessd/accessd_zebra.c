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
#include "frrevent.h"
#include "zclient.h"

DEFINE_HOOK(accessd_if_addr_add, (struct connected *c), (c));
DEFINE_KOOH(accessd_if_addr_del, (struct connected *c), (c));

struct zclient *zclient = NULL;

extern struct zebra_privs_t accessd_privs;

static int accessd_if_addr_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	hook_call(accessd_if_addr_add, ifc);
	return 0;
}

static int accessd_if_addr_del(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (!ifc)
		return 0;
	hook_call(accessd_if_addr_del, ifc);

	connected_free(&ifc);
	return 0;
}

static int if_addr_do(uint16_t cmd, struct interface *ifp,
		      union prefixconstptr pu)
{
	struct stream *s = accessd_zclient->obuf;
	
	stream_reset(s);
	zclient_create_header(s, cmd, ifp->vrf->vrf_id);

	stream_putl(s, ifp->ifindex);
	stream_putw(s, pu.p->family);
	stream_putc(s, pu.p->prefixlen);
	stream_put(s, &pu.p->u.prefix, prefix_blen(pu.p));

	stream_putw_at(s, 0, stream_get_endp(s));
	return zclient_send_message(accessd_zclient);
}

int if_addr_install(struct interface *ifp, union prefixconstptr pu)
{
	return if_addr_do(ZEBRA_INTERFACE_ADDRESS_INSTALL, ifp, pu.p);
}

int if_addr_uninstall(struct interface *ifp, union prefixconstptr pu)
{
	return if_addr_do(ZEBRA_INTERFACE_ADDRESS_UNINSTALL, ifp, pu.p);
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

	accessd_zclient = zclient_new(master, &opt, accessd_handlers,
			      array_size(accessd_handlers));
	zclient_init(accessd_zclient, ZEBRA_ROUTE_ACCESSD, 0, &accessd_privs);
	accessd_zclient->zebra_connected = accessd_zebra_connected;
}
