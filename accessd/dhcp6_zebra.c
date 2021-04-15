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

#include "command.h"
#include "memory.h"
#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "thread.h"
#include "zclient.h"

#include "accessd.h"

#include "dhcp6_state.h"
#include "dhcp6_zebra.h"
#include "dhcp6_iface.h"

struct zclient *zclient = NULL;

extern struct thread_master *master;

extern struct zebra_privs_t accessd_privs;

static int dhcp6r_if_addr_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	dhcp6r_if_refresh(c->ifp, false);

	return 0;
}

static int dhcp6r_if_addr_del(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	dhcp6r_if_refresh(c->ifp, false);
	connected_free(&c);
	return 0;
}

static void dhcp6r_zebra_connected(struct zclient *zclient)
{
	zlog_info("zebra connected");
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

static void dhcp6r_zebra_ipv6_send(struct dhcp6_binding *bnd,
				   struct dhcp6_pdprefix *pdp, uint8_t cmd)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	const struct prefix *p = (struct prefix *)&pdp->prefix;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_DHCP6R;
	api.safi = SAFI_UNICAST;
	api.prefix = *p;

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	api_nh = &api.nexthops[0];
	api_nh->vrf_id = VRF_DEFAULT;
	api_nh->gate.ipv6 = bnd->client;
	api_nh->ifindex = bnd->ifp->ifindex;
	api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;

	if (cmd == ZEBRA_ROUTE_ADD)
		pdp->in_zebra = true;
	else
		pdp->in_zebra = false;

	api.nexthop_num = 1;

/*
	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = rinfo->metric;

	if (rinfo->tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = rinfo->tag;
	}
*/
	zlog_info("sending cmd %d, %pFX, %pI6 to zebra", cmd, p,
		  &api_nh->gate.ipv6);
	zclient_route_send(cmd, zclient, &api);
}

void dhcp6r_zebra_ipv6_add(struct dhcp6_binding *bnd,
			   struct dhcp6_pdprefix *pdp)
{
	dhcp6r_zebra_ipv6_send(bnd, pdp, ZEBRA_ROUTE_ADD);
}

void dhcp6r_zebra_ipv6_del(struct dhcp6_binding *bnd,
			   struct dhcp6_pdprefix *pdp)
{
	dhcp6r_zebra_ipv6_send(bnd, pdp, ZEBRA_ROUTE_DELETE);
}

static zclient_handler *const accessd_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD]    = dhcp6r_if_addr_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = dhcp6r_if_addr_del,
};

void dhcp6r_zebra_init(void)
{
	struct zclient_options opt = { };

	zclient = zclient_new(master, &opt, accessd_handlers,
			      array_size(accessd_handlers));

	zclient_init(zclient, ZEBRA_ROUTE_DHCP6R, 0, &accessd_privs);
	zclient->zebra_connected = dhcp6r_zebra_connected;
}
