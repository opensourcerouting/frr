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
#include "zclient.h"

#include "accessd.h"
#include "accessd_zebra.h"

#include "dhcp6_state.h"
#include "dhcp6_zebra.h"
#include "dhcp6_iface.h"

extern struct zebra_privs_t accessd_privs;

static int dhcp6r_if_addr_add(struct connected *c)
{
	dhcp6r_if_refresh(c->ifp, false);

	return 0;
}

static int dhcp6r_if_addr_del(struct connected *c)
{
	dhcp6r_if_refresh(c->ifp, false);
	return 0;
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

void dhcp6r_zebra_init(void)
{
	hook_register(accessd_if_addr_add, dhcp6r_if_addr_add);
	hook_register(accessd_if_addr_del, dhcp6r_if_addr_del);
}
