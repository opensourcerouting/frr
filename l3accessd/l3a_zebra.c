#include "lib/zebra.h"

#include "lib/thread.h"
#include "lib/stream.h"
#include "lib/zclient.h"

#include "l3a.h"

DEFINE_MTYPE_STATIC(L3A, L3A_IFACE, "L3 access interface")

DECLARE_DLIST(l3a_route_iflist, struct l3a_route, iflist_itm)

static struct zclient *zclient;

struct l3a_if *l3a_if_get_byname(const char *name)
{
	struct interface *ifp = if_get_by_name(name, VRF_DEFAULT);
	struct l3a_if *l3a_if;

	if (!ifp->info) {
		l3a_if = XCALLOC(MTYPE_L3A_IFACE, sizeof(struct l3a_if));
		l3a_if->ifp = ifp;
		l3a_if->snoop_fd = -1;
		l3a_if->arp_fd = -1;
		l3a_route_iflist_init(&l3a_if->routes);
		ifp->info = l3a_if;
	} else
		l3a_if = ifp->info;

	return l3a_if;
}

static struct interface *stream_get_ifbyname(struct stream *s)
{
	char ifname_tmp[INTERFACE_NAMSIZ];

	stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);
	return if_lookup_by_name(ifname_tmp, VRF_DEFAULT);
}

static int interface_add(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	struct l3a_if *l3a_if;
	struct l3a_route *l3ar;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
	if (!ifp->info) {
		l3a_if = XCALLOC(MTYPE_L3A_IFACE, sizeof(struct l3a_if));
		l3a_if->ifp = ifp;
		l3a_if->snoop_fd = -1;
		l3a_if->arp_fd = -1;
		l3a_route_iflist_init(&l3a_if->routes);
		ifp->info = l3a_if;
	} else
		l3a_if = ifp->info;

	zlog_debug("interface %s added (%zu routes)", ifp->name,
		   l3a_route_iflist_count(&l3a_if->routes));

	if (ifp->flags & IFF_UP) {
		if (l3a_if->snoop)
			l3a_dhcpv6_snoop(l3a_if);
		if (l3a_if->arp_snoop)
			l3a_arp_snoop(l3a_if);
		frr_each (l3a_route_iflist, &l3a_if->routes, l3ar)
			l3a_zebra_update(l3ar);
	}
	return 0;
}

static int interface_delete(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	struct l3a_if *l3a_if;

	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

	l3a_if = ifp->info;
	assert(l3a_if);

	if_set_index(ifp, IFINDEX_INTERNAL);
	return 0;
}

static int interface_address_add(ZAPI_CALLBACK_ARGS)
{
	zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	return 0;
}

static int interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (!c)
		return 0;

	connected_free(c);
	return 0;
}

static int interface_state_up(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp = stream_get_ifbyname(zclient->ibuf);
	struct l3a_if *l3a_if;
	struct l3a_route *l3ar;

	assert(ifp && ifp->info);
	l3a_if = ifp->info;

	zlog_debug("interface %s came up (%zu routes)", ifp->name,
		   l3a_route_iflist_count(&l3a_if->routes));

	if (l3a_if->snoop)
		l3a_dhcpv6_snoop(l3a_if);
	if (l3a_if->arp_snoop)
		l3a_arp_snoop(l3a_if);
	frr_each (l3a_route_iflist, &l3a_if->routes, l3ar)
		l3a_zebra_update(l3ar);
	return 0;
}

static int interface_state_down(ZAPI_CALLBACK_ARGS)
{
	zebra_interface_state_read(zclient->ibuf, vrf_id);
	return 0;
}

static int route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table, &note))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_INSTALLED:
		break;
	case ZAPI_ROUTE_FAIL_INSTALL:
		zlog_debug("Failed install of route");
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		zlog_debug("Better Admin Distance won over us");
		break;
	case ZAPI_ROUTE_REMOVED:
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		zlog_debug("Route removal Failure");
		break;
	}
	return 0;
}

static void zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

#if 0
void route_add(struct prefix *p, vrf_id_t vrf_id,
	       uint8_t instance, struct nexthop_group *nhg)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct nexthop *nh;
	int i = 0;

	memset(&api, 0, sizeof(api));
	api.vrf_id = vrf_id;
	api.type = ZEBRA_ROUTE_SHARP;
	api.instance = instance;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, p, sizeof(*p));

	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);

	for (ALL_NEXTHOPS_PTR(nhg, nh)) {
		api_nh = &api.nexthops[i];
		api_nh->vrf_id = nh->vrf_id;
		api_nh->type = nh->type;
		switch (nh->type) {
		case NEXTHOP_TYPE_IPV4:
			api_nh->gate = nh->gate;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			api_nh->gate = nh->gate;
			api_nh->ifindex = nh->ifindex;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			api_nh->ifindex = nh->ifindex;
			break;
		case NEXTHOP_TYPE_IPV6:
			memcpy(&api_nh->gate.ipv6, &nh->gate.ipv6, 16);
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			api_nh->ifindex = nh->ifindex;
			memcpy(&api_nh->gate.ipv6, &nh->gate.ipv6, 16);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			api_nh->bh_type = nh->bh_type;
			break;
		}
		i++;
	}
	api.nexthop_num = i;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

void route_delete(struct prefix *p, vrf_id_t vrf_id, uint8_t instance)
{
	struct zapi_route api;

	memset(&api, 0, sizeof(api));
	api.vrf_id = vrf_id;
	api.type = ZEBRA_ROUTE_SHARP;
	api.safi = SAFI_UNICAST;
	api.instance = instance;
	memcpy(&api.prefix, p, sizeof(*p));
	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);

	return;
}
#endif

void l3a_zebra_update(struct l3a_route *l3ar)
{
	struct interface *ifp = if_get_by_name(l3ar->ifname, VRF_DEFAULT);
	struct l3a_if *l3a_if;

	if (!ifp->info) {
		l3a_if = XCALLOC(MTYPE_L3A_IFACE, sizeof(struct l3a_if));
		l3a_if->ifp = ifp;
		l3a_if->snoop_fd = -1;
		l3a_route_iflist_init(&l3a_if->routes);
		ifp->info = l3a_if;
	}

	if (ifp != l3ar->ifp) {
		if (l3ar->ifp) {
			l3a_if = l3ar->ifp->info;
			l3a_route_iflist_del(&l3a_if->routes, l3ar);
		}
		l3ar->ifp = ifp;
		l3a_if = ifp->info;
		l3a_route_iflist_add_tail(&l3a_if->routes, l3ar);
	}

	l3ar->nh.vrf_id = VRF_DEFAULT;
	l3ar->nh.ifindex = ifp->ifindex;
	l3ar->nh.type = NEXTHOP_TYPE_IPV6_IFINDEX;
	l3ar->nh.gate = l3ar->gw;

	if (ifp->ifindex == IFINDEX_INTERNAL) {
		zlog_info("zebra add: %pFX (skipped, no iface)", &l3ar->p);
		return;
	}

	zlog_info("route update: %pFX via %pI6 ifi %u", &l3ar->p, &l3ar->nh.gate, l3ar->nh.ifindex);

	struct zapi_route api;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_L3A;
	api.instance = 0;
	api.safi = SAFI_UNICAST;
	prefix_copy(&api.prefix, &l3ar->p);

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	api.nexthops[0].type = l3ar->nh.type;
	api.nexthops[0].vrf_id = l3ar->nh.vrf_id;
	api.nexthops[0].ifindex = l3ar->nh.ifindex;
	api.nexthops[0].gate = l3ar->nh.gate;
	api.nexthop_num = 1;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

void l3a_zebra_remove(struct l3a_route *l3ar)
{
	struct l3a_if *l3a_if = l3ar->ifp->info;

	l3a_route_iflist_del(&l3a_if->routes, l3ar);
	if (l3ar->ifp->ifindex == IFINDEX_INTERNAL) {
		zlog_info("zebra remove: %pFX (skipped, no iface)", &l3ar->p);
		return;
	}

	zlog_info("zebra remove: %pFX", &l3ar->p);

	struct zapi_route api;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_L3A;
	api.safi = SAFI_UNICAST;
	api.instance = 0;
	prefix_copy(&api.prefix, &l3ar->p);
	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
}

extern struct zebra_privs_t l3a_privs;

void l3a_zebra_init(struct thread_master *tm)
{
	struct zclient_options opt = {
		.receive_notify = true
	};

	zclient = zclient_new(tm, &opt);

	zclient_init(zclient, ZEBRA_ROUTE_L3A, 0, &l3a_privs);
	zclient->zebra_connected = zebra_connected;
	zclient->interface_add = interface_add;
	zclient->interface_delete = interface_delete;
	zclient->interface_up = interface_state_up;
	zclient->interface_down = interface_state_down;
	zclient->interface_address_add = interface_address_add;
	zclient->interface_address_delete = interface_address_delete;
	zclient->route_notify_owner = route_notify_owner;
}
