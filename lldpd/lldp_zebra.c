/*
 * utils_zebra.c
 *
 *  Created on: Oct 15, 2016
 *      Author: zhurish
 */

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "routemap.h"
#include "zclient.h"
#include "log.h"

#include "lldpd.h"
#include "lldp_db.h"
#include "lldp_interface.h"
#include "lldp_packet.h"
#include "lldp_socket.h"

/* All information about zebra. */
struct zclient *zclient = NULL;


/* Inteface link down message processing. */
static int lldp_interface_down(int command, struct zclient *zclient, zebra_size_t length)
{
	struct interface *ifp;
	struct stream *s;

	s = zclient->ibuf;

	/* zebra_interface_state_read() updates interface structure in
     iflist. */
	ifp = zebra_interface_state_read(s);

	if (ifp == NULL)
		return 0;

	//if (IS_RIP_DEBUG_ZEBRA)
	zlog_debug("interface %s index %d flags %llx metric %d mtu %d is down", ifp->name,
		   ifp->ifindex, (unsigned long long)ifp->flags, ifp->metric, ifp->mtu);
	lldp_change_event();
	return 0;
}

/* Inteface link up message processing */
static int lldp_interface_up(int command, struct zclient *zclient, zebra_size_t length)
{
	struct interface *ifp;

	/* zebra_interface_state_read () updates interface structure in
     iflist. */
	ifp = zebra_interface_state_read(zclient->ibuf);

	if (ifp == NULL)
		return 0;

	//if (IS_RIP_DEBUG_ZEBRA)
	zlog_debug("interface %s index %d flags %#llx metric %d mtu %d is up", ifp->name,
		   ifp->ifindex, (unsigned long long)ifp->flags, ifp->metric, ifp->mtu);
	lldp_change_event();
	return 0;
}

/* Inteface addition message from zebra. */
static int lldp_interface_add(int command, struct zclient *zclient, zebra_size_t length)
{
	struct interface *ifp;

	ifp = zebra_interface_add_read(zclient->ibuf);

	//if (IS_RIP_DEBUG_ZEBRA)
	zlog_debug("interface add %s index %d flags %#llx metric %d mtu %d", ifp->name,
		   ifp->ifindex, (unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

	zlog_debug("interface add %s index %d flags %#llx metric %d mtu %d", ifp->name,
		   ifp->ifindex, (unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

	/* Check if this interface is RIP enabled or not.*/
	//rip_enable_apply (ifp);

	/* Check for a passive interface */
	//rip_passive_interface_apply (ifp);

	/* Apply distribute list to the all interface. */
	//rip_distribute_update_interface (ifp);

	/* rip_request_neighbor_all (); */

	/* Check interface routemap. */
	//rip_if_rmap_update_interface (ifp);
	return 0;
}

static int lldp_interface_delete(int command, struct zclient *zclient, zebra_size_t length)
{
	struct interface *ifp;
	struct stream *s;


	s = zclient->ibuf;
	/* zebra_interface_state_read() updates interface structure in iflist */
	ifp = zebra_interface_state_read(s);

	if (ifp == NULL)
		return 0;

	//if (if_is_up (ifp)) {
	//  rip_if_down(ifp);
	//}

	zlog_info("interface delete %s index %d flags %#llx metric %d mtu %d", ifp->name,
		  ifp->ifindex, (unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

	/* To support pseudo interface do not free interface structure.  */
	/* if_delete(ifp); */
	ifp->ifindex = IFINDEX_INTERNAL;
	if (ifp)
		if_delete(ifp);
	return 0;
}
static int lldp_interface_address_add(int command, struct zclient *zclient, zebra_size_t length)
{
	struct connected *ifc;
	struct prefix *p;

	ifc = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD, zclient->ibuf);

	if (ifc == NULL)
		return 0;

	p = ifc->address;

	if (p->family == AF_INET) {
		//if (IS_RIP_DEBUG_ZEBRA)
		zlog_debug("connected address %s/%d is added", inet_ntoa(p->u.prefix4),
			   p->prefixlen);

		//rip_enable_apply(ifc->ifp);
		/* Check if this prefix needs to be redistributed */
		//rip_apply_address_add(ifc);

#ifdef HAVE_SNMP
		//rip_ifaddr_add (ifc->ifp, ifc);
#endif /* HAVE_SNMP */
	}
	lldp_change_event();
	return 0;
}
static int lldp_interface_address_delete(int command, struct zclient *zclient, zebra_size_t length)
{
	struct connected *ifc;
	struct prefix *p;

	ifc = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE, zclient->ibuf);

	if (ifc) {
		p = ifc->address;
		if (p->family == AF_INET) {
			//if (IS_RIP_DEBUG_ZEBRA)
			zlog_debug("connected address %s/%d is deleted", inet_ntoa(p->u.prefix4),
				   p->prefixlen);

#ifdef HAVE_SNMP
			//rip_ifaddr_delete (ifc->ifp, ifc);
#endif /* HAVE_SNMP */

			/* Chech wether this prefix needs to be removed */
			//    rip_apply_address_del(ifc);
		}

		connected_free(ifc);
		lldp_change_event();
	}

	return 0;
}

void lldp_zclient_init(void)
{
	/* Set default value to the zebra client structure. */
	zclient = zclient_new();
	zclient_init(zclient, 0);
	zclient->interface_add = lldp_interface_add;
	zclient->interface_delete = lldp_interface_delete;
	zclient->interface_address_add = lldp_interface_address_add;
	zclient->interface_address_delete = lldp_interface_address_delete;
	zclient->ipv4_route_add = NULL;
	zclient->ipv4_route_delete = NULL;
	zclient->interface_up = lldp_interface_up;
	zclient->interface_down = lldp_interface_down;
}
