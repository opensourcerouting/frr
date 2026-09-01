// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM southbound (data plane) interface.
 *
 * Copyright (C) 2021-2026 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 */

#ifndef PIM_SOUTHBOUND_H
#define PIM_SOUTHBOUND_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "lib/if.h"

#include "pim_addr.h"

struct channel_oil;
struct interface;
struct pim_instance;

/*
 * Here are declared all needed pieces to operate PIM southbound: the
 * default implementation uses the kernel, modules may replace it.
 */

/* Type definitions, used below in the callbacks data structure. */
typedef void (*pim_mroute_socket_cb)(struct pim_instance *pim);
typedef int (*pim_interface_enable_cb)(struct interface *ifp, pim_addr ifaddr,
				       unsigned char vif_flags);
typedef void (*pim_interface_disable_cb)(struct interface *ifp);
typedef void (*pim_gmp_join_cb)(struct interface *ifp);
typedef void (*pim_gmp_leave_cb)(struct interface *ifp, const pim_addr *source,
				 const pim_addr *group);
typedef int (*pim_multicast_route_cb)(struct channel_oil *c_oil, const char *name);
typedef void (*pim_multicast_update_counters_cb)(struct channel_oil *c_oil);
typedef ssize_t (*pim_packet_send_cb)(const struct interface *ifp, const pim_addr *source,
				      const pim_addr *destination, uint8_t protocol, uint8_t ttl,
				      const void *data, size_t data_length);

/* PIM southbound handler callbacks. */
struct pim_sb_cbs {
	/*
	 * (MANDATORY)
	 * Maximum number of multicast interfaces: valid indexes go from 0 to
	 * `interface_max - 1`, `interface_max` itself means "no interface".
	 *
	 * It may exceed `MAXVIFS`: the kernel MFC conversion
	 * (`channel_oil_to_mfcc`) is only used by the kernel southbound.
	 */
	ifindex_t interface_max;

	/*
	 * (OPTIONAL)
	 * Send route information to FPM.
	 */
	bool fpm_sync;

	/*
	 * (OPTIONAL)
	 * Southbound owns the GMP/PIM sockets, don't use OS sockets.
	 */
	bool own_sockets;

	/*
	 * (OPTIONAL)
	 * When southbound owns the sockets (GMP/PIM) use this instead: PIM
	 * interfaces only use it to tell whether PIM is up (so -1 means down,
	 * PIM interfaces won't come up until it is set).
	 */
	int pim_fd;

	/*
	 * (OPTIONAL)
	 * The data plane forwards the RP's own sources natively: never add
	 * `pimreg` as output interface when we are the group RP.
	 */
	bool no_register_on_rp;

	/*
	 * (MANDATORY)
	 * This callback is tasked to create the routing socket and set
	 * `pim->mroute_socket` and `pim->mroute_socket_creation` entries.
	 */
	pim_mroute_socket_cb mroute_enable;

	/*
	 * (MANDATORY)
	 * This callback is tasked to destroy the routing socket and
	 * unset `pim->mroute_socket`, `pim->mroute_socket_creation` entries.
	 */
	pim_mroute_socket_cb mroute_disable;

	/*
	 * (MANDATORY)
	 * This callback is tasked to install multicast route.
	 */
	pim_multicast_route_cb mroute_install;

	/*
	 * (MANDATORY)
	 * This callback is tasked to uninstall multicast route.
	 */
	pim_multicast_route_cb mroute_uninstall;

	/*
	 * (OPTIONAL)
	 * This callback is tasked to update route counters.
	 *
	 * This may not be needed if the data plane is responsible to
	 * monitor traffic stop: without it the traffic activity comes from
	 * `pim_upstream_data_start`/`pim_upstream_data_stop` (only available
	 * with `PIM_SOUTHBOUND_COMMON`, otherwise every source looks idle,
	 * except the SPT switched LHR ones which never look idle) and the
	 * interface counters are displayed as zero.
	 */
	pim_multicast_update_counters_cb mroute_update_counters;

	/*
	 * (MANDATORY)
	 * This callback is tasked to enable multicast in an interface.
	 *
	 * You may manipulate
	 * `((struct pim_interface *)interface->info)->mroute_vif_index`
	 * to select a different multicast interface index or use the
	 * already selected index.
	 */
	pim_interface_enable_cb interface_enable;

	/*
	 * (MANDATORY)
	 * This callback is tasked to disable multicast in an interface.
	 */
	pim_interface_disable_cb interface_disable;

	/*
	 * (OPTIONAL, MANDATORY with `own_sockets`)
	 * This callback is tasked to (re)announce the static IGMP/MLD joins
	 * of the interface: called when a join is added, the interface gets
	 * an address, queries are sent or received and memberships expire
	 * (it may coalesce the calls).
	 *
	 * On *BSD/Linux the kernel sends a report, so it's a no-op.
	 */
	pim_gmp_join_cb interface_join;

	/*
	 * (OPTIONAL, MANDATORY with `own_sockets`)
	 * This callback is tasked to leave a static IGMP/MLD group
	 * immediately by sending the appropriate GMP mechanism.
	 *
	 * On *BSD/Linux the kernel sends a report/leave, so it's a no-op.
	 */
	pim_gmp_leave_cb interface_leave;

	/*
	 * (OPTIONAL, MANDATORY with `own_sockets`)
	 * This callback is tasked to send IGMP/MLD/PIM packets: multicast
	 * ones and unicast ones tied to an interface (e.g. registers) go out
	 * of `ifp`, unicast ones without an interface (`ifp` NULL, or the VRF
	 * device in other VRFs) are routed by the data plane.
	 * `source` may be NULL when `ifp` is set: use the interface primary
	 * (IPv6: link-local) address then.
	 *
	 * On systems where interface is owned by OS this is not required.
	 *
	 * The data plane doesn't handle loopbacks: IGMP/MLD on those stay
	 * with the OS sockets (see `pim_sb_owns_interface`).
	 *
	 * Returns the bytes sent (`data_length`) or -1 (with `errno` set).
	 */
	pim_packet_send_cb send;
};

extern struct pim_sb_cbs southbound;

/**
 * Tells whether the southbound owns `ifp` IGMP/MLD sockets: loopbacks
 * (and VRF devices) are not handled by data planes, so they keep the OS ones.
 */
static inline bool pim_sb_owns_interface(const struct interface *ifp)
{
	return southbound.own_sockets && !if_is_loopback(ifp);
}

#endif /* PIM_SOUTHBOUND_H */
