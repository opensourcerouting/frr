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

#ifndef _FRR_DHCP6_IFACE_H
#define _FRR_DHCP6_IFACE_H

#include "lib/thread.h"
#include "nhrpd/zbuf.h"

enum dhcp6_client_state {
	DHCP6_CS_DISABLED = 0,
	DHCP6_CS_SOLICIT,
	DHCP6_CS_REQUEST,
	DHCP6_CS_BOUND_T1,
	DHCP6_CS_BOUND_T2,
};

struct dhcp6r_iface {
	struct interface *ifp;

	/* config */

	bool relay_enabled;
	char *ugroup_name;

	bool ra_self_enabled;

	/* state */

	bool running;
	int sock;
	struct connected *best_global;

	struct thread *rcv;

	/* self-deleg */

	struct thread *t_ra_self;
	enum dhcp6_client_state ra_self_state;
	unsigned ra_self_sol_delay;
	uint32_t ra_self_xid, ra_self_elapsed;
	struct dhcp6_duid ra_self_duid;

	struct prefix ra_self_adv_best;
};

extern void dhcp6r_if_refresh(struct interface *ifp, bool forcewarn);

#endif /* _FRR_DHCP6_IFACE_H */
