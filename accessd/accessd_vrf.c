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

#include "accessd_vrf.h"

#include "accessd.h"

#include "vrf.h"
#include "memory.h"

DEFINE_MTYPE_STATIC(ACCESSD, ACCESSD_VRF, "accessd VRF data");

static int accessd_vrf_create(struct vrf *vrf)
{
	struct accessd_vrf *acvrf;

	acvrf = XCALLOC(MTYPE_ACCESSD_VRF, sizeof(*acvrf));
	acvrf->vrf = vrf;
	vrf->info = acvrf;

	return 0;
}

static int accessd_vrf_enable(struct vrf *vrf)
{
	return 0;
}

static int accessd_vrf_disable(struct vrf *vrf)
{
	return 0;
}

static int accessd_vrf_destroy(struct vrf *vrf)
{
	XFREE(MTYPE_ACCESSD_VRF, vrf->info);

	return 0;
}

void accessd_vrf_init(void)
{
	vrf_init(accessd_vrf_create,
		 accessd_vrf_enable,
		 accessd_vrf_disable,
		 accessd_vrf_destroy);
}
