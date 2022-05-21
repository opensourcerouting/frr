// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>

#include "attachd_vrf.h"

#include "attachd.h"

#include "vrf.h"
#include "memory.h"

DEFINE_MTYPE_STATIC(ATTACHD, ATTACHD_VRF, "attachd VRF data");

static int attachd_vrf_create(struct vrf *vrf)
{
	struct attachd_vrf *acvrf;

	acvrf = XCALLOC(MTYPE_ATTACHD_VRF, sizeof(*acvrf));
	acvrf->vrf = vrf;
	vrf->info = acvrf;

	return 0;
}

static int attachd_vrf_enable(struct vrf *vrf)
{
	return 0;
}

static int attachd_vrf_disable(struct vrf *vrf)
{
	return 0;
}

static int attachd_vrf_destroy(struct vrf *vrf)
{
	XFREE(MTYPE_ATTACHD_VRF, vrf->info);

	return 0;
}

void attachd_vrf_init(void)
{
	vrf_init(attachd_vrf_create,
		 attachd_vrf_enable,
		 attachd_vrf_disable,
		 attachd_vrf_destroy);
}

void attachd_vrf_fini(void)
{
	vrf_terminate();
}
