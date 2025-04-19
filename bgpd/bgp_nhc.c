// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2025, Donatas Abraitis <donatas@opensourcerouting.org>
 */

#include "memory.h"
#include "prefix.h"
#include "filter.h"
#include "stream.h"

#include "bgpd.h"
#include "bgp_attr.h"
#include "bgpd/bgp_mpath.h"

#include "bgp_nhc.h"

struct bgp_nhc_tlv *bgp_nhc_tlv_encode_nnhn(struct bgp_path_info *bpi)
{
	struct bgp_nhc_tlv *new;
	struct bgp_path_info *exists;
	uint8_t *p;
	uint16_t total = IPV4_MAX_BYTELEN;

	for (exists = bgp_path_info_mpath_next(bpi); exists;
	     exists = bgp_path_info_mpath_next(exists))
		total += IPV4_MAX_BYTELEN;

	new = XCALLOC(MTYPE_BGP_NHC_TLV, sizeof(struct bgp_nhc_tlv) + total);
	new->code = BGP_ATTR_NHC_TLV_NNHN;
	new->length = total;
	new->value = XCALLOC(MTYPE_BGP_NHC_TLV_VAL, total);

	p = new->value;

	/* bpi->mpath has only non-selected paths, hence we need to put
	 * the router-id of the selected path also.
	 */
	memcpy(p, &bpi->peer->remote_id, IPV4_MAX_BYTELEN);

	/* ECMP nodes */
	for (exists = bgp_path_info_mpath_next(bpi); exists;
	     exists = bgp_path_info_mpath_next(exists)) {
		p += IPV4_MAX_BYTELEN;
		memcpy(p, &exists->peer->remote_id, IPV4_MAX_BYTELEN);
	}

	return new;
}
