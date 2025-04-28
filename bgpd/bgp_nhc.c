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

void bgp_nhc_tlv_add(struct bgp_nhc *nhc, struct bgp_nhc_tlv *tlv)
{
	struct bgp_nhc_tlv *last;

	if (!tlv)
		return;

	for (last = nhc->tlvs; last && last->next; last = last->next)
		;

	if (last)
		last->next = tlv;
	else
		nhc->tlvs = tlv;

	nhc->tlvs_length += tlv->length + BGP_NHC_TLV_MIN_LEN;
}

struct bgp_nhc_tlv *bgp_nhc_tlv_find(struct attr *attr, uint16_t code)
{
	struct bgp_nhc *nhc = bgp_attr_get_nhc(attr);
	struct bgp_nhc_tlv *tlv = NULL;

	if (!nhc)
		return tlv;

	for (tlv = nhc->tlvs; tlv; tlv = tlv->next) {
		if (tlv->code == code)
			return tlv;
	}

	return tlv;
}

void bgp_nhc_tlv_free(struct bgp_nhc_tlv *tlv)
{
	if (!tlv)
		return;

	if (tlv->value)
		XFREE(MTYPE_BGP_NHC_TLV_VAL, tlv->value);

	XFREE(MTYPE_BGP_NHC_TLV, tlv);
}

void bgp_nhc_tlvs_free(struct bgp_nhc_tlv *tlv)
{
	struct bgp_nhc_tlv *next;

	while (tlv) {
		next = tlv->next;
		bgp_nhc_tlv_free(tlv);
		tlv = next;
	}
}

void bgp_nhc_free(struct bgp_nhc *nhc)
{
	bgp_nhc_tlvs_free(nhc->tlvs);
	XFREE(MTYPE_BGP_NHC, nhc);
}
