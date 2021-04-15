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

#include "lib/printfrr.h"

#include "dhcp6_protocol.h"
#include "dhcp6_state.h"

static const char * const msgtypes[] = {
#define DH6MSG(name, val)			[DH6MSG_##name] = #name,
#include "dhcp6_constants.h"
};

printfrr_ext_autoreg_i("DHMT", printfrr_msgtype);
static ssize_t printfrr_msgtype(struct fbuf *fbuf, struct printfrr_eargs *ea,
				const uintmax_t val)
{
	if (val < array_size(msgtypes) && msgtypes[val])
		return bputs(fbuf, msgtypes[val]);
	return bprintfrr(fbuf, "MSGTYPE_%ju", val);
}

static const char * const opttypes[] = {
#define DH6OPT(name, val, o, s)			[DH6OPT_##name] = #name,
#include "dhcp6_constants.h"
};

printfrr_ext_autoreg_i("DOPT", printfrr_opttype);
static ssize_t printfrr_opttype(struct fbuf *fbuf, struct printfrr_eargs *ea,
				const uintmax_t val)
{
	if (val < array_size(opttypes) && opttypes[val])
		return bputs(fbuf, opttypes[val]);
	return bprintfrr(fbuf, "OPTTYPE_%ju", val);
}

static const char * const statuses[] = {
#define DH6ST(name, val)			[DH6ST_##name] = #name,
#include "dhcp6_constants.h"
};

printfrr_ext_autoreg_i("DHST", printfrr_status);
static ssize_t printfrr_status(struct fbuf *fbuf, struct printfrr_eargs *ea,
			       const uintmax_t val)
{
	if (val < array_size(statuses) && statuses[val])
		return bputs(fbuf, statuses[val]);
	return bprintfrr(fbuf, "STATUS_%ju", val);
}

printfrr_ext_autoreg_p("DUID", printfrr_duid);
static ssize_t printfrr_duid(struct fbuf *fbuf, struct printfrr_eargs *ea,
			     const void *ptr)
{
	const struct dhcp6_duid *duid = ptr;
	uint16_t type;
	uint32_t time, pen;

	if (!duid)
		return bputs(fbuf, "(null)");

	switch (duid->type) {
	case 1:
		if (duid->size < 6)
			break;

		memcpy(&type, duid->raw + 0, sizeof(type));
		memcpy(&time, duid->raw + 2, sizeof(time));
		if (ntohs(type) == 1 && duid->size == 12)
			return bprintfrr(fbuf, "duid(eth:%6pHXc,time(%u))",
					 duid->raw + 6, ntohl(time));
		else
			return bprintfrr(fbuf, "duid(hw(%u):%*pHXc,time(%u))",
					 type, (int)duid->size - 6,
					 duid->raw + 6, ntohl(time));

	case 2:
		memcpy(&pen, duid->raw + 0, sizeof(pen));
		return bprintfrr(fbuf, "duid(vendor(%u):%*pHXc)",
				 ntohl(pen), (int)duid->size - 4,
				 duid->raw + 4);

	case 3:
		if (duid->size < 2)
			break;

		memcpy(&type, duid->raw + 0, sizeof(type));
		if (ntohs(type) == 1 && duid->size == 8)
			return bprintfrr(fbuf, "duid(eth:%6pHXc)",
					 duid->raw + 2);
		else
			return bprintfrr(fbuf, "duid(hw(%u):%*pHXc)",
					 ntohs(type), (int)duid->size - 2,
					 duid->raw + 2);
	}

	return bprintfrr(fbuf, "duid(%u:%*pHXc)", duid->type, (int)duid->size,
			 duid->raw);
}
