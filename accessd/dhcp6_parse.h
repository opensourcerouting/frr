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

#ifndef _FRR_DHCP6_PARSE_H
#define _FRR_DHCP6_PARSE_H

#include <stdarg.h>
#include <stdint.h>

#include "lib/typesafe.h"

#include "nhrpd/zbuf.h"

struct dhcp6;
struct dhcp6_relay;

struct dhcp6_duid {
	uint8_t size;	/* 0-128, only the "raw" part */

	uint16_t type;
	uint8_t raw[128];
};

#pragma FRR printfrr_ext "%pDUID" (struct dhcp6_duid *)

PREDECL_DLIST(dh6p_optlist);
struct dh6p_option {
	uint16_t type;
	uint16_t len;

	struct zbuf zb[1];

	struct dh6p_optlist_item item;
};
DECLARE_DLIST(dh6p_optlist, struct dh6p_option, item);

struct dh6p_optspec {
	struct dh6p_option *single;
	bool optional;
	bool have;

	bool want;
	struct dh6p_optlist_head list[1];
};

extern bool dhcp6_parse_opts(struct zbuf *zb, struct dh6p_optspec *opts,
			     size_t n_opts, struct dh6p_option *buf,
			     size_t n_buf, const char **err);

extern uint8_t dhcp6_parse_msg(struct zbuf *zb, struct dh6p_optspec *opts,
			       size_t n_opts, struct dh6p_option *buf,
			       size_t n_buf, const char **err,
			       struct dhcp6 **dh6, struct dhcp6_relay **dh6r);

extern void dhcp6_parse_duid(struct zbuf *zb, struct dhcp6_duid *duid);
extern void dhcp6_put_duid(struct zbuf *zb, const struct dhcp6_duid *duid);
extern void dhcp6_put_duidopt(struct zbuf *zb, uint16_t opt,
			      const struct dhcp6_duid *duid);

extern int duid_compare(const struct dhcp6_duid *a, const struct dhcp6_duid *b);

#endif /* _FRR_DHCP6_PARSE_H */
