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

#include "command.h"
#include "if.h"
#include "jhash.h"
#include "memory.h"
#include "network.h"
#include "printfrr.h"
#include "prefix.h"
#include "privs.h"
#include "sockopt.h"
#include "thread.h"
#include "vrf.h"

#include "accessd.h"

#include "dhcp6_protocol.h"
#include "dhcp6_parse.h"
#include "dhcp6_state.h"

static inline void zbuf_pull_zbuf(struct zbuf *parent, struct zbuf *child,
				  size_t len)
{
	void *data = zbuf_pulln(parent, len);

	if (data)
		zbuf_init(child, data, len, len);
}

bool dhcp6_parse_opts(struct zbuf *zb, struct dh6p_optspec *opts,
		      size_t n_opts, struct dh6p_option *buf, size_t n_buf,
		      const char **errp)
{
	const char *err = NULL;
	size_t n_req = 0;
	struct dh6p_option *bufend = buf + n_buf;

	assert(n_opts > 0);
	for (size_t i = 0; i < n_opts; i++) {
		dh6p_optlist_init(opts[i].list);
		if (opts[i].single && !opts[i].optional)
			n_req++;
	}

	while (zbuf_used(zb)) {
		struct dh6p_optspec *dst;
		struct dh6p_option *opt;
		uint16_t typ, len;
		struct zbuf sub;

		typ = zbuf_get_be16(zb);
		len = zbuf_get_be16(zb);
		if (zb->error) {
			err = "truncated option header";
			break;
		}

		zbuf_pull_zbuf(zb, &sub, len);
		if (zb->error) {
			err = "truncated option";
			break;
		}

		zlog_debug("parser: %dDOPT(%u)", typ, len);

		if (typ >= n_opts) {
			if (!opts[0].want)
				continue;
			dst = &opts[0];
		} else {
			dst = &opts[typ];
			if (dst->single && dst->have) {
				err = "duplicate singleton option";
				break;
			}
			if (!dst->single && !dst->want)
				continue;
		}
		if (dst->single && !dst->optional && !dst->have)
			n_req--;
		dst->have = true;
		if (dst->single)
			opt = dst->single;
		else {
			if (buf == bufend) {
				err = "too many options";
				break;
			}
			opt = buf++;
		}

		opt->type = typ;
		opt->len = len;
		opt->zb[0] = sub;
		if (opt != dst->single)
			dh6p_optlist_add_tail(dst->list, opt);
	}

	if (n_req && !err)
		err = "required option missing";

	if (errp)
		*errp = err;
	return err == NULL;
}

uint8_t dhcp6_parse_msg(struct zbuf *zb, struct dh6p_optspec *opts,
			size_t n_opts, struct dh6p_option *buf, size_t n_buf,
			const char **errp, struct dhcp6 **dh6p,
			struct dhcp6_relay **dh6rp)
{
	const char *err = NULL;
	uint8_t msg_type = 0;
	struct dhcp6 *dh6 = NULL;
	struct dhcp6_relay *dh6r = NULL;

	if (zbuf_used(zb) < 1) {
		err = "truncated header";
		goto out;
	}
	msg_type = *(uint8_t *)zb->head;

	switch (msg_type) {
	case DH6MSG_RELAY_FORW:
	case DH6MSG_RELAY_REPL:
		dh6r = zbuf_pull(zb, struct dhcp6_relay);
		break;
	default:
		dh6 = zbuf_pull(zb, struct dhcp6);
		break;
	}

	if (zb->error) {
		err = "truncated header";
		goto out;
	}

	dhcp6_parse_opts(zb, opts, n_opts, buf, n_buf, &err);

out:
	if (dh6p)
		*dh6p = dh6;
	if (dh6rp)
		*dh6rp = dh6r;
	if (errp)
		*errp = err;
	return err ? 0 : msg_type;
}

void dhcp6_parse_duid(struct zbuf *zb, struct dhcp6_duid *duid)
{
	size_t rawbytes;

	duid->type = zbuf_get_be16(zb);
	rawbytes = zbuf_used(zb);
	if (rawbytes > sizeof(duid->raw) || zb->error)
		return;
	memcpy(duid->raw, zbuf_pulln(zb, rawbytes), rawbytes);
	duid->size = rawbytes;
}

void dhcp6_put_duid(struct zbuf *zb, const struct dhcp6_duid *duid)
{
	void *p;

	zbuf_put_be16(zb, duid->type);
	p = zbuf_pushn(zb, duid->size);
	if (p)
		memcpy(p, duid->raw, duid->size);
}

void dhcp6_put_duidopt(struct zbuf *zb, uint16_t opt,
		       const struct dhcp6_duid *duid)
{
	zbuf_put_be16(zb, opt);
	zbuf_put_be16(zb, duid->size + 2);
	dhcp6_put_duid(zb, duid);
}
