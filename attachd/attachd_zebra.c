// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>

#include "attachd_zebra.h"

#include "attachd.h"

#include "command.h"
#include "memory.h"
#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "frrevent.h"
#include "zclient.h"

DEFINE_HOOK(attachd_if_addr_add, (struct connected *c), (c));
DEFINE_KOOH(attachd_if_addr_del, (struct connected *c), (c));

struct zclient *attachd_zclient = NULL;

extern struct zebra_privs_t attachd_privs;

static int attachd_if_addr_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	hook_call(attachd_if_addr_add, ifc);
	return 0;
}

static int attachd_if_addr_del(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (!ifc)
		return 0;
	hook_call(attachd_if_addr_del, ifc);

	connected_free(&ifc);
	return 0;
}

static int if_addr_do(uint16_t cmd, struct interface *ifp,
		      union prefixconstptr pu)
{
	struct stream *s = attachd_zclient->obuf;

	stream_reset(s);
	zclient_create_header(s, cmd, ifp->vrf->vrf_id);

	stream_putl(s, ifp->ifindex);
	stream_putw(s, pu.p->family);
	stream_putc(s, pu.p->prefixlen);
	stream_put(s, &pu.p->u.prefix, prefix_blen(pu.p));

	stream_putw_at(s, 0, stream_get_endp(s));
	return zclient_send_message(attachd_zclient);
}

int if_addr_install(struct interface *ifp, union prefixconstptr pu)
{
	return if_addr_do(ZEBRA_INTERFACE_ADDRESS_INSTALL, ifp, pu.p);
}

int if_addr_uninstall(struct interface *ifp, union prefixconstptr pu)
{
	return if_addr_do(ZEBRA_INTERFACE_ADDRESS_UNINSTALL, ifp, pu.p);
}

static void attachd_zebra_connected(struct zclient *zclient)
{
	zlog_info("zebra connected");
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

static zclient_handler *const attachd_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD]    = attachd_if_addr_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = attachd_if_addr_del,
};

void attachd_zebra_init(void)
{
	struct zclient_options opt = { };

	attachd_zclient = zclient_new(master, &opt, attachd_handlers,
			      array_size(attachd_handlers));
	zclient_init(attachd_zclient, ZEBRA_ROUTE_ATTACHD, 0, &attachd_privs);
	attachd_zclient->zebra_connected = attachd_zebra_connected;
}

void attachd_zebra_fini(void)
{
	zclient_stop(attachd_zclient);
	zclient_free(attachd_zclient);
}
