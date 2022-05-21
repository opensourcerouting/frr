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

struct zclient *attachd_zclient = NULL;

extern struct zebra_privs_t attachd_privs;

static int attachd_if_addr_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	(void)c;

	return 0;
}

static int attachd_if_addr_del(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(&c);
	return 0;
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
