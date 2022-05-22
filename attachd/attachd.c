// SPDX-License-Identifier: GPL-2.0-or-later

#include "lib/zebra.h"

#include "lib/filter.h"
#include "lib/libfrr.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/privs.h"
#include "lib/routemap.h"
#include "lib/frrevent.h"
#include "lib/vrf.h"

#include "lib/version.h"

#include "attachd.h"

DEFINE_MGROUP(ATTACHD, "attachd");
DEFINE_MGROUP(NHRPD, "buffer management");

static void attachd_fini(void);

static zebra_capabilities_t _caps_p[] = {
	ZCAP_BIND,
	ZCAP_NET_RAW,
};

struct zebra_privs_t attachd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0,
};

static struct option longopts[] = {{0}};

struct event_loop *master;

static void sighup(void)
{
	zlog_info("SIGHUP received");
}

static void sigint(void)
{
	zlog_notice("Terminating on signal");
	attachd_fini();
	exit(0);
}

static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t attachd_signals[] = {
	{
		.signal = SIGHUP,
		.handler = &sighup,
	},
	{
		.signal = SIGUSR1,
		.handler = &sigusr1,
	},
	{
		.signal = SIGINT,
		.handler = &sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &sigint,
	},
};

#define ATTACHD_VTY_PORT 2622

static const struct frr_yang_module_info *const attachd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_vrf_info,
};

/* clang-format off */
FRR_DAEMON_INFO(attachd, ATTACHD,

	.vty_port = ATTACHD_VTY_PORT,

	.proghelp = "FRRouting end host attachment (\"UNI\") daemon",

	.signals = attachd_signals,
	.n_signals = array_size(attachd_signals),

	.privs = &attachd_privs,

	.yang_modules = attachd_yang_modules,
	.n_yang_modules = array_size(attachd_yang_modules),
);
/* clang-format on */

int main(int argc, char **argv, char **envp)
{
	frr_preinit(&attachd_di, argc, argv);
	frr_opt_add("", longopts, "");

	while (1) {
		int opt;

		opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		default:
			frr_help_exit(1);
			break;
		}
	}

	master = frr_init();

	prefix_list_init();
	route_map_init();

	attachd_zebra_init();
	attachd_vrf_init();
	attachd_if_init();

	rtadv_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}

static void attachd_fini(void)
{
	attachd_if_fini();
	attachd_vrf_fini();
	attachd_zebra_fini();

	route_map_finish();
	prefix_list_reset();

	frr_fini();
}
