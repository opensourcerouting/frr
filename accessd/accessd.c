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

#include "lib/zebra.h"

#include "lib/filter.h"
#include "lib/getopt.h"
#include "lib/libfrr.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/privs.h"
#include "lib/routemap.h"
#include "lib/thread.h"
#include "lib/vrf.h"

#include "lib/version.h"

#include "accessd.h"

DEFINE_MGROUP(ACCESSD, "accessd");
DEFINE_MGROUP(NHRPD, "buffer management");

static zebra_capabilities_t _caps_p[] = {
	ZCAP_BIND,
};

struct zebra_privs_t accessd_privs = {
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

struct thread_master *master;

static void sighup(void)
{
	zlog_info("SIGHUP received");
}

static void sigint(void)
{
	zlog_notice("Terminating on signal");
	frr_fini();
	exit(0);
}

static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t accessd_signals[] = {
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

#define ACCESSD_VTY_PORT 2622

static const struct frr_yang_module_info *const accessd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_vrf_info,
};

FRR_DAEMON_INFO(accessd, ACCESSD,

	.vty_port = ACCESSD_VTY_PORT,

	.proghelp = "FRRouting user access protocols / UNI daemon",

	.signals = accessd_signals,
	.n_signals = array_size(accessd_signals),

	.privs = &accessd_privs,

	.yang_modules = accessd_yang_modules,
	.n_yang_modules = array_size(accessd_yang_modules),
);

int main(int argc, char **argv, char **envp)
{
	frr_preinit(&accessd_di, argc, argv);
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

	accessd_zebra_init();
	accessd_vrf_init();
	accessd_if_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
