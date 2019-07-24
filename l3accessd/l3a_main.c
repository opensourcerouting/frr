#include "lib/zebra.h"

#include "lib/memory.h"
#include "lib/routemap.h"
#include "lib/filter.h"
#include "lib/vrf.h"
#include "lib/nexthop_group.h"
#include "lib/libfrr.h"
#include "lib/version.h"

#include "l3a.h"

DEFINE_MGROUP(L3A, "l3accessd")

zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_ADMIN,
	ZCAP_NET_RAW,
	ZCAP_BIND,
};

struct zebra_privs_t l3a_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0};

struct option longopts[] = {{0}};

/* Master of threads. */
struct thread_master *master;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");
}

/* SIGINT / SIGTERM handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct quagga_signal_t l3a_signals[] = {
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

#define L3A_VTY_PORT 2623

static const struct frr_yang_module_info *l3a_yang_modules[] = {
};

FRR_DAEMON_INFO(l3accessd, L3A,
	.vty_port = L3A_VTY_PORT,

	.proghelp = "Layer 3 access protocols (DHCPv6-PD & co.)",

	.signals = l3a_signals,
	.n_signals = array_size(l3a_signals),

	.privs = &l3a_privs,
	.yang_modules = l3a_yang_modules,
	.n_yang_modules = array_size(l3a_yang_modules),
)

int main(int argc, char **argv, char **envp)
{
	frr_preinit(&l3accessd_di, argc, argv);
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
	zlog_set_level(ZLOG_DEST_STDOUT, LOG_DEBUG);

	nexthop_group_init(NULL, NULL, NULL, NULL);
	vrf_init(NULL, NULL, NULL, NULL, NULL);

	access_list_init();
	route_map_init();

	l3a_route_init(master);
	l3a_zebra_init(master);
	l3a_vty_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
