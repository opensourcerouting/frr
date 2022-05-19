#include <zebra.h>

#include <lmdb.h>

#include "printfrr.h"
#include "hook.h"
#include "libfrr.h"
#include "command.h"
#include "lib/version.h"

static struct thread_master *master;
MDB_env *dbenv;

#pragma FRR printfrr_ext "%iLME" (int)

printfrr_ext_autoreg_i("LME", printfrr_lmdb_err);
static ssize_t printfrr_lmdb_err(struct fbuf *fbuf, struct printfrr_eargs *ea,
				 const uintmax_t val)
{
	return bputs(fbuf, mdb_strerror(val));
}


#ifndef VTYSH_EXTRACT_PL
#include "lmdb_clippy.c"
#endif

DEFPY (lmdb_setup,
       lmdb_setup_cmd,
       "persistent-state lmdb DIRECTORY",
       "Configure persistent state (DHCP leases, snooping tables) storage\n"
       "Use LMDB datastore\n"
       "LMDB directory\n")
{
	int rc;
	struct stat st;

	if (dbenv) {
		vty_out(vty, "database already configured (TODO)\n");
		return CMD_WARNING;
	}

	rc = mdb_env_create(&dbenv);
	if (rc || !dbenv) {
		vty_out(vty, "%% failed to create LMDB environment: %iLME\n",
			rc);
		return CMD_WARNING;
	}

	rc = stat(directory, &st);
	if (rc) {
		if (errno != ENOENT) {
			vty_out(vty, "%% cannot access %pSQq: %m", directory);
			return CMD_WARNING;
		}
		rc = mkdir(directory, 0770);
		if (rc) {
			vty_out(vty, "%% cannot create %pSQq: %m", directory);
			return CMD_WARNING;
		}
	}

	rc = mdb_env_open(dbenv, directory, 0, 0660);
	if (rc) {
		vty_out(vty, "%% failed to open LMDB environment %pSQq: %iLME\n",
			directory, rc);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

static int accessd_lmdb_init(struct thread_master *tm)
{
	master = tm;
	zlog_info("LMDB init");

	install_element(CONFIG_NODE, &lmdb_setup_cmd);
	return 0;
}

static int accessd_lmdb_module_init(void)
{
	hook_register(frr_late_init, accessd_lmdb_init);
	return 0;
}

FRR_MODULE_SETUP(
	.name = "accessd_lmdb",
	.version = FRR_VERSION,
	.description = "accessd LMDB persistent storage",
	.init = accessd_lmdb_module_init,
);
