/*
 * Copyright (C) 2020 Volta Networks, Inc
 *                     Brady Johnson
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <pcep_utils_counters.h>
#include <pcep_session_logic.h>

#include "log.h"
#include "command.h"
#include "libfrr.h"
#include "printfrr.h"
#include "version.h"
#include "northbound.h"
#include "frr_pthread.h"
#include "jhash.h"
#include "termtable.h"

#include "pathd/pathd.h"
#include "pathd/path_util.h"
#include "pathd/path_errors.h"
#include "pathd/path_pcep_memory.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_cli.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_debug.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_nb.h"
#include "pathd/path_pcep_pcc.h"

#ifndef VTYSH_EXTRACT_PL
#include "pathd/path_pcep_cli_clippy.c"
#endif

#define DEFAULT_PCE_PRECEDENCE 255
#define DEFAULT_PCC_MSD 4
#define DEFAULT_SR_DRAFT07 false
#define DEFAULT_PCE_INITIATED false
#define DEFAULT_TIMER_KEEP_ALIVE 30
#define DEFAULT_TIMER_KEEP_ALIVE_MIN 1
#define DEFAULT_TIMER_KEEP_ALIVE_MAX 120
#define DEFAULT_TIMER_DEADTIMER 120
#define DEFAULT_TIMER_DEADTIMER_MIN 4
#define DEFAULT_TIMER_DEADTIMER_MAX 480
#define DEFAULT_TIMER_PCEP_REQUEST 30
#define DEFAULT_TIMER_STATE_TIMEOUT_INTERVAL 30
#define DEFAULT_DELEGATION_TIMEOUT_INTERVAL 10

/* CLI Function declarations */
static int pcep_cli_debug_config_write(struct vty *vty);
static int pcep_cli_debug_set_all(uint32_t flags, bool set);
static int pcep_cli_pcc_config_write(struct vty *vty);
static int pcep_cli_pcc_peer_config_write(struct vty *vty);
static int pcep_cli_pcep_config_group_write(struct vty *vty);

/* Internal Util Function declarations */
static struct pce_opts_cli *pcep_cli_find_pce(const char *pce_name);
static bool pcep_cli_add_pce(struct pce_opts_cli *pce_opts_cli);
static struct pce_opts_cli *pcep_cli_create_pce_opts();
static void pcep_cli_delete_pce(const char *pce_name);
static void
pcep_cli_merge_pcep_config_group_options(struct pce_opts_cli *pce_opts_cli);
static struct pcep_config_group_opts *
pcep_cli_find_pcep_config_group(const char *group_name);
static bool pcep_cli_add_pcep_config_group(
	struct pcep_config_group_opts *config_group_opts);
static struct pcep_config_group_opts *
pcep_cli_create_pcep_config_group(const char *group_name);
static bool pcep_cli_is_pcep_config_group_used(const char *group_name);
static void pcep_cli_delete_pcep_config_group(const char *group_name);
static int
pcep_cli_print_config_group(struct pcep_config_group_opts *group_opts,
			    char *buf, size_t buf_len);
static void print_pcep_capabilities(char *buf, size_t buf_len,
				    pcep_configuration *config);
static void print_pcep_session(struct vty *vty, struct pce_opts *pce_opts,
			       struct pcep_pcc_info *pcc_info);
static bool pcep_cli_pcc_has_pce(const char *pce_name);
static void pcep_cli_add_pce_connection(struct pce_opts *pce_opts);
static void pcep_cli_remove_pce_connection(struct pce_opts *pce_opts);

/*
 * Globals.
 */

static const char PCEP_VTYSH_ARG_ADDRESS[] = "address";
static const char PCEP_VTYSH_ARG_SOURCE_ADDRESS[] = "source-address";
static const char PCEP_VTYSH_ARG_IP[] = "ip";
static const char PCEP_VTYSH_ARG_IPV6[] = "ipv6";
static const char PCEP_VTYSH_ARG_PORT[] = "port";
static const char PCEP_VTYSH_ARG_PRECEDENCE[] = "precedence";
static const char PCEP_VTYSH_ARG_MSD[] = "msd";
static const char PCEP_VTYSH_ARG_KEEP_ALIVE[] = "keep-alive";
static const char PCEP_VTYSH_ARG_KEEP_ALIVE_MIN[] = "min-peer-keep-alive";
static const char PCEP_VTYSH_ARG_KEEP_ALIVE_MAX[] = "max-peer-keep-alive";
static const char PCEP_VTYSH_ARG_DEAD_TIMER[] = "dead-timer";
static const char PCEP_VTYSH_ARG_DEAD_TIMER_MIN[] = "min-peer-dead-timer";
static const char PCEP_VTYSH_ARG_DEAD_TIMER_MAX[] = "max-peer-dead-timer";
static const char PCEP_VTYSH_ARG_PCEP_REQUEST[] = "pcep-request";
static const char PCEP_VTYSH_ARG_STATE_TIMEOUT[] = "state-timeout-interval";
static const char PCEP_VTYSH_ARG_DELEGATION_TIMEOUT[] = "delegation-timeout";
static const char PCEP_VTYSH_ARG_SR_DRAFT07[] = "sr-draft07";
static const char PCEP_VTYSH_ARG_PCE_INIT[] = "pce-inititated";
static const char PCEP_VTYSH_ARG_TCP_MD5[] = "tcp-md5-auth";
static const char PCEP_VTYSH_ARG_BASIC[] = "basic";
static const char PCEP_VTYSH_ARG_PATH[] = "path";
static const char PCEP_VTYSH_ARG_MESSAGE[] = "message";
static const char PCEP_VTYSH_ARG_PCEPLIB[] = "pceplib";
static const char PCEP_CLI_CAP_STATEFUL[] = " [Stateful PCE]";
static const char PCEP_CLI_CAP_INCL_DB_VER[] = " [Include DB version]";
static const char PCEP_CLI_CAP_LSP_TRIGGERED[] = " [LSP Triggered Resync]";
static const char PCEP_CLI_CAP_LSP_DELTA[] = " [LSP Delta Sync]";
static const char PCEP_CLI_CAP_PCE_TRIGGERED[] =
	" [PCE triggered Initial Sync]";
static const char PCEP_CLI_CAP_SR_TE_PST[] = " [SR TE PST]";
static const char PCEP_CLI_CAP_PCC_RESOLVE_NAI[] =
	" [PCC can resolve NAI to SID]";
static const char PCEP_CLI_CAP_PCC_INITIATED[] = " [PCC Initiated LSPs]";
static const char PCEP_CLI_CAP_PCC_PCE_INITIATED[] =
	" [PCC and PCE Initiated LSPs]";

struct pce_connections {
	int num_connections;
	struct pce_opts *connections[MAX_PCC];
};

struct pce_connections pce_connections_g = {.num_connections = 0};

/* Default PCE group that all PCE-Groups and PCEs will inherit from */
struct pcep_config_group_opts default_pcep_config_group_opts_g = {
	.name = "default",
	.tcp_md5_auth = "\0",
	.draft07 = DEFAULT_SR_DRAFT07,
	.pce_initiated = DEFAULT_PCE_INITIATED,
	.keep_alive_seconds = DEFAULT_TIMER_KEEP_ALIVE,
	.min_keep_alive_seconds = DEFAULT_TIMER_KEEP_ALIVE_MIN,
	.max_keep_alive_seconds = DEFAULT_TIMER_KEEP_ALIVE_MAX,
	.dead_timer_seconds = DEFAULT_TIMER_DEADTIMER,
	.min_dead_timer_seconds = DEFAULT_TIMER_DEADTIMER_MIN,
	.max_dead_timer_seconds = DEFAULT_TIMER_DEADTIMER_MAX,
	.pcep_request_time_seconds = DEFAULT_TIMER_PCEP_REQUEST,
	.state_timeout_inteval_seconds = DEFAULT_TIMER_STATE_TIMEOUT_INTERVAL,
	.delegation_timeout_seconds = DEFAULT_DELEGATION_TIMEOUT_INTERVAL,
	.source_port = DEFAULT_PCEP_TCP_PORT,
	.source_ip.ipa_type = IPADDR_NONE,
};

/* Used by PCE_GROUP_NODE sub-commands to operate on the current pce group */
struct pcep_config_group_opts *current_pcep_config_group_opts_g = NULL;
/* Used by PCC_PEER_NODE sub-commands to operate on the current pce opts */
struct pce_opts_cli *current_pce_opts_g = NULL;
short pcc_msd_g = DEFAULT_PCC_MSD;
bool pcc_msd_configured_g = false;

static struct cmd_node pcc_node = {.name = "pcep_pcc_node",
				   .node = PCC_NODE,
				   .parent_node = CONFIG_NODE,
				   .config_write = pcep_cli_pcc_config_write,
				   .prompt = "%s(config-pcc)# "};
static struct cmd_node pcc_peer_node = {.name = "pcep_pcc_peer_node",
					.node = PCC_PEER_NODE,
					.parent_node = CONFIG_NODE,
					.config_write =
						pcep_cli_pcc_peer_config_write,
					.prompt = "%s(config-pcc-peer)# "};
static struct cmd_node pcep_config_group_node = {
	.name = "pcep_pcep_config_group_node",
	.node = PCEP_CONFIG_GROUP_NODE,
	.parent_node = CONFIG_NODE,
	.config_write = pcep_cli_pcep_config_group_write,
	.prompt = "%s(pce-config-group)# "};

/* Common code used in VTYSH processing for int values */
#define PCEP_VTYSH_INT_ARG_CHECK(arg_str, arg_val, arg_store, min_value,       \
				 max_value)                                    \
	if (arg_str != NULL) {                                                 \
		if (arg_val <= min_value || arg_val >= max_value) {            \
			vty_out(vty,                                           \
				"%% Invalid value %ld in range [%d - %d]",     \
				arg_val, min_value, max_value);                \
			return CMD_WARNING;                                    \
		}                                                              \
		arg_store = arg_val;                                           \
	}

#define MERGE_COMPARE_CONFIG_GROUP_VALUE(config_param, not_set_value)          \
	pce_opts_cli->pce_opts.config_opts.config_param =                      \
		pce_opts_cli->pce_config_group_opts.config_param;              \
	if (pce_opts_cli->pce_config_group_opts.config_param                   \
	    == not_set_value) {                                                \
		pce_opts_cli->pce_opts.config_opts.config_param =              \
			((config_group != NULL                                 \
			  && config_group->config_param != not_set_value)      \
				 ? config_group->config_param                  \
				 : default_pcep_config_group_opts_g            \
					   .config_param);                     \
	}

/*
 * Internal Util functions
 */

/* Check if a pce_opts_cli already exists based on its name and return it,
 * return NULL otherwise */
static struct pce_opts_cli *pcep_cli_find_pce(const char *pce_name)
{
	for (int i = 0; i < MAX_PCE; i++) {
		struct pce_opts_cli *pce_rhs_cli = pcep_g->pce_opts_cli[i];
		if (pce_rhs_cli != NULL) {
			if (strcmp(pce_name, pce_rhs_cli->pce_opts.pce_name)
			    == 0) {
				return pce_rhs_cli;
			}
		}
	}

	return NULL;
}

/* Add a new pce_opts_cli to pcep_g, return false if MAX_PCES, true otherwise */
static bool pcep_cli_add_pce(struct pce_opts_cli *pce_opts_cli)
{
	for (int i = 0; i < MAX_PCE; i++) {
		if (pcep_g->pce_opts_cli[i] == NULL) {
			pcep_g->pce_opts_cli[i] = pce_opts_cli;
			pcep_g->num_pce_opts_cli++;
			return true;
		}
	}

	return false;
}

/* Create a new pce opts_cli */
static struct pce_opts_cli *pcep_cli_create_pce_opts(const char *name)
{
	struct pce_opts_cli *pce_opts_cli =
		XCALLOC(MTYPE_PCEP, sizeof(struct pce_opts_cli));
	strcpy(pce_opts_cli->pce_opts.pce_name, name);
	pce_opts_cli->pce_opts.port = PCEP_DEFAULT_PORT;

	return pce_opts_cli;
}

static void pcep_cli_delete_pce(const char *pce_name)
{
	for (int i = 0; i < MAX_PCE; i++) {
		if (pcep_g->pce_opts_cli[i] != NULL) {
			if (strcmp(pcep_g->pce_opts_cli[i]->pce_opts.pce_name,
				   pce_name)
			    == 0) {
				XFREE(MTYPE_PCEP, pcep_g->pce_opts_cli[i]);
				pcep_g->pce_opts_cli[i] = NULL;
				pcep_g->num_pce_opts_cli--;
				return;
			}
		}
	}
}

static void
pcep_cli_merge_pcep_config_group_options(struct pce_opts_cli *pce_opts_cli)
{
	if (pce_opts_cli->merged == true) {
		return;
	}

	struct pcep_config_group_opts *config_group =
		pcep_cli_find_pcep_config_group(
			pce_opts_cli->config_group_name);

	/* Configuration priorities:
	 * 1) pce_opts->config_opts, if present, overwrite config_group
	 * config_opts 2) config_group config_opts, if present, overwrite
	 * default config_opts 3) If neither pce_opts->config_opts nor
	 * config_group config_opts are set, then the default config_opts value
	 * will be used.
	 */

	const char *tcp_md5_auth_str =
		pce_opts_cli->pce_config_group_opts.tcp_md5_auth;
	if (pce_opts_cli->pce_config_group_opts.tcp_md5_auth[0] == '\0') {
		if (config_group != NULL
		    && config_group->tcp_md5_auth[0] != '\0') {
			tcp_md5_auth_str = config_group->tcp_md5_auth;
		} else {
			tcp_md5_auth_str =
				default_pcep_config_group_opts_g.tcp_md5_auth;
		}
	}
	strncpy(pce_opts_cli->pce_opts.config_opts.tcp_md5_auth,
		tcp_md5_auth_str, TCP_MD5SIG_MAXKEYLEN);

	struct ipaddr *source_ip =
		&pce_opts_cli->pce_config_group_opts.source_ip;
	if (pce_opts_cli->pce_config_group_opts.source_ip.ipa_type
	    == IPADDR_NONE) {
		if (config_group != NULL
		    && config_group->source_ip.ipa_type != IPADDR_NONE) {
			source_ip = &config_group->source_ip;
		} else {
			source_ip = &default_pcep_config_group_opts_g.source_ip;
		}
	}
	memcpy(&pce_opts_cli->pce_opts.config_opts.source_ip, source_ip,
	       sizeof(struct ipaddr));

	MERGE_COMPARE_CONFIG_GROUP_VALUE(draft07, false);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(pce_initiated, false);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(keep_alive_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(min_keep_alive_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(max_keep_alive_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(dead_timer_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(min_dead_timer_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(max_dead_timer_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(pcep_request_time_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(state_timeout_inteval_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(delegation_timeout_seconds, 0);
	MERGE_COMPARE_CONFIG_GROUP_VALUE(source_port, 0);

	pce_opts_cli->merged = true;
}

/* Check if a pcep_config_group_opts already exists based on its name and return
 * it, return NULL otherwise */
static struct pcep_config_group_opts *
pcep_cli_find_pcep_config_group(const char *group_name)
{
	for (int i = 0; i < MAX_PCE; i++) {
		struct pcep_config_group_opts *pcep_config_group_rhs =
			pcep_g->config_group_opts[i];
		if (pcep_config_group_rhs != NULL) {
			if (strcmp(group_name, pcep_config_group_rhs->name)
			    == 0) {
				return pcep_config_group_rhs;
			}
		}
	}

	return NULL;
}

/* Add a new pcep_config_group_opts to pcep_g, return false if MAX_PCE,
 * true otherwise */
static bool pcep_cli_add_pcep_config_group(
	struct pcep_config_group_opts *pcep_config_group_opts)
{
	for (int i = 0; i < MAX_PCE; i++) {
		if (pcep_g->config_group_opts[i] == NULL) {
			pcep_g->config_group_opts[i] = pcep_config_group_opts;
			pcep_g->num_config_group_opts++;
			return true;
		}
	}

	return false;
}

/* Create a new pce group, inheriting its values from the default pce group */
static struct pcep_config_group_opts *
pcep_cli_create_pcep_config_group(const char *group_name)
{
	struct pcep_config_group_opts *pcep_config_group_opts =
		XCALLOC(MTYPE_PCEP, sizeof(struct pcep_config_group_opts));
	strcpy(pcep_config_group_opts->name, group_name);

	return pcep_config_group_opts;
}

/* Iterate the pce_opts and return true if the pce-group-name is referenced,
 * false otherwise. */
static bool pcep_cli_is_pcep_config_group_used(const char *group_name)
{
	for (int i = 0; i < MAX_PCE; i++) {
		if (pcep_g->pce_opts_cli[i] != NULL) {
			if (strcmp(pcep_g->pce_opts_cli[i]->config_group_name,
				   group_name)
			    == 0) {
				return true;
			}
		}
	}

	return false;
}

static void pcep_cli_delete_pcep_config_group(const char *group_name)
{
	for (int i = 0; i < MAX_PCE; i++) {
		if (pcep_g->config_group_opts[i] != NULL) {
			if (strcmp(pcep_g->config_group_opts[i]->name,
				   group_name)
			    == 0) {
				XFREE(MTYPE_PCEP, pcep_g->config_group_opts[i]);
				pcep_g->config_group_opts[i] = NULL;
				pcep_g->num_config_group_opts--;
				return;
			}
		}
	}
}

static bool pcep_cli_pcc_has_pce(const char *pce_name)
{
	for (int i = 0; i < MAX_PCC; i++) {
		struct pce_opts *pce_opts = pce_connections_g.connections[i];
		if (pce_opts == NULL) {
			continue;
		}

		if (strcmp(pce_opts->pce_name, pce_name) == 0) {
			return true;
		}
	}

	return false;
}

static void pcep_cli_add_pce_connection(struct pce_opts *pce_opts)
{
	for (int i = 0; i < MAX_PCC; i++) {
		if (pce_connections_g.connections[i] == NULL) {
			pce_connections_g.num_connections++;
			pce_connections_g.connections[i] = pce_opts;
			return;
		}
	}
}

static void pcep_cli_remove_pce_connection(struct pce_opts *pce_opts)
{
	for (int i = 0; i < MAX_PCC; i++) {
		if (pce_connections_g.connections[i] == pce_opts) {
			pce_connections_g.num_connections--;
			pce_connections_g.connections[i] = NULL;
			return;
		}
	}
}

/*
 * VTY command implementations
 */

static int path_pcep_cli_debug(struct vty *vty, const char *no_str,
			       const char *basic_str, const char *path_str,
			       const char *message_str, const char *pceplib_str)
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = (no_str != NULL);

	DEBUG_MODE_SET(&pcep_g->dbg, mode, !no);

	if (basic_str != NULL) {
		DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_BASIC, !no);
	}
	if (path_str != NULL) {
		DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PATH, !no);
	}
	if (message_str != NULL) {
		DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEP, !no);
	}
	if (pceplib_str != NULL) {
		DEBUG_FLAGS_SET(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEPLIB, !no);
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_show_pcep_counters(struct vty *vty)
{
	int i, j, row;
	time_t diff_time;
	struct tm *tm_info;
	char tm_buffer[26];
	struct counters_group *group;
	struct counters_subgroup *subgroup;
	struct counter *counter;
	const char *group_name, *empty_string = "";
	struct ttable *tt;
	char *table;

	group = pcep_ctrl_get_counters(pcep_g->fpt, 1);

	if (group == NULL) {
		vty_out(vty, "No counters to display.\n\n");
		return CMD_SUCCESS;
	}

	diff_time = time(NULL) - group->start_time;
	tm_info = localtime(&group->start_time);
	strftime(tm_buffer, sizeof(tm_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

	vty_out(vty, "PCEP counters since %s (%luh %lum %lus):\n", tm_buffer,
		diff_time / 3600, (diff_time / 60) % 60, diff_time % 60);

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Group|Name|Value");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	for (row = 0, i = 0; i <= group->num_subgroups; i++) {
		subgroup = group->subgroups[i];
		if (subgroup != NULL) {
			group_name = subgroup->counters_subgroup_name;
			for (j = 0; j <= subgroup->num_counters; j++) {
				counter = subgroup->counters[j];
				if (counter != NULL) {
					ttable_add_row(tt, "%s|%s|%u",
						       group_name,
						       counter->counter_name,
						       counter->counter_value);
					row++;
					group_name = empty_string;
				}
			}
			ttable_rowseps(tt, row, BOTTOM, true, '-');
		}
	}

	/* Dump the generated table. */
	table = ttable_dump(tt, "\n");
	vty_out(vty, "%s\n", table);
	XFREE(MTYPE_TMP, table);

	ttable_del(tt);

	pcep_lib_free_counters(group);

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcep_config_group(struct vty *vty,
					   const char *pcep_config_group)
{
	struct pcep_config_group_opts *config_group =
		pcep_cli_find_pcep_config_group(pcep_config_group);
	if (config_group == NULL) {
		config_group =
			pcep_cli_create_pcep_config_group(pcep_config_group);
	} else {
		vty_out(vty,
			"Notice: changes to this pce-config-group will not affect PCEs already configured with this group\n");
	}

	if (pcep_cli_add_pcep_config_group(config_group) == false) {
		vty_out(vty,
			"%% Cannot create pce-config-group, as the Maximum limit of %d pce-config-groups has been reached.\n",
			MAX_PCE);
		XFREE(MTYPE_PCEP, config_group);
		return CMD_WARNING;
	}

	current_pcep_config_group_opts_g = config_group;
	vty->node = PCEP_CONFIG_GROUP_NODE;

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcep_config_group_delete(struct vty *vty,
						  const char *pcep_config_group)
{
	struct pcep_config_group_opts *config_group =
		pcep_cli_find_pcep_config_group(pcep_config_group);
	if (config_group == NULL) {
		vty_out(vty,
			"%% Cannot delete pce-config-group, since it does not exist.\n");
		return CMD_WARNING;
	}

	if (pcep_cli_is_pcep_config_group_used(config_group->name)) {
		vty_out(vty,
			"%% Cannot delete pce-config-group, since it is in use by a peer.\n");
		return CMD_WARNING;
	}

	pcep_cli_delete_pcep_config_group(config_group->name);

	return CMD_SUCCESS;
}

static int path_pcep_cli_show_pcep_config_group(struct vty *vty,
						const char *pcep_config_group)
{
	char buf[1024] = "";

	/* Only show 1 Peer config group */
	struct pcep_config_group_opts *group_opts;
	if (pcep_config_group != NULL) {
		if (strcmp(pcep_config_group, "default") == 0) {
			group_opts = &default_pcep_config_group_opts_g;
		} else {
			group_opts = pcep_cli_find_pcep_config_group(
				pcep_config_group);
		}
		if (group_opts == NULL) {
			vty_out(vty,
				"%% peer-config-group [%s] does not exist.\n",
				pcep_config_group);
			return CMD_WARNING;
		}

		vty_out(vty, "peer-config-group: %s\n", group_opts->name);
		pcep_cli_print_config_group(group_opts, buf, sizeof(buf));
		vty_out(vty, "%s", buf);
		return CMD_SUCCESS;
	}

	/* Show all Peer config groups */
	for (int i = 0; i < MAX_PCE; i++) {
		group_opts = pcep_g->config_group_opts[i];
		if (group_opts == NULL) {
			continue;
		}

		vty_out(vty, "peer-config-group: %s\n", group_opts->name);
		pcep_cli_print_config_group(group_opts, buf, sizeof(buf));
		vty_out(vty, "%s", buf);
		buf[0] = 0;
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_peer(struct vty *vty, const char *pcc_peer_name)
{
	/* If it already exists, it will be updated in the sub-commands */
	struct pce_opts_cli *pce_opts_cli = pcep_cli_find_pce(pcc_peer_name);
	if (pce_opts_cli == NULL) {
		pce_opts_cli = pcep_cli_create_pce_opts(pcc_peer_name);

		if (!pcep_cli_add_pce(pce_opts_cli)) {
			vty_out(vty,
				"%% Cannot create PCE, as the Maximum limit of %d PCEs has been reached.\n",
				MAX_PCE);
			XFREE(MTYPE_PCEP, pce_opts_cli);
			return CMD_WARNING;
		}
	}

	current_pce_opts_g = pce_opts_cli;
	vty->node = PCC_PEER_NODE;

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_peer_delete(struct vty *vty,
					 const char *pcc_peer_name)
{
	struct pce_opts_cli *pce_opts_cli = pcep_cli_find_pce(pcc_peer_name);
	if (pce_opts_cli == NULL) {
		vty_out(vty, "%% PCC peer does not exist.\n");
		return CMD_WARNING;
	}

	if (pcep_cli_pcc_has_pce(pcc_peer_name)) {
		vty_out(vty,
			"%% Cannot delete PCC peer, since it is in use by a PCC.\n");
		return CMD_WARNING;
	}

	pcep_cli_delete_pce(pcc_peer_name);

	return CMD_SUCCESS;
}

/* Internal Util func to show an individual PCE,
 * only used by path_pcep_cli_show_pcc_peer() */
static void show_pcc_peer(struct vty *vty, struct pce_opts_cli *pce_opts_cli)
{
	struct pce_opts *pce_opts = &pce_opts_cli->pce_opts;
	vty_out(vty, "PCC Peer: %s\n", pce_opts->pce_name);

	/* Remote PCE IP address */
	if (IS_IPADDR_V6(&pce_opts->addr)) {
		vty_out(vty, "  %s %s %pI6 %s %d\n", PCEP_VTYSH_ARG_ADDRESS,
			PCEP_VTYSH_ARG_IPV6, &pce_opts->addr.ipaddr_v6,
			PCEP_VTYSH_ARG_PORT, pce_opts->port);
	} else {
		vty_out(vty, "  %s %s %pI4 %s %d\n", PCEP_VTYSH_ARG_ADDRESS,
			PCEP_VTYSH_ARG_IP, &pce_opts->addr.ipaddr_v4,
			PCEP_VTYSH_ARG_PORT, pce_opts->port);
	}

	if (pce_opts_cli->config_group_name[0] != '\0') {
		vty_out(vty, "  peer-config-group: %s\n",
			pce_opts_cli->config_group_name);
	}

	char buf[1024] = "";
	pcep_cli_print_config_group(&pce_opts->config_opts, buf, sizeof(buf));
	vty_out(vty, "%s", buf);
}

static int path_pcep_cli_show_pcc_peer(struct vty *vty, const char *pcc_peer)
{
	/* Only show 1 PCE */
	struct pce_opts_cli *pce_opts_cli;
	if (pcc_peer != NULL) {
		pce_opts_cli = pcep_cli_find_pce(pcc_peer);
		if (pce_opts_cli == NULL) {
			vty_out(vty, "%% PCE [%s] does not exist.\n", pcc_peer);
			return CMD_WARNING;
		}

		pcep_cli_merge_pcep_config_group_options(pce_opts_cli);
		show_pcc_peer(vty, pce_opts_cli);

		return CMD_SUCCESS;
	}

	/* Show all PCEs */
	for (int i = 0; i < MAX_PCE; i++) {
		pce_opts_cli = pcep_g->pce_opts_cli[i];
		if (pce_opts_cli == NULL) {
			continue;
		}

		pcep_cli_merge_pcep_config_group_options(pce_opts_cli);
		show_pcc_peer(vty, pce_opts_cli);
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_sr_draft07(struct vty *vty)
{
	struct pcep_config_group_opts *config_group = NULL;

	if (vty->node == PCC_PEER_NODE) {
		/* TODO need to see if the pce is in use, and reset the
		 * connection */
		config_group = &current_pce_opts_g->pce_config_group_opts;
		current_pce_opts_g->merged = false;
	} else if (vty->node == PCEP_CONFIG_GROUP_NODE) {
		config_group = current_pcep_config_group_opts_g;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	config_group->draft07 = true;

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_pce_initiated(struct vty *vty)
{
	struct pcep_config_group_opts *config_group = NULL;

	if (vty->node == PCC_PEER_NODE) {
		/* TODO need to see if the pce is in use, and reset the
		 * connection */
		config_group = &current_pce_opts_g->pce_config_group_opts;
		current_pce_opts_g->merged = false;
	} else if (vty->node == PCEP_CONFIG_GROUP_NODE) {
		config_group = current_pcep_config_group_opts_g;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	config_group->pce_initiated = true;

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_tcp_md5_auth(struct vty *vty,
					   const char *tcp_md5_auth)
{
	struct pcep_config_group_opts *config_group = NULL;

	if (vty->node == PCC_PEER_NODE) {
		/* TODO need to see if the pce is in use, and reset the
		 * connection */
		config_group = &current_pce_opts_g->pce_config_group_opts;
		current_pce_opts_g->merged = false;
	} else if (vty->node == PCEP_CONFIG_GROUP_NODE) {
		config_group = current_pcep_config_group_opts_g;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	strncpy(config_group->tcp_md5_auth, tcp_md5_auth, TCP_MD5SIG_MAXKEYLEN);

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_address(struct vty *vty, const char *ip_str,
				      struct in_addr *ip, const char *ipv6_str,
				      struct in6_addr *ipv6,
				      const char *port_str, long port)
{
	struct pce_opts *pce_opts = NULL;
	if (vty->node == PCC_PEER_NODE) {
		/* TODO need to see if the pce is in use, and reset the
		 * connection */
		pce_opts = &current_pce_opts_g->pce_opts;
		current_pce_opts_g->merged = false;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	if (ipv6_str != NULL) {
		pce_opts->addr.ipa_type = IPADDR_V6;
		memcpy(&pce_opts->addr.ipaddr_v6, ipv6,
		       sizeof(struct in6_addr));
	} else if (ip_str != NULL) {
		pce_opts->addr.ipa_type = IPADDR_V4;
		memcpy(&pce_opts->addr.ipaddr_v4, ip, sizeof(struct in_addr));
	} else {
		return CMD_ERR_NO_MATCH;
	}

	/* Handle the optional port */
	pce_opts->port = PCEP_DEFAULT_PORT;
	PCEP_VTYSH_INT_ARG_CHECK(port_str, port, pce_opts->port, 0, 65535);

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_source_address(struct vty *vty,
					     const char *ip_str,
					     struct in_addr *ip,
					     const char *ipv6_str,
					     struct in6_addr *ipv6,
					     const char *port_str, long port)
{
	struct pcep_config_group_opts *config_group = NULL;
	if (vty->node == PCC_PEER_NODE) {
		/* TODO need to see if the pce is in use, and reset the
		 * connection */
		config_group = &current_pce_opts_g->pce_config_group_opts;
		current_pce_opts_g->merged = false;
	} else if (vty->node == PCEP_CONFIG_GROUP_NODE) {
		config_group = current_pcep_config_group_opts_g;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	/* Handle the optional source IP */
	if (ipv6_str != NULL) {
		config_group->source_ip.ipa_type = IPADDR_V6;
		memcpy(&config_group->source_ip.ipaddr_v6, ipv6,
		       sizeof(struct in6_addr));
	} else if (ip_str != NULL) {
		config_group->source_ip.ipa_type = IPADDR_V4;
		memcpy(&config_group->source_ip.ipaddr_v4, ip,
		       sizeof(struct in_addr));
	}

	/* Handle the optional port */
	PCEP_VTYSH_INT_ARG_CHECK(port_str, port, config_group->source_port, 0,
				 65535);

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_pcep_config_group(struct vty *vty,
						const char *config_group_name)
{
	if (vty->node == PCC_PEER_NODE) {
		/* TODO need to see if the pce is in use, and reset the
		 * connection */
		current_pce_opts_g->merged = false;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	struct pcep_config_group_opts *config_group =
		pcep_cli_find_pcep_config_group(config_group_name);
	if (config_group == NULL) {
		vty_out(vty, "%% pce-config-group [%s] does not exist.\n",
			config_group_name);
		return CMD_WARNING;
	}

	strcpy(current_pce_opts_g->config_group_name, config_group_name);

	return CMD_SUCCESS;
}

static int path_pcep_cli_peer_timers(
	struct vty *vty, const char *keep_alive_str, long keep_alive,
	const char *min_peer_keep_alive_str, long min_peer_keep_alive,
	const char *max_peer_keep_alive_str, long max_peer_keep_alive,
	const char *dead_timer_str, long dead_timer,
	const char *min_peer_dead_timer_str, long min_peer_dead_timer,
	const char *max_peer_dead_timer_str, long max_peer_dead_timer,
	const char *pcep_request_str, long pcep_request,
	const char *state_timeout_interval_str, long state_timeout_interval,
	const char *delegation_timeout_str, long delegation_timeout)
{
	struct pcep_config_group_opts *config_group = NULL;
	if (vty->node == PCC_PEER_NODE) {
		/* TODO need to see if the pce is in use, and reset the
		 * connection */
		config_group = &current_pce_opts_g->pce_config_group_opts;
		current_pce_opts_g->merged = false;
	} else if (vty->node == PCEP_CONFIG_GROUP_NODE) {
		config_group = current_pcep_config_group_opts_g;
	} else {
		return CMD_ERR_NO_MATCH;
	}

	/* Handle the arguments */
	PCEP_VTYSH_INT_ARG_CHECK(keep_alive_str, keep_alive,
				 config_group->keep_alive_seconds, 0, 241);
	PCEP_VTYSH_INT_ARG_CHECK(min_peer_keep_alive_str, min_peer_keep_alive,
				 config_group->min_keep_alive_seconds, 0, 61);
	PCEP_VTYSH_INT_ARG_CHECK(max_peer_keep_alive_str, max_peer_keep_alive,
				 config_group->max_keep_alive_seconds, 59, 241);
	PCEP_VTYSH_INT_ARG_CHECK(dead_timer_str, dead_timer,
				 config_group->dead_timer_seconds, 0, 961);
	PCEP_VTYSH_INT_ARG_CHECK(min_peer_dead_timer_str, min_peer_dead_timer,
				 config_group->min_dead_timer_seconds, 3, 61);
	PCEP_VTYSH_INT_ARG_CHECK(max_peer_dead_timer_str, max_peer_dead_timer,
				 config_group->max_dead_timer_seconds, 59, 961);
	PCEP_VTYSH_INT_ARG_CHECK(pcep_request_str, pcep_request,
				 config_group->pcep_request_time_seconds, 0,
				 121);
	PCEP_VTYSH_INT_ARG_CHECK(
		state_timeout_interval_str, state_timeout_interval,
		config_group->state_timeout_inteval_seconds, 0, 121);
	PCEP_VTYSH_INT_ARG_CHECK(delegation_timeout_str, delegation_timeout,
				 config_group->delegation_timeout_seconds, 0,
				 61);

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc(struct vty *vty)
{
	VTY_PUSH_CONTEXT_NULL(PCC_NODE);

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_delete(struct vty *vty)
{
	/* Clear the pce_connections */
	memset(&pce_connections_g, 0, sizeof(pce_connections_g));
	pcc_msd_configured_g = false;

	pcep_ctrl_remove_pcc(pcep_g->fpt, NULL);

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_pcc_msd(struct vty *vty, const char *msd_str,
				     long msd)
{
	pcc_msd_configured_g = true;
	PCEP_VTYSH_INT_ARG_CHECK(msd_str, msd, pcc_msd_g, 0, 17);

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_pcc_peer(struct vty *vty, const char *peer_name,
				      const char *precedence_str,
				      long precedence)
{
	/* Check if the pcc-peer exists */
	struct pce_opts_cli *pce_opts_cli = pcep_cli_find_pce(peer_name);
	if (pce_opts_cli == NULL) {
		vty_out(vty, "%% PCE [%s] does not exist.\n", peer_name);
		return CMD_WARNING;
	}
	struct pce_opts *pce_opts = &pce_opts_cli->pce_opts;

	/* Check if the pcc-peer is duplicated */
	if (pcep_cli_pcc_has_pce(peer_name)) {
		vty_out(vty, "%% The peer [%s] has already been configured.\n",
			peer_name);
		return CMD_WARNING;
	}

	/* Get the optional precedence argument */
	pce_opts->precedence = DEFAULT_PCE_PRECEDENCE;
	PCEP_VTYSH_INT_ARG_CHECK(precedence_str, precedence,
				 pce_opts->precedence, 0, 256);

	/* Finalize the pce_opts config values */
	pcep_cli_merge_pcep_config_group_options(pce_opts_cli);
	pcep_cli_add_pce_connection(&pce_opts_cli->pce_opts);

	/* Verify the PCE has the IP set */
	struct in6_addr zero_v6_addr;
	memset(&zero_v6_addr, 0, sizeof(struct in6_addr));
	if (memcmp(&pce_opts->addr.ip, &zero_v6_addr, IPADDRSZ(&pce_opts->addr))
	    == 0) {
		vty_out(vty,
			"%% The peer [%s] does not have an IP set and cannot be used until it does.\n",
			peer_name);
		return CMD_WARNING;
	}

	/* Update the pcc_opts with the source ip, port, and msd */
	struct pcc_opts *pcc_opts_copy =
		XMALLOC(MTYPE_PCEP, sizeof(struct pcc_opts));
	memcpy(&pcc_opts_copy->addr,
	       &pce_opts_cli->pce_opts.config_opts.source_ip,
	       sizeof(struct pcc_opts));
	pcc_opts_copy->msd = pcc_msd_g;
	pcc_opts_copy->port = pce_opts_cli->pce_opts.config_opts.source_port;
	if (pcep_ctrl_update_pcc_options(pcep_g->fpt, pcc_opts_copy)) {
		return CMD_WARNING;
	}

	/* Send a copy of the pce_opts, this one is only used for the CLI */
	struct pce_opts *pce_opts_copy =
		XMALLOC(MTYPE_PCEP, sizeof(struct pce_opts));
	memcpy(pce_opts_copy, pce_opts, sizeof(struct pce_opts));
	if (pcep_ctrl_update_pce_options(pcep_g->fpt, pce_opts_copy)) {
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_pcc_peer_delete(struct vty *vty,
					     const char *peer_name,
					     const char *precedence_str,
					     long precedence)
{
	/* Check if the pcc-peer is connected to the PCC */
	if (!pcep_cli_pcc_has_pce(peer_name)) {
		vty_out(vty, "%% The peer [%s] is not connected to the PCC.\n",
			peer_name);
		return CMD_WARNING;
	}

	struct pce_opts_cli *pce_opts_cli = pcep_cli_find_pce(peer_name);
	pcep_cli_remove_pce_connection(&pce_opts_cli->pce_opts);

	/* Send a copy of the pce_opts, this one is used for CLI only */
	struct pce_opts *pce_opts_copy =
		XMALLOC(MTYPE_PCEP, sizeof(struct pce_opts));
	memcpy(pce_opts_copy, &pce_opts_cli->pce_opts, sizeof(struct pce_opts));
	pcep_ctrl_remove_pcc(pcep_g->fpt, pce_opts_copy);

	return CMD_SUCCESS;
}

static int path_pcep_cli_show_pcc(struct vty *vty)
{
	vty_out(vty, "pcc msd %d\n", pcc_msd_g);

	return CMD_SUCCESS;
}

/* Internal util function to print pcep capabilities to a buffer */
static void print_pcep_capabilities(char *buf, size_t buf_len,
				    pcep_configuration *config)
{
	if (config->support_stateful_pce_lsp_update) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_STATEFUL);
	}
	if (config->support_include_db_version) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_INCL_DB_VER);
	}
	if (config->support_lsp_triggered_resync) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_LSP_TRIGGERED);
	}
	if (config->support_lsp_delta_sync) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_LSP_DELTA);
	}
	if (config->support_pce_triggered_initial_sync) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_PCE_TRIGGERED);
	}
	if (config->support_sr_te_pst) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_SR_TE_PST);
	}
	if (config->pcc_can_resolve_nai_to_sid) {
		csnprintfrr(buf, buf_len, "%s", PCEP_CLI_CAP_PCC_RESOLVE_NAI);
	}
}

/* Internal util function to print a pcep session */
static void print_pcep_session(struct vty *vty, struct pce_opts *pce_opts,
			       struct pcep_pcc_info *pcc_info)
{
	char buf[1024];
	buf[0] = '\0';

	vty_out(vty, "\nPCE %s\n", pce_opts->pce_name);

	/* PCE IP */
	if (IS_IPADDR_V4(&pce_opts->addr)) {
		vty_out(vty, " PCE IP %pI4 port %d\n",
			&pce_opts->addr.ipaddr_v4, pce_opts->port);
	} else if (IS_IPADDR_V6(&pce_opts->addr)) {
		vty_out(vty, " PCE IPv6 %pI6 port %d\n",
			&pce_opts->addr.ipaddr_v6, pce_opts->port);
	}

	/* PCC IP */
	if (IS_IPADDR_V4(&pcc_info->pcc_addr)) {
		vty_out(vty, " PCC IP %pI4 port %d\n",
			&pcc_info->pcc_addr.ipaddr_v4, pcc_info->pcc_port);
	} else if (IS_IPADDR_V6(&pcc_info->pcc_addr)) {
		vty_out(vty, " PCC IPv6 %pI6 port %d\n",
			&pcc_info->pcc_addr.ipaddr_v6, pcc_info->pcc_port);
	}
	vty_out(vty, " PCC MSD %d\n", pcc_info->msd);

	if (pcc_info->status == PCEP_PCC_OPERATING) {
		vty_out(vty, " Session Status UP\n");
	} else {
		vty_out(vty, " Session Status %s\n",
			pcc_status_name(pcc_info->status));
	}

	if (pcc_info->is_best_multi_pce) {
		vty_out(vty, " MultiPCE precedence %d, best candidate\n",
			((pcc_info->precedence > 0) ? pcc_info->precedence
						    : DEFAULT_PCE_PRECEDENCE));
	} else {
		vty_out(vty, " MultiPCE precedence %d\n",
			((pcc_info->precedence > 0) ? pcc_info->precedence
						    : DEFAULT_PCE_PRECEDENCE));
	}

	/* Config Options values */
	struct pcep_config_group_opts *config_opts = &pce_opts->config_opts;
	vty_out(vty, " Timer: KeepAlive %d\n", config_opts->keep_alive_seconds);
	vty_out(vty, " Timer: DeadTimer %d\n", config_opts->dead_timer_seconds);
	vty_out(vty, " Timer: PcRequest %d\n",
		config_opts->pcep_request_time_seconds);
	vty_out(vty, " Timer: StateTimeout Interval %d\n",
		config_opts->state_timeout_inteval_seconds);
	vty_out(vty, " Timer: Delegation Timeout %d\n",
		config_opts->delegation_timeout_seconds);
	if (strlen(config_opts->tcp_md5_auth) > 0) {
		vty_out(vty, " TCP MD5 Auth Str: %s\n",
			config_opts->tcp_md5_auth);
	} else {
		vty_out(vty, " No TCP MD5 Auth\n");
	}

	if (config_opts->draft07) {
		vty_out(vty, " PCE SR Version draft07\n");
	} else {
		vty_out(vty, " PCE SR Version draft16 and RFC8408\n");
	}

	vty_out(vty, " Next PcReq ID %d\n", pcc_info->next_reqid);
	vty_out(vty, " Next PLSP  ID %d\n", pcc_info->next_plspid);

	/* PCEPlib pcep session values, get a thread safe copy of the counters
	 */
	pcep_session *session =
		pcep_ctrl_get_pcep_session(pcep_g->fpt, pcc_info->pcc_id);
	if (session != NULL) {
		if (pcc_info->status == PCEP_PCC_SYNCHRONIZING
		    || pcc_info->status == PCEP_PCC_OPERATING) {
			time_t current_time = time(NULL);
			struct tm lt;
			lt.tm_zone = __tzname[0];
			gmtime_r(&session->time_connected, &lt);
			vty_out(vty,
				" Connected for %ld seconds, since %d-%02d-%02d %02d:%02d:%02d UTC\n",
				(current_time - session->time_connected),
				lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
				lt.tm_hour, lt.tm_min, lt.tm_sec);
		}

		/* PCC capabilities */
		buf[0] = '\0';
		int index = 0;
		if (config_opts->pce_initiated) {
			index += csnprintfrr(buf, sizeof(buf), "%s",
					     PCEP_CLI_CAP_PCC_PCE_INITIATED);
		} else {
			index += csnprintfrr(buf, sizeof(buf), "%s",
					     PCEP_CLI_CAP_PCC_INITIATED);
		}
		print_pcep_capabilities(buf, sizeof(buf) - index,
					&session->pcc_config);
		vty_out(vty, " PCC Capabilities:%s\n", buf);

		/* PCE capabilities */
		buf[0] = '\0';
		print_pcep_capabilities(buf, sizeof(buf), &session->pce_config);
		if (buf[0] != '\0') {
			vty_out(vty, " PCE Capabilities:%s\n", buf);
		}
		XFREE(MTYPE_PCEP, session);
	} else {
		vty_out(vty, " Detailed session information not available\n");
	}

	/* Message Counters, get a thread safe copy of the counters */
	struct counters_group *group =
		pcep_ctrl_get_counters(pcep_g->fpt, pcc_info->pcc_id);

	if (group != NULL) {
		struct counters_subgroup *rx_msgs =
			find_subgroup(group, COUNTER_SUBGROUP_ID_RX_MSG);
		struct counters_subgroup *tx_msgs =
			find_subgroup(group, COUNTER_SUBGROUP_ID_TX_MSG);

		if (rx_msgs != NULL && tx_msgs != NULL) {
			vty_out(vty, " PCEP Message Statistics\n");
			vty_out(vty, " %27s %6s\n", "Sent", "Rcvd");
			for (int i = 0; i < rx_msgs->max_counters; i++) {
				struct counter *rx_counter =
					rx_msgs->counters[i];
				struct counter *tx_counter =
					tx_msgs->counters[i];
				if (rx_counter != NULL && tx_counter != NULL) {
					vty_out(vty, " %20s: %5d  %5d\n",
						tx_counter->counter_name,
						tx_counter->counter_value,
						rx_counter->counter_value);
				}
			}
			vty_out(vty, " %20s: %5d  %5d\n", "Total",
				subgroup_counters_total(tx_msgs),
				subgroup_counters_total(rx_msgs));
		}
		pcep_lib_free_counters(group);
	} else {
		vty_out(vty, " Counters not available\n");
	}

	XFREE(MTYPE_PCEP, pcc_info);
}

static int path_pcep_cli_show_pcep_session(struct vty *vty,
					   const char *pcc_peer)
{
	struct pce_opts_cli *pce_opts_cli;
	struct pcep_pcc_info *pcc_info;

	/* Only show 1 PCEP session */
	if (pcc_peer != NULL) {
		pce_opts_cli = pcep_cli_find_pce(pcc_peer);
		if (pce_opts_cli == NULL) {
			vty_out(vty, "%% PCE [%s] does not exist.\n", pcc_peer);
			return CMD_WARNING;
		}

		if (!pcep_cli_pcc_has_pce(pcc_peer)) {
			vty_out(vty, "%% PCC is not connected to PCE [%s].\n",
				pcc_peer);
			return CMD_WARNING;
		}

		pcc_info = pcep_ctrl_get_pcc_info(pcep_g->fpt, pcc_peer);
		if (pcc_info == NULL) {
			vty_out(vty,
				"%% Cannot retrieve PCEP session info for PCE [%s]\n",
				pcc_peer);
			return CMD_WARNING;
		}

		print_pcep_session(vty, &pce_opts_cli->pce_opts, pcc_info);

		return CMD_SUCCESS;
	}

	/* Show all PCEP sessions */
	struct pce_opts *pce_opts;
	int num_pcep_sessions = 0;
	for (int i = 0; i < MAX_PCC; i++) {
		pce_opts = pce_connections_g.connections[i];
		if (pce_opts == NULL) {
			continue;
		}

		pcc_info =
			pcep_ctrl_get_pcc_info(pcep_g->fpt, pce_opts->pce_name);
		if (pcc_info == NULL) {
			vty_out(vty,
				"%% Cannot retrieve PCEP session info for PCE [%s]\n",
				pce_opts->pce_name);
			continue;
		}

		num_pcep_sessions++;
		print_pcep_session(vty, pce_opts, pcc_info);
	}

	vty_out(vty, "\nConnected PCEP Sessions: %d\n", num_pcep_sessions);

	return CMD_SUCCESS;
}

static int path_pcep_cli_clear_pcep_session(struct vty *vty,
					    const char *pcc_peer)
{
	struct pce_opts_cli *pce_opts_cli;
	struct pcep_pcc_info *pcc_info;

	/* Only clear 1 PCEP session */
	if (pcc_peer != NULL) {
		pce_opts_cli = pcep_cli_find_pce(pcc_peer);
		if (pce_opts_cli == NULL) {
			vty_out(vty, "%% PCE [%s] does not exist.\n", pcc_peer);
			return CMD_WARNING;
		}

		if (!pcep_cli_pcc_has_pce(pcc_peer)) {
			vty_out(vty, "%% PCC is not connected to PCE [%s].\n",
				pcc_peer);
			return CMD_WARNING;
		}

		pcep_ctrl_reset_pcc_session(pcep_g->fpt,
					    pce_opts_cli->pce_opts.pce_name);
		vty_out(vty, "PCEP session cleared for peer %s\n", pcc_peer);

		return CMD_SUCCESS;
	}

	/* Clear all PCEP sessions */
	struct pce_opts *pce_opts;
	int num_pcep_sessions = 0;
	for (int i = 0; i < MAX_PCC; i++) {
		pce_opts = pce_connections_g.connections[i];
		if (pce_opts == NULL) {
			continue;
		}

		num_pcep_sessions++;
		pcep_ctrl_reset_pcc_session(pcep_g->fpt, pce_opts->pce_name);
		vty_out(vty, "PCEP session cleared for peer %s\n",
			pce_opts->pce_name);
	}

	vty_out(vty, "Cleared [%d] PCEP sessions\n", num_pcep_sessions);

	return CMD_SUCCESS;
}

/*
 * Config Write functions
 */

int pcep_cli_debug_config_write(struct vty *vty)
{
	char buff[128] = "";

	if (DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_CONF)) {
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_BASIC))
			csnprintfrr(buff, sizeof(buff), " %s",
				    PCEP_VTYSH_ARG_BASIC);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PATH))
			csnprintfrr(buff, sizeof(buff), " %s",
				    PCEP_VTYSH_ARG_PATH);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEP))
			csnprintfrr(buff, sizeof(buff), " %s",
				    PCEP_VTYSH_ARG_MESSAGE);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEPLIB))
			csnprintfrr(buff, sizeof(buff), " %s",
				    PCEP_VTYSH_ARG_PCEPLIB);
		vty_out(vty, "debug pathd pcep%s\n", buff);
		buff[0] = 0;
		return 1;
	}

	return 0;
}

int pcep_cli_debug_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&pcep_g->dbg, flags, set);

	/* If all modes have been turned off, don't preserve options. */
	if (!DEBUG_MODE_CHECK(&pcep_g->dbg, DEBUG_MODE_ALL))
		DEBUG_CLEAR(&pcep_g->dbg);

	return 0;
}

int pcep_cli_pcc_config_write(struct vty *vty)
{
	struct pce_opts *pce_opts;
	char buf[128] = "";
	int lines = 0;

	/* The MSD, nor any PCE peers have been configured on the PCC */
	if (!pcc_msd_configured_g && pce_connections_g.num_connections == 0) {
		return lines;
	}

	vty_out(vty, "pcc\n");
	lines++;

	/* Prepare the MSD, if present */
	if (pcc_msd_configured_g) {
		vty_out(vty, " %s %d\n", PCEP_VTYSH_ARG_MSD, pcc_msd_g);
		lines++;
	}

	if (pce_connections_g.num_connections == 0) {
		return lines;
	}

	buf[0] = 0;
	for (int i = 0; i < MAX_PCC; i++) {
		pce_opts = pce_connections_g.connections[i];
		if (pce_opts == NULL) {
			continue;
		}

		/* Only show the PCEs configured in the pcc sub-command */
		if (!pcep_cli_pcc_has_pce(pce_opts->pce_name)) {
			continue;
		}

		csnprintfrr(buf, sizeof(buf), "  peer %s", pce_opts->pce_name);
		if (pce_opts->precedence > 0) {
			csnprintfrr(buf, sizeof(buf), " %s %d",
				    PCEP_VTYSH_ARG_PRECEDENCE,
				    pce_opts->precedence);
		}
		vty_out(vty, "%s\n", buf);
		lines++;
		buf[0] = 0;
	}

	return lines;
}

/* Internal function used by pcep_cli_pcc_peer_config_write()
 * and pcep_cli_pcep_config_group_write() */
static int
pcep_cli_print_config_group(struct pcep_config_group_opts *group_opts,
			    char *buf, size_t buf_len)
{
	int lines = 0;

	if (group_opts->source_ip.ipa_type != IPADDR_NONE
	    || group_opts->source_port != 0) {
		if (IS_IPADDR_V4(&group_opts->source_ip)) {
			csnprintfrr(buf, buf_len, "  %s %s %pI4",
				    PCEP_VTYSH_ARG_SOURCE_ADDRESS,
				    PCEP_VTYSH_ARG_IP,
				    &group_opts->source_ip.ipaddr_v4);
		} else if (IS_IPADDR_V6(&group_opts->source_ip)) {
			csnprintfrr(buf, buf_len, "  %s %s %pI6",
				    PCEP_VTYSH_ARG_SOURCE_ADDRESS,
				    PCEP_VTYSH_ARG_IPV6,
				    &group_opts->source_ip.ipaddr_v6);
		}
		if (group_opts->source_port > 0) {
			csnprintfrr(buf, buf_len, "  %s %d",
				    PCEP_VTYSH_ARG_PORT,
				    group_opts->source_port);
		}
		csnprintfrr(buf, buf_len, "\n");
		lines++;
	}
	if (group_opts->keep_alive_seconds > 0) {
		csnprintfrr(buf, buf_len, "  %s %d\n",
			    PCEP_VTYSH_ARG_KEEP_ALIVE,
			    group_opts->keep_alive_seconds);
		lines++;
	}
	if (group_opts->min_keep_alive_seconds > 0) {
		csnprintfrr(buf, buf_len, "  %s %d\n",
			    PCEP_VTYSH_ARG_KEEP_ALIVE_MIN,
			    group_opts->min_keep_alive_seconds);
		lines++;
	}
	if (group_opts->max_keep_alive_seconds > 0) {
		csnprintfrr(buf, buf_len, "  %s %d\n",
			    PCEP_VTYSH_ARG_KEEP_ALIVE_MAX,
			    group_opts->max_keep_alive_seconds);
		lines++;
	}
	if (group_opts->dead_timer_seconds > 0) {
		csnprintfrr(buf, buf_len, "  %s %d\n",
			    PCEP_VTYSH_ARG_DEAD_TIMER,
			    group_opts->dead_timer_seconds);
		lines++;
	}
	if (group_opts->min_dead_timer_seconds > 0) {
		csnprintfrr(buf, buf_len, "  %s %d\n",
			    PCEP_VTYSH_ARG_DEAD_TIMER_MIN,
			    group_opts->min_dead_timer_seconds);
		lines++;
	}
	if (group_opts->max_dead_timer_seconds > 0) {
		csnprintfrr(buf, buf_len, "  %s %d\n",
			    PCEP_VTYSH_ARG_DEAD_TIMER_MAX,
			    group_opts->max_dead_timer_seconds);
		lines++;
	}
	if (group_opts->pcep_request_time_seconds > 0) {
		csnprintfrr(buf, buf_len, "  %s %d\n",
			    PCEP_VTYSH_ARG_PCEP_REQUEST,
			    group_opts->pcep_request_time_seconds);
		lines++;
	}
	if (group_opts->state_timeout_inteval_seconds > 0) {
		csnprintfrr(buf, buf_len, "  %s %d\n",
			    PCEP_VTYSH_ARG_STATE_TIMEOUT,
			    group_opts->state_timeout_inteval_seconds);
		lines++;
	}
	if (group_opts->delegation_timeout_seconds > 0) {
		csnprintfrr(buf, buf_len, "  %s %d\n",
			    PCEP_VTYSH_ARG_DELEGATION_TIMEOUT,
			    group_opts->delegation_timeout_seconds);
		lines++;
	}
	if (group_opts->tcp_md5_auth[0] != '\0') {
		csnprintfrr(buf, buf_len, "  %s %s\n", PCEP_VTYSH_ARG_TCP_MD5,
			    group_opts->tcp_md5_auth);
		lines++;
	}
	if (group_opts->draft07) {
		csnprintfrr(buf, buf_len, "  %s\n", PCEP_VTYSH_ARG_SR_DRAFT07);
		lines++;
	}
	if (group_opts->pce_initiated) {
		csnprintfrr(buf, buf_len, "  %s\n", PCEP_VTYSH_ARG_PCE_INIT);
		lines++;
	}

	return lines;
}

int pcep_cli_pcc_peer_config_write(struct vty *vty)
{
	int lines = 0;
	char buf[1024] = "";

	for (int i = 0; i < MAX_PCE; i++) {
		struct pce_opts_cli *pce_opts_cli = pcep_g->pce_opts_cli[i];
		if (pce_opts_cli == NULL) {
			continue;
		}
		struct pce_opts *pce_opts = &pce_opts_cli->pce_opts;

		vty_out(vty, "pcc-peer %s\n", pce_opts->pce_name);
		if (IS_IPADDR_V6(&pce_opts->addr)) {
			vty_out(vty, "  %s %s %pI6", PCEP_VTYSH_ARG_ADDRESS,
				PCEP_VTYSH_ARG_IPV6, &pce_opts->addr.ipaddr_v6);
		} else if (IS_IPADDR_V4(&pce_opts->addr)) {
			vty_out(vty, "  address %s %pI4", PCEP_VTYSH_ARG_IP,
				&pce_opts->addr.ipaddr_v4);
		}
		if (pce_opts->port != PCEP_DEFAULT_PORT) {
			vty_out(vty, " %s %d", PCEP_VTYSH_ARG_PORT,
				pce_opts->port);
		}
		vty_out(vty, "%s\n", buf);
		lines += 2;

		if (pce_opts_cli->config_group_name[0] != '\0') {
			vty_out(vty, "  config-group %s\n",
				pce_opts_cli->config_group_name);
			lines++;
		}

		/* Only display the values configured on the PCE, not the values
		 * from its optional pce-config-group, nor the default values */
		lines += pcep_cli_print_config_group(
			&pce_opts_cli->pce_config_group_opts, buf, sizeof(buf));

		vty_out(vty, "%s", buf);
		buf[0] = '\0';
	}

	return lines;
}

int pcep_cli_pcep_config_group_write(struct vty *vty)
{
	int lines = 0;
	char buf[1024] = "";

	for (int i = 0; i < MAX_PCE; i++) {
		struct pcep_config_group_opts *group_opts =
			pcep_g->config_group_opts[i];
		if (group_opts == NULL) {
			continue;
		}

		vty_out(vty, "pce-config-group %s\n", group_opts->name);
		lines += 1;

		lines += pcep_cli_print_config_group(group_opts, buf,
						     sizeof(buf));
		vty_out(vty, "%s", buf);
		buf[0] = 0;
	}

	return lines;
}

/*
 * VTYSH command syntax definitions
 * The param names are taken from the path_pcep_cli_clippy.c generated file.
 */

DEFPY(pcep_cli_debug, pcep_cli_debug_cmd,
      "[no] debug pathd pcep [basic]$basic_str [path]$path_str [message]$message_str [pceplib]$pceplib_str",
      NO_STR DEBUG_STR
      "pathd debugging\n"
      "pcep module debugging\n"
      "module basic debugging\n"
      "path structures debugging\n"
      "pcep message debugging\n"
      "pceplib debugging\n")
{
	return path_pcep_cli_debug(vty, no, basic_str, path_str, message_str,
				   pceplib_str);
}

DEFPY(pcep_cli_show_pcep_counters, pcep_cli_show_pcep_counters_cmd,
      "show pcep counters",
      SHOW_STR
      "PCEP info\n"
      "PCEP counters\n")
{
	return path_pcep_cli_show_pcep_counters(vty);
}

DEFPY_NOSH(pcep_cli_pcep_config_group, pcep_cli_pcep_config_group_cmd,
	   "[no] pcep-config-group WORD",
	   NO_STR
	   "Peer Configuration Group\n"
	   "Peer Configuration Group name\n")
{
	if (no != NULL) {
		return path_pcep_cli_pcep_config_group_delete(
			vty, pcep_config_group);
	} else {
		return path_pcep_cli_pcep_config_group(vty, pcep_config_group);
	}
}

DEFPY(pcep_cli_show_pcep_config_group, pcep_cli_show_pcep_config_group_cmd,
      "show pcep-config-group [<default|WORD>$config_group]",
      SHOW_STR
      "Show detailed peer-config-group values\n"
      "Show default hard-coded peer-config-group values\n"
      "peer-config-group to show\n")
{
	return path_pcep_cli_show_pcep_config_group(vty, config_group);
}

DEFPY_NOSH(pcep_cli_pcc_peer, pcep_cli_pcc_peer_cmd, "[no] pcc-peer WORD",
	   NO_STR
	   "PCC Peer configuration, address sub-config is mandatory\n"
	   "PCE name\n")
{
	if (no != NULL) {
		return path_pcep_cli_pcc_peer_delete(vty, pcc_peer);
	} else {
		return path_pcep_cli_pcc_peer(vty, pcc_peer);
	}
}

DEFPY(pcep_cli_show_pcc_peer, pcep_cli_show_pcc_peer_cmd,
      "show pcc-peer [WORD]",
      SHOW_STR
      "Show detailed pcc-peer (PCE) values\n"
      "pcc-peer to show\n")
{
	return path_pcep_cli_show_pcc_peer(vty, pcc_peer);
}

DEFPY(pcep_cli_peer_sr_draft07, pcep_cli_peer_sr_draft07_cmd, "sr-draft07",
      "Configure PCC to send PCEP Open with SR draft07\n")
{
	return path_pcep_cli_peer_sr_draft07(vty);
}

DEFPY(pcep_cli_peer_pce_initiated, pcep_cli_peer_pce_initiated_cmd,
      "pce-initiated", "Configure PCC to accept PCE initiated LSPs\n")
{
	return path_pcep_cli_peer_pce_initiated(vty);
}

DEFPY(pcep_cli_peer_tcp_md5_auth, pcep_cli_peer_tcp_md5_auth_cmd,
      "tcp-md5-auth WORD",
      "Configure PCC TCP-MD5 RFC2385 Authentication\n"
      "TCP-MD5 Authentication string\n")
{
	return path_pcep_cli_peer_tcp_md5_auth(vty, tcp_md5_auth);
}

DEFPY(pcep_cli_peer_address, pcep_cli_peer_address_cmd,
      "address <ip A.B.C.D | ipv6 X:X::X:X> [port (1024-65535)]",
      "PCE IP Address configuration, mandatory configuration\n"
      "PCE IPv4 address\n"
      "Remote PCE server IPv4 address\n"
      "PCE IPv6 address\n"
      "Remote PCE server IPv6 address\n"
      "Remote PCE server port\n"
      "Remote PCE server port value\n")
{
	return path_pcep_cli_peer_address(vty, ip_str, &ip, ipv6_str, &ipv6,
					  port_str, port);
}

DEFPY(pcep_cli_peer_source_address, pcep_cli_peer_source_address_cmd,
      "source-address <ip A.B.C.D | ipv6 X:X::X:X> [port (1024-65535)]",
      "PCE source IP Address configuration\n"
      "PCE source IPv4 address\n"
      "PCE source IPv4 address value\n"
      "PCE source IPv6 address\n"
      "PCE source IPv6 address value\n"
      "Source PCE server port\n"
      "Source PCE server port value\n")
{
	return path_pcep_cli_peer_source_address(vty, ip_str, &ip, ipv6_str,
						 &ipv6, port_str, port);
}

DEFPY(pcep_cli_peer_pcep_config_group, pcep_cli_peer_pcep_config_group_cmd,
      "config-group WORD",
      "PCE Configuration Group\n"
      "PCE Configuration Group name\n")
{
	return path_pcep_cli_peer_pcep_config_group(vty, config_group);
}

DEFPY(pcep_cli_peer_timers, pcep_cli_peer_timers_cmd,
      "timer [keep-alive (1-240)] [min-peer-keep-alive (1-60)] [max-peer-keep-alive (60-240)] "
      "[dead-timer (4-480)] [min-peer-dead-timer (4-60)] [max-peer-dead-timer (60-480)] "
      "[pcep-request (1-120)] [state-timeout-interval (1-120)] [delegation-timeout (1-60)]",
      "PCE PCEP Session Timers configuration\n"
      "PCC Keep Alive Timer\n"
      "PCC Keep Alive Timer value in seconds\n"
      "Min Acceptable PCE Keep Alive Timer\n"
      "Min Acceptable PCE Keep Alive Timer value in seconds\n"
      "Max Acceptable PCE Keep Alive Timer\n"
      "Max Acceptable PCE Keep Alive Timer value in seconds\n"
      "PCC Dead Timer\n"
      "PCC Dead Timer value in seconds\n"
      "Min Acceptable PCE Dead Timer\n"
      "Min Acceptable PCE Dead Timer value in seconds\n"
      "Max Acceptable PCE Dead Timer\n"
      "Max Acceptable PCE Dead Timer value in seconds\n"
      "PCC PCEP Request Timer\n"
      "PCC PCEP Request Timer value in seconds\n"
      "PCC State Timeout Interval\n"
      "PCC State Timeout Interval value in seconds\n"
      "Multi-PCE delegation timeout\n"
      "Multi-PCE delegation timeout value in seconds\n")
{
	return path_pcep_cli_peer_timers(
		vty, keep_alive_str, keep_alive, min_peer_keep_alive_str,
		min_peer_keep_alive, max_peer_keep_alive_str,
		max_peer_keep_alive, dead_timer_str, dead_timer,
		min_peer_dead_timer_str, min_peer_dead_timer,
		max_peer_dead_timer_str, max_peer_dead_timer, pcep_request_str,
		pcep_request, state_timeout_interval_str,
		state_timeout_interval, delegation_timeout_str,
		delegation_timeout);
}

DEFPY_NOSH(pcep_cli_pcc, pcep_cli_pcc_cmd, "[no] pcc",
	   NO_STR "PCC configuration\n")
{
	if (no != NULL) {
		return path_pcep_cli_pcc_delete(vty);
	} else {
		return path_pcep_cli_pcc(vty);
	}
}

DEFPY(pcep_cli_pcc_pcc_msd, pcep_cli_pcc_pcc_msd_cmd, "msd (1-16)",
      "PCC maximum SID depth \n"
      "PCC maximum SID depth value\n")
{
	return path_pcep_cli_pcc_pcc_msd(vty, msd_str, msd);
}

DEFPY(pcep_cli_pcc_pcc_peer, pcep_cli_pcc_pcc_peer_cmd,
      "[no] peer WORD [precedence (1-255)]",
      NO_STR
      "PCC PCE peer\n"
      "PCC PCE name\n"
      "PCC Multi-PCE precedence\n"
      "PCE precedence\n")
{
	if (no != NULL) {
		return path_pcep_cli_pcc_pcc_peer_delete(
			vty, peer, precedence_str, precedence);
	} else {
		return path_pcep_cli_pcc_pcc_peer(vty, peer, precedence_str,
						  precedence);
	}
}

DEFPY_NOSH(pcep_cli_pcc_show, pcep_cli_pcc_show_cmd, "show pcc",
	   SHOW_STR "Show current PCC configuration\n")
{
	return path_pcep_cli_show_pcc(vty);
}

DEFPY(pcep_cli_show_pcep_session, pcep_cli_show_pcep_session_cmd,
      "show pcep-session [WORD]$pcc_peer",
      SHOW_STR
      "Show PCEP Session information\n"
      "PCC Peer name\n")
{
	return path_pcep_cli_show_pcep_session(vty, pcc_peer);
}

DEFPY(pcep_cli_clear_pcep_session, pcep_cli_clear_pcep_session_cmd,
      "clear pcep-session [WORD]$pcc_peer",
      CLEAR_STR
      "Reset PCEP connection\n"
      "PCC Peer name\n")
{
	return path_pcep_cli_clear_pcep_session(vty, pcc_peer);
}

void pcep_cli_init(void)
{
	hook_register(nb_client_debug_config_write,
		      pcep_cli_debug_config_write);
	hook_register(nb_client_debug_set_all, pcep_cli_debug_set_all);

	memset(&pce_connections_g, 0, sizeof(pce_connections_g));

	install_node(&pcc_node);
	install_node(&pcc_peer_node);
	install_node(&pcep_config_group_node);

	install_default(PCEP_CONFIG_GROUP_NODE);
	install_default(PCC_PEER_NODE);
	install_default(PCC_NODE);

	install_element(CONFIG_NODE, &pcep_cli_debug_cmd);
	install_element(ENABLE_NODE, &pcep_cli_debug_cmd);
	install_element(ENABLE_NODE, &pcep_cli_show_pcep_counters_cmd);

	/* PCEP-Group related commands */
	install_element(CONFIG_NODE, &pcep_cli_pcep_config_group_cmd);
	install_element(ENABLE_NODE, &pcep_cli_show_pcep_config_group_cmd);
	install_element(PCEP_CONFIG_GROUP_NODE,
			&pcep_cli_peer_source_address_cmd);
	install_element(PCEP_CONFIG_GROUP_NODE, &pcep_cli_peer_timers_cmd);
	install_element(PCEP_CONFIG_GROUP_NODE, &pcep_cli_peer_sr_draft07_cmd);
	install_element(PCEP_CONFIG_GROUP_NODE,
			&pcep_cli_peer_pce_initiated_cmd);
	install_element(PCEP_CONFIG_GROUP_NODE,
			&pcep_cli_peer_tcp_md5_auth_cmd);

	/* PCC-PEER (PCE) related commands */
	install_element(CONFIG_NODE, &pcep_cli_pcc_peer_cmd);
	install_element(ENABLE_NODE, &pcep_cli_show_pcc_peer_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_peer_address_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_peer_source_address_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_peer_pcep_config_group_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_peer_timers_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_peer_sr_draft07_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_peer_pce_initiated_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_peer_tcp_md5_auth_cmd);

	/* PCC related commands */
	install_element(ENABLE_NODE, &pcep_cli_pcc_show_cmd);
	install_element(CONFIG_NODE, &pcep_cli_pcc_cmd);
	install_element(PCC_NODE, &pcep_cli_pcc_pcc_peer_cmd);
	install_element(PCC_NODE, &pcep_cli_pcc_pcc_msd_cmd);

	install_element(ENABLE_NODE, &pcep_cli_show_pcep_session_cmd);
	install_element(ENABLE_NODE, &pcep_cli_clear_pcep_session_cmd);
}
