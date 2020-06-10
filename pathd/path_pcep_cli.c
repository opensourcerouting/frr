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
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_nb.h"

#define DEFAULT_PCC_MSD 4
#define DEFAULT_SR_DRAFT07 false
#define DEFAULT_PCE_INITIATED false
#define DEFAULT_TIMER_KEEP_ALIVE 30
#define DEFAULT_TIMER_KEEP_ALIVE_MIN 1
#define DEFAULT_TIMER_KEEP_ALIVE_MAX 120
#define DEFAULT_TIMER_DEADTIMER 120
#define DEFAULT_TIMER_DEADTIMER_MIN 60
#define DEFAULT_TIMER_DEADTIMER_MAX 240
#define DEFAULT_TIMER_PCEP_REQUEST 30
#define DEFAULT_TIMER_TIMEOUT_INTERVAL 30

/*
 * Globals.
 */

static const char PCEP_VTYSH_ARG_ADDRESS[] = "address";
static const char PCEP_VTYSH_ARG_IP[] = "ip";
static const char PCEP_VTYSH_ARG_IPV6[] = "ipv6";
static const char PCEP_VTYSH_ARG_PORT[] = "port";
static const char PCEP_VTYSH_ARG_PRIORITY[] = "priority";
static const char PCEP_VTYSH_ARG_MSD[] = "msd";
static const char PCEP_VTYSH_ARG_KEEP_ALIVE[] = "keep-alive-timer";
static const char PCEP_VTYSH_ARG_KEEP_ALIVE_MIN[] = "min-pce-keep-alive-timer";
static const char PCEP_VTYSH_ARG_KEEP_ALIVE_MAX[] = "max-pce-keep-alive-timer";
static const char PCEP_VTYSH_ARG_DEAD_TIMER[] = "dead-timer";
static const char PCEP_VTYSH_ARG_DEAD_TIMER_MIN[] = "min-pce-dead-timer";
static const char PCEP_VTYSH_ARG_DEAD_TIMER_MAX[] = "max-pce-dead-timer";
static const char PCEP_VTYSH_ARG_PCEP_REQUEST[] = "pcep-request-timer";
static const char PCEP_VTYSH_ARG_STATE_TIMEOUT[] = "state-timeout-interval";
static const char PCEP_VTYSH_ARG_SR_DRAFT07[] = "sr-draft07";
static const char PCEP_VTYSH_ARG_PCE_INIT[] = "pce-inititated";
static const char PCEP_VTYSH_ARG_TCP_MD5[] = "tcp-md5-auth";
static const char PCEP_VTYSH_ARG_BASIC[] = "basic";
static const char PCEP_VTYSH_ARG_PATH[] = "path";
static const char PCEP_VTYSH_ARG_MESSAGE[] = "message";
static const char PCEP_VTYSH_ARG_PCEPLIB[] = "pceplib";
static const char PCEP_VTYSH_NO_CMD[] = "no";

/* Default PCE group that all PCE-Groups and PCEs will inherit from */
struct pce_config_group_opts default_pce_config_group_opts = {
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
    .state_timeout_inteval_seconds = DEFAULT_TIMER_TIMEOUT_INTERVAL,
};

/* Used by PCE_GROUP_NODE sub-commands to operate on the current pce group */
struct pce_config_group_opts *current_pce_config_group_opts_g = NULL;
/* Used by PCC_PEER_NODE sub-commands to operate on the current pce opts */
struct pce_opts *current_pce_opts_g = NULL;

    // TODO un-comment these when the code is rebased
static struct cmd_node pcc_node = {
        //.name = "pcep_pcc_node",
        .node = PCC_NODE,
        //.parent_node = CONFIG_NODE,
        //.config_write = pcep_cli_pcc_config_write,
        .prompt = "%s(config-pcc)# "};
static struct cmd_node pcc_peer_node = {
        //.name = "pcep_pcc_peer_node",
        .node = PCC_PEER_NODE,
        //.parent_node = CONFIG_NODE,
        //.config_write = pcep_cli_pce_config_write,
        .prompt = "%s(config-pcc-peer)# "};
static struct cmd_node pce_config_group_node = {
        //.name = "pcep_pce_config_group_node",
        .node = PCE_CONFIG_GROUP_NODE,
        //.parent_node = CONFIG_NODE,
        //.config_write = pcep_cli_pce_config_group_write,
        .prompt = "%s(pce-config-group)# "};

/* Common code used in VTYSH processing for int values */
#define PCEP_VTYSH_INT_ARG_CHECK(index, arg_store, min_value, max_value) \
	index++;                                                 \
	if (index >= argc) {                                     \
		return CMD_ERR_NO_MATCH;                             \
	}                                                        \
	arg_store = atoi(argv[index]->arg);                      \
	if (arg_store <= min_value || arg_store >= max_value) {  \
		return CMD_ERR_INCOMPLETE;                           \
	}

#define MERGE_COMPARE_CONFIG_GROUP_VALUE(config_param, comp_value) \
    pce_opts->merged_opts.config_param = pce_opts->config_opts.config_param;  \
    if (pce_opts->config_opts.config_param == comp_value) {                   \
        pce_opts->merged_opts.config_param =                                   \
            (config_group != NULL && config_group->config_param == comp_value) \
                    ? config_group->config_param :                             \
                    default_pce_config_group_opts.config_param;                \
    }


/* CLI Function declarations */
static int pcep_cli_debug_config_write(struct vty *vty);
static int pcep_cli_debug_set_all(uint32_t flags, bool set);
static int pcep_cli_pcc_config_write(struct vty *vty);
static int pcep_cli_pce_config_write(struct vty *vty);
static int pcep_cli_pce_config_group_write(struct vty *vty);

/* Internal Util Function declarations */
static struct pce_opts *pcep_cli_find_pce(const char *pce_name);
static bool pcep_cli_add_pce(struct pce_opts *pce_opts);
static struct pce_opts *pcep_cli_create_pce_opts();
static bool pcep_cli_is_pce_used(const char *pce_name);
static void pcep_cli_delete_pce(const char *pce_name);
static void pcep_cli_merge_pce_config_group_options(struct pce_opts *pce_opts);
static struct pce_config_group_opts *pcep_cli_find_pce_config_group(const char *group_name);
static bool pcep_cli_add_pce_config_group(struct pce_config_group_opts *config_group_opts);
static struct pce_config_group_opts *pcep_cli_create_pce_config_group(const char *group_name);
static bool pcep_cli_is_pce_config_group_used(const char *group_name);
static void pcep_cli_delete_pce_config_group(const char *group_name);
static int pcep_cli_print_config_group(struct pce_config_group_opts *group_opts, char *buf);

/*
 * Internal Util functions
 */

/* Check if a pce_opts already exists based on its name and return it,
 * return NULL otherwise */
static struct pce_opts *pcep_cli_find_pce(const char *pce_name)
{
    int i = 0;
    for (; i < MAX_PCE; i++) {
        struct pce_opts *pce_rhs = pcep_g->pce_opts[i];
        if (pce_rhs != NULL) {
            if (strcmp(pce_name, pce_rhs->pce_name) == 0) {
                return pce_rhs;
            }
        }
    }

    return NULL;
}

/* Add a new pce_opts to pcep_g, return false if MAX_PCES, true otherwise */
static bool pcep_cli_add_pce(struct pce_opts *pce_opts)
{
    int i = 0;
    for (; i < MAX_PCE; i++) {
        if (pcep_g->pce_opts[i] == NULL) {
            pcep_g->pce_opts[i] = pce_opts;
            return true;
        }
    }

    return false;
}

/* Create a new pce opts, inheriting its values from the default pce group */
static struct pce_opts *pcep_cli_create_pce_opts(const char *name)
{
    struct pce_opts *pce_opts = XMALLOC(MTYPE_PCEP, sizeof(struct pce_opts));
    memset(pce_opts, 0, sizeof(struct pce_opts));
    strcpy(pce_opts->pce_name, name);
    pce_opts->port = PCEP_DEFAULT_PORT;

    return pce_opts;
}

static bool pcep_cli_is_pce_used(const char *pce_name)
{
    /* TODO finish this */
    return false;
}

static void pcep_cli_delete_pce(const char *pce_name)
{
    int i = 0;
    for (; i < MAX_PCE; i++) {
        if (pcep_g->pce_opts[i] != NULL) {
            if (strcmp(pcep_g->pce_opts[i]->pce_name, pce_name) == 0) {
                XFREE(MTYPE_PCEP, pcep_g->pce_opts[i]);
                pcep_g->pce_opts[i] = NULL;
            }
        }
    }
}

static void pcep_cli_merge_pce_config_group_options(struct pce_opts *pce_opts)
{
    if (pce_opts->merged == true) {
        return;
    }
    pce_opts->merged = true;

    struct pce_config_group_opts *config_group =
            pcep_cli_find_pce_config_group(pce_opts->config_group_name);

    /* Configuration priorities:
     * 1) pce_opts->config_opts, if present, overwrite config_group config_opts
     * 2) config_group config_opts, if present, overwrite default config_opts
     * 3) If neither pce_opts->config_opts nor config_group config_opts are set,
     *    then the default config_opts value will be used.
     */

    const char *tcp_md5_auth_str = pce_opts->config_opts.tcp_md5_auth;
    if (pce_opts->config_opts.tcp_md5_auth[0] == '\0') {
        if (config_group != NULL && config_group->tcp_md5_auth[0] != '\0') {
            tcp_md5_auth_str = config_group->tcp_md5_auth;
        } else {
            tcp_md5_auth_str = default_pce_config_group_opts.tcp_md5_auth;
        }
    }
    strncpy(pce_opts->merged_opts.tcp_md5_auth, tcp_md5_auth_str, TCP_MD5SIG_MAXKEYLEN);

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
}

/* Check if a pce_config_group_opts already exists based on its name and return it,
 * return NULL otherwise */
static struct pce_config_group_opts *pcep_cli_find_pce_config_group(const char *group_name)
{
    int i = 0;
    for (; i < MAX_PCE; i++) {
        struct pce_config_group_opts *pce_config_group_rhs = pcep_g->config_group_opts[i];
        if (pce_config_group_rhs != NULL) {
            if (strcmp(group_name, pce_config_group_rhs->name) == 0) {
                return pce_config_group_rhs;
            }
        }
    }

    return NULL;
}

/* Add a new pce_config_group_opts to pcep_g, return false if MAX_PCES, true otherwise */
static bool pcep_cli_add_pce_config_group(struct pce_config_group_opts *pce_config_group_opts)
{
    int i = 0;
    for (; i < MAX_PCE; i++) {
        if (pcep_g->config_group_opts[i] == NULL) {
            pcep_g->config_group_opts[i] = pce_config_group_opts;
            return true;
        }
    }

    return false;
}

/* Create a new pce group, inheriting its values from the default pce group */
static struct pce_config_group_opts *pcep_cli_create_pce_config_group(const char *group_name)
{
    struct pce_config_group_opts *pce_config_group_opts =
            XMALLOC(MTYPE_PCEP, sizeof(struct pce_config_group_opts));
    memcpy(pce_config_group_opts, &default_pce_config_group_opts, sizeof(struct pce_config_group_opts));

    return pce_config_group_opts;
}

/* Iterate the pce_opts and return true if the pce-group-name is referenced,
 * false otherwise. */
static bool pcep_cli_is_pce_config_group_used(const char *group_name)
{
    int i = 0;
    for (; i < MAX_PCE; i++) {
        if (pcep_g->pce_opts[i] != NULL) {
            if (strcmp(pcep_g->pce_opts[i]->config_group_name, group_name) == 0) {
                return true;
            }
        }
    }

    return false;
}

static void pcep_cli_delete_pce_config_group(const char *group_name)
{
    int i = 0;
    for (; i < MAX_PCE; i++) {
        if (pcep_g->config_group_opts[i] != NULL) {
            if (strcmp(pcep_g->config_group_opts[i]->name, group_name) == 0) {
                XFREE(MTYPE_PCEP, pcep_g->config_group_opts[i]);
                pcep_g->config_group_opts[i] = NULL;
            }
        }
    }
}

/*
 * VTY command implementations
 */

static int path_pcep_cli_debug(struct vty *vty, int argc, struct cmd_token *argv[])
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no = strmatch(argv[0]->text, PCEP_VTYSH_NO_CMD);
	int i;

	DEBUG_MODE_SET(&pcep_g->dbg, mode, !no);

	if (3 < argc) {
		for (i = (3 + no); i < argc; i++) {
			if (strcmp(PCEP_VTYSH_ARG_BASIC, argv[i]->arg) == 0) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_BASIC, !no);
			} else if (strcmp(PCEP_VTYSH_ARG_PATH, argv[i]->arg) == 0) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PATH, !no);
			} else if (strcmp(PCEP_VTYSH_ARG_MESSAGE, argv[i]->arg) == 0) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PCEP, !no);
			} else if (strcmp(PCEP_VTYSH_ARG_PCEPLIB, argv[i]->arg) == 0) {
				DEBUG_FLAGS_SET(&pcep_g->dbg,
						PCEP_DEBUG_MODE_PCEPLIB, !no);
			}
		}
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

static int path_pcep_cli_pce_config_group(struct vty *vty, int argc, struct cmd_token *argv[])
{
    struct pce_config_group_opts *config_group = pcep_cli_find_pce_config_group(argv[1]->arg);
    if (config_group == NULL) {
        config_group = pcep_cli_create_pce_config_group(argv[1]->arg);
    } else {
        vty_out(vty, "Notice: changes to this pce-config-group will not affect PCEs already configured with this group\n");
    }

    if (pcep_cli_add_pce_config_group(config_group) == false) {
        vty_out(vty, "Cannot create pce-config-group, as the Maximum limit of %d pce-config-groups has been reached.\n", MAX_PCE);
        XFREE(MTYPE_PCEP, config_group);
        return CMD_WARNING;
    }

    current_pce_config_group_opts_g = config_group;
    vty->node = PCE_CONFIG_GROUP_NODE;

	return CMD_SUCCESS;
}

static int path_pcep_cli_pce_config_group_delete(struct vty *vty, int argc, struct cmd_token *argv[])
{
    struct pce_config_group_opts *config_group = pcep_cli_find_pce_config_group(argv[2]->arg);
    if (config_group == NULL) {
        return CMD_ERR_NO_MATCH;
    }

    if (pcep_cli_is_pce_config_group_used(config_group->name)) {
        vty_out(vty, "Cannot delete pce-config-group, since it is in use by a PCE.\n");
        return CMD_WARNING;
    }

    pcep_cli_delete_pce_config_group(config_group->name);

	return CMD_SUCCESS;
}

/* Internal Util func to show an individual PCE,
 * only used by path_pcep_cli_show_pcc_peer() */
static void show_pcc_peer(struct vty *vty, struct pce_opts *pce_opts)
{
    vty_out(vty, "PCC Peer: %s\n", pce_opts->pce_name);
    if (IS_IPADDR_V6(&pce_opts->addr)) {
        vty_out(vty, "  %s %s %pI6 %s %d\n",
            PCEP_VTYSH_ARG_ADDRESS,
            PCEP_VTYSH_ARG_IPV6,
            &pce_opts->addr.ipaddr_v6,
            PCEP_VTYSH_ARG_PORT, pce_opts->port);
    } else {
        vty_out(vty, "  %s %s %pI4 %s %d\n",
            PCEP_VTYSH_ARG_ADDRESS,
            PCEP_VTYSH_ARG_IP,
            &pce_opts->addr.ipaddr_v4,
            PCEP_VTYSH_ARG_PORT, pce_opts->port);
    }
    if (pce_opts->config_group_name[0] != '\0') {
        vty_out(vty, "  pce-config-group: %s\n", pce_opts->config_group_name);
    }

	char buf[1024] = "";
    pcep_cli_print_config_group(&pce_opts->merged_opts, buf);
    vty_out(vty, "%s", buf);
}

static int path_pcep_cli_show_pcc_peer(
        struct vty *vty, int argc, struct cmd_token *argv[])
{
    /* There must be either 2 or 4 arguments */
	if (argc != 2 && argc != 4) {
		return CMD_ERR_NO_MATCH;
	}

    /* Only show 1 PCE */
    struct pce_opts *pce_opts;
    if (argc == 4) {
        pce_opts = pcep_cli_find_pce(argv[3]->arg);
        if (pce_opts == NULL) {
            vty_out(vty, "PCE [%s] does not exist.\n", argv[3]->arg);
            return CMD_ERR_NO_MATCH;
        }

		pcep_cli_merge_pce_config_group_options(pce_opts);
        show_pcc_peer(vty, pce_opts);

        return CMD_SUCCESS;
    }

    /* Show all PCEs */
	int i = 0;
	for (; i < MAX_PCE; i++) {
		pce_opts = pcep_g->pce_opts[i];
		if (pce_opts == NULL) {
            continue;
		}

		pcep_cli_merge_pce_config_group_options(pce_opts);
        show_pcc_peer(vty, pce_opts);
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_peer(struct vty *vty, int argc, struct cmd_token *argv[])
{
    /* There must be 2 arguments */
	if (argc != 2) {
		return CMD_ERR_NO_MATCH;
	}

    const char *pce_name = argv[1]->arg;

    /* If it already exists, it will be updated in the sub-commands */
    struct pce_opts *pce_config_opts = pcep_cli_find_pce(pce_name);
    if (pce_config_opts == NULL) {
        pce_config_opts = pcep_cli_create_pce_opts(pce_name);
    }

    if (!pcep_cli_add_pce(pce_config_opts)) {
        vty_out(vty, "Cannot create PCE, as the Maximum limit of %d PCEs has been reached.\n", MAX_PCE);
        XFREE(MTYPE_PCEP, pce_config_opts);
        return CMD_WARNING;
    }

    current_pce_opts_g = pce_config_opts;
    vty->node = PCC_PEER_NODE;

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_peer_delete(struct vty *vty, int argc, struct cmd_token *argv[])
{
    const char *pce_name = argv[2]->arg;
    struct pce_opts *pce_opts = pcep_cli_find_pce(pce_name);
    if (pce_opts == NULL) {
		return CMD_ERR_NO_MATCH;
    }

    if (pcep_cli_is_pce_used(pce_name)) {
        vty_out(vty, "Cannot delete PCE, since it is in use by a PCC.\n");
        return CMD_WARNING;
    }

    pcep_cli_delete_pce(pce_name);

    /* TODO this was the original delete pce code:
	pcep_ctrl_remove_pcc(pcep_g->fpt, 1);
    */

	return CMD_SUCCESS;
}

static int path_pcep_cli_pce_sr_draft07(struct vty *vty)
{
    struct pce_config_group_opts *config_group = NULL;

    if (vty->node == PCC_PEER_NODE) {
        /* TODO need to see if the pce is in use, and reset the connection */
        config_group = &current_pce_opts_g->config_opts;
        current_pce_opts_g->merged = false;
    } else if (vty->node == PCE_CONFIG_GROUP_NODE) {
        config_group = current_pce_config_group_opts_g;
    } else {
        return CMD_ERR_NO_MATCH;
    }

    config_group->draft07 = true;

	return CMD_SUCCESS;
}

static int path_pcep_cli_pce_pce_initiated(struct vty *vty)
{
    struct pce_config_group_opts *config_group = NULL;

    if (vty->node == PCC_PEER_NODE) {
        /* TODO need to see if the pce is in use, and reset the connection */
        config_group = &current_pce_opts_g->config_opts;
        current_pce_opts_g->merged = false;
    } else if (vty->node == PCE_CONFIG_GROUP_NODE) {
        config_group = current_pce_config_group_opts_g;
    } else {
        return CMD_ERR_NO_MATCH;
    }

    config_group->pce_initiated = true;

	return CMD_SUCCESS;
}

static int path_pcep_cli_pce_tcp_md5_auth(struct vty *vty, int argc, struct cmd_token *argv[])
{
    /* There must be 2 arguments */
	if (argc != 2) {
		return CMD_ERR_NO_MATCH;
	}

    struct pce_config_group_opts *config_group = NULL;

    if (vty->node == PCC_PEER_NODE) {
        /* TODO need to see if the pce is in use, and reset the connection */
        config_group = &current_pce_opts_g->config_opts;
        current_pce_opts_g->merged = false;
    } else if (vty->node == PCE_CONFIG_GROUP_NODE) {
        config_group = current_pce_config_group_opts_g;
    } else {
        return CMD_ERR_NO_MATCH;
    }

    strncpy(config_group->tcp_md5_auth, argv[1]->arg, TCP_MD5SIG_MAXKEYLEN);

	return CMD_SUCCESS;
}

static int path_pcep_cli_pce_address(struct vty *vty, int argc, struct cmd_token *argv[])
{
    /* There must be either 3 or 5 arguments */
	if (argc < 3 || argc == 4 || argc > 5) {
		return CMD_ERR_NO_MATCH;
	}

	struct pce_opts *pce_opts = NULL;
    if (vty->node == PCC_PEER_NODE) {
        /* TODO need to see if the pce is in use, and reset the connection */
        pce_opts = current_pce_opts_g;
        current_pce_opts_g->merged = false;
    } else {
        return CMD_ERR_NO_MATCH;
    }

	if (strcmp(PCEP_VTYSH_ARG_IPV6, argv[1]->arg) == 0) {
	    pce_opts->addr.ipa_type = IPADDR_V6;
		if (!inet_pton(AF_INET6, argv[2]->arg, &pce_opts->addr.ipaddr_v6)) {
			return CMD_ERR_INCOMPLETE;
		}
	} else if (strcmp(PCEP_VTYSH_ARG_IP, argv[1]->arg) == 0) {
	    pce_opts->addr.ipa_type = IPADDR_V4;
		if (!inet_pton(AF_INET, argv[2]->arg, &pce_opts->addr.ipaddr_v4)) {
			return CMD_ERR_INCOMPLETE;
		}
	} else {
		return CMD_ERR_NO_MATCH;
	}

	/* Handle the optional port */
	int i = 3;
    int port = PCEP_DEFAULT_PORT;
	if (argc == 5) {
		if (strcmp(PCEP_VTYSH_ARG_PORT, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, port, 0, 65535);
		} else {
		    return CMD_ERR_NO_MATCH;
		}
	}
    pce_opts->port = port;

	return CMD_SUCCESS;
}

static int path_pcep_cli_pce_pce_config_group(struct vty *vty, int argc, struct cmd_token *argv[])
{
    /* There must be 2 arguments */
	if (argc == 2) {
		return CMD_ERR_NO_MATCH;
	}

	struct pce_opts *pce_opts = NULL;
    if (vty->node == PCC_PEER_NODE) {
        /* TODO need to see if the pce is in use, and reset the connection */
        pce_opts = current_pce_opts_g;
        current_pce_opts_g->merged = false;
    } else {
        return CMD_ERR_NO_MATCH;
    }

    struct pce_config_group_opts *config_group = pcep_cli_find_pce_config_group(argv[1]->arg);
    if (config_group == NULL) {
        vty_out(vty, "pce-config-group [%s] does not exist.\n", argv[1]->arg);
		return CMD_ERR_NO_MATCH;
    }

    strcpy(pce_opts->config_group_name, config_group->name);

	return CMD_SUCCESS;
}

static int path_pcep_cli_pce_timers(struct vty *vty, int argc, struct cmd_token *argv[])
{
    /* There must be at least 3 arguments */
	if (argc < 3) {
		return CMD_ERR_NO_MATCH;
	}

    struct pce_config_group_opts *config_group = NULL;
    if (vty->node == PCC_PEER_NODE) {
        /* TODO need to see if the pce is in use, and reset the connection */
        config_group = &current_pce_opts_g->config_opts;
        current_pce_opts_g->merged = false;
    } else if (vty->node == PCE_CONFIG_GROUP_NODE) {
        config_group = current_pce_config_group_opts_g;
    } else {
        return CMD_ERR_NO_MATCH;
    }

	/* Handle the arguments */
	int i = 1;
	while (i < argc) {
		if (strcmp(PCEP_VTYSH_ARG_KEEP_ALIVE, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, config_group->keep_alive_seconds, 0, 241);
		} else if (strcmp(PCEP_VTYSH_ARG_KEEP_ALIVE_MIN, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, config_group->min_keep_alive_seconds, 0, 61);
		} else if (strcmp(PCEP_VTYSH_ARG_KEEP_ALIVE_MAX, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, config_group->max_keep_alive_seconds, 59, 241);
		} else if (strcmp(PCEP_VTYSH_ARG_DEAD_TIMER, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, config_group->dead_timer_seconds, 0, 241);
		} else if (strcmp(PCEP_VTYSH_ARG_DEAD_TIMER_MIN, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, config_group->min_dead_timer_seconds, 0, 61);
		} else if (strcmp(PCEP_VTYSH_ARG_DEAD_TIMER_MAX, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, config_group->max_dead_timer_seconds, 59, 241);
		} else if (strcmp(PCEP_VTYSH_ARG_PCEP_REQUEST, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, config_group->pcep_request_time_seconds, 0, 241);
		} else if (strcmp(PCEP_VTYSH_ARG_STATE_TIMEOUT, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, config_group->state_timeout_inteval_seconds, 0, 241);
		} else {
		    return CMD_ERR_NO_MATCH;
		}
		i++;
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc(struct vty *vty, int argc, struct cmd_token *argv[])
{
	struct pcc_opts local_opts, *opts, *opts_copy;
	int i = 1;

	memset(&local_opts, 0, sizeof(local_opts));
	local_opts.port = PCEP_DEFAULT_PORT;
	local_opts.msd = DEFAULT_PCC_MSD;

	/* Handle the rest of the arguments */
	while (i < argc) {
		if (strcmp(PCEP_VTYSH_ARG_IP, argv[i]->arg) == 0) {
			SET_FLAG(local_opts.flags, F_PCC_OPTS_IPV4);
			i++;
			if (i >= argc) {
				return CMD_ERR_NO_MATCH;
			}
			if (!inet_pton(AF_INET, argv[i]->arg, &local_opts.addr_v4)) {
				return CMD_ERR_INCOMPLETE;
			}
		} else if (strcmp(PCEP_VTYSH_ARG_IPV6, argv[i]->arg) == 0) {
			SET_FLAG(local_opts.flags, F_PCC_OPTS_IPV6);
			i++;
			if (i >= argc) {
				return CMD_ERR_NO_MATCH;
			}
			if (!inet_pton(AF_INET6, argv[i]->arg, &local_opts.addr_v6)) {
				return CMD_ERR_INCOMPLETE;
			}
		} else if (strcmp(PCEP_VTYSH_ARG_PORT, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, local_opts.port, 0, 65535);
		} else if (strcmp(PCEP_VTYSH_ARG_MSD, argv[i]->arg) == 0) {
		    PCEP_VTYSH_INT_ARG_CHECK(i, local_opts.msd, 0, 16);
		} else {
		    return CMD_ERR_NO_MATCH;
		}

		i++;
	}

    /* This copy of the opts is sent to the pcep controller thread */
	opts = XCALLOC(MTYPE_PCEP, sizeof(*opts));
	memcpy(opts, &local_opts, sizeof(*opts));

	if (pcep_ctrl_update_pcc_options(pcep_g->fpt, opts))
		return CMD_WARNING;

    /* This copy of the opts is stored in the global opts */
	if (pcep_g->pcc_opts != NULL)
		XFREE(MTYPE_PCEP, pcep_g->pcc_opts);
	opts_copy = XCALLOC(MTYPE_PCEP, sizeof(*opts));
	opts_copy = memcpy(opts_copy, opts, sizeof(*opts));
	pcep_g->pcc_opts = opts_copy;

	VTY_PUSH_CONTEXT_NULL(PCC_NODE);

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_delete(struct vty *vty, int argc, struct cmd_token *argv[])
{
	pcep_ctrl_remove_pcc(pcep_g->fpt, 1);
	if (pcep_g->pce_opts[0] != NULL) {
		XFREE(MTYPE_PCEP, pcep_g->pce_opts[0]);
		pcep_g->pce_opts[0] = NULL;
	}
	if (pcep_g->pcc_opts != NULL) {
		XFREE(MTYPE_PCEP, pcep_g->pcc_opts);
		pcep_g->pcc_opts = NULL;
	}

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_pce(struct vty *vty, int argc, struct cmd_token *argv[])
{
    /* There must be at least 2 arguments */
	if (2 > argc) {
		return CMD_ERR_NO_MATCH;
	}

	struct pce_opts *pce_opts = pcep_cli_find_pce(argv[1]->arg);
    if (pce_opts == NULL) {
        vty_out(vty, "PCE [%s] does not exist.\n", argv[1]->arg);
		return CMD_ERR_NO_MATCH;
    }

	int i = 2;
    int priority = 0;
	/* Get the optional priority argument */
	if (strcmp(PCEP_VTYSH_ARG_PRIORITY, argv[i]->arg) == 0) {
	    PCEP_VTYSH_INT_ARG_CHECK(i, priority, 1, 65535);
	} else {
		return CMD_ERR_NO_MATCH;
	}

    /* Finalize the pce_opts config values */
	pcep_cli_merge_pce_config_group_options(pce_opts);

    /* TODO need to store the priority */

	/* TODO if previous pce peers have been configured, then priority is mandatory */

    /* TODO send an update_pcc to connect to the PCE */

	return CMD_SUCCESS;
}

static int path_pcep_cli_pcc_pce_delete(struct vty *vty, int argc, struct cmd_token *argv[])
{
    /* TODO finish this */

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
			csnprintfrr(buff, sizeof(buff), " %s", PCEP_VTYSH_ARG_BASIC);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PATH))
			csnprintfrr(buff, sizeof(buff), " %s", PCEP_VTYSH_ARG_PATH);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEP))
			csnprintfrr(buff, sizeof(buff), " %s", PCEP_VTYSH_ARG_MESSAGE);
		if (DEBUG_FLAGS_CHECK(&pcep_g->dbg, PCEP_DEBUG_MODE_PCEPLIB))
			csnprintfrr(buff, sizeof(buff), " %s", PCEP_VTYSH_ARG_PCEPLIB);
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
	struct pcc_opts *pcc_opts = pcep_g->pcc_opts;
	struct pce_opts *pce_opts;
	char buff[128] = "";
	int lines = 0;

	if (pcep_g->pcc_opts != NULL) {
		if (CHECK_FLAG(pcc_opts->flags, F_PCC_OPTS_IPV4)) {
			csnprintfrr(buff, sizeof(buff), " %s %pI4",
			        PCEP_VTYSH_ARG_IP, &pcc_opts->addr_v4);
		} else if (CHECK_FLAG(pcc_opts->flags, F_PCC_OPTS_IPV4)) {
			csnprintfrr(buff, sizeof(buff), " %s %pI6",
			        PCEP_VTYSH_ARG_IPV6, &pcc_opts->addr_v6);
		}
		if (pcc_opts->port != PCEP_DEFAULT_PORT)
			csnprintfrr(buff, sizeof(buff), " %s %d",
			        PCEP_VTYSH_ARG_PORT, pcc_opts->port);
		if (pcc_opts->msd != DEFAULT_PCC_MSD)
			csnprintfrr(buff, sizeof(buff), " %s %d",
			        PCEP_VTYSH_ARG_MSD, pcc_opts->msd);
		vty_out(vty, "pcc%s\n", buff);
		buff[0] = 0;
		lines++;

        /* TODO instead of iterating pcep_g->pce_opts, iterate the actual
         * pce peers this pcc is connected to. */
		for (int i = 0; i < MAX_PCC; i++) {
			pce_opts = pcep_g->pce_opts[i];
            if (pce_opts == NULL) {
                continue;
            }

            /* TODO include the optional priority */
			vty_out(vty, "  peer %s\n", pce_opts->pce_name);
			lines++;
		}
	}

	return lines;
}

/* Internal function used by pcep_cli_pce_config_write()
 * and pcep_cli_pce_config_group_write() */
static int pcep_cli_print_config_group(
        struct pce_config_group_opts *group_opts, char *buf)
{
    int lines = 0;

    if (group_opts->keep_alive_seconds > 0) {
        csnprintfrr(buf, sizeof(buf), "  %s %d\n",
                PCEP_VTYSH_ARG_KEEP_ALIVE,
                group_opts->keep_alive_seconds);
        lines++;
    }
    if (group_opts->min_keep_alive_seconds > 0) {
        csnprintfrr(buf, sizeof(buf), "  %s %d\n",
                PCEP_VTYSH_ARG_KEEP_ALIVE_MIN,
                group_opts->min_keep_alive_seconds);
        lines++;
    }
    if (group_opts->max_keep_alive_seconds > 0) {
        csnprintfrr(buf, sizeof(buf), "  %s %d\n",
                PCEP_VTYSH_ARG_KEEP_ALIVE_MAX,
                group_opts->max_keep_alive_seconds);
        lines++;
    }
    if (group_opts->dead_timer_seconds > 0) {
        csnprintfrr(buf, sizeof(buf), "  %s %d\n",
                PCEP_VTYSH_ARG_DEAD_TIMER,
                group_opts->dead_timer_seconds);
        lines++;
    }
    if (group_opts->min_dead_timer_seconds > 0) {
        csnprintfrr(buf, sizeof(buf), "  %s %d\n",
                PCEP_VTYSH_ARG_DEAD_TIMER_MIN,
                group_opts->min_dead_timer_seconds);
        lines++;
    }
    if (group_opts->max_dead_timer_seconds > 0) {
        csnprintfrr(buf, sizeof(buf), "  %s %d\n",
                PCEP_VTYSH_ARG_DEAD_TIMER_MAX,
                group_opts->max_dead_timer_seconds);
        lines++;
    }
    if (group_opts->pcep_request_time_seconds > 0) {
        csnprintfrr(buf, sizeof(buf), "  %s %d\n",
                PCEP_VTYSH_ARG_PCEP_REQUEST,
                group_opts->pcep_request_time_seconds);
        lines++;
    }
    if (group_opts->state_timeout_inteval_seconds > 0) {
        csnprintfrr(buf, sizeof(buf), "  %s %d\n",
                PCEP_VTYSH_ARG_STATE_TIMEOUT,
                group_opts->state_timeout_inteval_seconds);
        lines++;
    }
    if (group_opts->tcp_md5_auth[0] != '\0') {
        csnprintfrr(buf, sizeof(buf), "  %s %s\n",
                PCEP_VTYSH_ARG_TCP_MD5,
                group_opts->tcp_md5_auth);
        lines++;
    }
    if (group_opts->draft07) {
        csnprintfrr(buf, sizeof(buf), "  %s\n",
                PCEP_VTYSH_ARG_SR_DRAFT07);
        lines++;
    }
    if (group_opts->pce_initiated) {
        csnprintfrr(buf, sizeof(buf), "  %s\n",
                PCEP_VTYSH_ARG_PCE_INIT);
        lines++;
    }

    return lines;
}

int pcep_cli_pce_config_write(struct vty *vty)
{
    int i = 0;
	int lines = 0;
	char buf[1024] = "";

	for(; i < MAX_PCE; i++) {
	    struct pce_opts *pce_opts = pcep_g->pce_opts[i];
        if (pce_opts == NULL) {
            continue;
        }
        csnprintfrr(buf, sizeof(buf), "pce %s\n", pce_opts->pce_name);
        if (IS_IPADDR_V6(&pce_opts->addr)) {
            csnprintfrr(buf, sizeof(buf), "  %s %s %pI6",
                    PCEP_VTYSH_ARG_ADDRESS,
                    PCEP_VTYSH_ARG_IPV6,
                    &pce_opts->addr.ipaddr_v6);
        } else {
            csnprintfrr(buf, sizeof(buf), "  address %s %pI4",
                    PCEP_VTYSH_ARG_IP, &pce_opts->addr.ipaddr_v4);
        }
        if (pce_opts->port != PCEP_DEFAULT_PORT) {
            csnprintfrr(buf, sizeof(buf),
                    " %s %d", PCEP_VTYSH_ARG_PORT, pce_opts->port);
        }
        csnprintfrr(buf, sizeof(buf), "\n");
        lines = 2;

        if (pce_opts->config_group_name[0] != '\0') {
            csnprintfrr(buf, sizeof(buf),
                    "  config-group %s", pce_opts->config_group_name);
            lines++;
        }

        /* Only display the values configured on the PCE, not the values
         * from its optional pce-config-group, nor the default values */
        lines += pcep_cli_print_config_group(&pce_opts->config_opts, buf);

        vty_out(vty, "%s", buf);
        buf[0] = 0;
	}

    return lines;
}

int pcep_cli_pce_config_group_write(struct vty *vty)
{
    int i = 0;
	int lines = 0;
	char buf[128] = "";

	for(; i < MAX_PCE; i++) {
	    struct pce_config_group_opts *group_opts = pcep_g->config_group_opts[i];
        if (group_opts == NULL) {
            continue;
        }

        csnprintfrr(buf, sizeof(buf), "pce-config-group %s\n", group_opts->name);
        lines = 1;

        lines += pcep_cli_print_config_group(group_opts, buf);

        vty_out(vty, "%s", buf);
        buf[0] = 0;
	}

    return lines;
}

/*
 * VTYSH command syntax definitions
 */

DEFUN(pcep_cli_debug, pcep_cli_debug_cmd,
      "[no] debug pathd pcep [basic] [path] [message] [pceplib]",
      NO_STR
      DEBUG_STR
      "pathd debugging\n"
      "pcep module debugging\n"
      "module basic debugging\n"
      "path structures debugging\n"
      "pcep message debugging\n"
      "pceplib debugging\n")
{
    return path_pcep_cli_debug(vty, argc, argv);
}

DEFUN(pcep_cli_show_pcep_counters, pcep_cli_show_pcep_counters_cmd,
      "show pcep counters",
      SHOW_STR
      "PCEP info\n"
      "PCEP counters\n")
{
    return path_pcep_cli_show_pcep_counters(vty);
}

DEFUN_NOSH(pcep_cli_pce_config_group, pcep_cli_pce_config_group_cmd,
      "[no] pce-config-group pce-config-group-name",
      NO_STR
      "PCE Configuration Group\n"
      "PCE Configuration Group name\n")
{
	if (strmatch(argv[0]->text, PCEP_VTYSH_NO_CMD)) {
	    return path_pcep_cli_pce_config_group_delete(vty, argc, argv);
	} else {
	    return path_pcep_cli_pce_config_group(vty, argc, argv);
	}
}

DEFUN(pcep_cli_show_pcc_peer, pcep_cli_show_pcc_peer_cmd,
      "show pcc-peer [pcc-peer name]",
      SHOW_STR
      "Show detailed pcc-peer (PCE) values\n"
      "pcc-peer to show")
{
    return path_pcep_cli_show_pcc_peer(vty, argc, argv);
}

DEFUN_NOSH(pcep_cli_pcc_peer, pcep_cli_pcc_peer_cmd,
      "[no] pcc-peer pce-name",
      NO_STR
      "PCC Peer configuration\n"
      "PCE name\n")
{
	if (strmatch(argv[0]->text, PCEP_VTYSH_NO_CMD)) {
	    return path_pcep_cli_pcc_peer_delete(vty, argc, argv);
	} else {
	    return path_pcep_cli_pcc_peer(vty, argc, argv);
	}
}

DEFUN(pcep_cli_pce_sr_draft07, pcep_cli_pce_sr_draft07_cmd,
	"sr-draft07\n",
    "Configure PCC to send PCEP Open with SR draft07\n")
{
    return path_pcep_cli_pce_sr_draft07(vty);
}

DEFUN(pcep_cli_pce_pce_initiated, pcep_cli_pce_pce_initiated_cmd,
	"pce-initiated\n",
    "Configure PCC to accept PCE initiated LSPs\n")
{
    return path_pcep_cli_pce_pce_initiated(vty);
}

DEFUN(pcep_cli_pce_tcp_md5_auth, pcep_cli_pce_tcp_md5_auth_cmd,
	"tcp-md5-auth auth-str\n",
    "Configure PCC TCP-MD5 RFC2385 Authentication\n"
    "TCP-MD5 Authentication string\n")
{
    return path_pcep_cli_pce_tcp_md5_auth(vty, argc, argv);
}

DEFUN(pcep_cli_pce_address, pcep_cli_pce_address_cmd,
	"address <ip A.B.C.D | ipv6 X:X::X:X> [port (1024-65535)]\n",
    "PCE IP Address configuration\n"
    "PCE IPv4 address\n"
    "Remote PCE server IPv4 address\n"
    "PCE IPv6 address\n"
    "Remote PCE server IPv6 address\n"
    "Remote PCE server port\n"
    "Remote PCE server port value\n")
{
    return path_pcep_cli_pce_address(vty, argc, argv);
}

DEFUN(pcep_cli_pce_pce_config_group, pcep_cli_pce_pce_config_group_cmd,
	"config-group pce-config-group-name\n",
    "PCE Configuration Group\n"
    "PCE Configuration Group name\n")
{
    return path_pcep_cli_pce_pce_config_group(vty, argc, argv);
}

DEFUN(pcep_cli_pce_timers, pcep_cli_pce_timers_cmd,
	"timers [keep-alive-timer (1-240)] [min-pce-keep-alive-timer (1-60)] [max-pce-keep-alive-timer (60-240)] "
	"[dead-timer (1-240)] [min-pce-dead-timer (1-60)] [max-dead-timer (60-240)] "
	"[pcep-request-timer (1-120)] [state-timeout-interval (1-120)]\n",
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
	"PCC State Timeout Interval value in seconds\n")
{
    return path_pcep_cli_pce_timers(vty, argc, argv);
}

DEFUN_NOSH(
	pcep_cli_pcc, pcep_cli_pcc_cmd,
	"[no] pcc [{ip A.B.C.D | ipv6 X:X::X:X}] [port (1024-65535)] [msd (1-16)]\n",
    NO_STR
	"PCC configuration\n"
	"PCC source ip\n"
	"PCC source IPv4 address\n"
	"PCC source ip\n"
	"PCC source IPv6 address\n"
	"PCC source port\n"
	"PCC source port value\n"
	"PCC maximum SID depth \n"
	"PCC maximum SID depth value\n")
{
	if (strmatch(argv[0]->text, PCEP_VTYSH_NO_CMD)) {
	    return path_pcep_cli_pcc_delete(vty, argc, argv);
	} else {
	    return path_pcep_cli_pcc(vty, argc, argv);
	}
}

DEFUN(pcep_cli_pcc_pce, pcep_cli_pcc_pce_cmd,
	  "[no] peer pce-name [priority (1-65535)]\n",
      NO_STR
	  "PCC PCE peer\n"
	  "PCC PCE name\n"
	  "PCC Multi-PCE priority\n"
	  "PCE priority\n")
{
	if (strmatch(argv[0]->text, PCEP_VTYSH_NO_CMD)) {
	    return path_pcep_cli_pcc_pce_delete(vty, argc, argv);
	} else {
	    return path_pcep_cli_pcc_pce(vty, argc, argv);
	}
}

void pcep_cli_init(void)
{
	hook_register(nb_client_debug_config_write,
		      pcep_cli_debug_config_write);
	hook_register(nb_client_debug_set_all, pcep_cli_debug_set_all);

	install_node(&pce_config_group_node, &pcep_cli_pce_config_group_write);
	install_node(&pcc_peer_node, &pcep_cli_pce_config_write);
	install_node(&pcc_node, &pcep_cli_pcc_config_write);

    // TODO change this when the code is rebased
	//install_node(&pcc_node);
	//install_node(&pcc_peer_node);
	//install_node(&pce_config_group_node);

	install_default(PCE_CONFIG_GROUP_NODE);
	install_default(PCC_PEER_NODE);
	install_default(PCC_NODE);

	install_element(CONFIG_NODE, &pcep_cli_debug_cmd);
	install_element(ENABLE_NODE, &pcep_cli_debug_cmd);
	install_element(ENABLE_NODE, &pcep_cli_show_pcep_counters_cmd);

    /* PCE-Group related commands */
	install_element(CONFIG_NODE, &pcep_cli_pce_config_group_cmd);
	install_element(PCE_CONFIG_GROUP_NODE, &pcep_cli_pce_timers_cmd);
	install_element(PCE_CONFIG_GROUP_NODE, &pcep_cli_pce_sr_draft07_cmd);
	install_element(PCE_CONFIG_GROUP_NODE, &pcep_cli_pce_pce_initiated_cmd);
	install_element(PCE_CONFIG_GROUP_NODE, &pcep_cli_pce_tcp_md5_auth_cmd);

    /* PCC-PEER (PCE) related commands */
	install_element(CONFIG_NODE, &pcep_cli_pcc_peer_cmd);
	install_element(ENABLE_NODE, &pcep_cli_show_pcc_peer_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_pce_address_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_pce_pce_config_group_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_pce_timers_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_pce_sr_draft07_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_pce_pce_initiated_cmd);
	install_element(PCC_PEER_NODE, &pcep_cli_pce_tcp_md5_auth_cmd);

    /* PCC related commands */
	install_element(CONFIG_NODE, &pcep_cli_pcc_cmd);
	install_element(PCC_NODE, &pcep_cli_pcc_pce_cmd);
}
