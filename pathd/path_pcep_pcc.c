/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sebastien Merle
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

/* TODOS:
	- Delete mapping from NB keys to PLSPID when an LSP is deleted either
	  by the PCE or by NB.
	- Revert the hacks to work around ODL requiring a report with
	  operational status DOWN when an LSP is activated.
	- Enforce only the PCE a policy has been delegated to can update it.
*/

#include <zebra.h>

#include "log.h"
#include "command.h"
#include "libfrr.h"
#include "printfrr.h"
#include "version.h"
#include "northbound.h"
#include "frr_pthread.h"
#include "jhash.h"

#include "pathd/pathd.h"
#include "pathd/path_util.h"
#include "pathd/path_zebra.h"
#include "pathd/path_errors.h"
#include "pathd/path_pcep_memory.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_lib.h"
#include "pathd/path_pcep_nb.h"
#include "pathd/path_pcep_debug.h"


/* The number of time we will skip connecting if we are missing the PCC
 * address for an inet family different from the selected transport one*/
#define OTHER_FAMILY_MAX_RETRIES 4
#define MAX_ERROR_MSG_SIZE 256

/* PCEP Event Handler */
static void handle_pcep_open(struct ctrl_state *ctrl_state,
			     struct pcc_state *pcc_state,
			     struct pcep_message *msg);
static void handle_pcep_message(struct ctrl_state *ctrl_state,
				struct pcc_state *pcc_state,
				struct pcep_message *msg);
static void handle_pcep_lsp_update(struct ctrl_state *ctrl_state,
				   struct pcc_state *pcc_state,
				   struct pcep_message *msg);
static void handle_pcep_lsp_initiate(struct ctrl_state *ctrl_state,
				     struct pcc_state *pcc_state,
				     struct pcep_message *msg);
static void handle_pcep_comp_reply(struct ctrl_state *ctrl_state,
				   struct pcc_state *pcc_state,
				   struct pcep_message *msg);

/* Internal Functions */
static const char* ipaddr_type_name(struct ipaddr *addr);
static bool filter_path(struct pcc_state *pcc_state, struct path *path);
static void select_pcc_addresses(struct pcc_state *pcc_state);
static void select_transport_address(struct pcc_state *pcc_state);
static void update_tag(struct pcc_state *pcc_state);
static void update_originator(struct pcc_state *pcc_state);
static void schedule_reconnect(struct ctrl_state *ctrl_state,
			       struct pcc_state *pcc_state);
static void send_pcep_message(struct pcc_state *pcc_state,
			      struct pcep_message *msg);
static void send_pcep_error(struct pcc_state *pcc_state,
			    enum pcep_error_type error_type,
			    enum pcep_error_value error_value);
static void send_report(struct pcc_state *pcc_state, struct path *path);
static void send_comp_request(struct pcc_state *pcc_state,
			      struct req_entry *req);
static void specialize_outgoing_path(struct pcc_state *pcc_state,
				     struct path *path);
static void specialize_incoming_path(struct pcc_state *pcc_state,
				     struct path *path);
static bool validate_incoming_path(struct pcc_state *pcc_state,
				   struct path *path,
				   char* errbuff, size_t buffsize);
static void set_pcc_address(struct pcc_state *pcc_state,
			    struct lsp_nb_key *nbkey, struct ipaddr *addr);
static int compare_pcc_opts(struct pcc_opts *lhs, struct pcc_opts *rhs);
static int compare_pce_opts(struct pce_opts *lhs, struct pce_opts *rhs);

/* Data Structure Helper Functions */
static void lookup_plspid(struct pcc_state *pcc_state, struct path *path);
static void lookup_nbkey(struct pcc_state *pcc_state, struct path *path);
static void free_req_entry(struct req_entry *req);
static struct req_entry* push_req(struct pcc_state *pcc_state,
				  struct path* path);
static struct req_entry* pop_req(struct pcc_state *pcc_state, uint32_t reqid);

/* Data Structure Callbacks */
static int plspid_map_cmp(const struct plspid_map_data *a,
			  const struct plspid_map_data *b);
static uint32_t plspid_map_hash(const struct plspid_map_data *e);
static int nbkey_map_cmp(const struct nbkey_map_data *a,
			 const struct nbkey_map_data *b);
static uint32_t nbkey_map_hash(const struct nbkey_map_data *e);

/* Data Structure Declarations */
DECLARE_HASH(plspid_map, struct plspid_map_data, mi, plspid_map_cmp,
	     plspid_map_hash)
DECLARE_HASH(nbkey_map, struct nbkey_map_data, mi, nbkey_map_cmp,
	     nbkey_map_hash)

static inline int req_entry_compare(const struct req_entry *a,
				    const struct req_entry *b)
{
	return a->path->req_id - b->path->req_id;
}
RB_GENERATE(req_entry_head, req_entry, entry, req_entry_compare)


/* ------------ API Functions ------------ */

struct pcc_state *pcep_pcc_initialize(struct ctrl_state *ctrl_state, int index)
{
	struct pcc_state *pcc_state = XCALLOC(MTYPE_PCEP, sizeof(*pcc_state));

	pcc_state->id = index;
	pcc_state->status = PCEP_PCC_DISCONNECTED;
	pcc_state->next_reqid = 1;
	pcc_state->next_plspid = 1;

	RB_INIT(req_entry_head, &pcc_state->requests);

	update_tag(pcc_state);
	update_originator(pcc_state);

	PCEP_DEBUG("%s PCC initialized", pcc_state->tag);

	return pcc_state;
}

void pcep_pcc_finalize(struct ctrl_state *ctrl_state,
		       struct pcc_state *pcc_state)
{
	PCEP_DEBUG("%s PCC finalizing...", pcc_state->tag);

	pcep_pcc_disable(ctrl_state, pcc_state);

	if (pcc_state->pcc_opts != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->pcc_opts);
		pcc_state->pcc_opts = NULL;
	}
	if (pcc_state->pce_opts != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->pce_opts);
		pcc_state->pce_opts = NULL;
	}
	if (pcc_state->originator != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->originator);
		pcc_state->originator = NULL;
	}
	XFREE(MTYPE_PCEP, pcc_state);
}

int compare_pcc_opts(struct pcc_opts *lhs, struct pcc_opts *rhs)
{
	int retval;

	if (lhs == NULL) {
		return 1;
	}

	if (rhs == NULL) {
		return -1;
	}

	retval = lhs->port - rhs->port;
	if (retval != 0) {
		return retval;
	}

	retval = lhs->msd - rhs->msd;
	if (retval != 0) {
		return retval;
	}

	if (IS_IPADDR_V4(&lhs->addr)) {
		retval = memcmp(&lhs->addr.ipaddr_v4, &rhs->addr.ipaddr_v4,
				sizeof(lhs->addr.ipaddr_v4));
		if (retval != 0) {
			return retval;
		}
	} else if (IS_IPADDR_V6(&lhs->addr)) {
		retval = memcmp(&lhs->addr.ipaddr_v6, &rhs->addr.ipaddr_v6,
				sizeof(lhs->addr.ipaddr_v6));
		if (retval != 0) {
			return retval;
		}
	}

	return 0;
}

int compare_pce_opts(struct pce_opts *lhs, struct pce_opts *rhs)
{
	if (lhs == NULL) {
		return 1;
	}

	if (rhs == NULL) {
		return -1;
	}

	int retval = lhs->port - rhs->port;
	if (retval != 0) {
		return retval;
	}

	retval = strcmp(lhs->pce_name, rhs->pce_name);
	if (retval != 0) {
		return retval;
	}

	retval = lhs->precedence - rhs->precedence;
	if (retval != 0) {
		return retval;
	}

	retval = memcmp(&lhs->addr, &rhs->addr, sizeof(lhs->addr));
	if (retval != 0) {
		return retval;
	}

	return 0;
}

int pcep_pcc_update(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state,
		    struct pcc_opts *pcc_opts, struct pce_opts *pce_opts)
{
	int ret = 0;

	// If the options did not change, then there is nothing to do
	if ((compare_pce_opts(pce_opts, pcc_state->pce_opts) == 0)
	    && (compare_pcc_opts(pcc_opts, pcc_state->pcc_opts) == 0)) {
		return ret;
	}

	if ((ret = pcep_pcc_disable(ctrl_state, pcc_state))) {
		XFREE(MTYPE_PCEP, pcc_opts);
		XFREE(MTYPE_PCEP, pce_opts);
		return ret;
	}

	if (pcc_state->pcc_opts != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->pcc_opts);
	}
	if (pcc_state->pce_opts != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->pce_opts);
	}

	pcc_state->pcc_opts = pcc_opts;
	pcc_state->pce_opts = pce_opts;

	if (IS_IPADDR_V4(&pcc_opts->addr)) {
		pcc_state->pcc_addr_v4 = pcc_opts->addr.ipaddr_v4;
		SET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4);
	} else {
		UNSET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4);
	}

	if (IS_IPADDR_V6(&pcc_opts->addr)) {
		memcpy(&pcc_state->pcc_addr_v6, &pcc_opts->addr.ipaddr_v6,
		       sizeof(struct in6_addr));
		SET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6);
	} else {
		UNSET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6);
	}

	update_tag(pcc_state);
	update_originator(pcc_state);

	return pcep_pcc_enable(ctrl_state, pcc_state);
}

void pcep_pcc_reconnect(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state)
{
	if (pcc_state->status == PCEP_PCC_DISCONNECTED)
		pcep_pcc_enable(ctrl_state, pcc_state);
}

int pcep_pcc_enable(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
	char pcc_buff[40];
	char pce_buff[40];

	assert(pcc_state->status == PCEP_PCC_DISCONNECTED);
	assert(pcc_state->sess == NULL);

	if (pcc_state->t_reconnect != NULL) {
		thread_cancel(pcc_state->t_reconnect);
		pcc_state->t_reconnect = NULL;
	}

	select_transport_address(pcc_state);

	/* Even though we are connecting using IPv6. we want to have an IPv4
	 * address so we can handle candidate path with IPv4 endpoints */
	if (!CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4)) {
		if (pcc_state->retry_count < OTHER_FAMILY_MAX_RETRIES) {
			flog_warn(EC_PATH_PCEP_MISSING_SOURCE_ADDRESS,
				  "skipping connection to PCE %s:%d due to "
				  "missing PCC IPv4 address",
				  ipaddr2str(&pcc_state->pce_opts->addr,
					     pce_buff, sizeof(pce_buff)),
				  pcc_state->pce_opts->port);
			schedule_reconnect(ctrl_state, pcc_state);
			return 0;
		}
	}

	/* TODO: when IPv6 router ID is available, we want to do the same */

	if (pcc_state->pcc_addr_tr.ipa_type == IPADDR_NONE) {
		flog_warn(EC_PATH_PCEP_MISSING_SOURCE_ADDRESS,
			  "skipping connection to PCE %s:%d due to missing "
			  "PCC address",
			  ipaddr2str(&pcc_state->pce_opts->addr, pce_buff,
				     sizeof(pce_buff)),
			  pcc_state->pce_opts->port);
		schedule_reconnect(ctrl_state, pcc_state);
		return 0;
	}

	PCEP_DEBUG("%s PCC connecting", pcc_state->tag);
	pcc_state->sess = pcep_lib_connect(
		&pcc_state->pcc_addr_tr, pcc_state->pcc_opts->port,
		&pcc_state->pce_opts->addr, pcc_state->pce_opts->port,
		pcc_state->pcc_opts->msd, &pcc_state->pce_opts->config_opts);

	if (pcc_state->sess == NULL) {
		flog_warn(EC_PATH_PCEP_LIB_CONNECT,
			  "failed to connect to PCE %s:%d from %s:%d",
			  ipaddr2str(&pcc_state->pce_opts->addr, pce_buff,
				     sizeof(pce_buff)),
			  pcc_state->pce_opts->port,
			  ipaddr2str(&pcc_state->pcc_addr_tr, pcc_buff,
				     sizeof(pcc_buff)),
			  pcc_state->pcc_opts->port);
		schedule_reconnect(ctrl_state, pcc_state);
		return 0;
	}

  // In case some best pce alternative were waiting to activate
	if (pcc_state->t_update_best != NULL) {
		thread_cancel(pcc_state->t_update_best);
		pcc_state->t_update_best = NULL;
	}

	pcc_state->status = PCEP_PCC_CONNECTING;

	return 0;
}

int pcep_pcc_disable(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
	switch (pcc_state->status) {
	case PCEP_PCC_DISCONNECTED:
		return 0;
	case PCEP_PCC_CONNECTING:
	case PCEP_PCC_SYNCHRONIZING:
	case PCEP_PCC_OPERATING:
		PCEP_DEBUG("%s Disconnecting PCC...", pcc_state->tag);
		pcep_lib_disconnect(pcc_state->sess);
		pcc_state->sess = NULL;
		pcc_state->status = PCEP_PCC_DISCONNECTED;
		return 0;
	default:
		return 1;
	}
}

void pcep_pcc_sync_path(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state, struct path *path)
{
	if (pcc_state->status == PCEP_PCC_SYNCHRONIZING) {
		path->is_synching = true;
	} else if (pcc_state->status == PCEP_PCC_OPERATING)
		path->is_synching = false;
	else
		return;

	path->go_active = true;

	/* Accumulate the dynamic paths without any LSP so computation
	 * requests can be performed after synchronization */
	if ((path->type == SRTE_CANDIDATE_TYPE_DYNAMIC)
	    && (path->first_hop == NULL)) {
		PCEP_DEBUG("%s Scheduling computation request for path %s",
			   pcc_state->tag, path->name);
		push_req(pcc_state, path);
		return;
	}

	/* Synchronize the path if the PCE supports LSP updates and the
	 * endpoint address familly is supported */
	if (pcc_state->caps.is_stateful) {
		if (filter_path(pcc_state, path)) {
			PCEP_DEBUG("%s Synchronizing path %s", pcc_state->tag,
				   path->name);
			send_report(pcc_state, path);
		} else {
			PCEP_DEBUG(
				"%s Skipping %s candidate path %s "
				"synchronization",
				pcc_state->tag,
				ipaddr_type_name(&path->nbkey.endpoint),
				path->name);
		}
	}
}

void pcep_pcc_sync_done(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state)
{
	struct req_entry *req;

	if (pcc_state->status != PCEP_PCC_SYNCHRONIZING)
		return;

	if (pcc_state->caps.is_stateful) {
		struct path *path = pcep_new_path();
		*path = (struct path){.name = NULL,
				      .srp_id = 0,
				      .plsp_id = 0,
				      .status = PCEP_LSP_OPERATIONAL_DOWN,
				      .do_remove = false,
				      .go_active = false,
				      .was_created = false,
				      .was_removed = false,
				      .is_synching = false,
				      .is_delegated = false,
				      .first_hop = NULL,
				      .first_metric = NULL};
		send_report(pcc_state, path);
		pcep_free_path(path);
	}

	pcc_state->synchronized = true;
	pcc_state->status = PCEP_PCC_OPERATING;

	PCEP_DEBUG("%s Synchronization done", pcc_state->tag);

	/* Start the computation request accumulated during synchronization */
	RB_FOREACH (req, req_entry_head, &pcc_state->requests) {
		send_comp_request(pcc_state, req);
	}
}

void pcep_pcc_send_report(struct ctrl_state *ctrl_state,
			  struct pcc_state *pcc_state,
			  struct path *path)
{
	if (pcc_state->status != PCEP_PCC_OPERATING)
		return;

	if (pcc_state->caps.is_stateful) {
		PCEP_DEBUG("%s Send report for candidate path %s",
			   pcc_state->tag, path->name);
		send_report(pcc_state, path);
	}
}

void pcep_pcc_start_sync(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
			pcep_thread_start_sync(ctrl_state, pcc_state->id);
}
/* ------------ Pathd event handler ------------ */

void pcep_pcc_pathd_event_handler(struct ctrl_state *ctrl_state,
				  struct pcc_state *pcc_state,
				  enum pcep_pathd_event_type type,
				  struct path *path)
{
	struct req_entry* req;

	if (pcc_state->status != PCEP_PCC_OPERATING)
		return;

	/* Skipping candidate path with endpoint that do not match the
	 * configured or deduced PCC IP version */
	if (!filter_path(pcc_state, path)) {
		PCEP_DEBUG("%s Skipping %s candidate path %s event",
			   pcc_state->tag,
			   ipaddr_type_name(&path->nbkey.endpoint), path->name);
		return;
	}

	switch (type) {
	case PCEP_PATH_CREATED:
		PCEP_DEBUG("%s Candidate path %s created", pcc_state->tag,
			   path->name);
		if ((path->first_hop == NULL)
		    && (path->type == SRTE_CANDIDATE_TYPE_DYNAMIC)) {
			req = push_req(pcc_state, path);
			send_comp_request(pcc_state, req);
		} else if (pcc_state->caps.is_stateful)
			send_report(pcc_state, path);
		return;
	case PCEP_PATH_UPDATED:
		PCEP_DEBUG("%s Candidate path %s updated", pcc_state->tag,
			   path->name);
		if (pcc_state->caps.is_stateful)
			send_report(pcc_state, path);
		return;
	case PCEP_PATH_REMOVED:
		PCEP_DEBUG("%s Candidate path %s removed", pcc_state->tag,
			   path->name);
		path->was_removed = true;
		if (pcc_state->caps.is_stateful)
			send_report(pcc_state, path);
		return;
	default:
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "Unexpected pathd event received by pcc %s: %u",
			  pcc_state->tag, type);
		return;
	}
}


/* ------------ PCEP event handler ------------ */

void pcep_pcc_pcep_event_handler(struct ctrl_state *ctrl_state,
				 struct pcc_state *pcc_state, pcep_event *event)
{
	PCEP_DEBUG("%s Received PCEP event: %s", pcc_state->tag,
		   pcep_event_type_name(event->event_type));
	switch (event->event_type) {
	case PCC_CONNECTED_TO_PCE:
		assert(PCEP_PCC_CONNECTING == pcc_state->status);
		PCEP_DEBUG("%s Connection established", pcc_state->tag);
		pcc_state->status = PCEP_PCC_SYNCHRONIZING;
		pcc_state->retry_count = 0;
		pcc_state->synchronized = false;
		PCEP_DEBUG("%s Starting PCE synchronization", pcc_state->tag);
		pcep_thread_start_sync(ctrl_state, pcc_state->id);
		break;
	case PCC_RCVD_INVALID_OPEN:
		PCEP_DEBUG("%s Received invalid OPEN message", pcc_state->tag);
		PCEP_DEBUG_PCEP("%s PCEP message: %s", pcc_state->tag,
				format_pcep_message(event->message));
		break;
	case PCE_DEAD_TIMER_EXPIRED:
	case PCE_CLOSED_SOCKET:
	case PCE_SENT_PCEP_CLOSE:
	case PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED:
	case PCC_PCEP_SESSION_CLOSED:
	case PCC_RCVD_MAX_INVALID_MSGS:
	case PCC_RCVD_MAX_UNKOWN_MSGS:
		pcep_pcc_disable(ctrl_state, pcc_state);
		schedule_reconnect(ctrl_state, pcc_state);
		break;
	case MESSAGE_RECEIVED:
		PCEP_DEBUG_PCEP("%s Received PCEP message: %s", pcc_state->tag,
				format_pcep_message(event->message));
		if (pcc_state->status == PCEP_PCC_CONNECTING) {
			handle_pcep_open(ctrl_state, pcc_state, event->message);
			break;
		}
		assert(pcc_state->status == PCEP_PCC_SYNCHRONIZING
		       || pcc_state->status == PCEP_PCC_OPERATING);
		handle_pcep_message(ctrl_state, pcc_state, event->message);
		break;
	default:
		flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEPLIB_EVENT,
			  "Unexpected event from pceplib: %s",
			  format_pcep_event(event));
		break;
	}
}

void handle_pcep_open(struct ctrl_state *ctrl_state,
		      struct pcc_state *pcc_state, struct pcep_message *msg)
{
	assert(msg->msg_header->type == PCEP_TYPE_OPEN);
	pcep_lib_parse_capabilities(msg, &pcc_state->caps);
}

void handle_pcep_message(struct ctrl_state *ctrl_state,
			 struct pcc_state *pcc_state, struct pcep_message *msg)
{
	if (pcc_state->status != PCEP_PCC_OPERATING)
		return;

	switch (msg->msg_header->type) {
	case PCEP_TYPE_INITIATE:
		handle_pcep_lsp_initiate(ctrl_state, pcc_state, msg);
		break;
	case PCEP_TYPE_UPDATE:
		handle_pcep_lsp_update(ctrl_state, pcc_state, msg);
		break;
	case PCEP_TYPE_PCREP:
		handle_pcep_comp_reply(ctrl_state, pcc_state, msg);
		break;
	default:
		flog_warn(EC_PATH_PCEP_UNEXPECTED_PCEP_MESSAGE,
			  "Unexpected pcep message from pceplib: %s",
			  format_pcep_message(msg));
		break;
	}
}

void handle_pcep_lsp_update(struct ctrl_state *ctrl_state,
			    struct pcc_state *pcc_state,
			    struct pcep_message *msg)
{
	char err[MAX_ERROR_MSG_SIZE] = "";
	struct path *path;
	path = pcep_lib_parse_path(msg);
	lookup_nbkey(pcc_state, path);
	/* TODO: Investigate if this is safe to do in the controller thread */
	path_nb_lookup(path);
	specialize_incoming_path(pcc_state, path);
	PCEP_DEBUG("%s Received LSP update", pcc_state->tag);
	PCEP_DEBUG_PATH("%s", format_path(path));

	if (validate_incoming_path(pcc_state, path, err, sizeof(err)))
		pcep_thread_update_path(ctrl_state, pcc_state->id, path);
	else {
		/* FIXME: Monitor the amount of errors from the PCE and
		 * possibly disconnect and blacklist */
		flog_warn(EC_PATH_PCEP_UNSUPPORTED_PCEP_FEATURE,
			  "Unsupported PCEP protocol feature: %s", err);
		pcep_free_path(path);
	}
}

void handle_pcep_lsp_initiate(struct ctrl_state *ctrl_state,
			      struct pcc_state *pcc_state,
			      struct pcep_message *msg)
{
	PCEP_DEBUG("%s Received LSP initiate, not supported yet",
		   pcc_state->tag);

	/* TODO when we support both PCC and PCE initiated sessions,
	 *      we should first check the session type before
	 *      rejecting this message. */
	send_pcep_error(pcc_state, PCEP_ERRT_INVALID_OPERATION,
			PCEP_ERRV_LSP_NOT_PCE_INITIATED);
}

void handle_pcep_comp_reply(struct ctrl_state *ctrl_state,
			    struct pcc_state *pcc_state,
			    struct pcep_message *msg)
{
	char err[MAX_ERROR_MSG_SIZE] = "";
	struct req_entry *req;
	struct path *path;
	path = pcep_lib_parse_path(msg);
	req = pop_req(pcc_state, path->req_id);
	if (req == NULL) {
		/* TODO: check the rate of bad computation reply and close
		 * the connection if more that a given rate.
		 */
		PCEP_DEBUG("%s Received computation reply for unknown request "
			   "%d", pcc_state->tag, path->req_id);
		PCEP_DEBUG_PATH("%s", format_path(path));
		send_pcep_error(pcc_state, PCEP_ERRT_UNKNOWN_REQ_REF,
				PCEP_ERRV_UNASSIGNED);
		return;
	}

	/* Transfer relevent metadata from the request to the response */
	path->nbkey = req->path->nbkey;
	path->plsp_id = req->path->plsp_id;
	path->type = req->path->type;
	path->name = XSTRDUP(MTYPE_PCEP, req->path->name);
	specialize_incoming_path(pcc_state, path);

	PCEP_DEBUG("%s Received computation reply %d (no-path: %s)",
		   pcc_state->tag, path->req_id,
		   path->no_path?"true":"false");
	PCEP_DEBUG_PATH("%s", format_path(path));

	if (path->no_path) {
		PCEP_DEBUG("%s Computation for path %s did not find any result",
			   pcc_state->tag, path->name);
	} else if (validate_incoming_path(pcc_state, path, err, sizeof(err))) {
		/* Updating a dynamic path will automatically delegate it */
		pcep_thread_update_path(ctrl_state, pcc_state->id, path);
		free_req_entry(req);
		return;
	} else {
		/* FIXME: Monitor the amount of errors from the PCE and
		 * possibly disconnect and blacklist */
		flog_warn(EC_PATH_PCEP_UNSUPPORTED_PCEP_FEATURE,
			  "Unsupported PCEP protocol feature: %s", err);
	}

	pcep_free_path(path);

	/* Delegate the path regardless of the outcome */
	/* TODO: For now we are using the path from the request, when
	 * pathd API is thread safe, we could get a new path */
	if (pcc_state->caps.is_stateful) {
		PCEP_DEBUG("%s Delegating undefined dynamic path %s to PCE %s",
			   pcc_state->tag, path->name, pcc_state->originator);
		path = pcep_copy_path(req->path);
		path->is_delegated = true;
		send_report(pcc_state, path);
		pcep_free_path(path);
	}

	free_req_entry(req);
}


/* ------------ Internal Functions ------------ */

const char* ipaddr_type_name(struct ipaddr *addr)
{
	if (IS_IPADDR_V4(addr)) return "IPv4";
	if (IS_IPADDR_V6(addr)) return "IPv6";
	return "undefined";
}

bool filter_path(struct pcc_state *pcc_state, struct path *path)
{
	return (IS_IPADDR_V4(&path->nbkey.endpoint)
		&& CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4))
	       || (IS_IPADDR_V6(&path->nbkey.endpoint)
		   && CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6));
}

void select_pcc_addresses(struct pcc_state *pcc_state)
{
	/* If no IPv4 address was specified, try to get one from zebra */
	if (!CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4)) {
		if (get_inet_router_id(&pcc_state->pcc_addr_v4)) {
			SET_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4);
		}
	}

	/* TODO: Add support for IPv6 router ID when available */
}

void select_transport_address(struct pcc_state *pcc_state)
{
	struct ipaddr *taddr = &pcc_state->pcc_addr_tr;

	select_pcc_addresses(pcc_state);

	taddr->ipa_type = IPADDR_NONE;

	/* TODO: Add support for IPv6 router ID when available */

	/* Select a transport source address in function of the configured PCE
	 * address */
	if (IS_IPADDR_V4(&pcc_state->pce_opts->addr)) {
		if (CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4)) {
			taddr->ipa_type = IPADDR_V4;
			taddr->ipaddr_v4 = pcc_state->pcc_addr_v4;
		}
	} else {
		if (CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6)) {
			taddr->ipa_type = IPADDR_V6;
			taddr->ipaddr_v6 = pcc_state->pcc_addr_v6;
		}
	}
}

void update_tag(struct pcc_state *pcc_state)
{
	if (pcc_state->pce_opts != NULL) {
		assert(!IS_IPADDR_NONE(&pcc_state->pce_opts->addr));
		if (IS_IPADDR_V6(&pcc_state->pce_opts->addr)) {
			snprintfrr(pcc_state->tag, sizeof(pcc_state->tag),
				   "%pI6:%i (%u)",
				   &pcc_state->pce_opts->addr.ipaddr_v6,
				   pcc_state->pce_opts->port, pcc_state->id);
		} else {
			snprintfrr(pcc_state->tag, sizeof(pcc_state->tag),
				   "%pI4:%i (%u)",
				   &pcc_state->pce_opts->addr.ipaddr_v4,
				   pcc_state->pce_opts->port, pcc_state->id);
		}
	} else {
		snprintfrr(pcc_state->tag, sizeof(pcc_state->tag), "(%u)",
			   pcc_state->id);
	}
}

void update_originator(struct pcc_state *pcc_state)
{
	char *originator;
	if (pcc_state->originator != NULL) {
		XFREE(MTYPE_PCEP, pcc_state->originator);
		pcc_state->originator = NULL;
	}
	if (pcc_state->pce_opts == NULL)
		return;
	originator = XCALLOC(MTYPE_PCEP, 52);
	assert(!IS_IPADDR_NONE(&pcc_state->pce_opts->addr));
	if (IS_IPADDR_V6(&pcc_state->pce_opts->addr)) {
		snprintfrr(originator, 52, "%pI6:%i",
			   &pcc_state->pce_opts->addr.ipaddr_v6,
			   pcc_state->pce_opts->port);
	} else {
		snprintfrr(originator, 52, "%pI4:%i",
			   &pcc_state->pce_opts->addr.ipaddr_v4,
			   pcc_state->pce_opts->port);
	}
	pcc_state->originator = originator;
}

void schedule_reconnect(struct ctrl_state *ctrl_state,
			struct pcc_state *pcc_state)
{
	pcc_state->retry_count++;
	pcep_thread_schedule_reconnect(ctrl_state, pcc_state->id,
				       pcc_state->retry_count,
				       &pcc_state->t_reconnect);
  if (pcc_state->retry_count == 1) {
          pcep_thread_schedule_sync_best_pce(
                  ctrl_state, pcc_state->id, pcc_state->pce_opts->config_opts.delegation_timeout_seconds ,
                  &pcc_state->t_update_best);
      }
}

void send_pcep_message(struct pcc_state *pcc_state, struct pcep_message *msg)
{
	PCEP_DEBUG_PCEP("%s Sending PCEP message: %s", pcc_state->tag,
			format_pcep_message(msg));
	send_message(pcc_state->sess, msg, true);
}

void send_pcep_error(struct pcc_state *pcc_state,
		     enum pcep_error_type error_type,
		     enum pcep_error_value error_value)
{
	struct pcep_message*  msg;
	PCEP_DEBUG("%s Sending PCEP error type %s (%d) value %s (%d)",
		   pcc_state->tag, pcep_error_type_name(error_type), error_type,
		   pcep_error_value_name(error_type, error_value), error_value);
	msg = pcep_lib_format_error(error_type, error_value);
	send_pcep_message(pcc_state, msg);
}

void send_report(struct pcc_state *pcc_state, struct path *path)
{
	struct pcep_message *report;

	specialize_outgoing_path(pcc_state, path);
	PCEP_DEBUG_PATH("%s Sending path %s: %s", pcc_state->tag, path->name,
			format_path(path));
	report = pcep_lib_format_report(path);
	send_pcep_message(pcc_state, report);
}

/* Updates the path for the PCE, updating the delegation and creation flags */
void specialize_outgoing_path(struct pcc_state *pcc_state, struct path *path)
{
	bool is_delegated = false;
	bool was_created = false;

	lookup_plspid(pcc_state, path);

	set_pcc_address(pcc_state, &path->nbkey, &path->pcc_addr);
	path->sender = pcc_state->pcc_addr_tr;

	/* TODO: When the pathd API have a way to mark a path as
	 * delegated, use it instead of considering all dynamic path
	 * delegated. We need to disable the originator check for now,
	 * because path could be delegated without having any originator yet */
	// if ((path->originator == NULL)
	//     || (strcmp(path->originator, pcc_state->originator) == 0)) {
	// 	is_delegated = (path->type == SRTE_CANDIDATE_TYPE_DYNAMIC)
	// 			&& (path->first_hop != NULL);
	// 	/* it seems the PCE consider updating an LSP a creation ?!?
	// 	at least Cisco does... */
	// 	was_created = path->update_origin == SRTE_ORIGIN_PCEP;
	// }
	is_delegated = (path->type == SRTE_CANDIDATE_TYPE_DYNAMIC);
	was_created = path->update_origin == SRTE_ORIGIN_PCEP;

	path->pcc_id = pcc_state->id;
	path->go_active = is_delegated && pcc_state->is_best;
	path->is_delegated = is_delegated && pcc_state->is_best;
	path->was_created = was_created;
}

/* Updates the path for the PCC */
void specialize_incoming_path(struct pcc_state *pcc_state, struct path *path)
{
	set_pcc_address(pcc_state, &path->nbkey, &path->pcc_addr);
	path->sender = pcc_state->pce_opts->addr;
	path->pcc_id = pcc_state->id;
	path->update_origin = SRTE_ORIGIN_PCEP;
	path->originator = XSTRDUP(MTYPE_PCEP, pcc_state->originator);
}

/* Ensure the path can be handled by the PCC and if not, sends an error */
bool validate_incoming_path(struct pcc_state *pcc_state, struct path *path,
			    char* errbuff, size_t buffsize)
{
	struct path_hop *hop;
	enum pcep_error_type err_type = 0;
	enum pcep_error_value err_value = PCEP_ERRV_UNASSIGNED;

	for (hop = path->first_hop; hop != NULL; hop = hop->next) {
		/* Hops without SID are not supported */
		if (!hop->has_sid) {
			snprintfrr(errbuff, buffsize, "SR segment without SID");
			err_type = PCEP_ERRT_RECEPTION_OF_INV_OBJECT;
			err_value = PCEP_ERRV_DISJOINTED_CONF_TLV_MISSING;
			break;
		}
		/* Hops with non-MPLS SID are not supported */
		if (!hop->is_mpls) {
			snprintfrr(errbuff, buffsize, "SR segment with non-MPLS SID");
			err_type = PCEP_ERRT_RECEPTION_OF_INV_OBJECT;
			err_value = PCEP_ERRV_UNSUPPORTED_NAI;
			break;
		}
	}

	if (err_type != 0) {
		send_pcep_error(pcc_state, err_type, err_value);
		return false;
	}

	return true;
}

void send_comp_request(struct pcc_state *pcc_state, struct req_entry *req)
{
	assert(req != NULL);
	assert(req->path != NULL);
	assert(req->path->req_id > 0);
	assert(RB_FIND(req_entry_head, &pcc_state->requests, req) == req);

	char buff[40];
	struct pcep_message *msg;

	if (!pcc_state->is_best) {
		return;
	}
	/* TODO: Add a timer to retry the computation request ? */

	specialize_outgoing_path(pcc_state, req->path);

	PCEP_DEBUG("%s Sending computation request %d for path %s to %s",
		   pcc_state->tag, req->path->req_id, req->path->name,
		   ipaddr2str(&req->path->nbkey.endpoint, buff, sizeof(buff)));
	PCEP_DEBUG_PATH("%s Computation request path %s: %s", pcc_state->tag,
			req->path->name, format_path(req->path));

	msg = pcep_lib_format_request(req->path->req_id, &req->path->pcc_addr,
				      &req->path->nbkey.endpoint);
	send_pcep_message(pcc_state, msg);
}

void set_pcc_address(struct pcc_state *pcc_state, struct lsp_nb_key *nbkey,
		     struct ipaddr *addr)
{
	select_pcc_addresses(pcc_state);
	if (IS_IPADDR_V6(&nbkey->endpoint)) {
		assert(CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV6));
		addr->ipa_type = IPADDR_V6;
		addr->ipaddr_v6 = pcc_state->pcc_addr_v6;
	} else if (IS_IPADDR_V4(&nbkey->endpoint)) {
		assert(CHECK_FLAG(pcc_state->flags, F_PCC_STATE_HAS_IPV4));
		addr->ipa_type = IPADDR_V4;
		addr->ipaddr_v4 = pcc_state->pcc_addr_v4;
	} else {
		addr->ipa_type = IPADDR_NONE;
	}
}


/* ------------ Data Structure Helper Functions ------------ */

void lookup_plspid(struct pcc_state *pcc_state, struct path *path)
{
	struct plspid_map_data key, *plspid_mapping;
	struct nbkey_map_data *nbkey_mapping;

	if (path->nbkey.color != 0) {
		key.nbkey = path->nbkey;
		plspid_mapping = plspid_map_find(&pcc_state->plspid_map, &key);
		if (plspid_mapping == NULL) {
			plspid_mapping =
				XCALLOC(MTYPE_PCEP, sizeof(*plspid_mapping));
			plspid_mapping->nbkey = key.nbkey;
			plspid_mapping->plspid = pcc_state->next_plspid;
			plspid_map_add(&pcc_state->plspid_map, plspid_mapping);
			nbkey_mapping =
				XCALLOC(MTYPE_PCEP, sizeof(*nbkey_mapping));
			nbkey_mapping->nbkey = key.nbkey;
			nbkey_mapping->plspid = pcc_state->next_plspid;
			nbkey_map_add(&pcc_state->nbkey_map, nbkey_mapping);
			pcc_state->next_plspid++;
			// FIXME: Send some error to the PCE isntead of crashing
			assert(pcc_state->next_plspid <= 1048576);
		}
		path->plsp_id = plspid_mapping->plspid;
	}
}

void lookup_nbkey(struct pcc_state *pcc_state, struct path *path)
{
	struct nbkey_map_data key, *mapping;
	// TODO: Should give an error to the PCE instead of crashing
	assert(path->plsp_id != 0);
	key.plspid = path->plsp_id;
	mapping = nbkey_map_find(&pcc_state->nbkey_map, &key);
	assert(mapping != NULL);
	path->nbkey = mapping->nbkey;
}

void free_req_entry(struct req_entry *req)
{
	pcep_free_path(req->path);
	XFREE(MTYPE_PCEP, req);
}

struct req_entry* push_req(struct pcc_state *pcc_state, struct path* path)
{
	assert(path->req_id == 0);

	uint32_t reqid = pcc_state->next_reqid;
	struct req_entry *req;
	void* res;

	req = XCALLOC(MTYPE_PCEP, sizeof(*req));
	req->path = pcep_copy_path(path);
	req->path->req_id = reqid;
	res = RB_INSERT(req_entry_head, &pcc_state->requests, req);
	assert(res == NULL);

	pcc_state->next_reqid += 1;
	/* Wrapping is allowed, but 0 is not a valid id */
	if (pcc_state->next_reqid == 0)
		pcc_state->next_reqid = 1;

	return req;
}

struct req_entry* pop_req(struct pcc_state *pcc_state, uint32_t reqid)
{
	struct path path = {.req_id = reqid};
	struct req_entry key = {.path = &path};
	struct req_entry *req;

	req = RB_FIND(req_entry_head, &pcc_state->requests, &key);
	if (req == NULL)
		return NULL;
	RB_REMOVE(req_entry_head, &pcc_state->requests, req);

	return req;
}


/* ------------ Data Structure Callbacks ------------ */

#define CMP_RETURN(A, B)                                                       \
	if (A != B)                                                            \
	return (A < B) ? -1 : 1

static int plspid_map_cmp(const struct plspid_map_data *a,
			  const struct plspid_map_data *b)
{
	CMP_RETURN(a->nbkey.color, b->nbkey.color);
	int cmp = ipaddr_cmp(&a->nbkey.endpoint, &b->nbkey.endpoint);
	if (cmp != 0)
		return cmp;
	CMP_RETURN(a->nbkey.preference, b->nbkey.preference);
	return 0;
}

static uint32_t plspid_map_hash(const struct plspid_map_data *e)
{
	uint32_t hash;
	hash = jhash_2words(e->nbkey.color, e->nbkey.preference, 0x55aa5a5a);
	switch (e->nbkey.endpoint.ipa_type) {
	case IPADDR_V4:
		return jhash(&e->nbkey.endpoint.ipaddr_v4,
			     sizeof(e->nbkey.endpoint.ipaddr_v4), hash);
	case IPADDR_V6:
		return jhash(&e->nbkey.endpoint.ipaddr_v6,
			     sizeof(e->nbkey.endpoint.ipaddr_v6), hash);
	default:
		return hash;
	}
}

static int nbkey_map_cmp(const struct nbkey_map_data *a,
			 const struct nbkey_map_data *b)
{
	CMP_RETURN(a->plspid, b->plspid);
	return 0;
}

static uint32_t nbkey_map_hash(const struct nbkey_map_data *e)
{
	return e->plspid;
}
