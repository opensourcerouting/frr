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
#include "pathd/path_errors.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_controller.h"
#include "pathd/path_pcep_pcc.h"
#include "pathd/path_pcep_nb.h"
#include "pathd/path_pcep_debug.h"

#define MAX_RECONNECT_DELAY 120

#define min(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a <= _b ? _a : _b;                                            \
	})


/* Event handling data structures */
enum pcep_ctrl_event_type {
	EV_UPDATE_PCC_OPTS = 1,
	EV_UPDATE_PCE_OPTS,
	EV_REMOVE_PCC,
	EV_PATHD_EVENT,
	EV_SYNC_PATH,
	EV_SYNC_DONE,
	EV_PCEPLIB_EVENT
};

struct pcep_ctrl_event_data {
	struct ctrl_state *ctrl_state;
	enum pcep_ctrl_event_type type;
	uint32_t sub_type;
	int pcc_id;
	void *payload;
};

struct pcep_main_event_data {
	pcep_main_event_handler_t handler;
	int pcc_id;
	enum pcep_main_event_type type;
	void *payload;
};

/* Synchronous call arguments */

struct get_counters_args {
	struct ctrl_state *ctrl_state;
	int pcc_id;
	struct counters_group *counters;
};

struct send_report_args {
	struct ctrl_state *ctrl_state;
	int pcc_id;
	struct path *path;
};


/* Internal Functions Called From Main Thread */
static int pcep_ctrl_halt_cb(struct frr_pthread *fpt, void **res);

/* Internal Functions Called From Controller Thread */
static int pcep_thread_finish_event_handler(struct thread *thread);
static int pcep_thread_get_counters_callback(struct thread *t);
static int pcep_thread_send_report_callback(struct thread *t);
static int pcep_thread_update_best_pce(struct ctrl_state *ctrl_state,
					     int pcc_id);

/* Controller Thread Timer Handler */
static int schedule_thread_timer(struct ctrl_state *ctrl_state, int pcc_id,
				 enum pcep_ctrl_timer_type type, uint32_t delay,
				 void *payload, struct thread **thread);
static int schedule_thread_timer_with_cb(struct ctrl_state *ctrl_state,
					 int pcc_id,
					 enum pcep_ctrl_timer_type type,
					 uint32_t delay, void *payload,
					 struct thread **thread,
					 pcep_ctrl_thread_callback timer_cb);
static int pcep_thread_timer_handler(struct thread *thread);
static int pcep_thread_timer_update_best_pce(struct ctrl_state *ctrl_state, int pcc_id);

/* Controller Thread Socket read/write Handler */
static int schedule_thread_socket(struct ctrl_state *ctrl_state, int pcc_id,
				  enum pcep_ctrl_socket_type type, bool is_read,
				  void *payload, int fd, struct thread **thread,
				  pcep_ctrl_thread_callback cb);

/* Controller Thread Event Handler */
static int send_to_thread(struct ctrl_state *ctrl_state, int pcc_id,
			  enum pcep_ctrl_event_type type, uint32_t sub_type,
			  void *payload);
static int send_to_thread_with_cb(struct ctrl_state *ctrl_state, int pcc_id,
				  enum pcep_ctrl_event_type type,
				  uint32_t sub_type, void *payload,
				  pcep_ctrl_thread_callback event_cb);
static int pcep_thread_event_handler(struct thread *thread);
static int pcep_thread_event_update_pcc_options(struct ctrl_state *ctrl_state,
						struct pcc_opts *opts);
static int pcep_thread_event_update_pce_options(struct ctrl_state *ctrl_state,
						int pcc_id,
						struct pce_opts *opts);
static int pcep_thread_event_remove_pcc_by_id(struct ctrl_state *ctrl_state,
					      int pcc_id);
static int pcep_thread_event_remove_pcc_all(struct ctrl_state *ctrl_state);
static int pcep_thread_event_remove_pcc(struct ctrl_state *ctrl_state,
					struct pce_opts *pce_opts);
static int pcep_thread_event_sync_path(struct ctrl_state *ctrl_state,
				       int pcc_id, struct path *path);
static int pcep_thread_event_sync_done(struct ctrl_state *ctrl_state,
				       int pcc_id);
static int pcep_thread_event_pathd_event(struct ctrl_state *ctrl_state,
					 enum pcep_pathd_event_type type,
					 struct path *path);

/* Main Thread Event Handler */
static int send_to_main(struct ctrl_state *ctrl_state, int pcc_id,
			enum pcep_main_event_type type, void *payload);
static int pcep_main_event_handler(struct thread *thread);

/* Helper functions */
static void set_ctrl_state(struct frr_pthread *fpt,
			   struct ctrl_state *ctrl_state);
static struct ctrl_state *get_ctrl_state(struct frr_pthread *fpt);
static struct pcc_state *get_pcc_state(struct ctrl_state *ctrl_state,
				       int pcc_id);
static int set_pcc_state(struct ctrl_state *ctrl_state,
			 struct pcc_state *pcc_state);
static void remove_pcc_state(struct ctrl_state *ctrl_state,
			     struct pcc_state *pcc_state);
static uint32_t backoff_delay(uint32_t max, uint32_t base, uint32_t attempt);
static int calculate_best_pce(struct ctrl_state *ctrl_state);
static int get_next_id(struct ctrl_state *ctrl_state);
static bool is_best_pce(struct ctrl_state *ctrl_state, int pce);
static int get_previous_best_pce(struct ctrl_state *ctrl_state);
static int get_pcc_id_by_ip_port(struct ctrl_state *ctrl_state,
			  struct pce_opts *pce_opts);
static int get_pcc_idx_by_id(struct ctrl_state *ctrl_state, int id);
static int get_pcc_idx_by_ip_port(struct pce_opts **array_pce_opts,
			   struct pce_opts *pce_opts);
static int get_pcc_id_by_idx(struct ctrl_state *ctrl_state, int idx);
static struct pcc_state *get_pcc_by_id(struct ctrl_state *ctrl_state, int id);
static int pcep_ctrl_get_free_pcc_idx(struct ctrl_state *ctrl_state);


/* ------------ API Functions Called from Main Thread ------------ */

int pcep_ctrl_initialize(struct thread_master *main_thread,
			 struct frr_pthread **fpt,
			 pcep_main_event_handler_t event_handler)
{
	assert(fpt != NULL);

	int ret = 0;
	struct ctrl_state *ctrl_state;
	struct frr_pthread_attr attr = {
		.start = frr_pthread_attr_default.start,
		.stop = pcep_ctrl_halt_cb,
	};

	PCEP_DEBUG("Initializing pcep module controller");

	/* Create and start the FRR pthread */
	*fpt = frr_pthread_new(&attr, "PCEP thread", "pcep");
	if (*fpt == NULL) {
		flog_err(EC_PATH_SYSTEM_CALL,
			 "failed to initialize PCEP thread");
		return 1;
	}
	ret = frr_pthread_run(*fpt, NULL);
	if (ret < 0) {
		flog_err(EC_PATH_SYSTEM_CALL, "failed to create PCEP thread");
		return ret;
	}
	frr_pthread_wait_running(*fpt);

	/* Initialise the thread state */
	ctrl_state = XCALLOC(MTYPE_PCEP, sizeof(*ctrl_state));
	ctrl_state->main = main_thread;
	ctrl_state->self = (*fpt)->master;
	ctrl_state->main_event_handler = event_handler;
	ctrl_state->pcc_count = 0;
	ctrl_state->pcc_last_id = 0;
	ctrl_state->pcc_opts =
		XCALLOC(MTYPE_PCEP, sizeof(*ctrl_state->pcc_opts));
	/* Default to no PCC address defined */
	ctrl_state->pcc_opts->addr.ipa_type = IPADDR_NONE;
	ctrl_state->pcc_opts->port = PCEP_DEFAULT_PORT;

	/* Keep the state reference for events */
	set_ctrl_state(*fpt, ctrl_state);

	return ret;
}

int pcep_ctrl_finalize(struct frr_pthread **fpt)
{
	assert(fpt != NULL);

	int ret = 0;

	PCEP_DEBUG("Finalizing pcep module controller");

	if (*fpt != NULL) {
		frr_pthread_stop(*fpt, NULL);
		*fpt = NULL;
	}

	return ret;
}

int pcep_ctrl_update_pcc_options(struct frr_pthread *fpt, struct pcc_opts *opts)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, 0, EV_UPDATE_PCC_OPTS, 0, opts);
}

int pcep_ctrl_update_pce_options(struct frr_pthread *fpt, struct pce_opts *opts)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, 0, EV_UPDATE_PCE_OPTS, 0, opts);
}

int pcep_ctrl_remove_pcc(struct frr_pthread *fpt, struct pce_opts *pce_opts)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, 0, EV_REMOVE_PCC, 0, pce_opts);
}

int pcep_ctrl_pathd_event(struct frr_pthread *fpt,
			  enum pcep_pathd_event_type type, struct path *path)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, 0, EV_PATHD_EVENT, type, path);
}

int pcep_ctrl_sync_path(struct frr_pthread *fpt, int pcc_id, struct path *path)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, pcc_id, EV_SYNC_PATH, 0, path);
}

int pcep_ctrl_sync_done(struct frr_pthread *fpt, int pcc_id)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	return send_to_thread(ctrl_state, pcc_id, EV_SYNC_DONE, 0, NULL);
}

struct counters_group *pcep_ctrl_get_counters(struct frr_pthread *fpt,
					      int pcc_id)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	struct get_counters_args args = {
		.ctrl_state = ctrl_state, .pcc_id = pcc_id, .counters = NULL};
	thread_execute(ctrl_state->self, pcep_thread_get_counters_callback,
		       &args, 0);
	return args.counters;
}

struct pcc_state *pcep_ctrl_get_pcc_state(struct frr_pthread *fpt,
					  const char *pce_name)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	for (int i = 0; i < MAX_PCE; i++) {
		if (ctrl_state->pcc[i] == NULL) {
			continue;
		}

		if (strcmp(ctrl_state->pcc[i]->pce_opts->pce_name, pce_name)
		    == 0) {
			return ctrl_state->pcc[i];
		}
	}

	return NULL;
}

bool pcep_ctrl_pcc_has_pce(struct frr_pthread *fpt, const char *pce_name)
{
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	for (int i = 0; i < MAX_PCC; i++) {
		if (ctrl_state->pcc[i] == NULL) {
			continue;
		}

		if (strcmp(ctrl_state->pcc[i]->pce_opts->pce_name, pce_name)
		    == 0) {
			return true;
		}
	}

	return false;
}

void pcep_ctrl_send_report(struct frr_pthread *fpt, int pcc_id,
			   struct path *path)
{
	/* Sends a report stynchronously */
	struct ctrl_state *ctrl_state = get_ctrl_state(fpt);
	struct send_report_args args = {
		.ctrl_state = ctrl_state, .pcc_id = pcc_id, .path = path};
	thread_execute(ctrl_state->self, pcep_thread_send_report_callback,
		       &args, 0);
}

/* ------------ Internal Functions Called from Main Thread ------------ */

int pcep_ctrl_halt_cb(struct frr_pthread *fpt, void **res)
{
	thread_add_event(fpt->master, pcep_thread_finish_event_handler,
			 (void *)fpt, 0, NULL);
	pthread_join(fpt->thread, res);

	return 0;
}


/* ------------ API Functions Called From Controller Thread ------------ */

void pcep_thread_start_sync(struct ctrl_state *ctrl_state, int pcc_id)
{
	send_to_main(ctrl_state, pcc_id, PCEP_MAIN_EVENT_START_SYNC, NULL);
}

void pcep_thread_update_path(struct ctrl_state *ctrl_state, int pcc_id,
			     struct path *path)
{
	send_to_main(ctrl_state, pcc_id, PCEP_MAIN_EVENT_UPDATE_CANDIDATE,
		     path);
}

void pcep_thread_schedule_sync_best_pce(struct ctrl_state *ctrl_state,
					int pcc_id, int delay,
					struct thread **thread)
{

	schedule_thread_timer(ctrl_state, pcc_id, TM_CALCULATE_BEST_PCE, delay,
			      NULL, thread);
}

void pcep_thread_schedule_reconnect(struct ctrl_state *ctrl_state, int pcc_id,
				    int retry_count, struct thread **thread)
{
	uint32_t delay = backoff_delay(MAX_RECONNECT_DELAY, 1, retry_count);
	PCEP_DEBUG("Schedule reconnection in %us (retry %u)", delay,
		   retry_count);
	schedule_thread_timer(ctrl_state, pcc_id, TM_RECONNECT_PCC, delay, NULL,
			      thread);
}

void pcep_thread_schedule_pceplib_timer(struct ctrl_state *ctrl_state,
				    int delay, void *payload, struct thread **thread,
				    pcep_ctrl_thread_callback timer_cb)
{
	PCEP_DEBUG("Schedule pceplib timer for %us", delay);
	schedule_thread_timer_with_cb(ctrl_state, 0, TM_PCEPLIB_TIMER, delay,
				      payload, thread, timer_cb);
}

void pcep_thread_cancel_pceplib_timer(struct thread **thread)
{
	PCEP_DEBUG("Cancel pceplib timer");

	if (thread == NULL || *thread == NULL) {
		return;
	}

	struct pcep_ctrl_timer_data *data = THREAD_ARG(*thread);
	if (data != NULL) {
		XFREE(MTYPE_PCEP, data);
	}

	if ((*thread)->master->owner == pthread_self()) {
		thread_cancel(*thread);
	} else {
		thread_cancel_async((*thread)->master, thread, NULL);
	}
}

/* ------------ Internal Functions Called From Controller Thread ------------ */

int pcep_thread_finish_event_handler(struct thread *thread)
{
	int i;
	struct frr_pthread *fpt = THREAD_ARG(thread);
	struct ctrl_state *ctrl_state = fpt->data;

	assert(ctrl_state != NULL);

	for (i = 0; i < MAX_PCC; i++) {
		if (ctrl_state->pcc[i]) {
			pcep_pcc_finalize(ctrl_state, ctrl_state->pcc[i]);
			ctrl_state->pcc[i] = NULL;
		}
	}

	XFREE(MTYPE_PCEP, ctrl_state->pcc_opts);
	XFREE(MTYPE_PCEP, ctrl_state);
	fpt->data = NULL;

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);
	return 0;
}

int pcep_thread_get_counters_callback(struct thread *t)
{
	struct get_counters_args *args = THREAD_ARG(t);
	assert(args != NULL);
	struct ctrl_state *ctrl_state = args->ctrl_state;
	assert(ctrl_state != NULL);
	struct pcc_state *pcc_state;

		pcc_state = get_pcc_state(ctrl_state, args->pcc_id);
		if (pcc_state) {
			args->counters =
				pcep_lib_copy_counters(pcc_state->sess);
		}
		return 0;

	args->counters = NULL;
	return 0;
}

int pcep_thread_send_report_callback(struct thread *t)
{
	struct send_report_args *args = THREAD_ARG(t);
	assert(args != NULL);
	struct ctrl_state *ctrl_state = args->ctrl_state;
	assert(ctrl_state != NULL);
	struct pcc_state *pcc_state;

	if (args->pcc_id == 0) {
		for (int i = 0; i < MAX_PCC; i++) {
			if (ctrl_state->pcc[i]) {
				pcep_pcc_send_report(ctrl_state,
						     ctrl_state->pcc[i],
						     args->path);
			}
		}
	} else {
		pcc_state = get_pcc_state(ctrl_state, args->pcc_id);
		pcep_pcc_send_report(ctrl_state, pcc_state, args->path);
	}

	return 0;
}


/* ------------ Controller Thread Timer Handler ------------ */

int schedule_thread_timer_with_cb(struct ctrl_state *ctrl_state, int pcc_id,
			  enum pcep_ctrl_timer_type type, uint32_t delay,
			  void *payload, struct thread **thread,
			  pcep_ctrl_thread_callback timer_cb)
{
	assert(thread != NULL);

	struct pcep_ctrl_timer_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->ctrl_state = ctrl_state;
	data->type = type;
	data->pcc_id = pcc_id;
	data->payload = payload;

	thread_add_timer(ctrl_state->self, timer_cb,
			 (void *)data, delay, thread);

	return 0;
}

int schedule_thread_timer(struct ctrl_state *ctrl_state, int pcc_id,
			  enum pcep_ctrl_timer_type type, uint32_t delay,
			  void *payload, struct thread **thread)
{
	return schedule_thread_timer_with_cb(ctrl_state, pcc_id, type, delay,
					     payload, thread,
					     pcep_thread_timer_handler);
}

int pcep_thread_timer_update_best_pce(struct ctrl_state *ctrl_state, int pcc_id)
{
    int ret=0;
    // resync whatever were new best
    int best_id = calculate_best_pce(ctrl_state);
    if (best_id) {
        struct pcc_state *pcc_state =
            get_pcc_state(ctrl_state, best_id);
        ret = pcep_thread_update_best_pce(ctrl_state, pcc_state->id);
    }

    return ret;
}

int pcep_thread_timer_handler(struct thread *thread)
{
	/* data unpacking */
	struct pcep_ctrl_timer_data *data = THREAD_ARG(thread);
	assert(data != NULL);
	struct ctrl_state *ctrl_state = data->ctrl_state;
	assert(ctrl_state != NULL);
	enum pcep_ctrl_timer_type type = data->type;
	int pcc_id = data->pcc_id;
	XFREE(MTYPE_PCEP, data);

	int ret = 0;
	struct pcc_state *pcc_state = NULL;
	pcc_state = get_pcc_state(ctrl_state, pcc_id);
	if (!pcc_state) {
		return ret;
	}
	switch (type) {
	case TM_RECONNECT_PCC:
		pcc_state = get_pcc_state(ctrl_state, pcc_id);
		if (pcc_state)
			pcep_pcc_reconnect(ctrl_state, pcc_state);
		break;
	case TM_CALCULATE_BEST_PCE://Previous best disconnect so new best should be synced
		ret = pcep_thread_timer_update_best_pce(ctrl_state, pcc_id);
		break;
	default:
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "Unknown controller timer triggered: %u", type);
		break;
	}

	return ret;
}

int pcep_thread_pcep_event(struct thread *thread)
{
	struct pcep_ctrl_event_data *data = THREAD_ARG(thread);
	assert(data != NULL);
	struct ctrl_state *ctrl_state = data->ctrl_state;
	pcep_event *event = data->payload;
	XFREE(MTYPE_PCEP, data);
	int i;

	for (i = 0; i < MAX_PCC; i++) {
		if (ctrl_state->pcc[i]) {
			struct pcc_state *pcc_state = ctrl_state->pcc[i];
			if (pcc_state->sess != event->session)
				continue;
			pcep_pcc_pcep_event_handler(ctrl_state, pcc_state,
						    event);
			break;
		}
	}
	destroy_pcep_event(event);

	return 0;
}

/* ------------ Controller Thread Socket Functions ------------ */

int schedule_thread_socket(struct ctrl_state *ctrl_state, int pcc_id,
			   enum pcep_ctrl_socket_type type, bool is_read,
			   void *payload, int fd, struct thread **thread,
			   pcep_ctrl_thread_callback socket_cb)
{
	assert(thread != NULL);

	struct pcep_ctrl_socket_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->ctrl_state = ctrl_state;
	data->type = type;
	data->is_read = is_read;
	data->fd = fd;
	data->pcc_id = pcc_id;
	data->payload = payload;

	if (is_read) {
		thread_add_read(ctrl_state->self, socket_cb,
				(void *)data, fd, thread);
	} else {
		thread_add_write(ctrl_state->self, socket_cb,
				 (void *)data, fd, thread);
	}

	return 0;
}

int pcep_thread_socket_write(void *fpt, void **thread, int fd, void *payload,
			     pcep_ctrl_thread_callback socket_cb)
{
	struct ctrl_state *ctrl_state = ((struct frr_pthread *)fpt)->data;

	return schedule_thread_socket(ctrl_state, 0, SOCK_PCEPLIB, false,
				      payload, fd, (struct thread **)thread, socket_cb);
}

int pcep_thread_socket_read(void *fpt, void **thread, int fd, void *payload,
			    pcep_ctrl_thread_callback socket_cb)
{
	struct ctrl_state *ctrl_state = ((struct frr_pthread *)fpt)->data;

	return schedule_thread_socket(ctrl_state, 0, SOCK_PCEPLIB, true,
				      payload, fd, (struct thread **)thread, socket_cb);
}

int pcep_thread_send_ctrl_event(void *fpt, void *payload,
				pcep_ctrl_thread_callback cb)
{
	struct ctrl_state *ctrl_state = ((struct frr_pthread *)fpt)->data;

	return send_to_thread_with_cb(ctrl_state, 0, EV_PCEPLIB_EVENT, 0,
				      payload, cb);
}

/* ------------ Controller Thread Event Handler ------------ */

int send_to_thread(struct ctrl_state *ctrl_state, int pcc_id,
		   enum pcep_ctrl_event_type type, uint32_t sub_type,
		   void *payload)
{
	return send_to_thread_with_cb(ctrl_state, pcc_id, type, sub_type,
				      payload, pcep_thread_event_handler);
}

int send_to_thread_with_cb(struct ctrl_state *ctrl_state, int pcc_id,
			   enum pcep_ctrl_event_type type, uint32_t sub_type,
			   void *payload, pcep_ctrl_thread_callback event_cb)
{
	struct pcep_ctrl_event_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->ctrl_state = ctrl_state;
	data->type = type;
	data->sub_type = sub_type;
	data->pcc_id = pcc_id;
	data->payload = payload;

	thread_add_event(ctrl_state->self, event_cb, (void *)data, 0, NULL);

	return 0;
}

int pcep_thread_event_handler(struct thread *thread)
{
	/* data unpacking */
	struct pcep_ctrl_event_data *data = THREAD_ARG(thread);
	assert(data != NULL);
	struct ctrl_state *ctrl_state = data->ctrl_state;
	assert(ctrl_state != NULL);
	enum pcep_ctrl_event_type type = data->type;
	uint32_t sub_type = data->sub_type;
	int pcc_id = data->pcc_id;
	void *payload = data->payload;
	XFREE(MTYPE_PCEP, data);

	int ret = 0;

	/* Possible sub-type values */
	enum pcep_pathd_event_type path_event_type = PCEP_PATH_UNDEFINED;

	/* Possible payload values */
	struct path *path = NULL;
	struct pcc_opts *pcc_opts = NULL;
	struct pce_opts *pce_opts = NULL;

	int previous_best_pcc_id = -1;
	int new_best_pcc_id = -1;

	switch (type) {
	case EV_UPDATE_PCC_OPTS:
		assert(payload != NULL);
		pcc_opts = (struct pcc_opts *)payload;
		ret = pcep_thread_event_update_pcc_options(ctrl_state,
							   pcc_opts);
		break;
	case EV_UPDATE_PCE_OPTS:
		assert(payload != NULL);
		pce_opts = (struct pce_opts *)payload;
		ret = pcep_thread_event_update_pce_options(ctrl_state, pcc_id,
							   pce_opts);
		break;
	case EV_REMOVE_PCC:
		pce_opts = (struct pce_opts *)payload;
		ret = pcep_thread_event_remove_pcc(ctrl_state, pce_opts);
		new_best_pcc_id = calculate_best_pce(ctrl_state);
		if (new_best_pcc_id) {
			ret = pcep_thread_update_best_pce(
				ctrl_state, new_best_pcc_id);
		}
		break;
	case EV_PATHD_EVENT:
		assert(payload != NULL);
		path_event_type = (enum pcep_pathd_event_type)sub_type;
		path = (struct path *)payload;
		ret = pcep_thread_event_pathd_event(ctrl_state, path_event_type,
						    path);
		break;
	case EV_SYNC_PATH:
		assert(payload != NULL);
		path = (struct path *)payload;
		if (pcc_id == calculate_best_pce(ctrl_state)) {
			previous_best_pcc_id =
				get_previous_best_pce(ctrl_state);
			if (previous_best_pcc_id
			    != 0) { //while adding new pce, path have to resync the previous best
				pcep_thread_update_best_pce(ctrl_state,
							  previous_best_pcc_id);
			}
		}
		ret = pcep_thread_event_sync_path(ctrl_state, pcc_id, path);
		break;
	case EV_SYNC_DONE:
		ret = pcep_thread_event_sync_done(ctrl_state, pcc_id);
		break;
	default:
		flog_warn(EC_PATH_PCEP_RECOVERABLE_INTERNAL_ERROR,
			  "Unexpected event received in controller thread: %u",
			  type);
		break;
	}

	return ret;
}

int pcep_thread_event_update_pcc_options(struct ctrl_state *ctrl_state,
					 struct pcc_opts *opts)
{
	assert(opts != NULL);
	if (ctrl_state->pcc_opts != NULL) {
		XFREE(MTYPE_PCEP, ctrl_state->pcc_opts);
	}
	ctrl_state->pcc_opts = opts;
	return 0;
}

int pcep_thread_update_best_pce(struct ctrl_state *ctrl_state, int best)
{
	PCEP_DEBUG(" recalculating pce precedence ");
	if (best) {
		struct pcc_state *best_pcc_state =
			get_pcc_state(ctrl_state, best);
		if (best_pcc_state->previous_best != best_pcc_state->is_best) {
			PCEP_DEBUG(" %s Resynchro best (%i) previous best (%i)",
				   best_pcc_state->tag, best_pcc_state->id,
				   best_pcc_state->previous_best);
			pcep_pcc_start_sync(ctrl_state, best_pcc_state);
		} else {
			PCEP_DEBUG(
				" %s No Resynchro best (%i) previous best (%i)",
				best_pcc_state->tag, best_pcc_state->id,
				best_pcc_state->previous_best);
		}
	} else {
		PCEP_DEBUG(" None best pce , all pce seem disconnected");
	}
	return 0;
}

int pcep_thread_event_update_pce_options(struct ctrl_state *ctrl_state,
					 int pcc_id, struct pce_opts *pce_opts)
{
	if (!pce_opts || !ctrl_state) {
		return 0;
	}
	struct pcc_state *pcc_state;
	struct pcc_opts *pcc_opts;

	int current_pcc_id = get_pcc_id_by_ip_port(ctrl_state, pce_opts);
	if (current_pcc_id) {
		pcc_state = get_pcc_state(ctrl_state, current_pcc_id);
	} else {
		pcc_state = pcep_pcc_initialize(ctrl_state,
						get_next_id(ctrl_state));
		if (set_pcc_state(ctrl_state, pcc_state)) {
			XFREE(MTYPE_PCEP, pcc_state);
			return 0;
		}
	}

	/* Copy the pcc options to delegate it to the update function */
	pcc_opts = XCALLOC(MTYPE_PCEP, sizeof(*pcc_opts));
	memcpy(pcc_opts, ctrl_state->pcc_opts, sizeof(*pcc_opts));

	if (pcep_pcc_update(ctrl_state, pcc_state, pcc_opts, pce_opts)) {
		flog_err(EC_PATH_PCEP_PCC_CONF_UPDATE,
			 "failed to update PCC configuration");
	}

	calculate_best_pce(ctrl_state);
	return 0;
}

int pcep_thread_event_remove_pcc_by_id(struct ctrl_state *ctrl_state,
				       int pcc_id)
{
	if (pcc_id) {
		struct pcc_state *pcc_state = get_pcc_state(ctrl_state, pcc_id);
		if (pcc_state) {
			remove_pcc_state(ctrl_state, pcc_state);
			pcep_pcc_finalize(ctrl_state, pcc_state);
		}
	}
	return 0;
}

int pcep_thread_event_remove_pcc_all(struct ctrl_state *ctrl_state)
{
	assert(ctrl_state != NULL);

	for (int i = 0; i < MAX_PCC; i++) {
		pcep_thread_event_remove_pcc_by_id(
			ctrl_state, get_pcc_id_by_idx(ctrl_state, i));
	}
	return 0;
}

int pcep_thread_event_remove_pcc(struct ctrl_state *ctrl_state,
				 struct pce_opts *pce_opts)
{
	assert(ctrl_state != NULL);

	if (pce_opts) {
		int pcc_id = get_pcc_id_by_ip_port(ctrl_state, pce_opts);
		if (pcc_id) {
			pcep_thread_event_remove_pcc_by_id(ctrl_state, pcc_id);
		} else {
			return -1;
		}
		XFREE(MTYPE_PCEP, pce_opts);
	} else {
		pcep_thread_event_remove_pcc_all(ctrl_state);
	}

	return 0;
}

int pcep_thread_event_sync_path(struct ctrl_state *ctrl_state, int pcc_id,
				struct path *path)
{
	struct pcc_state *pcc_state = get_pcc_state(ctrl_state, pcc_id);
	pcep_pcc_sync_path(ctrl_state, pcc_state, path);
	pcep_free_path(path);
	return 0;
}

int pcep_thread_event_sync_done(struct ctrl_state *ctrl_state, int pcc_id)
{
	struct pcc_state *pcc_state = get_pcc_state(ctrl_state, pcc_id);
	pcep_pcc_sync_done(ctrl_state, pcc_state);
	return 0;
}

int pcep_thread_event_pathd_event(struct ctrl_state *ctrl_state,
				  enum pcep_pathd_event_type type,
				  struct path *path)
{
	int i;

	for (i = 0; i < MAX_PCC; i++) {
		if (ctrl_state->pcc[i]) {
			struct pcc_state *pcc_state = ctrl_state->pcc[i];
			pcep_pcc_pathd_event_handler(ctrl_state, pcc_state,
						     type, path);
		}
	}

	pcep_free_path(path);

	return 0;
}


/* ------------ Main Thread Event Handler ------------ */

int send_to_main(struct ctrl_state *ctrl_state, int pcc_id,
		 enum pcep_main_event_type type, void *payload)
{
	struct pcep_main_event_data *data;

	data = XCALLOC(MTYPE_PCEP, sizeof(*data));
	data->handler = ctrl_state->main_event_handler;
	data->type = type;
	data->pcc_id = pcc_id;
	data->payload = payload;

	thread_add_event(ctrl_state->main, pcep_main_event_handler,
			 (void *)data, 0, NULL);
	return 0;
}

int pcep_main_event_handler(struct thread *thread)
{
	/* data unpacking */
	struct pcep_main_event_data *data = THREAD_ARG(thread);
	assert(data != NULL);
	pcep_main_event_handler_t handler = data->handler;
	enum pcep_main_event_type type = data->type;
	int pcc_id = data->pcc_id;
	void *payload = data->payload;
	XFREE(MTYPE_PCEP, data);

	return handler(type, pcc_id, payload);
}


/* ------------ Helper functions ------------ */
int get_next_id(struct ctrl_state *ctrl_state)
{
	return ++ctrl_state->pcc_last_id;
}

bool is_best_pce(struct ctrl_state *ctrl_state, int pce)
{
	if (ctrl_state && ctrl_state->pcc[pce]) {
		return ctrl_state->pcc[pce]->is_best;
	} else {
		return false;
	}
}

int get_previous_best_pce(struct ctrl_state *ctrl_state)
{
	if (!ctrl_state || !ctrl_state->pcc_count)
		return 0;

	int previous_best_pce = -1;
	struct pcc_state **pcc = &ctrl_state->pcc[0];
	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i] && pcc[i]->pce_opts && pcc[i]->previous_best == true
		    && pcc[i]->status != PCEP_PCC_DISCONNECTED) {
			previous_best_pce = i;
			break;
		}
	}
	return previous_best_pce != -1 ? pcc[previous_best_pce]->id : 0;
}

int calculate_best_pce(struct ctrl_state *ctrl_state)
{
	int best_precedence = 255; // DEFAULT_PCE_PRECEDENCE;
	int best_pce = -1;
	int one_connected_pce = -1;
	int previous_best_pce = -1;
	int step_0_best = -1;
	int step_0_previous = -1;

	if (!ctrl_state || !ctrl_state->pcc_count)
		return 0;

	struct pcc_state **pcc = &ctrl_state->pcc[0];

	// Get state
	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i] && pcc[i]->pce_opts) {
			if (pcc[i]->is_best == true) {
				step_0_best = i;
			}
			if (pcc[i]->previous_best == true) {
				step_0_previous = i;
			}
		}
	}
	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i] && pcc[i]->pce_opts) {
			zlog_debug(
				"calculate all : i (%i) is_best (%i) previous_best (%i)   ",
				i, pcc[i]->is_best, pcc[i]->previous_best);
		}
	}

	// Calculate best
	for (int i = 0; i < MAX_PCC; i++) {
		if (pcc[i] && pcc[i]->pce_opts
		    && pcc[i]->status != PCEP_PCC_DISCONNECTED) {
			one_connected_pce = i; // In case none better
			if (pcc[i]->pce_opts->precedence <= best_precedence) {
				if (best_pce != -1
				    && pcc[best_pce]->pce_opts->precedence
					       == pcc[i]->pce_opts->precedence
				    && ipaddr_cmp(
					       &pcc[i]->pce_opts->addr,
					       &pcc[best_pce]->pce_opts->addr)
					       > 0) {
					// collide of precedences so compare ip
					best_pce = i;
				} else {
					if (!pcc[i]->previous_best) {
						best_precedence =
							pcc[i]->pce_opts
								->precedence;
						best_pce = i;
					}
				}
			}
		}
	}

	zlog_debug("calculate data : sb (%i) sp (%i) oc (%i) b (%i)  ",
		   step_0_best, step_0_previous, one_connected_pce, best_pce);

	// Changed of state so ...
	if (step_0_best != best_pce) {
		// Calculate previous
		previous_best_pce = step_0_best;
		// Clean state
		if (step_0_best != -1) {
			pcc[step_0_best]->is_best = false;
		}
		if (step_0_previous != -1) {
			pcc[step_0_previous]->previous_best = false;
		}

		// Set previous
		if (previous_best_pce != -1) {
			pcc[previous_best_pce]->previous_best = true;
			zlog_debug("previous best pce (%i) ",
				   previous_best_pce + 1);
		}


		// Set best
		if (best_pce != -1) {
			pcc[best_pce]->is_best = true;
			zlog_debug("best pce (%i) ", best_pce + 1);
		} else {
			if (one_connected_pce != -1) {
				best_pce = one_connected_pce;
				pcc[one_connected_pce]->is_best = true;
				zlog_debug(
					"one connected best pce (default) (%i) ",
					one_connected_pce + 1);
			} else {
				for (int i = 0; i < MAX_PCC; i++) {
					if (pcc[i] && pcc[i]->pce_opts) {
						best_pce = i;
						pcc[i]->is_best = true;
						zlog_debug(
							"(disconnected) best pce (default) (%i) ",
							i + 1);
						break;
					}
				}
			}
		}
	}


	return best_pce == -1 ? 0 : pcc[best_pce]->id;
}

int get_free_pcc_idx(struct ctrl_state *ctrl_state)
{
	assert(ctrl_state != NULL);

	struct pcc_state **pcc_state = &ctrl_state->pcc[0];
	for (int idx = 0; idx < MAX_PCC; idx++) {
		if (pcc_state[idx] == NULL) {
			zlog_debug("new pcc_idx (%d)", idx);
			return idx;
		}
	}

	return -1;
}

void set_ctrl_state(struct frr_pthread *fpt, struct ctrl_state *ctrl_state)
{
	assert(fpt != NULL);
	fpt->data = ctrl_state;
}

struct ctrl_state *get_ctrl_state(struct frr_pthread *fpt)
{
	assert(fpt != NULL);
	assert(fpt->data != NULL);

	struct ctrl_state *ctrl_state;
	ctrl_state = (struct ctrl_state *)fpt->data;
	assert(ctrl_state != NULL);
	return ctrl_state;
}

int get_pcc_idx_by_ip_port(struct pce_opts **array_pce_opts,
			   struct pce_opts *pce_opts)
{
	if (!array_pce_opts || !pce_opts) {
		return -1;
	}
	for (int idx = 0; idx < MAX_PCC; idx++) {
		if (array_pce_opts[idx]) {
			if ((ipaddr_cmp(
				     (const struct ipaddr *)&array_pce_opts[idx]
					     ->addr,
				     (const struct ipaddr *)&pce_opts->addr)
			     == 0)
			    && array_pce_opts[idx]->port == pce_opts->port) {
				char buf[50];
				zlog_debug("found pcc_idx (%d) (%s):(%i)", idx,
					   ipaddr2str(&pce_opts->addr, buf, 50),
					   pce_opts->port);
				return idx;
			}
		}
	}
	return -1;
}

int get_pcc_id_by_ip_port(struct ctrl_state *ctrl_state,
			  struct pce_opts *pce_opts)
{
	for (int idx = 0; idx < MAX_PCC; idx++) {
		if (ctrl_state->pcc[idx]) {
			if ((ipaddr_cmp((const struct ipaddr *)&ctrl_state
						->pcc[idx]
						->pce_opts->addr,
					(const struct ipaddr *)&pce_opts->addr)
			     == 0)
			    && ctrl_state->pcc[idx]->pce_opts->port
				       == pce_opts->port) {
				zlog_debug("found pcc_id (%d) idx (%d)",
					   ctrl_state->pcc[idx]->id, idx);
				return ctrl_state->pcc[idx]->id;
			}
		}
	}
	return 0;
}

int get_pcc_id_by_idx(struct ctrl_state *ctrl_state, int idx)
{
	if (idx>=0) {
		return ctrl_state->pcc[idx]?ctrl_state->pcc[idx]->id:0;
	} else {
		return 0;
	}
}

struct pcc_state *get_pcc_by_id(struct ctrl_state *ctrl_state, int id)
{
	for (int i = 0; i < MAX_PCC; i++) {
		if (ctrl_state->pcc[i]) {
			if (ctrl_state->pcc[i]->id == id) {
				zlog_debug("found id (%d) pcc_idx (%d)",
					   ctrl_state->pcc[i]->id, i);
				return ctrl_state->pcc[i];
			}
		}
	}
	return NULL;
}

int get_pcc_idx_by_id(struct ctrl_state *ctrl_state, int id)
{
	for (int idx = 0; idx < MAX_PCC; idx++) {
		if (ctrl_state->pcc[idx]) {
			if (ctrl_state->pcc[idx]->id == id) {
				zlog_debug("found pcc_id (%d) array_idx (%d)",
					   ctrl_state->pcc[idx]->id, idx);
				return idx;
			}
		}
	}
	return -1;
}

struct pcc_state *get_pcc_state(struct ctrl_state *ctrl_state, int id)
{
	assert(ctrl_state != NULL);
	struct pcc_state *pcc_state;

	if (!id)
		return NULL;

	pcc_state = get_pcc_by_id(ctrl_state, id);
	return pcc_state;
}

int set_pcc_state(struct ctrl_state *ctrl_state, struct pcc_state *pcc_state)
{
	assert(ctrl_state != NULL);
	assert(pcc_state->id != 0);

	int current_pcc_idx = get_free_pcc_idx(ctrl_state);
	if (current_pcc_idx >= 0) {
		ctrl_state->pcc[current_pcc_idx] = pcc_state;
		ctrl_state->pcc_count++;
		PCEP_DEBUG("added pce pcc_id (%d) idx (%d)", pcc_state->id,
			   current_pcc_idx);
		return 0;
	} else {
		PCEP_DEBUG("Max number of pce ");
		return 1;
	}
}

void remove_pcc_state(struct ctrl_state *ctrl_state,
		      struct pcc_state *pcc_state)
{
	assert(ctrl_state != NULL);
	assert(pcc_state->id != 0);

	int idx = 0;
	idx = get_pcc_idx_by_id(ctrl_state, pcc_state->id);
	if (idx != -1) {
		ctrl_state->pcc[idx] = NULL;
		ctrl_state->pcc_count--;
		PCEP_DEBUG("removed pce pcc_id (%d)", pcc_state->id);
	}
}

uint32_t backoff_delay(uint32_t max, uint32_t base, uint32_t retry_count)
{
	uint32_t a = min(max, base * (1 << retry_count));
	uint64_t r = rand(), m = RAND_MAX;
	uint32_t b = (a / 2) + (r * (a / 2)) / m;
	return b;
}
