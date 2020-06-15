/*
 * Copyright (C) 2019  NetDEF, Inc.
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
#include <lib_errors.h>

#include "northbound.h"
#include "libfrr.h"

#include "pathd/pathd.h"
#include "pathd/path_nb.h"

/*
 * XPath: /frr-pathd:pathd
 */
void pathd_apply_finish(struct nb_cb_apply_finish_args *args)
{
	srte_apply_changes();
}

/*
 * XPath: /frr-pathd:pathd/segment-list
 */
int pathd_te_segment_list_create(struct nb_cb_create_args *args)
{
	struct srte_segment_list *segment_list;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "./name");
	segment_list = srte_segment_list_add(name);
	nb_running_set_entry(args->dnode, segment_list);
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_NEW);

	return NB_OK;
}

int pathd_te_segment_list_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_segment_list *segment_list;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment_list = nb_running_unset_entry(args->dnode);
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_DELETED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/segment-list/protocol-origin
 */
int pathd_te_segment_list_protocol_origin_modify(struct nb_cb_modify_args *args)
{
	struct srte_segment_list *segment_list;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment_list = nb_running_get_entry(args->dnode, NULL, true);
	segment_list->protocol_origin = yang_dnode_get_enum(args->dnode, NULL);
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/segment-list/originator
 */
int pathd_te_segment_list_originator_modify(struct nb_cb_modify_args *args)
{
	struct srte_segment_list *segment_list;
	const char *originator;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment_list = nb_running_get_entry(args->dnode, NULL, true);
	originator = yang_dnode_get_string(args->dnode, NULL);
	strlcpy(segment_list->originator, originator,
		sizeof(segment_list->originator));
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_MODIFIED);

	return NB_OK;
}


/*
 * XPath: /frr-pathd:pathd/segment-list/segment
 */
int pathd_te_segment_list_segment_create(struct nb_cb_create_args *args)
{
	struct srte_segment_list *segment_list;
	struct srte_segment_entry *segment;
	uint32_t index;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment_list = nb_running_get_entry(args->dnode, NULL, true);
	index = yang_dnode_get_uint32(args->dnode, "./index");
	segment = srte_segment_entry_add(segment_list, index);
	nb_running_set_entry(args->dnode, segment);
	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_MODIFIED);

	return NB_OK;
}

int pathd_te_segment_list_segment_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_segment_entry *segment;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment = nb_running_unset_entry(args->dnode);
	srte_segment_entry_del(segment);
	SET_FLAG(segment->segment_list->flags, F_SEGMENT_LIST_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/segment-list/segment/sid-value
 */
int pathd_te_segment_list_segment_sid_value_modify(
	struct nb_cb_modify_args *args)
{
	mpls_label_t sid_value;
	struct srte_segment_entry *segment;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment = nb_running_get_entry(args->dnode, NULL, true);
	sid_value = yang_dnode_get_uint32(args->dnode, NULL);
	segment->sid_value = sid_value;
	SET_FLAG(segment->segment_list->flags, F_SEGMENT_LIST_MODIFIED);

	return NB_OK;
}

int pathd_te_segment_list_segment_nai_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_segment_entry *segment;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	segment = nb_running_get_entry(args->dnode, NULL, true);
	segment->nai_type = SRTE_SEGMENT_NAI_TYPE_NONE;
	segment->nai_local_addr.ipa_type = IPADDR_NONE;
	segment->nai_local_iface = 0;
	segment->nai_remote_addr.ipa_type = IPADDR_NONE;
	segment->nai_remote_iface = 0;

	return NB_OK;
}

void pathd_te_segment_list_segment_nai_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct srte_segment_entry *segment;
	enum srte_segment_nai_type type;
	segment = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "./type");
	switch (type) {
	case SRTE_SEGMENT_NAI_TYPE_IPV4_NODE:
	case SRTE_SEGMENT_NAI_TYPE_IPV6_NODE:
		segment->nai_type = type;
		yang_dnode_get_ip(&segment->nai_local_addr, args->dnode,
				  "./local-address");
		break;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY:
	case SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY:
		segment->nai_type = type;
		yang_dnode_get_ip(&segment->nai_local_addr, args->dnode,
				  "./local-address");
		yang_dnode_get_ip(&segment->nai_remote_addr, args->dnode,
				  "./remote-address");
		break;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_UNNUMBERED_ADJACENCY:
		segment->nai_type = type;
		yang_dnode_get_ip(&segment->nai_local_addr, args->dnode,
				  "./local-address");
		segment->nai_local_iface =
			yang_dnode_get_uint32(args->dnode, "./local-interface");
		yang_dnode_get_ip(&segment->nai_remote_addr, args->dnode,
				  "./remote-address");
		segment->nai_remote_iface =
			yang_dnode_get_uint32(args->dnode, "./remote-interface");
		break;
	default:
		segment->nai_type = SRTE_SEGMENT_NAI_TYPE_NONE;
		return;
	}
}

/*
 * XPath: /frr-pathd:pathd/sr-policy
 */
int pathd_te_sr_policy_create(struct nb_cb_create_args *args)
{
	struct srte_policy *policy;
	uint32_t color;
	struct ipaddr endpoint;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	color = yang_dnode_get_uint32(args->dnode, "./color");
	yang_dnode_get_ip(&endpoint, args->dnode, "./endpoint");
	policy = srte_policy_add(color, &endpoint);

	nb_running_set_entry(args->dnode, policy);
	SET_FLAG(policy->flags, F_POLICY_NEW);

	return NB_OK;
}

int pathd_te_sr_policy_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_policy *policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_unset_entry(args->dnode);
	SET_FLAG(policy->flags, F_POLICY_DELETED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/name
 */
int pathd_te_sr_policy_name_modify(struct nb_cb_modify_args *args)
{
	struct srte_policy *policy;
	const char *name;

	if (args->event != NB_EV_APPLY && args->event != NB_EV_VALIDATE)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);

	if (args->event == NB_EV_VALIDATE) {
		/* the policy name is fixed after setting it once */
		if (strlen(policy->name) > 0) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "The SR Policy name is fixed!");
			return NB_ERR_RESOURCE;
		} else
			return NB_OK;
	}

	name = yang_dnode_get_string(args->dnode, NULL);
	strlcpy(policy->name, name, sizeof(policy->name));
	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

int pathd_te_sr_policy_name_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_policy *policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	policy->name[0] = '\0';
	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/binding-sid
 */
int pathd_te_sr_policy_binding_sid_modify(struct nb_cb_modify_args *args)
{
	struct srte_policy *policy;
	mpls_label_t binding_sid;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	binding_sid = yang_dnode_get_uint32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
		if (path_zebra_request_label(binding_sid) < 0)
			return NB_ERR_RESOURCE;
		break;
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		srte_policy_update_binding_sid(policy, binding_sid);
		SET_FLAG(policy->flags, F_POLICY_MODIFIED);
		break;
	}

	return NB_OK;
}

int pathd_te_sr_policy_binding_sid_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_policy *policy;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	srte_policy_update_binding_sid(policy, MPLS_LABEL_NONE);
	SET_FLAG(policy->flags, F_POLICY_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path
 */
int pathd_te_sr_policy_candidate_path_create(struct nb_cb_create_args *args)
{
	struct srte_policy *policy;
	struct srte_candidate *candidate;
	uint32_t preference;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	policy = nb_running_get_entry(args->dnode, NULL, true);
	preference = yang_dnode_get_uint32(args->dnode, "./preference");
	candidate = srte_candidate_add(policy, preference);
	nb_running_set_entry(args->dnode, candidate);
	SET_FLAG(candidate->flags, F_CANDIDATE_NEW);

	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_destroy(struct nb_cb_destroy_args *args)
{
	struct srte_candidate *candidate;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_unset_entry(args->dnode);
	SET_FLAG(candidate->flags, F_CANDIDATE_DELETED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/name
 */
int pathd_te_sr_policy_candidate_path_name_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	const char *name;
	char xpath[XPATH_MAXLEN];
	char xpath_buf[XPATH_MAXLEN - 3];

	if (args->event != NB_EV_APPLY && args->event != NB_EV_VALIDATE)
		return NB_OK;

	/* the candidate name is fixed after setting it once, this is checked
	 * here */
	if (args->event == NB_EV_VALIDATE) {
		/* first get the precise path to the candidate path */
		yang_dnode_get_path(args->dnode, xpath_buf, sizeof(xpath_buf));
		snprintf(xpath, sizeof(xpath), "%s%s", xpath_buf, "/..");

		candidate = nb_running_get_entry_non_rec(NULL, xpath, false);

		/* then check if it exists and if the name was provided */
		if (candidate && strlen(candidate->name) > 0) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "The candidate name is fixed!");
			return NB_ERR_RESOURCE;
		} else
			return NB_OK;
	}

	candidate = nb_running_get_entry(args->dnode, NULL, true);

	name = yang_dnode_get_string(args->dnode, NULL);
	strlcpy(candidate->name, name, sizeof(candidate->name));
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/metrics
 */
int pathd_te_sr_policy_candidate_path_metrics_destroy(
	struct nb_cb_destroy_args *args)
{
	struct srte_candidate *candidate;
	enum srte_candidate_metric_type type;
	bool is_config;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	assert(args->context != NULL);
	is_config = args->context->client == NB_CLIENT_CLI;
	candidate = nb_running_get_entry(args->dnode, NULL, true);

	type = yang_dnode_get_enum(args->dnode, "./type");
	srte_candidate_unset_metric(candidate, type, is_config);

	return NB_OK;
}

void pathd_te_sr_policy_candidate_path_metrics_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct srte_candidate *candidate;
	enum srte_candidate_metric_type type;
	float value;
	bool is_bound = false, is_computed = false, is_config;

	assert(args->context != NULL);
	is_config = args->context->client == NB_CLIENT_CLI;

	candidate = nb_running_get_entry(args->dnode, NULL, true);

	type = yang_dnode_get_enum(args->dnode, "./type");
	value = (float)yang_dnode_get_dec64(args->dnode, "./value");
	if (yang_dnode_exists(args->dnode, "./is-bound"))
		is_bound = yang_dnode_get_bool(args->dnode, "./is-bound");
	if (yang_dnode_exists(args->dnode, "./is-computed"))
		is_computed = yang_dnode_get_bool(args->dnode, "./is-computed");

	srte_candidate_set_metric(candidate, type, value, is_bound, is_computed,
				  is_config);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/protocol-origin
 */
int pathd_te_sr_policy_candidate_path_protocol_origin_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	enum srte_protocol_origin protocol_origin;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	protocol_origin = yang_dnode_get_enum(args->dnode, NULL);
	candidate->protocol_origin = protocol_origin;
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/originator
 */
int pathd_te_sr_policy_candidate_path_originator_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	const char *originator;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	originator = yang_dnode_get_string(args->dnode, NULL);
	strlcpy(candidate->originator, originator,
		sizeof(candidate->originator));
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/discriminator
 */
int pathd_te_sr_policy_candidate_path_discriminator_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	uint32_t discriminator;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	discriminator = yang_dnode_get_uint32(args->dnode, NULL);
	candidate->discriminator = discriminator;
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/type
 */
int pathd_te_sr_policy_candidate_path_type_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	enum srte_candidate_type type;
	char xpath[XPATH_MAXLEN];
	char xpath_buf[XPATH_MAXLEN - 3];

	if (args->event != NB_EV_APPLY && args->event != NB_EV_VALIDATE)
		return NB_OK;

	/* the candidate type is fixed after setting it once, this is checked
	 * here */
	if (args->event == NB_EV_VALIDATE) {
		/* first get the precise path to the candidate path */
		yang_dnode_get_path(args->dnode, xpath_buf, sizeof(xpath_buf));
		snprintf(xpath, sizeof(xpath), "%s%s", xpath_buf, "/..");

		candidate = nb_running_get_entry_non_rec(NULL, xpath, false);

		/* then check if it exists and if the type was provided */
		if (candidate
		    && candidate->type != SRTE_CANDIDATE_TYPE_UNDEFINED) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "The candidate type is fixed!");
			return NB_ERR_RESOURCE;
		} else
			return NB_OK;
	}

	candidate = nb_running_get_entry(args->dnode, NULL, true);

	type = yang_dnode_get_enum(args->dnode, NULL);
	candidate->type = type;
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/segment-list-name
 */
int pathd_te_sr_policy_candidate_path_segment_list_name_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	const char *segment_list_name;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	segment_list_name = yang_dnode_get_string(args->dnode, NULL);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate->segment_list = srte_segment_list_find(segment_list_name);
	assert(candidate->segment_list);
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_segment_list_name_destroy(
	struct nb_cb_destroy_args *args)
{
	struct srte_candidate *candidate;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	candidate = nb_running_get_entry(args->dnode, NULL, true);
	candidate->segment_list = NULL;
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);

	return NB_OK;
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path/bandwidth
 */
int pathd_te_sr_policy_candidate_path_bandwidth_modify(
	struct nb_cb_modify_args *args)
{
	struct srte_candidate *candidate;
	float value;
	bool is_config;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	assert(args->context != NULL);
	is_config = args->context->client == NB_CLIENT_CLI;
	candidate = nb_running_get_entry(args->dnode, NULL, true);
	value = (float)yang_dnode_get_dec64(args->dnode, NULL);
	srte_candidate_set_bandwidth(candidate, value, is_config);
	return NB_OK;
}

int pathd_te_sr_policy_candidate_path_bandwidth_destroy(
	struct nb_cb_destroy_args *args)
{
	struct srte_candidate *candidate;
	bool is_config;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	assert(args->context != NULL);
	is_config = args->context->client == NB_CLIENT_CLI;
	candidate = nb_running_get_entry(args->dnode, NULL, true);
	srte_candidate_unset_bandwidth(candidate, is_config);
	return NB_OK;
}
