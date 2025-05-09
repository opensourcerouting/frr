// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018        Vmware
 *                           Vishal Dhingra
 */
#ifndef _FRR_STATIC_NB_H_
#define _FRR_STATIC_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_staticd_info;
extern const struct frr_yang_module_info frr_staticd_cli_info;

int routing_control_plane_protocols_staticd_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_staticd_destroy(
	struct nb_cb_destroy_args *args);

/* Mandatory callbacks. */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_tag_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_bh_type_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_onlink_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_color_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_color_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_seg_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_seg_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_encap_behavior_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_encap_behavior_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy(
	struct nb_cb_destroy_args *args);
int route_next_hop_bfd_create(struct nb_cb_create_args *args);
int route_next_hop_bfd_destroy(struct nb_cb_destroy_args *args);
int route_next_hop_bfd_source_modify(struct nb_cb_modify_args *args);
int route_next_hop_bfd_source_destroy(struct nb_cb_destroy_args *args);
int route_next_hop_bfd_profile_modify(struct nb_cb_modify_args *args);
int route_next_hop_bfd_profile_destroy(struct nb_cb_destroy_args *args);
int route_next_hop_bfd_multi_hop_modify(struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_behavior_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_behavior_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_vrf_name_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_vrf_name_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_interface_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_interface_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_next_hop_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_next_hop_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_locator_name_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_locator_name_destroy(
	struct nb_cb_destroy_args *args);

/* Optional 'apply_finish' callbacks. */

void routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_apply_finish(
	struct nb_cb_apply_finish_args *args);
void routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_apply_finish(
	struct nb_cb_apply_finish_args *args);

/* Optional 'pre_validate' callbacks. */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_pre_validate(
	struct nb_cb_pre_validate_args *args);

/*
 * Callback registered with routing_nb lib to validate only
 * one instance of staticd is allowed
 */
int routing_control_plane_protocols_name_validate(
	struct nb_cb_create_args *args);

/* xpath macros */
/* route-list */
#define FRR_STATIC_ROUTE_INFO_KEY_XPATH                                                            \
	"/frr-routing:routing/control-plane-protocols/"                                            \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"                                  \
	"frr-staticd:staticd/route-list[prefix='%s'][src-prefix='%s'][afi-safi='%s']/"             \
	"path-list[table-id='%u'][distance='%u']"

#define FRR_STATIC_ROUTE_INFO_KEY_NO_DISTANCE_XPATH                                                \
	"/frr-routing:routing/control-plane-protocols/"                                            \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"                                  \
	"frr-staticd:staticd/route-list[prefix='%s'][src-prefix='%s'][afi-safi='%s']/"             \
	"path-list[table-id='%u']"


#define FRR_STATIC_ROUTE_PATH_TAG_XPATH "/tag"

/* route-list/frr-nexthops */
#define FRR_STATIC_ROUTE_NH_KEY_XPATH                                          \
	"/frr-nexthops/"                                                       \
	"nexthop[nh-type='%s'][vrf='%s'][gateway='%s'][interface='%s']"

#define FRR_STATIC_ROUTE_NH_ONLINK_XPATH "/onlink"

#define FRR_STATIC_ROUTE_NH_COLOR_XPATH "/srte-color"

#define FRR_STATIC_ROUTE_NH_BH_XPATH "/bh-type"

#define FRR_STATIC_ROUTE_NH_LABEL_XPATH "/mpls-label-stack"

#define FRR_STATIC_ROUTE_NHLB_KEY_XPATH "/entry[id='%u']/label"

#define FRR_STATIC_ROUTE_NH_SRV6_SEGS_XPATH "/srv6-segs-stack"

#define FRR_STATIC_ROUTE_NH_SRV6_KEY_SEG_XPATH "/entry[id='%u']/seg"

#define FRR_STATIC_ROUTE_NH_SRV6_ENCAP_BEHAVIOR_XPATH "/encap-behavior"

/* route-list/frr-nexthops */
#define FRR_DEL_S_ROUTE_NH_KEY_XPATH                                           \
	FRR_STATIC_ROUTE_INFO_KEY_XPATH                                        \
	FRR_STATIC_ROUTE_NH_KEY_XPATH

/* route-list/frr-nexthops */
#define FRR_DEL_S_ROUTE_NH_KEY_NO_DISTANCE_XPATH                               \
	FRR_STATIC_ROUTE_INFO_KEY_NO_DISTANCE_XPATH                            \
	FRR_STATIC_ROUTE_NH_KEY_XPATH

/* srv6 */
#define FRR_STATIC_SRV6_INFO_KEY_XPATH                                                             \
	"/frr-routing:routing/control-plane-protocols/"                                            \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"                                  \
	"frr-staticd:staticd/segment-routing/srv6"

/* srv6/static-sids */
#define FRR_STATIC_SRV6_STATIC_SIDS_XPATH                                                          \
	FRR_STATIC_SRV6_INFO_KEY_XPATH                                                             \
	"/static-sids"

#define FRR_STATIC_SRV6_SID_KEY_XPATH                                                              \
	FRR_STATIC_SRV6_INFO_KEY_XPATH                                                             \
	"/static-sids/"                                                                            \
	"sid[sid='%s']"

#define FRR_STATIC_SRV6_SID_BEHAVIOR_XPATH "/behavior"

#define FRR_STATIC_SRV6_SID_VRF_NAME_XPATH "/vrf-name"

#define FRR_STATIC_SRV6_SID_LOCATOR_NAME_XPATH "/locator-name"

#define FRR_STATIC_SRV6_SID_INTERFACE_XPATH "/paths[path-index=%u]/interface"

#define FRR_STATIC_SRV6_SID_NEXTHOP_XPATH "/paths[path-index=%u]/next-hop"

#ifdef __cplusplus
}
#endif

#endif
