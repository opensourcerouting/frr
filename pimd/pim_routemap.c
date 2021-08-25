// SPDX-License-Identifier: GPL-2.0-or-later
/* PIM Route-map Code
 * Copyright (C) 2016 Cumulus Networks <sharpd@cumulusnetworks.com>
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of Quagga
 */
#include <zebra.h>

#include "if.h"
#include "vty.h"
#include "routemap.h"

#include "pimd.h"
#include "pim_routemap.h"
#include "pim_util.h"

DEFINE_MTYPE_STATIC(PIMD, PIM_ACL_REF, "PIM filter name");

DECLARE_DLIST(pim_filter_refs, struct pim_filter_ref, itm);

static struct pim_filter_refs_head refs[1] = { INIT_DLIST(refs[0]) };

static void rmap_cli_init(void);

void pim_filter_ref_init(struct pim_filter_ref *ref)
{
	memset(ref, 0, sizeof(*ref));
	pim_filter_refs_add_tail(refs, ref);
}

void pim_filter_ref_fini(struct pim_filter_ref *ref)
{
	pim_filter_refs_del(refs, ref);

	XFREE(MTYPE_PIM_ACL_REF, ref->rmapname);
}

void pim_filter_ref_set_rmap(struct pim_filter_ref *ref, const char *rmapname)
{
	XFREE(MTYPE_PIM_ACL_REF, ref->rmapname);
	ref->rmap = NULL;

	if (rmapname) {
		ref->rmapname = XSTRDUP(MTYPE_PIM_ACL_REF, rmapname);
		ref->rmap = route_map_lookup_by_name(ref->rmapname);
	}
}

void pim_filter_ref_update(void)
{
	struct pim_filter_ref *ref;

	frr_each (pim_filter_refs, refs, ref) {
		ref->rmap = route_map_lookup_by_name(ref->rmapname);
	}
}

void pim_sg_to_prefix(const pim_sgaddr *sg, struct prefix_sg *prefix)
{
	prefix->family = PIM_AF;

#if PIM_IPV == 4
	prefix->prefixlen = IPV4_MAX_BITLEN;
	prefix->src.ipaddr_v4 = sg->src;
	prefix->grp.ipaddr_v4 = sg->grp;
#else
	prefix->prefixlen = IPV6_MAX_BITLEN;
	prefix->src.ipaddr_v6 = sg->src;
	prefix->grp.ipaddr_v6 = sg->grp;
#endif
}

/*
 * PIM currently uses route-maps only as (S,G) & nexthop/iface filters.
 * There are no "set" actions for the time being.
 *
 *   sg.group	=> match ip multicast-group prefix-list PLIST
 *   sg.source	=> match ip multicast-source prefix-list PLIST
 */

struct pim_rmap_info {
	const struct prefix_sg *sg;
	struct interface *generic_ifp, *iif;
};

bool pim_filter_match(const struct pim_filter_ref *ref, const struct prefix_sg *sg,
		      struct interface *generic_ifp, struct interface *iif)
{
#if PIM_IPV == 4
	if (sg->grp.ipaddr_v4.s_addr && !pim_is_group_224_4(sg->grp.ipaddr_v4))
		return false;
	if (sg->src.ipaddr_v4.s_addr && IPV4_CLASS_DE(ntohl(sg->src.ipaddr_v4.s_addr)))
		return false;
#else
	if (sg->grp.ipaddr_v6.s6_addr[0] && !pim_addr_is_multicast(sg->grp.ipaddr_v6))
		return false;
	if (sg->src.ipaddr_v6.s6_addr[0] && pim_addr_is_multicast(sg->src.ipaddr_v6))
		return false;
#endif

	if (ref->rmapname) {
		route_map_result_t result;
		struct prefix dummy_prefix = { .family = PIM_AF };
		struct pim_rmap_info info = {
			.sg = sg,
			.iif = iif,
			.generic_ifp = generic_ifp,
		};

		if (!ref->rmap)
			return false;

		result = route_map_apply(ref->rmap, &dummy_prefix, &info);
		if (result != RMAP_PERMITMATCH)
			return false;
	}

	return true;
}

/* matches */

static void *route_map_rule_str_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_map_rule_str_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* interfaces */

static enum route_map_cmd_result_t route_match_interface(void *rule, const struct prefix *prefix,
							 void *object)
{
	struct pim_rmap_info *info = object;
	struct interface *ifp = NULL;
	struct vrf *vrf;

	if (!info->generic_ifp)
		return RMAP_NOMATCH;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_name(rule, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL || ifp != info->generic_ifp)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static enum route_map_cmd_result_t route_match_iif(void *rule, const struct prefix *prefix,
						   void *object)
{
	struct pim_rmap_info *info = object;
	struct interface *ifp = NULL;
	struct vrf *vrf;

	if (!info->iif)
		return RMAP_NOMATCH;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_name(rule, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL || ifp != info->iif)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_iif_cmd = {
	"iif",
	route_match_iif,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static const struct route_map_rule_cmd route_match_interface_cmd = {
	"interface",
	route_match_interface,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

/* address matches */

static enum route_map_cmd_result_t route_match_src(void *rule, const struct prefix *prefix,
						   void *object)
{
	struct pim_rmap_info *info = object;
	struct in_addr addr;
	int ret;

	ret = inet_pton(AF_INET, rule, &addr);
	if (ret != 1)
		return RMAP_NOMATCH;

	if (addr.s_addr != info->sg->src.ipaddr_v4.s_addr)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static enum route_map_cmd_result_t route_match_srcv6(void *rule, const struct prefix *prefix,
						     void *object)
{
	struct pim_rmap_info *info = object;
	struct in6_addr addr;
	int ret;

	ret = inet_pton(AF_INET6, rule, &addr);
	if (ret != 1)
		return RMAP_NOMATCH;

	if (memcmp(&addr, &info->sg->src.ipaddr_v6, sizeof(addr)) != 0)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static enum route_map_cmd_result_t route_match_grp(void *rule, const struct prefix *prefix,
						   void *object)
{
	struct pim_rmap_info *info = object;
	struct in_addr addr;
	int ret;

	ret = inet_pton(AF_INET, rule, &addr);
	if (ret != 1)
		return RMAP_NOMATCH;

	if (addr.s_addr != info->sg->grp.ipaddr_v4.s_addr)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static enum route_map_cmd_result_t route_match_grpv6(void *rule, const struct prefix *prefix,
						     void *object)
{
	struct pim_rmap_info *info = object;
	struct in6_addr addr;
	int ret;

	ret = inet_pton(AF_INET6, rule, &addr);
	if (ret != 1)
		return RMAP_NOMATCH;

	if (memcmp(&addr, &info->sg->grp.ipaddr_v6, sizeof(addr)) != 0)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_src_cmd = {
	"src",
	route_match_src,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static const struct route_map_rule_cmd route_match_srcv6_cmd = {
	"srcv6",
	route_match_srcv6,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static const struct route_map_rule_cmd route_match_grp_cmd = {
	"grp",
	route_match_grp,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static const struct route_map_rule_cmd route_match_grpv6_cmd = {
	"grpv6",
	route_match_grpv6,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static enum route_map_cmd_result_t route_match_src_plist(void *rule, const struct prefix *prefix,
							 void *object)
{
	struct pim_rmap_info *info = object;
	struct prefix_list *plist;
	struct prefix_ipv4 p;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = info->sg->src.ipaddr_v4;

	plist = prefix_list_lookup(AFI_IP, (char *)rule);
	if (!plist)
		return RMAP_NOMATCH;

	if (prefix_list_apply_ext(plist, NULL, &p, true) != PREFIX_PERMIT)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static enum route_map_cmd_result_t route_match_srcv6_plist(void *rule, const struct prefix *prefix,
							   void *object)
{
	struct pim_rmap_info *info = object;
	struct prefix_list *plist;
	struct prefix_ipv6 p;

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.prefix = info->sg->src.ipaddr_v6;

	plist = prefix_list_lookup(AFI_IP6, (char *)rule);
	if (!plist)
		return RMAP_NOMATCH;

	if (prefix_list_apply_ext(plist, NULL, &p, true) != PREFIX_PERMIT)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static enum route_map_cmd_result_t route_match_grp_plist(void *rule, const struct prefix *prefix,
							 void *object)
{
	struct pim_rmap_info *info = object;
	struct prefix_list *plist;
	struct prefix_ipv4 p;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = info->sg->grp.ipaddr_v4;

	plist = prefix_list_lookup(AFI_IP, (char *)rule);
	if (!plist)
		return RMAP_NOMATCH;

	if (prefix_list_apply_ext(plist, NULL, &p, true) != PREFIX_PERMIT)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static enum route_map_cmd_result_t route_match_grpv6_plist(void *rule, const struct prefix *prefix,
							   void *object)
{
	struct pim_rmap_info *info = object;
	struct prefix_list *plist;
	struct prefix_ipv6 p;

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.prefix = info->sg->grp.ipaddr_v6;

	plist = prefix_list_lookup(AFI_IP6, (char *)rule);
	if (!plist)
		return RMAP_NOMATCH;

	if (prefix_list_apply_ext(plist, NULL, &p, true) != PREFIX_PERMIT)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

static const struct route_map_rule_cmd route_match_src_plist_cmd = {
	"src prefix-list",
	route_match_src_plist,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static const struct route_map_rule_cmd route_match_srcv6_plist_cmd = {
	"srcv6 prefix-list",
	route_match_srcv6_plist,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static const struct route_map_rule_cmd route_match_grp_plist_cmd = {
	"grp prefix-list",
	route_match_grp_plist,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};

static const struct route_map_rule_cmd route_match_grpv6_plist_cmd = {
	"grpv6 prefix-list",
	route_match_grpv6_plist,
	route_map_rule_str_compile,
	route_map_rule_str_free,
};


static void pim_route_map_add(const char *rmap_name)
{
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

static void pim_route_map_delete(const char *rmap_name)
{
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_DELETED);
}

static void pim_route_map_event(const char *rmap_name)
{
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

void pim_route_map_init(void)
{
	route_map_init();

	route_map_add_hook(pim_route_map_add);
	route_map_delete_hook(pim_route_map_delete);
	route_map_event_hook(pim_route_map_event);

	route_map_match_interface_hook(generic_match_add);
	route_map_no_match_interface_hook(generic_match_delete);

	route_map_install_match(&route_match_src_cmd);
	route_map_install_match(&route_match_srcv6_cmd);
	route_map_install_match(&route_match_grp_cmd);
	route_map_install_match(&route_match_grpv6_cmd);
	route_map_install_match(&route_match_src_plist_cmd);
	route_map_install_match(&route_match_srcv6_plist_cmd);
	route_map_install_match(&route_match_grp_plist_cmd);
	route_map_install_match(&route_match_grpv6_plist_cmd);
	route_map_install_match(&route_match_iif_cmd);
	route_map_install_match(&route_match_interface_cmd);

	rmap_cli_init();
}

void pim_route_map_terminate(void)
{
	route_map_finish();
}

/* NB */

#include "pim_nb.h"

static int pim_nb_rmap_match_item_modify(struct nb_cb_modify_args *args, const char *rulename)
{
	struct routemap_hook_context *rhc;
	const char *addr;
	int rv;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Add configuration. */
	rhc = nb_running_get_entry(args->dnode, NULL, true);
	addr = yang_dnode_get_string(args->dnode, NULL);

	/* Set destroy information. */
	rhc->rhc_mhook = generic_match_delete;
	rhc->rhc_rule = rulename;
	rhc->rhc_event = RMAP_EVENT_MATCH_DELETED;

	rv = generic_match_add(rhc->rhc_rmi, rhc->rhc_rule, addr, RMAP_EVENT_MATCH_ADDED,
			       args->errmsg, args->errmsg_len);
	if (rv != CMD_SUCCESS) {
		rhc->rhc_mhook = NULL;
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int pim_nb_rmap_match_source_modify(struct nb_cb_modify_args *args)
{
	return pim_nb_rmap_match_item_modify(args, "src");
}

int pim_nb_rmap_match_sourcev6_modify(struct nb_cb_modify_args *args)
{
	return pim_nb_rmap_match_item_modify(args, "srcv6");
}

int pim_nb_rmap_match_group_modify(struct nb_cb_modify_args *args)
{
	return pim_nb_rmap_match_item_modify(args, "grp");
}

int pim_nb_rmap_match_groupv6_modify(struct nb_cb_modify_args *args)
{
	return pim_nb_rmap_match_item_modify(args, "grpv6");
}

int pim_nb_rmap_match_iif_modify(struct nb_cb_modify_args *args)
{
	return pim_nb_rmap_match_item_modify(args, "iif");
}

int pim_nb_rmap_match_plist_modify(struct nb_cb_modify_args *args)
{
	const char *condition;

	condition = yang_dnode_get_string(args->dnode, "../../condition");

	if (IS_MATCH_IPV4_MCAST_SRC_PL(condition))
		return pim_nb_rmap_match_item_modify(args, "src prefix-list");
	else if (IS_MATCH_IPV4_MCAST_GRP_PL(condition))
		return pim_nb_rmap_match_item_modify(args, "grp prefix-list");
	if (IS_MATCH_IPV6_MCAST_SRC_PL(condition))
		return pim_nb_rmap_match_item_modify(args, "srcv6 prefix-list");
	else if (IS_MATCH_IPV6_MCAST_GRP_PL(condition))
		return pim_nb_rmap_match_item_modify(args, "grpv6 prefix-list");
	else
		assertf(0, "unknown YANG condition %s", condition);
}

/* CLI */

#include "northbound_cli.h"

#ifndef VTYSH_EXTRACT_PL
#include "pimd/pim_routemap_clippy.c"
#endif

DEFPY_YANG (rmap_match_addr,
	    rmap_match_addr_cmd,
	    "[no] match ip <multicast-source$do_src A.B.C.D$addr|multicast-group$do_grp A.B.C.D$addr>",
	    NO_STR
	    MATCH_STR
	    IP_STR
	    "Multicast source address\n"
	    "Multicast source address\n"
	    "Multicast group address\n"
	    "Multicast group address\n")
{
	const char *xpath, *xpval;
	char xpath_value[XPATH_MAXLEN];

	assert(do_src || do_grp);

	if (do_src) {
		xpath = "./match-condition[condition='frr-pim-route-map:ipv4-multicast-source']";
		xpval = "/rmap-match-condition/frr-pim-route-map:ipv4-multicast-source-address";
	} else {
		xpath = "./match-condition[condition='frr-pim-route-map:ipv4-multicast-group']";
		xpval = "/rmap-match-condition/frr-pim-route-map:ipv4-multicast-group-address";
	}

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value), "%s%s", xpath, xpval);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, addr_str);
	}
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (rmap_match_addr,
            no_rmap_match_addr_cmd,
            "no match ip <multicast-source$do_src|multicast-group$do_grp>",
            NO_STR
            MATCH_STR
            IP_STR
            "Multicast source address\n"
            "Multicast group address\n")

DEFPY_YANG (rmap_match_v6_addr,
	    rmap_match_v6_addr_cmd,
	    "[no] match ipv6 <multicast-source$do_src X:X::X:X$addr|multicast-group$do_grp X:X::X:X$addr>",
	    NO_STR
	    MATCH_STR
	    IPV6_STR
	    "Multicast source address\n"
	    "Multicast source address\n"
	    "Multicast group address\n"
	    "Multicast group address\n")
{
	const char *xpath, *xpval;
	char xpath_value[XPATH_MAXLEN];

	assert(do_src || do_grp);

	if (do_src) {
		xpath = "./match-condition[condition='frr-pim-route-map:ipv6-multicast-source']";
		xpval = "/rmap-match-condition/frr-pim-route-map:ipv6-multicast-source-address";
	} else {
		xpath = "./match-condition[condition='frr-pim-route-map:ipv6-multicast-group']";
		xpval = "/rmap-match-condition/frr-pim-route-map:ipv6-multicast-group-address";
	}

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value), "%s%s", xpath, xpval);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, addr_str);
	}
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (rmap_match_v6_addr,
            no_rmap_match_v6_addr_cmd,
            "no match ipv6 <multicast-source$do_src|multicast-group$do_grp>",
            NO_STR
            MATCH_STR
            IPV6_STR
            "Multicast source address\n"
            "Multicast group address\n")

DEFPY_YANG (rmap_match_plist,
	    rmap_match_plist_cmd,
	    "[no] match ip <multicast-source$do_src|multicast-group$do_grp> prefix-list WORD",
	    NO_STR
	    MATCH_STR
	    IP_STR
	    "Multicast source address\n"
	    "Multicast group address\n"
	    "Match against ip prefix list\n"
	    "Prefix list name\n")
{
	const char *xpath, *xpval;
	char xpath_value[XPATH_MAXLEN];

	assert(do_src || do_grp);

	if (do_src)
		xpath = "./match-condition[condition='frr-pim-route-map:ipv4-multicast-source-prefix-list']";
	else
		xpath = "./match-condition[condition='frr-pim-route-map:ipv4-multicast-group-prefix-list']";

	xpval = "/rmap-match-condition/frr-pim-route-map:list-name";

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value), "%s%s", xpath, xpval);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, prefix_list);
	}
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (rmap_match_plist,
            no_rmap_match_plist_cmd,
            "no match ip <multicast-source$do_src|multicast-group$do_grp> prefix-list",
            NO_STR
            MATCH_STR
            IP_STR
            "Multicast source address\n"
            "Multicast group address\n"
            "Match against ip prefix list\n")

DEFPY_YANG (rmap_match_v6_plist,
	    rmap_match_v6_plist_cmd,
	    "[no] match ipv6 <multicast-source$do_src|multicast-group$do_grp> prefix-list WORD",
	    NO_STR
	    MATCH_STR
	    IPV6_STR
	    "Multicast source address\n"
	    "Multicast group address\n"
	    "Match against ip prefix list\n"
	    "Prefix list name\n")
{
	const char *xpath, *xpval;
	char xpath_value[XPATH_MAXLEN];

	assert(do_src || do_grp);

	if (do_src)
		xpath = "./match-condition[condition='frr-pim-route-map:ipv6-multicast-source-prefix-list']";
	else
		xpath = "./match-condition[condition='frr-pim-route-map:ipv6-multicast-group-prefix-list']";

	xpval = "/rmap-match-condition/frr-pim-route-map:list-name";

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value), "%s%s", xpath, xpval);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, prefix_list);
	}
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (rmap_match_v6_plist,
            no_rmap_match_v6_plist_cmd,
            "no match ipv6 <multicast-source$do_src|multicast-group$do_grp> prefix-list",
            NO_STR
            MATCH_STR
            IPV6_STR
            "Multicast source address\n"
            "Multicast group address\n"
            "Match against ip prefix list\n")


DEFPY_YANG (rmap_match_iif,
	    rmap_match_iif_cmd,
	    "[no] match multicast-iif IFNAME",
	    NO_STR
	    MATCH_STR
	    "Multicast data incoming interface\n"
	    "Interface name\n")
{
	const char *xpath, *xpval;
	char xpath_value[XPATH_MAXLEN];

	xpath = "./match-condition[condition='frr-pim-route-map:multicast-iif']";
	xpval = "/rmap-match-condition/frr-pim-route-map:multicast-iif";

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value), "%s%s", xpath, xpval);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, ifname);
	}
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (rmap_match_iif,
            no_rmap_match_iif_cmd,
            "no match multicast-iif",
            NO_STR
            MATCH_STR
            "Multicast data incoming interface\n")

static void rmap_cli_init(void)
{
	install_element(RMAP_NODE, &rmap_match_addr_cmd);
	install_element(RMAP_NODE, &no_rmap_match_addr_cmd);
	install_element(RMAP_NODE, &rmap_match_v6_addr_cmd);
	install_element(RMAP_NODE, &no_rmap_match_v6_addr_cmd);
	install_element(RMAP_NODE, &rmap_match_plist_cmd);
	install_element(RMAP_NODE, &no_rmap_match_plist_cmd);
	install_element(RMAP_NODE, &rmap_match_v6_plist_cmd);
	install_element(RMAP_NODE, &no_rmap_match_v6_plist_cmd);
	install_element(RMAP_NODE, &rmap_match_iif_cmd);
	install_element(RMAP_NODE, &no_rmap_match_iif_cmd);
}
