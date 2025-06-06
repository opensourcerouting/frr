// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_IFCHANNEL_H
#define PIM_IFCHANNEL_H

#include <zebra.h>

#include <stdbool.h>
#include <stdint.h>

#include "lib/openbsd-tree.h"

#include "pimd/pim_addr.h"
#include "pimd/pim_str.h"
#include "pimd/pim_assert.h"

struct interface;

enum pim_ifmembership { PIM_IFMEMBERSHIP_NOINFO, PIM_IFMEMBERSHIP_INCLUDE };

enum pim_ifjoin_state {
	PIM_IFJOIN_NOINFO,
	PIM_IFJOIN_JOIN,
	PIM_IFJOIN_PRUNE,
	PIM_IFJOIN_PRUNE_PENDING,
	PIM_IFJOIN_PRUNE_TMP,
	PIM_IFJOIN_PRUNE_PENDING_TMP,
};

/*
  Flag to detect change in CouldAssert(S,G,I)
*/
#define PIM_IF_FLAG_MASK_COULD_ASSERT (1 << 0)
#define PIM_IF_FLAG_TEST_COULD_ASSERT(flags) ((flags) & PIM_IF_FLAG_MASK_COULD_ASSERT)
#define PIM_IF_FLAG_SET_COULD_ASSERT(flags) ((flags) |= PIM_IF_FLAG_MASK_COULD_ASSERT)
#define PIM_IF_FLAG_UNSET_COULD_ASSERT(flags) ((flags) &= ~PIM_IF_FLAG_MASK_COULD_ASSERT)
/*
  Flag to detect change in AssertTrackingDesired(S,G,I)
*/
#define PIM_IF_FLAG_MASK_ASSERT_TRACKING_DESIRED (1 << 1)
#define PIM_IF_FLAG_TEST_ASSERT_TRACKING_DESIRED(flags) ((flags) & PIM_IF_FLAG_MASK_ASSERT_TRACKING_DESIRED)
#define PIM_IF_FLAG_SET_ASSERT_TRACKING_DESIRED(flags) ((flags) |= PIM_IF_FLAG_MASK_ASSERT_TRACKING_DESIRED)
#define PIM_IF_FLAG_UNSET_ASSERT_TRACKING_DESIRED(flags) ((flags) &= ~PIM_IF_FLAG_MASK_ASSERT_TRACKING_DESIRED)

/*
 * Flag to tell us if the ifchannel is (S,G,rpt)
 */
#define PIM_IF_FLAG_MASK_S_G_RPT         (1 << 2)
#define PIM_IF_FLAG_TEST_S_G_RPT(flags)  ((flags) & PIM_IF_FLAG_MASK_S_G_RPT)
#define PIM_IF_FLAG_SET_S_G_RPT(flags)   ((flags) |= PIM_IF_FLAG_MASK_S_G_RPT)
#define PIM_IF_FLAG_UNSET_S_G_RPT(flags) ((flags) &= ~PIM_IF_FLAG_MASK_S_G_RPT)

/*
 * Flag to tell us if the ifchannel is proto PIM
 */
#define PIM_IF_FLAG_MASK_PROTO_PIM (1 << 3)
#define PIM_IF_FLAG_TEST_PROTO_PIM(flags) ((flags)&PIM_IF_FLAG_MASK_PROTO_PIM)
#define PIM_IF_FLAG_SET_PROTO_PIM(flags) ((flags) |= PIM_IF_FLAG_MASK_PROTO_PIM)
#define PIM_IF_FLAG_UNSET_PROTO_PIM(flags)                                     \
	((flags) &= ~PIM_IF_FLAG_MASK_PROTO_PIM)
/*
 * Flag to tell us if the ifchannel is proto IGMP
 */
#define PIM_IF_FLAG_MASK_PROTO_IGMP (1 << 4)
#define PIM_IF_FLAG_TEST_PROTO_IGMP(flags) ((flags)&PIM_IF_FLAG_MASK_PROTO_IGMP)
#define PIM_IF_FLAG_SET_PROTO_IGMP(flags)                                      \
	((flags) |= PIM_IF_FLAG_MASK_PROTO_IGMP)
#define PIM_IF_FLAG_UNSET_PROTO_IGMP(flags)                                    \
	((flags) &= ~PIM_IF_FLAG_MASK_PROTO_IGMP)
/*
  Per-interface (S,G) state
*/
struct pim_ifchannel {
	RB_ENTRY(rb_ifchannel) pim_ifp_rb;

	struct pim_ifchannel *parent;
	struct list *sources;
	pim_sgaddr sg;
	char sg_str[PIM_SG_LEN];
	struct interface *interface; /* backpointer to interface */
	uint32_t flags;
	uint16_t prune_holdtime;

	/* IGMPv3 determined interface has local members for (S,G) ? */
	enum pim_ifmembership local_ifmembership;

	/* Per-interface (S,G) Join/Prune State (Section 4.1.4 of RFC4601) */
	enum pim_ifjoin_state ifjoin_state;
	struct event *t_ifjoin_expiry_timer;
	struct event *t_ifjoin_prune_pending_timer;
	int64_t ifjoin_creation; /* Record uptime of ifjoin state */

	/* Per-interface (S,G) Assert State (Section 4.6.1 of RFC4601) */
	enum pim_ifassert_state ifassert_state;
	struct event *t_ifassert_timer;
	pim_addr ifassert_winner;
	struct pim_assert_metric ifassert_winner_metric;
	int64_t ifassert_creation; /* Record uptime of ifassert state */
	struct pim_assert_metric ifassert_my_metric;

	/* Upstream (S,G) state */
	struct pim_upstream *upstream;
};

RB_HEAD(pim_ifchannel_rb, pim_ifchannel);
RB_PROTOTYPE(pim_ifchannel_rb, pim_ifchannel, pim_ifp_rb,
	     pim_ifchannel_compare);

void pim_ifchannel_delete(struct pim_ifchannel *ch);
void pim_ifchannel_delete_all(struct interface *ifp);
void pim_ifchannel_membership_clear(struct interface *ifp);
void pim_ifchannel_delete_on_noinfo(struct interface *ifp);
struct pim_ifchannel *pim_ifchannel_find(struct interface *ifp, pim_sgaddr *sg);
struct pim_ifchannel *pim_ifchannel_add(struct interface *ifp, pim_sgaddr *sg,
					uint8_t ch_flags, int up_flags);
void pim_ifchannel_join_add(struct interface *ifp, pim_addr neigh_addr,
			    pim_addr upstream, pim_sgaddr *sg,
			    uint8_t source_flags, uint16_t holdtime);
void pim_ifchannel_prune(struct interface *ifp, pim_addr upstream,
			 pim_sgaddr *sg, uint8_t source_flags,
			 uint16_t holdtime);
int pim_ifchannel_local_membership_add(struct interface *ifp, pim_sgaddr *sg,
				       bool is_vxlan);
void pim_ifchannel_local_membership_del(struct interface *ifp, pim_sgaddr *sg);

void pim_ifchannel_ifjoin_switch(const char *caller, struct pim_ifchannel *ch,
				 enum pim_ifjoin_state new_state);
const char *pim_ifchannel_ifjoin_name(enum pim_ifjoin_state ifjoin_state,
				      int flags);
const char *pim_ifchannel_ifassert_name(enum pim_ifassert_state ifassert_state);

int pim_ifchannel_isin_oiflist(struct pim_ifchannel *ch);

void reset_ifassert_state(struct pim_ifchannel *ch);

void pim_ifchannel_update_could_assert(struct pim_ifchannel *ch);
void pim_ifchannel_update_my_assert_metric(struct pim_ifchannel *ch);
void pim_ifchannel_update_assert_tracking_desired(struct pim_ifchannel *ch);

void pim_ifchannel_scan_forward_start(struct interface *new_ifp);
void pim_ifchannel_set_star_g_join_state(struct pim_ifchannel *ch, int eom,
					 uint8_t join);

int pim_ifchannel_compare(const struct pim_ifchannel *ch1,
			  const struct pim_ifchannel *ch2);

void delete_on_noinfo(struct pim_ifchannel *ch);
#endif /* PIM_IFCHANNEL_H */
