// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 David Lamparter for NetDEF, Inc.
 */

#ifndef _FRR_KEYCHAIN_PRIVATE_H
#define _FRR_KEYCHAIN_PRIVATE_H

static inline int keychains_cmp(const struct keychain *a, const struct keychain *b)
{
	return strcmp(a->name, b->name);
}

DECLARE_RBTREE_UNIQ(keychains, struct keychain, keychains_item, keychains_cmp);

static inline int kc_keys_cmp(const struct key *a, const struct key *b)
{
	return numcmp(a->index, b->index);
}

DECLARE_RBTREE_UNIQ(kc_keys, struct key, kc_keys_item, kc_keys_cmp);

extern struct keychains_head keychains[1];

#endif /* _FRR_KEYCHAIN_PRIVATE_H */
