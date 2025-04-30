// SPDX-License-Identifier: GPL-2.0-or-later
/* key-chain for authentication.
 * Copyright (C) 2000 Kunihiro Ishiguro
 */

#include "config.h"
#include <zebra.h>

#include "keychain.h"
#include "linklist.h"
#include "memory.h"

#include "keychain_private.h"

DEFINE_MTYPE(LIB, KEY, "Key");
DEFINE_MTYPE(LIB, KEYCHAIN, "Key chain");
DEFINE_MTYPE(LIB, KEYCHAIN_DESC, "Key chain description");

DEFINE_QOBJ_TYPE(keychain);
DEFINE_QOBJ_TYPE(key);

static void key_free(struct key *key);

/* Master list of key chain. */
struct keychains_head keychains[1] = { INIT_RBTREE_UNIQ(keychains[0]) };

static struct keychain *keychain_new(const char *name)
{
	struct keychain *keychain;

	keychain = XCALLOC(MTYPE_KEYCHAIN, sizeof(struct keychain));
	keychain->name = XSTRDUP(MTYPE_KEYCHAIN, name);
	kc_keys_init(keychain->keys);
	QOBJ_REG(keychain, keychain);

	return keychain;
}

static void keychain_free(struct keychain *keychain)
{
	struct key *key;

	QOBJ_UNREG(keychain);

	while ((key = kc_keys_pop(keychain->keys)))
		key_free(key);

	kc_keys_fini(keychain->keys);
	XFREE(MTYPE_KEYCHAIN, keychain->name);
	XFREE(MTYPE_KEYCHAIN, keychain);
}

static struct key *key_new(uint32_t index)
{
	struct key *key = XCALLOC(MTYPE_KEY, sizeof(struct key));

	key->index = index;
	key->hash_algo = KEYCHAIN_ALGO_NULL;
	QOBJ_REG(key, key);
	return key;
}

static void key_free(struct key *key)
{
	QOBJ_UNREG(key);
	XFREE(MTYPE_KEY, key);
}

struct keychain *keychain_lookup(const char *name)
{
	const struct keychain ref = { .name = (char *)name };

	if (!name)
		return NULL;

	return keychains_find(keychains, &ref);
}

struct keychain *keychain_get(const char *name)
{
	struct keychain *keychain;

	keychain = keychain_lookup(name);

	if (!keychain) {
		keychain = keychain_new(name);
		keychains_add(keychains, keychain);
	}
	return keychain;
}

void keychain_delete(struct keychain *keychain)
{
	keychains_del(keychains, keychain);
	keychain_free(keychain);
}

struct key *key_lookup(const struct keychain *keychain_const, uint32_t index)
{
	struct keychain *keychain = (struct keychain *)keychain_const;
	const struct key ref = { .index = index };

	return kc_keys_find(keychain->keys, &ref);
}

const struct key *key_lookup_for_accept(const struct keychain *keychain, uint32_t index)
{
	const struct key *key;
	time_t now;

	now = time(NULL);

	frr_each (kc_keys_const, keychain->keys, key) {
		if (key->index >= index) {
			if (key->accept.start == 0)
				return key;

			if (key->accept.start <= now)
				if (key->accept.end >= now
				    || key->accept.end == -1)
					return key;
		}
	}
	return NULL;
}

const struct key *key_match_for_accept(const struct keychain *keychain, const char *auth_str)
{
	const struct key *key;
	time_t now;

	now = time(NULL);

	frr_each (kc_keys_const, keychain->keys, key) {
		if (key->accept.start == 0
		    || (key->accept.start <= now
			&& (key->accept.end >= now || key->accept.end == -1)))
			if (key->string && (strncmp(key->string, auth_str, 16) == 0))
				return key;
	}
	return NULL;
}

const struct key *key_lookup_for_send(const struct keychain *keychain)
{
	const struct key *key;
	time_t now;

	now = time(NULL);

	frr_each (kc_keys_const, keychain->keys, key) {
		if (key->send.start == 0)
			return key;

		if (key->send.start <= now)
			if (key->send.end >= now || key->send.end == -1)
				return key;
	}
	return NULL;
}

struct key *key_get(struct keychain *keychain, uint32_t index)
{
	struct key *key;

	key = key_lookup(keychain, index);

	if (!key) {
		key = key_new(index);
		kc_keys_add(keychain->keys, key);
	}
	return key;
}

void key_delete(struct keychain *keychain, struct key *key)
{
	kc_keys_del(keychain->keys, key);

	key_free(key);
}

const struct keychain_algo_info algo_info[] = {
	{KEYCHAIN_ALGO_NULL, "null", 0, 0, "NULL"},
	{KEYCHAIN_ALGO_MD5, "md5", KEYCHAIN_MD5_HASH_SIZE,
	 KEYCHAIN_ALGO_MD5_INTERNAL_BLK_SIZE, "MD5"},
	{KEYCHAIN_ALGO_HMAC_SHA1, "hmac-sha-1", KEYCHAIN_HMAC_SHA1_HASH_SIZE,
	 KEYCHAIN_ALGO_SHA1_INTERNAL_BLK_SIZE, "HMAC-SHA-1"},
	{KEYCHAIN_ALGO_HMAC_SHA256, "hmac-sha-256",
	 KEYCHAIN_HMAC_SHA256_HASH_SIZE, KEYCHAIN_ALGO_SHA256_INTERNAL_BLK_SIZE,
	 "HMAC-SHA-256"},
	{KEYCHAIN_ALGO_HMAC_SHA384, "hmac-sha-384",
	 KEYCHAIN_HMAC_SHA384_HASH_SIZE, KEYCHAIN_ALGO_SHA384_INTERNAL_BLK_SIZE,
	 "HMAC-SHA-384"},
	{KEYCHAIN_ALGO_HMAC_SHA512, "hmac-sha-512",
	 KEYCHAIN_HMAC_SHA512_HASH_SIZE, KEYCHAIN_ALGO_SHA512_INTERNAL_BLK_SIZE,
	 "HMAC-SHA-512"},
	{KEYCHAIN_ALGO_MAX, "max", KEYCHAIN_MAX_HASH_SIZE,
	 KEYCHAIN_ALGO_MAX_INTERNAL_BLK_SIZE, "Not defined"}
};

uint16_t keychain_get_block_size(enum keychain_hash_algo key)
{
	return algo_info[key].block;
}

uint16_t keychain_get_hash_len(enum keychain_hash_algo key)
{
	return algo_info[key].length;
}

const char *keychain_get_description(enum keychain_hash_algo key)
{
	return algo_info[key].desc;
}

struct keychain_algo_info
keychain_get_hash_algo_info(enum keychain_hash_algo key)
{
	return algo_info[key];
}

enum keychain_hash_algo keychain_get_algo_id_by_name(const char *name)
{
#ifdef CRYPTO_INTERNAL
	if (!strncmp(name, "hmac-sha-2", 10))
		return KEYCHAIN_ALGO_HMAC_SHA256;
	else if (!strncmp(name, "m", 1))
		return KEYCHAIN_ALGO_MD5;
	else
		return KEYCHAIN_ALGO_NULL;
#else
	if (!strncmp(name, "m", 1))
		return KEYCHAIN_ALGO_MD5;
	else if (!strncmp(name, "hmac-sha-1", 10))
		return KEYCHAIN_ALGO_HMAC_SHA1;
	else if (!strncmp(name, "hmac-sha-2", 10))
		return KEYCHAIN_ALGO_HMAC_SHA256;
	else if (!strncmp(name, "hmac-sha-3", 10))
		return KEYCHAIN_ALGO_HMAC_SHA384;
	else if (!strncmp(name, "hmac-sha-5", 10))
		return KEYCHAIN_ALGO_HMAC_SHA512;
	else
		return KEYCHAIN_ALGO_NULL;
#endif
}

const char *keychain_get_algo_name_by_id(enum keychain_hash_algo key)
{
	return algo_info[key].name;
}

void keychain_terminate(void)
{
	struct keychain *keychain;

	while ((keychain = keychains_pop(keychains)))
		keychain_free(keychain);

	/* keychains is static (INIT_RBTREE_UNIQ), no keychains_free here */
}

void keychain_init_new(bool in_backend)
{
	if (!in_backend)
		keychain_cli_init();
}

void keychain_init(void)
{
	keychain_init_new(false);
}

const struct frr_yang_module_info ietf_key_chain_deviation_info = {
	.name = "frr-deviations-ietf-key-chain",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = NULL,
		},
	},
};
