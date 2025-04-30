#pragma once

#include "typesafe.h"

struct vty;
struct fbuf;
struct pskstore;
struct pskref;

/* a PSK's actual final guts - just bytes and a length
 *
 * Note that PSKs are really arbitrary data and can - in generic - contain
 * both NUL bytes as well as unprintable characters.
 */
struct key_basic {
	union {
		char *string;
		uint8_t *data;
	};
	size_t len;
};

/* Definitions for a pskref usage site.
 *
 * name is a freeform string describing the user, e.g. "BGP neighbor TCP-MD5"
 *
 * identity MUST be filled in with a callback that provides UNIQUE text
 * describing the user.  It must be deterministic and no two possible places
 * in config should ever be able to collide.  It also must be documented for
 * end users since the value is required to externally precalculate encrypted
 * keys (e.g. in a config management system).
 *
 * an example name returned from the identity function could generated with
 * "keychain %pSE %u"
 *
 * update SHOULD be a function that handles changes in the key.  Note that for
 * some keystores, the key might initially be unavailable due to some external
 * condition (e.g. platform initialization, or some external key manager
 * process starting).
 *
 * Both identity and update are guaranteed to be called on the main event loop
 */
struct pskref_consumer {
	const char *name;

	/* mandatory; use bprintfrr to fill nameout.  return value is full
	 * length of output (even if the buffer wasn't large enough)
	 */
	size_t (*identity)(const struct pskref *ref, struct fbuf *nameout);

	/* optional; called when key changes (or is loaded) */
	void (*notify)(struct pskref *ref);
};

/* abstracted set of data for a keystore'd (encrypted) key
 * Contents depend on the keystore in use.
 *
 * The distinction between params and ciphertext is made solely for the
 * purpose of inputting keys.  A key is input using a keystore-specific value
 * for params plus the unencrypted key.  The keystore then returns some blob
 * of ciphertext.  The params value is part of config, kept and stored.
 *
 * Note that ciphertext does not necessarily have to contain encrypted data.
 * In particular of the keystore manages key data externally, it would be
 * either some kind of key ID, or just plain empty (if the reference identity
 * is sufficient.)
 *
 * CLI representation of these values is:
 *   "<modulename>[:<params>] <ciphertext>"
 * Due to CLI constraints, neither params nor ciphertext can contain spaces,
 * and ciphertext also cannot be empty.  It is the keystore module's
 * responsibility to ensure these constraints, in particular for ciphertext
 * returned on input.
 */
struct psk_encdata {
	const struct pskstore *store;

	/* can be NULL if params was omitted */
	char *params;

	/* MUST be valid non-empty CLI token (no spaces or newlines) */
	char *ciphertext;
};

enum psk_kind {
	PSK_NONE = 0,
	PSK_CLEARTEXT,
	PSK_ENCRYPTED,
	PSK_KEYCHAIN,
};

struct pskref {
	/* keep this at the beginning for the time being - keychain code
	 * relies on this
	 */
	struct key_basic key;

	/* see above */
	enum psk_kind kind;
	bool valid;

	/* callbacks to the usage site.  must be set before using. */
	const struct pskref_consumer *consumer;

	/* should not be touched by the calling code */
	union {
		struct psk_encdata encrypted;
		struct keychain *keychain;
	};
};

/* all of the following functions are currently required to be called only
 * on the main event loop
 */

const struct key_basic *psk_recv_first(struct pskref *psk);
const struct key_basic *psk_recv_next(struct pskref *psk, const struct key_basic *prev);
const struct key_basic *psk_send(struct pskref *psk);

void psk_init(struct pskref *ref, const struct pskref_consumer *consumer);
void psk_set_none(struct pskref *ref);
void psk_set_keychain(struct pskref *ref, const char *keychainname);
void psk_set_cleartext(struct pskref *psk, const char *cleartext);
/* TODO: return value for "LOADING"? */
bool psk_set_encrypted(struct pskref *psk, const char *store_params, const char *ciphertext);
void psk_clear(struct pskref *ref);

int psk_input_encrypt(struct vty *vty, const char *identity, struct psk_encdata *out,
		      const char *store_params, const char *cleartext);

/* keystore implementation
 *
 */
enum pskstore_result {
	PSKSTORE_OK = 0,
	PSKSTORE_LOADING,
	PSKSTORE_INVALID,
};

static const uint8_t aead_aad_signature[16] = "\xf0\x9f\x90\x94" "FRRouting:" "\x00\x00";

struct pskstore {
	const char *name;

	enum pskstore_result (*request)(const char *identity, const struct psk_encdata *data,
					struct key_basic *out);

	bool (*cli_input)(struct vty *vty, const char *identity, struct psk_encdata *out,
			  const char *params, const char *cleartext);

	/* TODO: cli_autocomplete? */
};

void pskstore_notify(const char *identity);

PREDECL_RBTREE_UNIQ(pskstores);

struct pskstore_run {
	struct pskstores_item item;
	const struct pskstore *store;
};

void pskstore_register(const struct pskstore *store, struct pskstore_run *run);

void secrets_init(void);
