#include "config.h"

#include "lib/secrets.h"
#include "lib/keychain.h"
#include "lib/printfrr.h"
#include "lib/command.h"

#include "lib/secrets_clippy.c"

static int pskstores_cmp(const struct pskstore_run *a, const struct pskstore_run *b)
{
	return strcmp(a->store->name, b->store->name);
}

DECLARE_RBTREE_UNIQ(pskstores, struct pskstore_run, item, pskstores_cmp);

struct pskstores_head stores[1] = { INIT_RBTREE_UNIQ(algs[1]) };

static const struct pskstore *pskstore(const char *name, const char **params)
{
	size_t name_len = strlen(name);
	char name_copy[name_len + 1];
	const struct pskstore ref = { .name = name_copy };
	struct pskstore_run *store_run, ref_run = { .store = &ref };

	*params = strchr(name, ':');
	if (*params) {
		name_len = (*params) - name;
		(*params)++;
	}

	memcpy(name_copy, name, name_len);
	name_copy[name_len] = '\0';

	store_run = pskstores_find(stores, &ref_run);
	return store_run ? store_run->store : NULL;
}

void psk_init(struct pskref *psk, const struct pskref_consumer *consumer)
{
	psk->consumer = consumer;
	psk->kind = PSK_NONE;
	psk->valid = false;
}

void psk_clear(struct pskref *psk)
{
	switch (psk->kind) {
	case PSK_NONE:
		break;
	case PSK_ENCRYPTED:
		psk->encrypted.store = NULL;
		XFREE(MTYPE_KEY, psk->encrypted.params);
		XFREE(MTYPE_KEY, psk->encrypted.ciphertext);
		/* fallthru */
	case PSK_CLEARTEXT:
		XFREE(MTYPE_KEY, psk->key.data);
		break;
	case PSK_KEYCHAIN:
		psk->keychain = NULL;
		break;
	}

	psk->kind = PSK_NONE;
	psk->valid = false;
}

void psk_set_none(struct pskref *psk)
{
	psk_clear(psk);
	psk->valid = true;
}

void psk_set_cleartext(struct pskref *psk, const char *cleartext)
{
	psk_clear(psk);

	psk->kind = PSK_CLEARTEXT;
	psk->key.string = XSTRDUP(MTYPE_KEY, cleartext);
	psk->key.len = strlen(psk->key.string);
	psk->valid = true;
}

static inline char *pskref_get_id(struct pskref *ref, char *stackbuf, size_t stacksize)
{
	char *ret = stackbuf;
	struct fbuf fbuf = { .buf = ret, .pos = ret, .len = stacksize };
	size_t len;

	len = ref->consumer->identity(ref, &fbuf);
	if (len + 1 > stacksize) {
		ret = XMALLOC(MTYPE_TMP, len + 1);
		fbuf = (struct fbuf){ .buf = ret, .pos = ret, .len = len + 1 };
		ref->consumer->identity(ref, &fbuf);
	}
	ret[len] = '\0';

	return ret;
}

bool psk_set_encrypted(struct pskref *psk, const char *store_params, const char *ciphertext)
{
	const char *params;
	const struct pskstore *store = pskstore(store_params, &params);
	enum pskstore_result res;
	char *identity, id_buf[128];

	if (!store)
		return false;
	assertf(psk->consumer, "psk=%p store_params=%pSQq ciphertext=%pSQq",
		psk, store_params, ciphertext);

	psk_clear(psk);
	psk->encrypted.store = store;
	psk->encrypted.ciphertext = XSTRDUP(MTYPE_KEY, ciphertext);
	
	if (params)
		psk->encrypted.params = XSTRDUP(MTYPE_KEY, params);

	identity = pskref_get_id(psk, id_buf, sizeof(id_buf));

	res = store->request(identity, &psk->encrypted, &psk->key);

	if (identity != id_buf)
		XFREE(MTYPE_TMP, identity);

	if (res == PSKSTORE_INVALID) {
		psk_clear(psk);
		return false;
	}

	psk->valid = (res == PSKSTORE_OK);
	return true;
}

void pskstore_register(const struct pskstore *store, struct pskstore_run *run)
{
	run->store = store;
	pskstores_add(stores, run);
}

int psk_input_encrypt(struct vty *vty, const char *identity, struct psk_encdata *out,
		      const char *store_params, const char *cleartext)
{
	const char *params;
	struct pskstore *store = pskstore(store_params, &params);

	if (!store) {
		vty_out(vty, "%% no keystore matching %*pSQq available\n",
			(int)(params ? (params - store_params) : strlen(store_params)), store_params);
		return CMD_WARNING;
	}

	if (!store->cli_input(vty, identity, out, params, cleartext))
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFPY(secrets_input,
      secrets_input_cmd,
      "secret input IDENTITY ALG PLAINTEXT",
      "secret\ntest\nidentity\nalgorithm\nplaintext\n")
{
	struct psk_encdata ed;
	int ret;

	ret = psk_input_encrypt(vty, identity, &ed, alg, plaintext);
	if (ret == CMD_SUCCESS)
		vty_out(vty, "output: %pSQq\n", ed.ciphertext);

	return CMD_SUCCESS;
}

DEFPY(secrets_access,
      secrets_access_cmd,
      "secret access IDENTITY ALG CIPHERTEXT",
      "secret\ntest\nidentity\nalgorithm\nciphertext\n")
{
	struct pskstore_run *store_run, ref_run;
	struct pskstore ref;
	struct psk_encdata ed;
	struct key_basic key;

	ref.name = (char *)argv[2]->arg;
	ref_run.store = &ref;

	store_run = pskstores_find(stores, &ref_run);
	if (!store_run) {
		vty_out(vty, "no such alg\n");
		return CMD_WARNING;
	}

	ed.store = store_run->store;
	ed.ciphertext = (char *)argv[3]->arg;

	bool success = store_run->store->request(identity, &ed, &key);

	vty_out(vty, "output: %d %pSQq\n", success, key.string);

	return CMD_SUCCESS;
}

void secrets_init(void)
{
	install_element(ENABLE_NODE, &secrets_input_cmd);
	install_element(ENABLE_NODE, &secrets_access_cmd);
}
