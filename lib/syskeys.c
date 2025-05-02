
#include "config.h"

#include "lib/secrets.h"

#include "lib/keychain.h"
#include "lib/libfrr.h"
#include "lib/command.h"
#include "lib/json.h"
#include "lib/base64.h"
#include "lib/version.h"

#include <json-c/json_object.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "lib/syskeys_clippy.c"

struct key_cfg {
	EVP_CIPHER *cipher;
	size_t iv_len;
	size_t block_len;

	uint8_t *key;
	size_t key_len;
};

struct key_cfg syskeys_default;

static const size_t aead_tag_len = 4;

static enum pskstore_result syskeys_request(const char *identity, const struct psk_encdata *data,
					    struct key_basic *out)
{
	enum pskstore_result result = PSKSTORE_INVALID;
	struct key_cfg *key = &syskeys_default;
	EVP_CIPHER_CTX *ctx;
	char *in_pos = data->ciphertext;
	char *iv_end;
	char *aad_end;
	size_t have_iv;
	uint8_t *iv = NULL;
	struct base64_decodestate b64;
	size_t plain_len;
	uint8_t *b64buf;
	size_t id_len;
	int len;
	int rv;

	if (*in_pos++ != '$')
		return PSKSTORE_INVALID;

	iv_end = strchr(in_pos, '$');
	if (!iv_end)
		return PSKSTORE_INVALID;

	aad_end = strchr(iv_end + 1, '$');
	if (!aad_end)
		return PSKSTORE_INVALID;

	if (key->iv_len) {
		iv = XMALLOC(MTYPE_TMP, iv_end - in_pos);

		base64_init_decodestate(&b64);
		have_iv = base64_decode_block(in_pos, iv_end - in_pos, (char *)iv, &b64);

		if (have_iv != key->iv_len)
			goto out_free_iv;
	}

	/* FIXME: memory management */
	in_pos = iv_end + 1;

	b64buf = malloc(strlen(in_pos));

	base64_init_decodestate(&b64);
	id_len = base64_decode_block(in_pos, aad_end - in_pos, (char *)b64buf, &b64);
	b64buf[id_len] = '\0';
	if (strcmp((char *)b64buf, identity)) {
		zlog_err("key identity mismatch: expected %pSQq, got %pSQq", identity, (char *)b64buf);
		goto out_free_iv;
	}

	in_pos = aad_end + 1;

	base64_init_decodestate(&b64);
	plain_len = base64_decode_block(in_pos, strlen(in_pos), (char *)b64buf, &b64);

	out->data = malloc(plain_len + 1);

	ctx = EVP_CIPHER_CTX_new();
	assert(ctx);
	rv = EVP_DecryptInit(ctx, key->cipher, key->key, iv);
	if (rv != 1)
		goto out_free;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
				aead_tag_len, b64buf + plain_len - aead_tag_len) != 1)
		goto out_free;

	rv = EVP_DecryptUpdate(ctx, NULL, &len, aead_aad_signature, sizeof(aead_aad_signature));
	if (rv != 1)
		goto out_free;

	rv = EVP_DecryptUpdate(ctx, NULL, &len, (uint8_t *)identity, strlen(identity));
	if (rv != 1)
		goto out_free;

	rv = EVP_DecryptUpdate(ctx, out->data, &len, b64buf, plain_len - aead_tag_len);
	if (rv != 1)
		goto out_free;

	out->len = len;
	rv = EVP_DecryptFinal(ctx, out->data + len, &len);
	if (rv != 1)
		goto out_free;

	out->len += len;
	out->data[out->len] = '\0';
	result = PSKSTORE_OK;

out_free:
	EVP_CIPHER_CTX_free(ctx);
out_free_iv:
	XFREE(MTYPE_TMP, iv);
	return result;
}

static bool syskeys_cli_input(struct vty *vty, const char *identity, struct psk_encdata *out,
			      const char *params, const char *cleartext)
{
	bool ret = false;
	uint8_t *iv = NULL;
	struct key_cfg *key = &syskeys_default;
	EVP_CIPHER_CTX *ctx;
	size_t clear_len = strlen(cleartext);
	size_t out_max_len = clear_len + key->block_len * 2 + 16;
	size_t out_len;
	int len = 0;
	uint8_t *outbuf, *outpos;
	struct base64_encodestate b64;
	char *b64buf, *b64pos;
	int rv;

	assert(key->cipher);

	if (key->iv_len) {
		//vty_out(vty, "generating %zu bytes of IV\n", key->iv_len);
		iv = XMALLOC(MTYPE_TMP, key->iv_len);
		RAND_priv_bytes(iv, key->iv_len);
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		vty_out(vty, "failed to allocate context for cipher\n");
		goto out_free_iv;
	}

	rv = EVP_EncryptInit(ctx, key->cipher, key->key, iv);
	if (rv != 1) {
		vty_out(vty, "failed to initialize context for cipher\n");
		goto out_free;
	}

	rv = EVP_EncryptUpdate(ctx, NULL, &len, aead_aad_signature, sizeof(aead_aad_signature));
	if (rv != 1)
		goto out_free;

	rv = EVP_EncryptUpdate(ctx, NULL, &len, (uint8_t *)identity, strlen(identity));
	if (rv != 1)
		goto out_free;

	/* FIXME: memory management */
	outbuf = outpos = malloc(out_max_len);
	rv = EVP_EncryptUpdate(ctx, outpos, &len, (const uint8_t *)cleartext, clear_len);
	if (rv != 1) {
		vty_out(vty, "failed to encrypt\n");
		goto out_free;
	}
	outpos += len;

	rv = EVP_EncryptFinal_ex(ctx, outpos, &len);
	if (rv != 1) {
		vty_out(vty, "failed to finish encrypt\n");
		goto out_free;
	}
	outpos += len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, aead_tag_len, outpos) != 1) {
		vty_out(vty, "failed to get AEAD tag\n");
		goto out_free;
	}

	out_len = outpos - outbuf + aead_tag_len;
	
	size_t b64_len = 4; /* null byte + 3* '$' */

	b64_len += base64_encoded_length(key->iv_len);
	b64_len += base64_encoded_length(out_len);
	b64_len += base64_encoded_length(strlen(identity));

	b64buf = b64pos = XMALLOC(MTYPE_KEY, b64_len);

	*b64pos++ = '$';
	if (key->iv_len) {
		base64_init_encodestate(&b64);
		b64pos += base64_encode_block((char *)iv, key->iv_len, b64pos, &b64);
		b64pos += base64_encode_blockend(b64pos, &b64);
	}

	*b64pos++ = '$';
	base64_init_encodestate(&b64);
	b64pos += base64_encode_block(identity, strlen(identity), b64pos, &b64);
	b64pos += base64_encode_blockend(b64pos, &b64);

	*b64pos++ = '$';
	base64_init_encodestate(&b64);
	b64pos += base64_encode_block((char *)outbuf, out_len, b64pos, &b64);
	b64pos += base64_encode_blockend(b64pos, &b64);
	*b64pos = '\0';

	out->ciphertext = b64buf;
	out->params = NULL;
	ret = true;

out_free:
	EVP_CIPHER_CTX_free(ctx);
out_free_iv:
	XFREE(MTYPE_TMP, iv);
	return ret;
}

static void syskeys_parse_one(struct vty *vty, struct key_cfg *key, struct json_object *js)
{
	struct json_object *js_key = json_object_object_get(js, "key");
	const char *key_val = json_object_get_string(js_key);
	size_t key_len = json_object_get_string_len(js_key);
	size_t expect_len;
	const char *cipher = json_object_get_string(json_object_object_get(js, "cipher"));

	if (!cipher || !key) {
		vty_out(vty, "invalid JSON\n");
		return;
	}

	key->cipher = EVP_CIPHER_fetch(NULL, cipher, NULL);
	if (!key->cipher) {
		vty_out(vty, "unknown cipher %pSQq\n", cipher);
		return;
	}
	expect_len = EVP_CIPHER_get_key_length(key->cipher);
	if (key_len != expect_len) {
		vty_out(vty, "invalid key length %zu for cipher %pSQq (need %zu)\n",
			key_len, cipher, expect_len);
		return;
	}

	key->iv_len = EVP_CIPHER_get_iv_length(key->cipher);
	key->block_len = EVP_CIPHER_get_block_size(key->cipher);
	key->key_len = key_len;
	/* FIXME: memory management */
	key->key = malloc(key_len);
	memcpy(key->key, key_val, key_len);
}

DEFPY(syskeys_storage,
      syskeys_storage_cmd,
      "crypto syskeys storage FILENAME",
      "crypto\nsyskeys\nstorage\nfilename\n")
{
	struct json_object *js;
	struct json_object *js_defkey;

	js = json_object_from_file(filename);
	if (!js) {
		vty_out(vty, "Failed to load %pSQq: %s\n", filename,
			json_util_get_last_err());
		return CMD_WARNING;
	}

	js_defkey = json_object_object_get(js, "default-key");
	if (js_defkey)
		syskeys_parse_one(vty, &syskeys_default, js_defkey);

	json_object_put(js);
	return CMD_SUCCESS;
}

static int syskeys_late_init(struct event_loop *tm)
{
	install_element(CONFIG_NODE, &syskeys_storage_cmd);
	return 0;
}

const struct pskstore syskeys = {
	.name = "syskeys",
	.request = syskeys_request,
	.cli_input = syskeys_cli_input,
};
static struct pskstore_run syskeys_run;

static int syskeys_init(void)
{
	pskstore_register(&syskeys, &syskeys_run);
	hook_register(frr_late_init, syskeys_late_init);
	//hook_register(frr_early_fini, syskeys_early_fini);
	return 0;
}

/* clang-format off */
FRR_MODULE_SETUP(
	.name = "pskenc_syskeys",
	.version = FRR_VERSION,
	.description = "key encryption using system keys in /etc",
	.init = syskeys_init,
);
