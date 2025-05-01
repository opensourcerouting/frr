
#include "config.h"

#include <linux/if_alg.h>
#include <sys/socket.h>
#include <sys/random.h>

#include "lib/secrets.h"

#include "lib/keychain.h"
#include "lib/libfrr.h"
#include "lib/command.h"
#include "lib/json.h"
#include "lib/base64.h"
#include "lib/version.h"

#include "lib/keyctl_clippy.c"


static const size_t aead_tag_len = 4;


#ifdef DEBUG_AF_ALG_SUBMIT
static inline void msgdump(struct msghdr *msg)
{
	int i;

	zlog_debug("msghdr @ %p", msg);

	for (i = 0; i < msg->msg_iovlen; i++) {
		struct iovec *iov = &msg->msg_iov[i];

		zlog_debug("[%2d] (@%16p) %3zu:  %.*pHX", i, iov->iov_base, iov->iov_len,
			  (int)iov->iov_len, iov->iov_base);
	}

	zlog_debug("cmsg (@%16p) %3zu:  %.*pHX", msg->msg_control, msg->msg_controllen,
		   (int)msg->msg_controllen, msg->msg_control);
}
#else
#define msgdump(msg) do { } while (0)
#endif

DECLARE_MGROUP(KEYSTORE_LINUX_KEYCTL);

DEFINE_MGROUP(KEYSTORE_LINUX_KEYCTL, "Linux kernel keyring keystore module");
DEFINE_MTYPE_STATIC(KEYSTORE_LINUX_KEYCTL, KEYSTORE_KEYCTL, "Linux kernel keyring association");

PREDECL_RBTREE_UNIQ(keys);

struct key_cfg {
	struct keys_item item;
	char *keystore_name;

	char *alg_name;
	uint32_t key_id;
	int fd;

	size_t iv_len;
	size_t aead_tag_len;
};

static inline int key_name_cmp(const struct key_cfg *a, const struct key_cfg *b)
{
	return strcmp(a->keystore_name, b->keystore_name);
}

DECLARE_RBTREE_UNIQ(keys, struct key_cfg, item, key_name_cmp);

static struct key_cfg key_default = { .fd = -1 };
static struct keys_head keys[1] = { INIT_RBTREE_UNIQ(head[0]) };

static struct key_cfg *keycfg_new(const char *name)
{
	struct key_cfg *key;

	key = XCALLOC(MTYPE_KEYSTORE_KEYCTL, sizeof(*key) + strlen(name) + 1);
	key->fd = -1;
	key->keystore_name = (char *)(key + 1);
	memcpy(key->keystore_name, name, strlen(name) + 1);
	return key;
}

static struct key_cfg *keycfg_find(const char *name)
{
	struct key_cfg ref = { .keystore_name = (char *)name };

	return name ? keys_find(keys, &ref) : &key_default;
}

static struct key_cfg *keycfg_get(const char *name)
{
	struct key_cfg *key;

	key = keycfg_find(name);
	if (!key) {
		key = keycfg_new(name);
		keys_add(keys, key);
	}

	return key;
}

/* helpers for ingesting $base64_A$base64_B$xyz style data */

static char *dollar_chop(char **pos)
{
	char *ret, *dollar;

	ret = *pos;
	if (!ret)
		return NULL;

	dollar = strchr(ret, '$');
	if (dollar)
		*dollar++ = '\0';
	*pos = dollar;

	return ret;
}

static uint8_t *get_base64(char **pos, uint8_t **bufp, size_t *len)
{
	char *field = dollar_chop(pos);
	struct base64_decodestate b64;
	uint8_t *ret = *bufp;

	*len = 0;
	if (!field)
		return NULL;

	base64_init_decodestate(&b64);
	*len = base64_decode_block(field, strlen(field), (char *)ret, &b64);
	*bufp = ret + *len;
	return ret;
}

static char *get_base64_str(char **pos, uint8_t **bufp, size_t *len)
{
	uint8_t *val = get_base64(pos, bufp, len);

	if (!val)
		return NULL;

	val[*len] = '\0';
	if (*bufp)
		(*bufp)++;
	return (char *)val;
}


static enum pskstore_result kskeyctl_decrypt(struct key_cfg *key, uint8_t *iv,
					     uint8_t *aad, size_t aad_len,
					     uint8_t *encb, size_t encb_len,
					     struct key_basic *out)
{
	char discard[sizeof(aead_aad_signature)];
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(key->iv_len + 4) + CMSG_SPACE(4)] = {};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivp;
	struct iovec iovecs[3], *iov = iovecs;
	struct msghdr msg = {
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
		.msg_iov = iovecs,
		.msg_iovlen = 3,
	};
	ssize_t nread;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(uint32_t *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(uint32_t *)CMSG_DATA(cmsg) = sizeof(aead_aad_signature) + aad_len;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(key->iv_len + 4);
	ivp = (struct af_alg_iv *)CMSG_DATA(cmsg);
	ivp->ivlen = key->iv_len;
	memcpy(ivp->iv, iv, key->iv_len);

	iov->iov_base = (void *)aead_aad_signature;
	iov->iov_len = sizeof(aead_aad_signature);
	iov++;
	iov->iov_base = (void *)aad;
	iov->iov_len = aad_len;
	iov++;
	iov->iov_base = encb;
	iov->iov_len = encb_len;
	iov++;

	msg.msg_iovlen = iov - iovecs;

	msgdump(&msg);
	if (sendmsg(key->fd, &msg, 0) <= 0) {
		zlog_err("sendmsg(AF_ALG): %m");
		return PSKSTORE_INVALID;
	}

	/* the read gives back the AAD unmodified, so...
	 * just reuse the iovec from the send */

	/* aead_aad_signature is a constant, need to shunt it elsewhere */
	iovecs[0].iov_base = discard;

	/* the AEAD tag is at the end and removed */
	encb_len -= key->aead_tag_len;
	iovecs[2].iov_base = out->data = XMALLOC(MTYPE_KEY, encb_len + 1);
	iovecs[2].iov_len = encb_len + 1;

	nread = readv(key->fd, iovecs, 3);

	if (nread < 0) {
		zlog_err("decrypt(AF_ALG): %m");
		goto out_free;
	} else if ((size_t)nread != sizeof(aead_aad_signature) + aad_len + encb_len) {
		zlog_err("decrypt(AF_ALG): wrong len?");
		goto out_free;
	}

	out->data[encb_len] = '\0';
	return PSKSTORE_OK;

out_free:
	XFREE(MTYPE_KEY, out->data);
	return PSKSTORE_INVALID;
}

static enum pskstore_result kskeyctl_request(const char *identity, const struct psk_encdata *data,
					     struct key_basic *out)
{
	struct key_cfg *key = &key_default;
	/* data->ciphertext cannot be modified. just make an on-stack copy */
	size_t cipherlen = strlen(data->ciphertext);
	char enc_copy[cipherlen + 1], *in_pos = enc_copy;
	/* base64 decode is always shorter than input - just use input len
	 * note only aad_identity has a NUL terminator byte
	 */
	uint8_t raw[cipherlen + 1], *raw_pos = raw;
	uint8_t *iv, *encb;
	size_t iv_len, encb_len, aad_len;
	char *aad_identity;

	memcpy(enc_copy, data->ciphertext, cipherlen + 1);

	if (*in_pos++ != '$')
		return PSKSTORE_INVALID;

	iv = get_base64(&in_pos, &raw_pos, &iv_len);
	aad_identity = get_base64_str(&in_pos, &raw_pos, &aad_len);
	encb = get_base64(&in_pos, &raw_pos, &encb_len);

	if (!iv || !aad_identity || !encb || in_pos) {
		zlog_warn("invalid encrypted key %pSQq", data->ciphertext);
		return PSKSTORE_INVALID;
	}

	if (iv_len != key->iv_len) {
		zlog_warn("cannot load key, IV length mismatch (got %zu, need %zu for %pSQq)",
			  iv_len, key->iv_len, key->alg_name);
		return PSKSTORE_INVALID;
	}

	if (strcmp(aad_identity, identity)) {
		zlog_err("key identity mismatch: got %pSQq, want %pSQq", aad_identity, identity);
		return PSKSTORE_INVALID;
	}
	if (encb_len < key->aead_tag_len) {
		zlog_err("key is too short (%zu < %zu)", encb_len, key->aead_tag_len);
		return PSKSTORE_INVALID;
	}

	return kskeyctl_decrypt(key, iv, (uint8_t *)aad_identity, aad_len, encb, encb_len, out);
}

static bool kskeyctl_wrap(struct key_cfg *key, const uint8_t *iv, const char *identity, size_t identity_len,
			  const uint8_t *encb, size_t encb_len, struct psk_encdata *out)
{
	size_t b64_len = 4 /* null byte + 3* '$' */
		+ base64_encoded_length(key->iv_len)
		+ base64_encoded_length(identity_len)
		+ base64_encoded_length(encb_len);
	char *b64buf, *b64pos;
	struct base64_encodestate b64;

	b64buf = b64pos = XMALLOC(MTYPE_KEY, b64_len);

	*b64pos++ = '$';
	base64_init_encodestate(&b64);
	b64pos += base64_encode_block((char *)iv, key->iv_len, b64pos, &b64);
	b64pos += base64_encode_blockend(b64pos, &b64);

	*b64pos++ = '$';
	base64_init_encodestate(&b64);
	b64pos += base64_encode_block(identity, identity_len, b64pos, &b64);
	b64pos += base64_encode_blockend(b64pos, &b64);

	*b64pos++ = '$';
	base64_init_encodestate(&b64);
	b64pos += base64_encode_block((char *)encb, encb_len, b64pos, &b64);
	b64pos += base64_encode_blockend(b64pos, &b64);

	*b64pos = '\0';

	out->params = NULL;
	out->ciphertext = b64buf;
	return true;
}

static bool kskeyctl_cli_input(struct vty *vty, const char *identity, struct psk_encdata *out,
			       const char *params, const char *cleartext)
{
	struct key_cfg *key = &key_default;
	size_t identity_len = strlen(identity);
	size_t clear_len = strlen(cleartext);
	uint8_t aad[sizeof(aead_aad_signature) + identity_len];
	uint8_t encb[clear_len + key->aead_tag_len + 1];

	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(key->iv_len + 4) + CMSG_SPACE(4)] = {};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivp;
	struct iovec iovecs[3], *iov = iovecs;
	struct msghdr msg = {
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
		.msg_iov = iovecs,
	};
	ssize_t nread;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(uint32_t *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(uint32_t *)CMSG_DATA(cmsg) = sizeof(aead_aad_signature) + strlen(identity);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(key->iv_len + 4);
	ivp = (struct af_alg_iv *)CMSG_DATA(cmsg);
	ivp->ivlen = key->iv_len;
	getrandom(ivp->iv, key->iv_len, 0);

	iov->iov_base = (char *)aead_aad_signature;
	iov->iov_len = sizeof(aead_aad_signature);
	iov++;
	iov->iov_base = (char *)identity;
	iov->iov_len = identity_len;
	iov++;
	iov->iov_base = (char *)cleartext;
	iov->iov_len = clear_len;
	iov++;

	msg.msg_iovlen = iov - iovecs;

	if (sendmsg(key->fd, &msg, 0) <= 0) {
		zlog_err("sendmsg(AF_ALG): %m");
		return false;
	}

	iov = iovecs;
	/* aead_aad_signature and identity are read-only */
	iov->iov_base = aad;
	iov->iov_len = sizeof(aad);
	iov++;

	/* output will be aead_tag_len longer */
	iov->iov_base = encb;
	iov->iov_len = sizeof(encb);
	iov++;

	nread = readv(key->fd, iovecs, iov - iovecs);
	//char *foo = malloc(512);
	//ssize_t rd = read(key->fd, foo, 512);

	if (nread > 0) {
		msg.msg_controllen = 0;
		msgdump(&msg);
	}

	if (nread < 0) {
		zlog_err("encrypt(AF_ALG): %m");
		return false;
	} else if ((size_t)nread != sizeof(aad) + sizeof(encb) - 1) {
		zlog_err("encrypt(AF_ALG): wrong len?");
		return false;
	}

	return kskeyctl_wrap(key, ivp->iv, identity, identity_len,
			     encb, sizeof(encb) - 1, out);
}

/* AF_ALG instantiation */

struct proc_field {
	const char *name;
	long *num;
	char **text;
	bool found;
};

static int proc_alg_details(struct vty *vty, const char *alg, struct proc_field *fields)
{
	FILE *proc_crypto;
	bool this_block = false;
	char line[256];

	proc_crypto = fopen("/proc/crypto", "r");
	if (!proc_crypto) {
		vty_out(vty, "Failed to open /proc/crypto: %m\n");
		return -1;
	}

	while (fgets(line, sizeof(line), proc_crypto)) {
		char *nl, *colon;

		nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';

		colon = strchr(line, ':');
		if (!colon && this_block)
			break;
		if (!colon && !this_block)
			continue;

		for (char *erase = colon; erase > line && erase[-1] == ' '; erase--)
			erase[-1] = '\0';
	
		colon++;
		while (*colon == ' ')
			colon++;

		if (!strcmp(line, "name")) {
			if (!strcmp(colon, alg))
				this_block = true;
			else if (this_block)
				break;
			continue;
		}

		for (struct proc_field *pf = fields; pf->name; pf++) {
			if (strcmp(pf->name, line))
				continue;
			if (pf->num) {
				char *endp = NULL;

				*pf->num = strtol(colon, &endp, 0);
				if (!*colon || *endp)
					continue;
			} else {
				qfree(MTYPE_TMP, *pf->text);
				*pf->text = XSTRDUP(MTYPE_TMP, colon);
			}
			pf->found = true;
		}
	}

	fclose(proc_crypto);

	if (!this_block)
		return -2;

	for (struct proc_field *pf = fields; pf->name; pf++)
		if (!pf->found)
			return 1;

	return 0;
}

static int setup_by_id(struct vty *vty, struct key_cfg *key, const char *alg, uint32_t id)
{
	int alg_fd, run_fd;
	int proc_ok, err;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "aead",
	};
	long ivsize = 0, maxauthsize = 0, blocksize = 0;
	char *type = NULL;
	struct proc_field proc_fields[] = {
		{ .name = "type", .text = &type },
		{ .name = "ivsize", .num = &ivsize },
		{ .name = "maxauthsize", .num = &maxauthsize },
		{ .name = "blocksize", .num = &blocksize },
		{ }
	};

	strlcpy((char *)sa.salg_name, alg, sizeof(sa.salg_name));

	alg_fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (alg_fd == -1) {
		err = errno;
		vty_out(vty, "Error creating AF_ALG socket: %m\n");
		if (err == EAFNOSUPPORT)
			vty_out(vty,
				"is CONFIG_CRYPTO_ALGAPI enabled and loaded in your kernel?\n");
		return CMD_WARNING;
	}

	proc_ok = proc_alg_details(vty, alg, proc_fields);
	if (proc_ok == -1)
		goto out_close;

	/* this is intentionally before the other checks, to be more helpful
	 * when the algorithm isn't an AEAD
	 *
	 * non-AEAD algorithms will fail the bind() call due to .salg_type
	 * with EINVAL, which is really not informative at all
	 *
	 * (they also have different fields in their /proc listing, so don't
	 * check proc_ok == 0 here)
	 */
	if (type && strcmp(type, "aead")) {
		vty_out(vty, "Error: an AEAD algorithm is required, but %pSQq is a %s\n",
			alg, type);
		goto out_close;
	}

	if (bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa))) {
		switch (errno) {
		case ENOENT:
			vty_out(vty,
				"Error: unknown (to kernel) encryption algorithm %pSQq\n"
				"If the name is correct, it may need to be loaded with modprobe\n",
				alg);
			break;

		case EINVAL:
			vty_out(vty,
				"Error: Invalid argument on selecting encryption algorithm %pSQq\n"
				"Please verify that it is an AEAD algorithm.\n",
				alg);
			break;

		default:
			vty_out(vty, "Error binding AF_ALG socket for algorithm %pSQq: %m\n", alg);
		}
		goto out_close;
	}

	/* try again in case a module was autoloaded */
	if (proc_ok != 0) {
		proc_ok = proc_alg_details(vty, alg, proc_fields);
		if (proc_ok == -2)
			vty_out(vty, "Could not find %pSQq in /proc/crypto\n", alg);
		if (proc_ok < 0)
			goto out_close;
	}

	XFREE(MTYPE_TMP, type);

	if (proc_ok != 0) {
		vty_out(vty,
			"Error: kernel info on %pSQq is incomplete - kernel version problem?\n",
			alg);
		goto out_close;
	}
	if (blocksize != 1) {
		vty_out(vty,
			"Error: an algorithm with block size = 1 byte is required.\n"
			"%pSQq reports block size %ld\n",
			alg, blocksize);
		goto out_close;
	}
	if (maxauthsize < (long)aead_tag_len) {
		vty_out(vty,
			"Error: an algorithm with authentication tag size >= %zu is required.\n"
			"%pSQq reports maximum size size %ld\n",
			aead_tag_len, alg, maxauthsize);
		goto out_close;
	}

	if (setsockopt(alg_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, aead_tag_len)) {
		vty_out(vty, "Error setting AEAD tag size to %zu for %pSQq: %m\n",
			aead_tag_len, alg);
		goto out_close;
	}
	if (setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY_BY_KEY_SERIAL, &id, sizeof(id))) {
		vty_out(vty, "Error selecting key %#08x: %m\n", id);
		goto out_close;
	}

	run_fd = accept4(alg_fd, NULL, 0, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (run_fd < 0) {
		vty_out(vty, "Error on AF_ALG accept(): %m\n");
		goto out_close;
	}
	//close(alg_fd);

	if (key->fd != -1)
		close(key->fd);

	key->key_id = id;
	key->fd = run_fd;
	key->iv_len = ivsize;
	key->aead_tag_len = aead_tag_len;

	return CMD_SUCCESS;

out_close:
	XFREE(MTYPE_TMP, type);
	close(alg_fd);
	return CMD_WARNING;
}

DEFPY(kskeyctl_key_name,
      kskeyctl_key_name_cmd,
      "keystore keyctl-enc <default$dflt|name NAME> name KEYCTLNAME <user|encrypted|trusted|logon> [ALG]",
      "Key storage management\n"
      "Linux kernel / keyctl keyring based encryption\n"
      "Configure default key\n"
      "Configure additional named keys\n"
      "Additional key name\n"
      "Reference Linux kernel / keyctl key by name (\"desc\" in keyctl)\n"
      "Linux kernel / keyctl key name (aka \"desc\", text)\n"
      "Kernel key type: user key\n"
      "Kernel key type: encrypted key\n"
      "Kernel key type: trusted (TPM, TEE, etc.) key\n"
      "Kernel key type: logon key\n"
      "Linux kernel encryption algorithm name (default and recommended: \"gcm(aes)\"\n")
{
	vty_out(vty, "TODO\n");
	return CMD_WARNING;
}

DEFPY(kskeyctl_key_id,
      kskeyctl_key_id_cmd,
      "keystore keyctl-enc <default$dflt|name NAME> id (0-4294967295) [ALG]",
      "Key storage management\n"
      "Linux kernel / keyctl keyring based encryption\n"
      "Configure default key\n"
      "Configure additional named keys\n"
      "Additional key name\n"
      "Reference Linux kernel / keyctl key by decimal ID\n"
      "Linux kernel / keyctl key ID (decimal)\n"
      "Linux kernel encryption algorithm name (default and recommended: \"gcm(aes)\"\n")
{
	struct key_cfg *key;

	if (dflt)
		key = &key_default;
	else
		key = keycfg_get(name);

	return setup_by_id(vty, key, alg ?: "gcm(aes)", id);
}

static int kskeyctl_late_init(struct event_loop *tm)
{
	install_element(CONFIG_NODE, &kskeyctl_key_name_cmd);
	install_element(CONFIG_NODE, &kskeyctl_key_id_cmd);
	return 0;
}

const struct pskstore kskeyctl = {
	.name = "linux-keyring",
	.request = kskeyctl_request,
	.cli_input = kskeyctl_cli_input,
};
static struct pskstore_run kskeyctl_run;

static int kskeyctl_init(void)
{
	pskstore_register(&kskeyctl, &kskeyctl_run);
	hook_register(frr_late_init, kskeyctl_late_init);
	//hook_register(frr_early_fini, kskeyctl_early_fini);
	return 0;
}

/* clang-format off */
FRR_MODULE_SETUP(
	.name = "keystore_linux_keyring",
	.version = FRR_VERSION,
	.description = "Key encryption using Linux Keyrings",
	.init = kskeyctl_init,
);
