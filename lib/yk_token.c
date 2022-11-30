#include "config.h"

#include "memory.h"
#include "log.h"
#include "printfrr.h"

#include "yangkheg.h"

DEFINE_MTYPE_STATIC(YANGKHEG, YK_TOKEN, "YANGkheg token");

struct yangkheg_token *yk_token_create(void)
{
	struct yangkheg_token *tkn;

	tkn = XCALLOC(MTYPE_YK_TOKEN, sizeof(*tkn));
	tkn->refcount = 1;
	return tkn;
}

struct yangkheg_token *yk_token_get(const struct yangkheg_token *csttkn)
{
	struct yangkheg_token *tkn = (struct yangkheg_token *)csttkn;

	tkn->refcount++;
	return tkn;
}

void yk_token_put(struct yangkheg_token **tknp)
{
	struct yangkheg_token *tkn = *tknp;

	if (!tkn)
		return;
	*tknp = NULL;

	if (!--tkn->refcount) {
		free(tkn->raw);
		free(tkn->cooked);

		XFREE(MTYPE_YK_TOKEN, tkn);
	}
}

static const char * const tkn_names[] = {
#define item(n)  [n - 256] = #n
	item(ID),
	item(PREPROC),
	item(STRING),
	item(COMMENT),

	item(YK_TRACE),
	item(YK_PATH),
	item(YK_IMPLEMENTS),
	item(YK_EMIT),

	item(YK_NOOP),
	item(YK_NODEVAL),
	item(YK_LVAL),

	item(YK_CREATE),
	item(YK_MODIFY),
	item(YK_DESTROY),

	item(YK_TYPE),
	item(YK_CTYPE),
	item(YK_DEFAULT),
	item(YK_KIND),
	item(YK_LYD_VALUE),

	item(YKCC_OPEN),
	item(YKCC_CLOSE),
	item(YKCC_WSP),
	item(YKCC_ID),
	item(YKCC_AT),
};

printfrr_ext_autoreg_i("YKN", printfrr_ykn)
static ssize_t printfrr_ykn(struct fbuf *buf, struct printfrr_eargs *ea,
			    uintmax_t uival)
{
	ssize_t rv = 0;
	unsigned int val = uival;

	if (val < 32 || (val >= 127 && val < 256) || val == '\'')
		rv += bprintfrr(buf, "%#02x", val);
	else if (val < 127)
		rv += bprintfrr(buf, "'%c'", val);
	else {
		unsigned int idx = val - 256;

		if (idx >= array_size(tkn_names) || !tkn_names[idx])
			rv += bprintfrr(buf, "%u?", val);
		else
			rv += bputs(buf, tkn_names[idx]);
	}

	return rv;
}

printfrr_ext_autoreg_p("YKT", printfrr_ykt)
static ssize_t printfrr_ykt(struct fbuf *buf, struct printfrr_eargs *ea,
			    const void *ptr)
{
	const struct yangkheg_token *tkn = ptr;
	ssize_t rv = 0;
	bool pos = false, debug = false;

	switch (*ea->fmt) {
	case 'p':
		ea->fmt++;
		pos = true;
		break;
	case 'd':
		ea->fmt++;
		debug = true;
		break;
	}

	if (!tkn)
		return bputs(buf, "(null token)");

	if (pos) {
		return bprintfrr(buf, "%s:%u:%u:", tkn->file->filename,
				 tkn->line_s, tkn->col_s + 1);
	}

	if (debug) {
		long startpos = tkn->byte_s - tkn->col_s;
		fpos_t savepos;
		char rbuf[256], *nl;
		ssize_t nread;
		size_t nprint;

		fgetpos(tkn->file->fd, &savepos);
		fseek(tkn->file->fd, startpos, SEEK_SET);
		nread = fread(rbuf, 1, sizeof(rbuf), tkn->file->fd);
		fsetpos(tkn->file->fd, &savepos);

		if (nread < 0)
			return 0;

		nl = memchr(rbuf, '\n', nread);
		nprint = nl ? nl - rbuf : nread;

		rv += bprintfrr(buf, "%5u | %.*s\n      | ", tkn->line_s,
				(int)nprint, rbuf);
		for (size_t i = 0; i < nprint && i < tkn->col_s; i++) {
			if (rbuf[i] == '\t')
				rv += bputch(buf, '\t');
			else
				rv += bputch(buf, ' ');
		}

		memset(rbuf, '~', sizeof(rbuf));
		rv += bprintfrr(buf, "\033[31;1m^%.*s\033[m",
				(int)MIN(tkn->col_e - tkn->col_s - 1, sizeof(rbuf)),
				rbuf);
		return rv;
	}

	rv += bputch(buf, '<');
	if (tkn->token < 32 || (tkn->token >= 127 && tkn->token < 256)
	    || tkn->token == '\'')
		rv += bprintfrr(buf, "%#02x", tkn->token);
	else if (tkn->token < 127)
		rv += bprintfrr(buf, "'%c'", tkn->token);
	else {
		unsigned int idx = tkn->token - 256;

		if (idx >= array_size(tkn_names) || !tkn_names[idx])
			rv += bprintfrr(buf, "%u?", tkn->token);
		else
			rv += bputs(buf, tkn_names[idx]);

		if (tkn->text)
			rv += bprintfrr(buf, " %pSQq", tkn->text);
	}
	rv += bputch(buf, '>');
	return rv;
}

