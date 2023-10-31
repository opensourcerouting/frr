#include "config.h"

#include "memory.h"
#include "log.h"
#include "jhash.h"
#include "printfrr.h"

#include "yangkheg.h"

DEFINE_MTYPE_STATIC(LIB, YK_CBLOCK, "C code block");
DEFINE_MTYPE_STATIC(LIB, YK_CITEM,  "C code block item");
DEFINE_MTYPE_STATIC(LIB, YK_CITTKN, "C code block item token");
DEFINE_MTYPE_STATIC(LIB, YK_CTEXT,  "C code block text");
DEFINE_MTYPE_STATIC(LIB, YK_CARG,   "C render argument");
DEFINE_MTYPE_STATIC(LIB, YK_CCOND,  "C render condition");

static void parse_cat(struct yangkheg_lexer *lex, struct yk_citem *atitem)
{
	const struct yangkheg_token *ntoken;
	int brace_level = 1;

	atitem->type = YK_CIT_AT;

	ntoken = yangkheg_next(lex);

	if (ntoken->token == YKCC_AT) {
		yk_ctokens_add_tail(atitem->tokens, yk_token_get(ntoken));
		return;
	}

	if (ntoken->token == YKCC_ID) {
		yk_ctokens_add_tail(atitem->tokens, yk_token_get(ntoken));

		ntoken = yangkheg_next(lex);
		if (ntoken->token == YKCC_AT) {
			yk_ctokens_add_tail(atitem->tokens,
					    yk_token_get(ntoken));
			return;
		}
	}

	if (ntoken->token != '(') {
		fprintf(stderr, "@ parse error #1\n");
		exit(1);
	}
	yk_ctokens_add_tail(atitem->tokens, yk_token_get(ntoken));

	while (brace_level && (ntoken = yangkheg_next(lex))
	       && (ntoken->token != YKCC_CLOSE)) {
		if (ntoken->token == COMMENT)
			continue;

		yk_ctokens_add_tail(atitem->tokens, yk_token_get(ntoken));

		switch (ntoken->token) {
		case '(':
			brace_level++;
			break;
		case ')':
			brace_level--;
			break;
		}
	}
}

struct yk_cblock *yk_parse_cblock(struct yangkheg_lexer *lex)
{
	const struct yangkheg_token *ntoken;
	struct yk_cblock *cblock;
	struct yk_citem *textitem = NULL, *atitem;
	const char *text;
	char chbuf[2];
	bool after_at = false;

	cblock = XCALLOC(MTYPE_YK_CBLOCK, sizeof(*cblock));
	yk_citems_init(cblock->items);

	while ((ntoken = yangkheg_next(lex))
	       && (ntoken->token != YKCC_CLOSE)) {
		switch (ntoken->token) {
		case YKCC_AT:
			textitem = NULL;
			atitem = XCALLOC(MTYPE_YK_CITEM, sizeof(*atitem));
			atitem->lineno = ntoken->line_s;
			atitem->column = ntoken->col_s;
			yk_ctokens_init(atitem->tokens);
			parse_cat(lex, atitem);
			yk_citems_add_tail(cblock->items, atitem);
			after_at = true;
			break;

		case STRING:
		case PREPROC:
		case COMMENT:
		case YKCC_OPEN:
		case YKCC_CLOSE:
		case YKCC_WSP:
		case YKCC_ID:
			assert(ntoken->text);
			text = ntoken->text;

			if (0) {
		default:
				chbuf[0] = ntoken->token;
				chbuf[1] = '\0';
				text = chbuf;
			}
			if (after_at && ntoken->token != YKCC_ID) {
				textitem = NULL;
				after_at = false;
			}
			if (textitem) {
				size_t len1 = strlen(textitem->text);
				size_t len2 = strlen(text);

				textitem->text = XREALLOC(MTYPE_YK_CTEXT,
							  textitem->text,
							  len1 + len2 + 1);
				memcpy(textitem->text + len1, text, len2);
				textitem->text[len1 + len2] = '\0';

				yk_ctokens_add_tail(textitem->tokens,
						    yk_token_get(ntoken));
				break;
			}

			textitem = XCALLOC(MTYPE_YK_CITEM, sizeof(*textitem));
			textitem->type = YK_CIT_TEXT;
			textitem->text = XSTRDUP(MTYPE_YK_CTEXT, text);
			textitem->lineno = ntoken->line_s;
			textitem->column = ntoken->col_s;
			yk_citems_add_tail(cblock->items, textitem);
			yk_ctokens_init(textitem->tokens);
			yk_ctokens_add_tail(textitem->tokens,
					    yk_token_get(ntoken));
			break;
		}
	}

	cblock->close_token = yk_token_get(ntoken);
	return cblock;
}

static int yk_carg_cmp(const struct yk_carg *a, const struct yk_carg *b)
{
	return strcmp(a->name, b->name);
}

static uint32_t yk_carg_hash(const struct yk_carg *a)
{
	return jhash(a->name, strlen(a->name), 0xd1044749);
}

DECLARE_HASH(yk_cargs, struct yk_carg, item, yk_carg_cmp, yk_carg_hash);

void yk_crender_init(struct yk_crender_ctx *ctx, FILE *out)
{
	ctx->out = out;
	yk_cargs_init(ctx->cargs);
	yk_condstack_init(ctx->condstack);
}

void yk_crender_arg_set(struct yk_crender_ctx *ctx, const char *name,
			const char *value)
{
	struct yk_carg *carg, *prev;
	size_t vallen = strlen(value) + 1;

	carg = XCALLOC(MTYPE_YK_CARG, sizeof(*carg) + vallen);
	carg->name = name;
	memcpy(carg->value, value, vallen);

	prev = yk_cargs_add(ctx->cargs, carg);
	if (prev) {
		yk_cargs_del(ctx->cargs, prev);
		XFREE(MTYPE_YK_CARG, prev);
		yk_cargs_add(ctx->cargs, carg);
	}
}

const struct yk_carg *yk_crender_arg_gettkn(struct yk_crender_ctx *ctx,
					    const struct yangkheg_token *tkn)
{
	struct yk_carg ref, *res;

	if (!tkn)
		ref.name = "";
	else
		ref.name = tkn->text;

	res = yk_cargs_find(ctx->cargs, &ref);
	if (!res && !ctx->suppress)
		yk_token_diag(DIAG_ERR, tkn,
			      "undefined template argument %pSQq", ref.name);
	return res;
}

void yk_crender_cond_push(struct yk_crender_ctx *ctx,
			  const struct yangkheg_token *tkn,
			  bool value)
{
	struct yk_cond *cond;

	cond = XCALLOC(MTYPE_YK_CCOND, sizeof(*cond));
	cond->open_at = yk_token_get(tkn);
	cond->value = value;
	cond->any_arc_taken = value;

	yk_condstack_add_head(ctx->condstack, cond);
	ctx->suppress = !cond->value;
}

void yk_crender_cond_else(struct yk_crender_ctx *ctx,
			  const struct yangkheg_token *tkn,
			  bool value)
{
	struct yk_cond *cond = yk_condstack_first(ctx->condstack);

	if (!cond) {
		yk_token_diag(DIAG_ERR, tkn,
			      "else() without if()");
		return;
	}
	cond->value = !cond->any_arc_taken && value;
	cond->any_arc_taken |= value;

	ctx->suppress = !cond->value;
}

void yk_crender_cond_pop(struct yk_crender_ctx *ctx,
			  const struct yangkheg_token *tkn)
{
	struct yk_cond *cond;

	cond = yk_condstack_pop(ctx->condstack);
	if (!cond) {
		yk_token_diag(DIAG_ERR, tkn,
			      "endif() without if()");
		return;
	}
	yk_token_put(&cond->open_at);
	XFREE(MTYPE_YK_CCOND, cond);

	cond = yk_condstack_first(ctx->condstack);
	if (cond && !cond->value)
		ctx->suppress = true;
	else
		ctx->suppress = false;
}

void yk_crender_fini(struct yk_crender_ctx *ctx)
{
	struct yk_carg *carg;
	struct yk_cond *cond;

	while ((cond = yk_condstack_pop(ctx->condstack))) {
		yk_token_put(&cond->open_at);
		XFREE(MTYPE_YK_CCOND, cond);
	}

	yk_condstack_fini(ctx->condstack);

	while ((carg = yk_cargs_pop(ctx->cargs)))
		XFREE(MTYPE_YK_CARG, carg);

	yk_cargs_fini(ctx->cargs);
}


static void emit_line(FILE *out, struct yangkheg_token *tkn)
{
	long startpos = tkn->byte_s - tkn->col_s;
	fpos_t savepos;
	char rbuf[256];
	ssize_t nread;

	if (f_no_line_numbers)
		return;

	fprintf(out, "#line %d \"%s\"\n", tkn->line_s, tkn->file->filename);

	fgetpos(tkn->file->fd, &savepos);
	fseek(tkn->file->fd, startpos, SEEK_SET);
	nread = fread(rbuf, 1, sizeof(rbuf), tkn->file->fd);
	fsetpos(tkn->file->fd, &savepos);

	for (size_t i = 0; (ssize_t)i < nread && i < tkn->col_s; i++) {
		if (rbuf[i] == '\t')
			putc('\t', out);
		else
			putc(' ', out);
	}
}

static void yk_cblock_render_common(struct yk_crender_ctx *ctx,
				    struct yk_cblock *cblock)
{
	bool needline = true;
	bool line_at_token = false;
	struct yk_citem *it;

	frr_each (yk_citems, cblock->items, it) {
		if (it->type == YK_CIT_TEXT) {
			struct yangkheg_token *first;

			if (ctx->suppress)
				continue;

			first = yk_ctokens_first(it->tokens);
			if (line_at_token && first->token != YKCC_ID) {
				line_at_token = false;
				needline = true;
				if (!f_no_line_numbers)
					fputs("\n", ctx->out);
			}
			if (needline) {
				emit_line(ctx->out, first);
				needline = false;
			}
			fputs(it->text ?: "(NULL?!?)", ctx->out);
			continue;
		}

		struct ykat_ctx at_ctx = {
			.item = it,
			.ctx = ctx,
			.line_at_token = false,
		};

		int ret = ykat_parse(&at_ctx);

		(void)ret;
		//yk_token_diag(DIAG_TRACE, yk_ctokens_first(it->tokens),
		//	      "atexpr returned %d", ret);

		if (at_ctx.line_at_token)
			line_at_token = true;
		else
			needline = true;
	}

	if (yk_condstack_count(ctx->condstack)) {
		fprintf(stderr, "conditional unterminated\n");
	}
}

void yk_cblock_render(struct yk_crender_ctx *ctx, struct yk_cblock *cblock)
{
	fprintf(ctx->out, "\n/* begin inline cblock { */\n");
	yk_cblock_render_common(ctx, cblock);
	fprintf(ctx->out, "\n/* } end cblock */\n");
}

void yk_cblock_render_template(struct yk_crender_ctx *ctx,
			       struct yk_template *tpl)
{
	struct yk_carg *carg;

	fprintfrr(ctx->out, "\n/* begin template %pSQq\n", tpl->name);
	frr_each (yk_cargs, ctx->cargs, carg) {
		fprintfrr(ctx->out, " * @%-20pSE = %pSQq\n", carg->name,
			  carg->value);
	}
	fprintfrr(ctx->out, " */\n");

	yk_cblock_render_common(ctx, tpl->cblock);
	fprintfrr(ctx->out, "\n/* } end template %pSQq */\n", tpl->name);
}

char *yk_cblock_typename(struct yk_cblock *cblock)
{
	struct yangkheg_token *token;
	struct yk_citem *item;

	if (!yk_citems_count(cblock->items)) {
		yk_token_diag(DIAG_ERR, cblock->close_token,
			      "empty typename");
		return NULL;
	}

	if (yk_citems_count(cblock->items) > 1) {
		yk_token_diag(DIAG_ERR, cblock->close_token,
			      "typename must be simple C token without @...");
		return NULL;
	}

	item = yk_citems_first(cblock->items);

	char buf[256];
	size_t len = 0;
	struct fbuf fb[1] = { { .buf = buf, .pos = buf, .len = sizeof(buf), } };
	bool need_space = false;

	frr_each (yk_ctokens, item->tokens, token) {
		switch (token->token) {
		case COMMENT:
		case YKCC_WSP:
			continue;

		case YKCC_ID:
			if (need_space)
				len += bputch(fb, ' ');
			len += bputs(fb, token->text);
			need_space = true;
			continue;

		case '*':
			if (need_space)
				len += bputch(fb, ' ');
			len += bputch(fb, '*');
			need_space = false;
			continue;

		default:
			yk_token_diag(DIAG_ERR, token,
				      "invalid input for typename");
			return NULL;
		}
	}

	if (len > sizeof(buf)) {
		yk_token_diag(DIAG_ERR, cblock->close_token,
			      "typename exceeds maximum length (%zu)",
			      sizeof(buf));
		return NULL;
	}
	return strndup(buf, len);
}

#include "yangkheg-yk_atexpr_eval.h"

int ykat_lex(YKAT_STYPE *val, YKAT_LTYPE *loc, struct ykat_ctx *ctx)
{
	int tokenval = 0;

	if (!ctx->started) {
		ctx->pos = yk_ctokens_first(ctx->item->tokens);
		ctx->started = true;
	}

	if (!ctx->pos)
		return YKAT_EOF;

	if (ctx->pos->token < 256)
		tokenval = ctx->pos->token;
	else switch (ctx->pos->token) {
		case YKCC_AT:
			tokenval = '@';
			break;
		case YKCC_ID:
			{
				char quoted[strlen(ctx->pos->text) + 3];

				snprintf(quoted, sizeof(quoted), "\"%s\"",
					 ctx->pos->text);
				tokenval = ykat_find_id_token(quoted);
			}
			if (tokenval < 0)
				tokenval = YKAT_ID;
			break;
		case STRING:
			tokenval = YKAT_STRING;
			break;
		default:
			yk_token_diag(DIAG_ERR, ctx->pos,
				      "cannot translate token to bison");
	}

	val->token = ctx->pos;
	loc->first = ctx->pos;
	loc->last = ctx->pos;

	ctx->pos = yk_ctokens_next(ctx->item->tokens, ctx->pos);
	return tokenval;
}

int ykat_error(YKAT_LTYPE *loc, struct ykat_ctx *ctx, const char *msg)
{
	fprintfrr(stderr, "%pYKTp...%pYKTp: bison error: %s\n",
		  loc->first, loc->last, msg);
	return 0;
}

int ykat_locprint(FILE *fd, const YKAT_LTYPE *loc)
{
	yk_token_diag(DIAG_TRACE, loc->first, "bison locprint (end: %pYKTp)", loc->last);
	return 0;
}
