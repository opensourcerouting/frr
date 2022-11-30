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

	while ((ntoken = yangkheg_next(lex))
	       && (ntoken->token != YKCC_CLOSE) && brace_level) {
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

void yk_cblock_render(struct yk_crender_ctx *ctx, struct yk_cblock *cblock)
{
	bool needline = true;
	struct yk_citem *it;

	fprintf(ctx->out, "\n/* begin cblock { */\n");
	frr_each (yk_citems, cblock->items, it) {
		if (it->type == YK_CIT_TEXT) {
			if (needline) {
				fprintf(ctx->out, "#line %d \"test.yk\"\n",
					it->lineno - 1);
				needline = false;
			}
			fputs(it->text ?: "(NULL?!?)", ctx->out);
			continue;
		}

		struct ykat_ctx ctx = {
			.item = it,
		};

		int ret = ykat_parse(&ctx);

		yk_token_diag(DIAG_TRACE, yk_ctokens_first(it->tokens),
			      "atexpr returned %d", ret);

		needline = true;
	}
	fprintf(ctx->out, "\n/* } end cblock */\n");
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
