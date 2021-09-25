#include "config.h"

#include "memory.h"
#include "log.h"
#include "jhash.h"
#include "printfrr.h"

#include "yangkheg.h"

DEFINE_MTYPE_STATIC(LIB, YK_CBLOCK, "C code block");
DEFINE_MTYPE_STATIC(LIB, YK_CITEM,  "C code block item");
DEFINE_MTYPE_STATIC(LIB, YK_CTEXT,  "C code block text");
DEFINE_MTYPE_STATIC(LIB, YK_CARG,   "C code block template argument");

static void parse_cat(struct yangkheg_lexer *lex, struct yk_citem *atitem)
{
	const struct yangkheg_token *ntoken;
	int brace_level = 1;
	struct yk_carg *arg = NULL;

	ntoken = yangkheg_next(lex);

	if (ntoken->token == YKCC_AT) {
		atitem->type = YK_CIT_AT_VAR;
		return;
	}
	if (ntoken->token == YKCC_ID) {
		atitem->atname = strdup(ntoken->text);
		ntoken = yangkheg_next(lex);

		if (ntoken->token == YKCC_AT) {
			atitem->type = YK_CIT_AT_VAR;
			return;
		}
	}

	if (ntoken->token != '(') {
		fprintf(stderr, "@ parse error #1\n");
		exit(1);
	}

	atitem->type = YK_CIT_AT_FUNC;

	while ((ntoken = yangkheg_next(lex))
	       && (ntoken->token != YKCC_CLOSE) && brace_level) {
		switch (ntoken->token) {
		case YKCC_WSP:
			continue;

		case STRING:
			if (!arg) {
				arg = XCALLOC(MTYPE_YK_CARG, sizeof(*arg));
				arg->type = YK_CARG_STRING;
				arg->strval = strdup(ntoken->cooked);
				continue;
			}
			if (arg->type != YK_CARG_STRING) {
				fprintf(stderr, "@ parse error #2\n");
				exit(1);
			}
			break;

		case '(':
			brace_level++;
			break;
		case ')':
			brace_level--;
			/* fallthru */
		case ',':
			if (!arg) {
				arg = XCALLOC(MTYPE_YK_CARG, sizeof(*arg));
				arg->type = YK_CARG_EMPTY;
			}
			yk_cargs_add_tail(atitem->args, arg);
			arg = NULL;
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
			yk_cargs_init(atitem->args);
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
		case YKCC_OPERATOR:
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
				break;
			}

			textitem = XCALLOC(MTYPE_YK_CITEM, sizeof(*textitem));
			textitem->type = YK_CIT_TEXT;
			textitem->text = XSTRDUP(MTYPE_YK_CTEXT, text);
			textitem->lineno = ntoken->line_s;
			textitem->column = ntoken->col_s;
			yk_citems_add_tail(cblock->items, textitem);
			break;
		}
	}

	return cblock;
}
