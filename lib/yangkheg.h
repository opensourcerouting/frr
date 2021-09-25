#ifndef _YANGKHEG_H
#define _YANGKHEG_H

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "typesafe.h"
#include "memory.h"

DECLARE_MGROUP(YANGKHEG);

enum yangkheg_tokens {
	ID = 258,
	PREPROC,
	STRING,
	COMMENT,

	YK_PATH,

	YK_IMPLEMENTS,
	YK_EMIT,
	YK_TRACE,

	YK_NOOP,
	YK_NODEVAL,
	YK_LVAL,
	YK_CREATE,
	YK_MODIFY,
	YK_DESTROY,

	YKCC_OPEN,
	YKCC_CLOSE,
	YKCC_WSP,
	YKCC_ID,
	YKCC_AT,
	YKCC_OPERATOR,
};

struct yangkheg_file {
	FILE *fd;
	char *filename;
};

struct yangkheg_token {
	size_t refcount;

	int token;

	const char *text;
	char *raw, *cooked;

	struct yangkheg_file *file;

	size_t byte_s;
	unsigned int line_s, line_e, col_s, col_e;
};

struct yangkheg_lexer;

extern struct yangkheg_token *yk_token_create(void);
extern struct yangkheg_token *yk_token_get(struct yangkheg_token *tkn);
extern void yk_token_put(struct yangkheg_token **tkn);

extern struct yangkheg_lexer *yangkheg_begin(struct yangkheg_file *file);
extern struct yangkheg_token *yangkheg_next(struct yangkheg_lexer *lex);
extern void yangkheg_end(struct yangkheg_lexer *lex);

enum diag_level {
	DIAG_TRACE = 1,
	DIAG_WARN,
	DIAG_ERR,
};

extern void yk_token_diagv(enum diag_level lvl,
			   const struct yangkheg_token *tkn, const char *fmt,
			   va_list *ap) PRINTFRR(3, 0);
static inline void yk_token_diag(enum diag_level lvl,
				 const struct yangkheg_token *tkn,
				 const char *fmt, ...) PRINTFRR(3, 4);

static inline void yk_token_diag(enum diag_level lvl,
				 const struct yangkheg_token *tkn,
				 const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	yk_token_diagv(lvl, tkn, fmt, &ap);
	va_end(ap);
}

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%dYKN" (int)
#pragma FRR printfrr_ext "%pYKT" (struct yangkheg_token *)
#endif

/* cblock */

PREDECL_DLIST(yk_cargs);

enum yk_carg_type {
	YK_CARG_EMPTY,
	YK_CARG_STRING,
};

struct yk_carg {
	struct yk_cargs_item itm;
	enum yk_carg_type type;

	char *strval;
};

PREDECL_DLIST(yk_citems);

enum yk_citem_type {
	YK_CIT_TEXT,
	YK_CIT_AT_VAR,
	YK_CIT_AT_FUNC,
};

struct yk_citem {
	struct yk_citems_item itm;
	enum yk_citem_type type;
	int lineno, column;

	char *text;
	char *atname;
	struct yk_cargs_head args[1];
};

DECLARE_DLIST(yk_citems, struct yk_citem, itm);
DECLARE_DLIST(yk_cargs, struct yk_carg, itm);

struct yk_cblock {
	struct yk_citems_head items[1];
};

struct ykat_ctx {
	int dummy;
};

extern struct yk_cblock *yk_parse_cblock(struct yangkheg_lexer *lex);

#endif /* _YANGKHEG_H */
