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
	YK_TEMPLATE,

	YK_NOOP,
	YK_NODEVAL,
	YK_LVAL,
	YK_CREATE,
	YK_MODIFY,
	YK_DESTROY,

	YK_TYPE,
	YK_CTYPE,
	YK_DEFAULT,
	YK_KIND,
	YK_LYD_VALUE,

	YK_KEY_INPUT,
	YK_JSON_INPUT,
	YK_JSON_OUTPUT,

	YKCC_OPEN,
	YKCC_CLOSE,
	YKCC_WSP,
	YKCC_ID,
	YKCC_AT,
};

struct yangkheg_file {
	FILE *fd;
	char *filename;
};

PREDECL_DLIST(yk_ctokens);

struct yangkheg_token {
	struct yk_ctokens_item itm;
	size_t refcount;

	int token;

	const char *text;
	char *raw, *cooked;

	struct yangkheg_file *file;

	size_t byte_s;
	unsigned int line_s, line_e, col_s, col_e;
};

DECLARE_DLIST(yk_ctokens, struct yangkheg_token, itm);

struct yangkheg_lexer;

extern struct yangkheg_token *yk_token_create(void);
extern struct yangkheg_token *yk_token_get(const struct yangkheg_token *tkn);
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

PREDECL_HASH(yk_cargs);

struct yk_carg {
	struct yk_cargs_item item;

	const char *name;
	char value[0];
};

PREDECL_DLIST(yk_condstack);

struct yk_cond {
	struct yk_condstack_item item;
	struct yangkheg_token *open_at;

	bool value;
	bool any_arc_taken;
};

DECLARE_DLIST(yk_condstack, struct yk_cond, item);

PREDECL_DLIST(yk_citems);

enum yk_citem_type {
	YK_CIT_TEXT,
	YK_CIT_AT,
};

struct yk_citem {
	struct yk_citems_item itm;
	enum yk_citem_type type;

	int lineno, column;

	char *text;
	struct yk_ctokens_head tokens[1];
};

DECLARE_DLIST(yk_citems, struct yk_citem, itm);

struct yk_cblock {
	struct yk_citems_head items[1];
	struct yangkheg_token *close_token;
};

struct yk_crender_ctx {
	FILE *out;

	struct yangkheg_state *state;
	struct yangkheg_stack *stk;

	struct yk_cargs_head cargs[1];
	struct yk_condstack_head condstack[1];
	bool suppress;
};

struct ykat_ctx {
	struct yk_citem *item;
	struct yk_crender_ctx *ctx;

	bool started;
	bool line_at_token;
	struct yangkheg_token *pos;
};

struct ykat_loc {
	struct yangkheg_token *first, *last;
};

extern struct yk_cblock *yk_parse_cblock(struct yangkheg_lexer *lex);
extern void yk_cblock_render(struct yk_crender_ctx *ctx,
			     struct yk_cblock *cblock);
extern char *yk_cblock_typename(struct yk_cblock *cblock);
extern void yk_crender_init(struct yk_crender_ctx *ctx, FILE *out);
extern void yk_crender_arg_set(struct yk_crender_ctx *ctx, const char *name,
			       const char *value);
extern const struct yk_carg *yk_crender_arg_gettkn(struct yk_crender_ctx *ctx,
						   const struct yangkheg_token *tkn);
extern void yk_crender_fini(struct yk_crender_ctx *ctx);

extern void yk_crender_cond_push(struct yk_crender_ctx *ctx,
			  const struct yangkheg_token *tkn,
			  bool value);
extern void yk_crender_cond_else(struct yk_crender_ctx *ctx,
			  const struct yangkheg_token *tkn,
			  bool value);
extern void yk_crender_cond_pop(struct yk_crender_ctx *ctx,
			  const struct yangkheg_token *tkn);

extern void ykat_debug_show_type(struct yk_crender_ctx *ctx,
				 struct yk_citem *item, const char *xpath);
extern void ykat_implement(struct ykat_ctx *at_ctx, const char *xpath);

extern int ykat_parse(struct ykat_ctx *ctx);
extern void ykat_mktab(void);
extern int ykat_find_id_token(const char *text);

struct lysc_type;
struct yk_yangtype;

PREDECL_DLIST(yk_cmaps);
PREDECL_HASH(yk_yangtypes);

enum cmap_kind {
	CMAP_SIMPLE_VALUE = 1,
	CMAP_ALLOC_POINTER,
};

struct yk_cmap {
	struct yk_cmaps_item itm;
	struct yk_yangtype *yangtype;
	struct yangkheg_token *origin_loc;

	char *name;
	bool dflt;

	enum cmap_kind kind;
	struct yk_cblock *lyd_value;

	struct yk_cblock *key_input;
	struct yk_cblock *json_input;
	struct yk_cblock *json_output;
};

struct yk_yangtype {
	struct yk_yangtypes_item itm;

	struct lysc_type *lysc_type;
	const struct lys_module *mod;
	const char *name;
	int basetype;

	struct yk_cmap *dflt;
	struct yk_cmaps_head cmaps[1];
};

DECLARE_DLIST(yk_cmaps, struct yk_cmap, itm);

struct yk_nodeinfo {
	const struct lysc_node *node;
	struct yk_cblock *nodeval;
	struct yk_cblock *lval;
};

extern bool f_no_line_numbers;

#endif /* _YANGKHEG_H */
