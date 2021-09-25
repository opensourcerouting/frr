#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "memory.h"
#include "log.h"
#include "jhash.h"
#include "printfrr.h"

#include "yangkheg.h"

#include <libyang/libyang.h>

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pLYCN" (struct lysc_node *)
#endif

DEFINE_MGROUP(YANGKHEG, "YANGkheg");

PREDECL_HASH(yang_prefix);

struct yang_prefix {
	struct yang_prefix_item itm;

	const char *prefix;
	const char *name;
	const struct lys_module *module;
};

static int yang_prefix_cmp(const struct yang_prefix *a,
			   const struct yang_prefix *b)
{
	return strcmp(a->prefix, b->prefix);
}

static uint32_t yang_prefix_hash(const struct yang_prefix *i)
{
	return jhash(i->prefix, strlen(i->prefix), 0x12b740ae);
}

DECLARE_HASH(yang_prefix, struct yang_prefix, itm, yang_prefix_cmp,
	     yang_prefix_hash);

void vzlogx(const struct xref_logmsg *xref, int prio,
	    const char *format, va_list args)
{
	vfprintf(stderr, format, args);
	fputs("\n", stderr);
}

void memory_oom(size_t size, const char *name)
{
	abort();
}

bool use_color = true;
#define CC(seq) (use_color ? seq : "")

static const char * const levels_plain[] = {
	NULL, "trace:", "warning:", "error:",
};
static const char * const levels_color[] = {
	NULL,
	"\033[97mtrace:\033[m",
	"\033[33;1mwarning:\033[m",
	"\033[31;1merror:\033[m",
};

void yk_token_diagv(enum diag_level lvl, const struct yangkheg_token *tkn,
		    const char *fmt, va_list *ap)
{
	const char *lstr = use_color ? levels_color[lvl] : levels_plain[lvl];
	struct va_format vaf = {
		.fmt = fmt,
		.va = ap,
	};

	if (lvl >= DIAG_WARN)
		fprintfrr(stderr, "%s%pYKTp%s %s %pVA\n%pYKTd\n",
			  CC("\033[1m"), tkn, CC("\033[m"), lstr, &vaf, tkn);
	else
		fprintfrr(stderr, "%s%pYKTp%s %s %pVA\n",
			  CC("\033[1m"), tkn, CC("\033[m"), lstr, &vaf);
}

printfrr_ext_autoreg_p("LYCN", printfrr_lycn)
static ssize_t printfrr_lycn(struct fbuf *buf, struct printfrr_eargs *ea,
			     const void *ptr)
{
	const struct lysc_node *node = ptr;

	if (!node)
		return bputs(buf, "(null lysc_node)");

	return bprintfrr(buf, "{%s %s:%s}", lys_nodetype2str(node->nodetype),
			 node->module->name, node->name);
}

static const struct yangkheg_token *
yangkheg_pull(struct yangkheg_lexer *lex, int expect)
{
	const struct yangkheg_token *token;

	token = yangkheg_next(lex);
	if (token->token != expect) {
		yk_token_diag(DIAG_ERR, token, "unexpected token %pYKT", token);
		exit(1);
	}
	return token;
}

static char *yangkheg_pull_str(struct yangkheg_lexer *lex, int expect)
{
	const struct yangkheg_token *token;

	token = yangkheg_pull(lex, expect);
	if (!token)
		return NULL;
	if (token->cooked)
		return strdup(token->cooked);
	if (token->text)
		return strdup(token->text);
	return NULL;
}

enum handler_res {
	H_OK = 0,
	H_ERROR,
};

struct yangkheg_state;

#define MAXARGS 8

struct yangkheg_handler {
	int tokens[MAXARGS];
	uint32_t flags;
	enum handler_res (*fn)(struct yangkheg_state *st,
			       struct yangkheg_lexer *lex,
			       const struct yangkheg_token *tokens[],
			       struct yk_cblock *cblocks[],
			       size_t tokenc);
};

enum {
	H_STANDALONE = (1 << 0),
};

struct yangkheg_stack {
	struct yangkheg_stack *parent;

	struct lys_module *lys_module;
	const struct lysc_node *lysc_node;
};

struct yangkheg_state {
	struct yangkheg_state *parent;

	struct ly_ctx *ly_ctx;
	struct lys_module *lys_module;
	struct yang_prefix_head pfxs[1];

	struct yangkheg_token *open_at;
	struct yangkheg_stack *stack, *stacktop;
	bool in_statement;
};

static void error_skip(struct yangkheg_lexer *lex)
{
	const struct yangkheg_token *token;
	int depth = 0;

	do {
		token = yangkheg_next(lex);
		if (!token) 
			exit(1);

		switch (token->token) {
		case '{':
			depth++;
			break;
		case '}':
			if (!depth)
				yk_token_diag(DIAG_ERR, token,
					      "no block to close here");
			else
				depth--;
			break;
		case YKCC_OPEN:
			while ((token = yangkheg_next(lex)))
				if (token->token == YKCC_CLOSE)
					break;
		}
	} while (depth || token->token != ';');
}

DEFINE_MTYPE_STATIC(YANGKHEG, YK_STACK, "stack");
DEFINE_MTYPE_STATIC(YANGKHEG, YK_STATE, "state");

static void yangkheg_process(struct yangkheg_state *state,
			     struct yangkheg_lexer *lex,
			     const struct yangkheg_handler *htab)
{
	struct yangkheg_state *oldstate;
	struct yangkheg_stack *stack, *stacknext;
	struct yangkheg_token *token = NULL;
	const struct yangkheg_handler *h;
	const struct yangkheg_token *args[MAXARGS];
	struct yk_cblock *cblocks[MAXARGS];
	size_t i;

	state->in_statement = false;
	state->stack = state->stacktop = NULL;
	yang_prefix_init(state->pfxs);

	while ((token = yangkheg_next(lex))) {
		enum handler_res res = H_OK;

		switch (token->token) {
		case COMMENT:
			continue;

		case '{':
			if (!state->in_statement)
				yk_token_diag(DIAG_WARN, token,
					      "block has no function");

			oldstate = state;
			state = XMALLOC(MTYPE_YK_STATE, sizeof(*state));
			*state = *oldstate;

			state->parent = oldstate;
			state->open_at = yk_token_get(token);
			state->stacktop = state->stack;
			state->in_statement = false;
			continue;

		case '}':
			if (state->in_statement) {
				yk_token_diag(DIAG_ERR, token,
					      "missing semicolon before `}`");
				for (stack = state->stack;
				     stack && stack != state->stacktop;
				     stack = stacknext) {
					stacknext = stack->parent;

					/* TODO: free(stack) */
				}
			}

			if (!state->parent) {
				yk_token_diag(DIAG_ERR, token,
					      "no block to close here");
				continue;
			}

			oldstate = state;
			state = state->parent;
			yk_token_put(&oldstate->open_at);
			XFREE(MTYPE_YK_STATE, oldstate);

			state->in_statement = true;
			continue;

		case ';':
			goto done_up;
		}

		state->in_statement = true;

		args[0] = token;
		if (token->token == YKCC_OPEN)
			cblocks[0] = yk_parse_cblock(lex);
		else
			cblocks[0] = NULL;

		for (h = htab; h->tokens[0]; h++) {
			if (h->tokens[0] == token->token)
				break;
		}

		if (!h->tokens[0]) {
			yk_token_diag(DIAG_ERR, token,
				      "unhandled token %pYKT, skipping until next `;`",
				      token);
			goto error_skip;
		}

		for (i = 1; i < MAXARGS && h->tokens[i]; i++) {
			args[i] = yangkheg_next(lex);
			cblocks[i] = NULL;

			while (args[i] && args[i]->token == COMMENT)
				args[i] = yangkheg_next(lex);

			if (!args[i]) {
				yk_token_diag(DIAG_ERR, token,
					      "EOF while processing statement");
				return;
			}

			if (args[i]->token != h->tokens[i]) {
				yk_token_diag(DIAG_ERR, args[i],
					      "expected %dYKN here, got %dYKN",
					      h->tokens[i], args[i]->token);
				goto error_skip;
			}

			if (args[i]->token == YKCC_OPEN)
				cblocks[i] = yk_parse_cblock(lex);
		}

		if (h->fn)
			res = h->fn(state, lex, args, cblocks, i);
		if (res == H_OK)
			continue;

error_skip:
		error_skip(lex);
done_up:
		for (stack = state->stack;
		     stack && stack != state->stacktop;
		     stack = stacknext) {
			stacknext = stack->parent;
			/* TODO: free(stack) */
		}
		state->stack = state->stacktop;
		state->in_statement = false;
		continue;
	};

	if (token) {
		yk_token_diag(DIAG_ERR, token,
			      "internal error on token %pYKT, "
			      "this code should never be reached",
			      token);
		exit(1);
	}

	while (state->parent) {
		yk_token_diag(DIAG_ERR, state->open_at, "unterminated block");

		state = state->parent;
		/* todo: free() */
	}
}

#define handler_prototype(name)                                                \
	static enum handler_res name(struct yangkheg_state *state,             \
				     struct yangkheg_lexer *lex,               \
				     const struct yangkheg_token *tokens[],    \
				     struct yk_cblock *cblocks[],              \
				     size_t argc)                              \
	/* end */

handler_prototype(handle_path);
handler_prototype(handle_implements);
handler_prototype(handle_emit);
handler_prototype(handle_trace);

handler_prototype(handle_nodeval);
handler_prototype(handle_lval);

static const struct yangkheg_handler h_root[] = {
	{ { YK_PATH, },		0,		handle_path },
	{ { YK_IMPLEMENTS, },	H_STANDALONE,	handle_implements },
	{ { YK_EMIT, STRING, YKCC_OPEN },
				0,		handle_emit },
	{ { YK_TRACE, },	H_STANDALONE,	handle_trace },

	{ { YK_NOOP, },
				0,		NULL },
	{ { YK_NODEVAL, YKCC_OPEN },
				0,		handle_nodeval },
	{ { YK_LVAL, YKCC_OPEN },
				0,		handle_lval },
	{ { YK_CREATE, YKCC_OPEN },
				0,		NULL },
	{ { YK_DESTROY, YKCC_OPEN },
				0,		NULL },
	{ },
};

static struct yang_prefix *yang_prefix_find_name(struct yangkheg_state *state,
						 const char *name)
{
	struct yang_prefix ref = { .prefix = name };

	while (state->parent)
		state = state->parent;

	return yang_prefix_find(state->pfxs, &ref);
}

static enum handler_res handle_path(struct yangkheg_state *state,
				    struct yangkheg_lexer *lex,
				    const struct yangkheg_token *tokens[],
				    struct yk_cblock *cblocks[],
				    size_t tokenc)
{
	const struct yangkheg_token *token = tokens[0];
	struct yangkheg_stack *nextstk, *parent;

	char *freeme, *item, *pfx = NULL, *colon;
	const struct lysc_node *yn;
	const struct lys_module *mod;
	struct lysc_ext_instance *ext;

	nextstk = XCALLOC(MTYPE_YK_STACK, sizeof(*nextstk));
	nextstk->parent = parent = state->stack;
	state->stack = nextstk;

	freeme = item = strdup(token->text);

	colon = strchr(item, ':');
	if (colon) {
		pfx = item;
		*colon++ = '\0';
		item = colon;
	}
	if (pfx) {
		struct yang_prefix *pfxres;

		pfxres = yang_prefix_find_name(state, pfx);
		if (!pfxres) {
			yk_token_diag(DIAG_ERR, token, "invalid prefix %pSQq",
				      pfx);
			return H_ERROR;
		}
		mod = pfxres->module;
	} else if (parent && parent->lysc_node) {
		mod = parent->lysc_node->module;
	} else {
		yk_token_diag(DIAG_ERR, token,
			      "prefix required for paths at root level");
		return H_ERROR;
	}

	yn = lys_find_child(parent ? parent->lysc_node : NULL, mod, item,
			    strlen(item), 0, 0);

	if (!yn) {
		yk_token_diag(DIAG_ERR, token,
			      "element %pSQq not found in YANG model below %pLYCN",
			      item, parent ? parent->lysc_node : NULL);
		return H_ERROR;
	}

	nextstk->lysc_node = yn;

	yk_token_diag(DIAG_TRACE, token, "path: {%s}%s",
		      yn->module->name, yn->name);

	LY_ARRAY_FOR(yn->exts, struct lysc_ext_instance, ext) {
		printfrr("\text {%s}%s %pSQq\n", ext->def->module->name,
			 ext->def->name, ext->argument);
	}

	free(freeme);
	return H_OK;
}

static enum handler_res handle_nodeval(struct yangkheg_state *state,
				       struct yangkheg_lexer *lex,
				       const struct yangkheg_token *tokens[],
				       struct yk_cblock *cblocks[],
				       size_t tokenc)
{
	struct yangkheg_stack *stk = state->stack;
	const char *varname = NULL;

	if (!stk) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "no path to bind here");
		return H_ERROR;
	}

	printf("\tbind to cblock %p\n", cblocks[1]);
	return H_OK;
}

struct render_ctx {
	FILE *out;

	struct yangkheg_state *state;
	struct yangkheg_stack *stk;
};

struct render_fn {
	const char *funcname;
	void (*render)(struct render_ctx *ctx, struct yk_citem *item);
};

#if 0
const struct lysp_tpdf *get_type(const struct lysc_node_leaf *node)
{
	struct lysp_module *modp = node->module->parsed;
	struct lysp_tpdf *thistype;

	LY_ARRAY_FOR(modp->typedefs, struct lysp_tpdf, thistype) {
		printfrr("iter typedef %s %p %p\n", thistype->name, thistype,
			 thistype->);
	}

	return NULL;
}
#endif

static void render_debug_show_type(struct render_ctx *ctx,
				   struct yk_citem *item)
{
	struct yangkheg_state *state = ctx->state;
	struct yangkheg_stack *stk = ctx->stk;
	struct yk_carg *arg = yk_cargs_first(item->args);
	const char *xpath = ".";
	struct ly_set *set = NULL;
	LY_ERR err;

	if (arg->type == YK_CARG_STRING)
		xpath = arg->strval;

	err = lys_find_xpath(state->ly_ctx, stk->lysc_node, xpath, 0, &set);
	if (err != LY_SUCCESS) {
		fprintf(stderr, "xpath error\n");
		return;
	}

	fprintf(stderr, "debug_show_type(%s) =>\n", xpath);
	for (size_t i = 0; i < set->count; i++) {
		const struct lysc_node *node = set->snodes[i];

		fprintf(stderr, "[%zu] %s {%s}%s\n", i,
			lys_nodetype2str(node->nodetype), node->module->name,
			node->name);

		struct lysc_ext_instance *ext;

		LY_ARRAY_FOR(node->exts, struct lysc_ext_instance, ext) {
			printfrr("\text {%s}%s %pSQq\n",
				 ext->def->module->name, ext->def->name,
				 ext->argument);
		}

		if (node->nodetype != LYS_LEAF)
			continue;

		const struct lysc_node_leaf *leaf =
			container_of(node, struct lysc_node_leaf, node);
		const struct lysc_type *typ;
		const struct lysc_typeinfo *ti;

		for (typ = leaf->type; typ && (ti = lysc_typeinfo(typ));
		     typ = ti ? ti->base : NULL) {
			printfrr("\ttype: %p {%s}%s %p\n", typ,
				 ti->mod ? ti->mod->name : "BUILTIN",
				 ti->name, ti->base);

			LY_ARRAY_FOR(typ->exts, struct lysc_ext_instance, ext) {
				printfrr("\text {%s}%s %pSQq\n",
					 ext->def->module->name, ext->def->name,
					 ext->argument);
			}
		}
	}

	ly_set_free(set, NULL);
}

static const struct render_fn render_fns[] = {
	{ "debug_show_type", render_debug_show_type },
	{ },
};

static void render_cblock(struct render_ctx *ctx, struct yk_cblock *cblock)
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

		if (it->type == YK_CIT_AT_FUNC) {
			const char *name = it->atname ?: "";
			const struct render_fn *fn;

			for (fn = render_fns; fn->funcname; fn++)
				if (!strcmp(fn->funcname, name))
					break;
			if (fn) {
				fn->render(ctx, it);
				continue;
			}
			fprintf(ctx->out, "\n@unrecognized @%s()", name);
		}

		size_t i = 0;
		struct yk_carg *arg;

		needline = true;
		fprintf(ctx->out, "\n@%d name=%s\n", it->type, it->atname);
		frr_each (yk_cargs, it->args, arg) {
			fprintf(ctx->out, "arg%zu: %d/%s\n", i, arg->type,
				arg->strval);
			i++;
		}
	}
	fprintf(ctx->out, "\n/* } end cblock */\n");
}

static enum handler_res handle_emit(struct yangkheg_state *state,
				    struct yangkheg_lexer *lex,
				    const struct yangkheg_token *tokens[],
				    struct yk_cblock *cblocks[],
				    size_t tokenc)
{
	struct yangkheg_stack *stk = state->stack;
	struct render_ctx ctx = { .state = state, .stk = stk };
	const char *outname;

	outname = tokens[1]->text;

	ctx.out = fopen(outname, "w");
	if (!ctx.out) {
		perror(outname);
		exit(1);
	}

	render_cblock(&ctx, cblocks[2]);
	fclose(ctx.out);

	return H_OK;
}

static enum handler_res handle_lval(struct yangkheg_state *state,
				    struct yangkheg_lexer *lex,
				    const struct yangkheg_token *tokens[],
				    struct yk_cblock *cblocks[],
				    size_t tokenc)
{
	return H_OK;
}

static enum handler_res handle_trace(struct yangkheg_state *state,
				     struct yangkheg_lexer *lex,
				     const struct yangkheg_token *tokens[],
				     struct yk_cblock *cblocks[],
				     size_t tokenc)
{
	struct yangkheg_state *i_state;
	struct yangkheg_stack *i_stk = state->stack;

	for (i_state = state; i_state; i_state = i_state->parent) {
		const struct yangkheg_token *token;

		token = i_state->open_at ? i_state->open_at : tokens[0];

		for (; i_stk && i_stk != i_state->stacktop;
		     i_stk = i_stk->parent)
			yk_token_diag(DIAG_TRACE, token,
				      "trace! -   stack: %p node: %pLYCN",
				      i_stk, i_stk->lysc_node);

		if (i_state->open_at)
			yk_token_diag(DIAG_TRACE, i_state->open_at,
				      "trace! - block opened here");
		else
			yk_token_diag(DIAG_TRACE, tokens[0],
				      "trace! - file root/end");
	}
	return H_OK;
}

static enum handler_res handle_implements(struct yangkheg_state *state,
					  struct yangkheg_lexer *lex,
					  const struct yangkheg_token *tokens[],
					  struct yk_cblock *cblocks[],
					  size_t tokenc)
{
	char *model;
	LY_ERR err;
	int fd;

	model = yangkheg_pull_str(lex, STRING);
	//yangkheg_pull(lex, ';');

	if (state->parent) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "'implements' statement must be used at top level");
		return H_ERROR;
	}

	if (state->lys_module) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "duplicate 'implements' statement");
		return H_ERROR;
	}

	fd = open(model, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		perror(model);
		exit(1);
	}

	err = lys_parse_fd(state->ly_ctx, fd, LYS_IN_YANG, &state->lys_module);
	if (err) {
		fprintf(stderr, "YANG load failed\n");
		return 1;
	}
	close(fd);

	const struct lys_module *m = state->lys_module;
	struct lysp_import *imp;
	struct yang_prefix *yp;

	yp = calloc(sizeof(*yp), 1);
	yp->prefix = m->prefix;
	yp->name = m->name;
	yp->module = m;

	yang_prefix_add(state->pfxs, yp);

	LY_ARRAY_FOR(m->parsed->imports, struct lysp_import, imp) {
		yp = calloc(sizeof(*yp), 1);
		yp->prefix = imp->prefix;
		yp->name = imp->name;
		yp->module = imp->module;

		yang_prefix_add(state->pfxs, yp);
	}

	yk_token_diag(DIAG_TRACE, tokens[0], "implementing %pSQq rev %pSE %d",
		      m->name, m->revision, m->implemented);

	return H_OK;
}

static void ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
	if (path)
		fprintf(stderr, "ly<%d>%s %pSQq\n", level, msg, path);
	else
		fprintf(stderr, "ly<%d>%s\n", level, msg);
}

int main(int argc, char **argv)
{
	struct yangkheg_lexer *lex;
	struct yangkheg_state state = { };
	LY_ERR err;

	struct yangkheg_file file[1];
	const char *yang_models_path = "yang/";

	file->filename = argv[1];
	file->fd = fopen(argv[1], "r");
	if (!file->fd) {
		perror("fopen");
		return 1;
	}

	ly_set_log_clb(ly_log_cb, 1);
	ly_log_options(LY_LOLOG | LY_LOSTORE);

	uint options = LY_CTX_NO_YANGLIBRARY | LY_CTX_DISABLE_SEARCHDIR_CWD;
	err = ly_ctx_new(yang_models_path, options, &state.ly_ctx);
	if (err) {
		fprintf(stderr, "YANG initialization failed\n");
		return 1;
	}

	lex = yangkheg_begin(file);
	yangkheg_process(&state, lex, h_root);
	yangkheg_end(lex);

	return 0;
}
