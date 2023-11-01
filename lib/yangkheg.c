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
#pragma FRR printfrr_ext "%pLYCT" (struct lysc_type *)
#pragma FRR printfrr_ext "%pLYM"  (struct lys_module *)
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

static int yk_yangtype_cmp(const struct yk_yangtype *a,
			   const struct yk_yangtype *b)
{
	if (a->mod != b->mod)
		return numcmp(a->mod, b->mod);
	return strcmp(a->name, b->name);
}

static uint32_t yk_yangtype_hash(const struct yk_yangtype *typ)
{
	uint32_t hashval = 0xfbcec464;

	hashval = jhash(typ->name, strlen(typ->name), hashval);
	hashval = jhash(&typ->mod, sizeof(typ->mod), hashval);
	return hashval;
}

DECLARE_HASH(yk_yangtypes, struct yk_yangtype, itm, yk_yangtype_cmp,
	     yk_yangtype_hash);

static struct yk_yangtypes_head types[1] = { INIT_HASH(types[0]), };

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

printfrr_ext_autoreg_p("LYCN", printfrr_lycn);
static ssize_t printfrr_lycn(struct fbuf *buf, struct printfrr_eargs *ea,
			     const void *ptr)
{
	const struct lysc_node *node = ptr;

	if (!node)
		return bputs(buf, "(null lysc_node)");

	return bprintfrr(buf, "{%s %s:%s}", lys_nodetype2str(node->nodetype),
			 node->module->name, node->name);
}

printfrr_ext_autoreg_p("LYCT", printfrr_lyct);
static ssize_t printfrr_lyct(struct fbuf *buf, struct printfrr_eargs *ea,
			     const void *ptr)
{
	const struct lysc_type *typ = ptr;
	const struct lysc_typeinfo *tinfo;
	ssize_t rv = 0;

	if (!typ)
		return bputs(buf, "(null lysc_type)");
	tinfo = lysc_typeinfo(typ);

	rv += bprintfrr(buf, "{%s ", ly_data_type2str[typ->basetype]);
	if (!tinfo) {
		rv += bputs(buf, "NO_TYPEINFO!}");
		return rv;
	}

	rv += bprintfrr(buf, "%s:%s", tinfo->mod->name, tinfo->name);

	rv += bputch(buf, '}');
	return rv;
}

printfrr_ext_autoreg_p("LYM", printfrr_lym);
static ssize_t printfrr_lym(struct fbuf *buf, struct printfrr_eargs *ea,
			    const void *ptr)
{
	const struct lys_module *module = ptr;

	if (!module)
		return bputs(buf, "(null lys_module)");

	return bprintfrr(buf, "{module %pSQq rev %s [%s%s%s]}",
			 module->name, module->revision,
			 module->parsed ? "P" : "",
			 module->compiled ? "C" : "",
			 module->implemented ? "I" : "");
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
struct yangkheg_file_state;

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

	void (*close)(struct yangkheg_state *st, struct yangkheg_token *tkn);

	struct lys_module *lys_module;
	const struct lysc_node *lysc_node;

	struct yk_cmap *cmap;
};

struct yangkheg_state {
	struct yangkheg_state *parent;
	struct yangkheg_file_state *fs;

	struct yangkheg_token *open_at;
	struct yangkheg_stack *stack, *stacktop;
	bool in_statement;
};

struct yangkheg_file_state {
	struct yangkheg_file_state *parent;

	struct ly_ctx *ly_ctx;
	struct lys_module *lys_module;
	struct yang_prefix_head pfxs[1];
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

static void yangkheg_process(struct yangkheg_file_state *file_state,
			     struct yangkheg_lexer *lex,
			     const struct yangkheg_handler *htab)
{
	struct yangkheg_state file_root_state[1] = {};
	struct yangkheg_state *state = file_root_state;
	struct yangkheg_state *oldstate;
	struct yangkheg_stack *stack, *stacknext;
	struct yangkheg_token *token = NULL;
	const struct yangkheg_handler *h;
	struct yangkheg_token *args[MAXARGS];
	struct yk_cblock *cblocks[MAXARGS];
	size_t i;

	yang_prefix_init(file_state->pfxs);
	file_root_state->fs = file_state;

	state->in_statement = false;
	state->stack = state->stacktop = NULL;

	while ((token = yangkheg_next(lex))) {
		enum handler_res res = H_OK;
		struct yangkheg_token *close_token = token;

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

		args[0] = yk_token_get(token);
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
			yk_token_put(&args[0]);
			/* free cblock ... */
			goto error_skip;
		}

		for (i = 1; i < MAXARGS && h->tokens[i]; i++) {
			struct yangkheg_token *atoken;

			for (atoken = yangkheg_next(lex);
			     atoken && atoken->token == COMMENT;
			     atoken = yangkheg_next(lex))
				; /* nothing */

			args[i] = yk_token_get(atoken);
			cblocks[i] = NULL;

			if (!args[i]) {
				yk_token_diag(DIAG_ERR, token,
					      "EOF while processing statement");
				return;
			}

			if (args[i]->token == YKCC_OPEN)
				cblocks[i] = yk_parse_cblock(lex);

			if (args[i]->token != h->tokens[i]) {
				yk_token_diag(DIAG_ERR, args[i],
					      "expected %dYKN here, got %dYKN",
					      h->tokens[i], args[i]->token);
				for (size_t j = 0; j < i + 1; j++)
					yk_token_put(&args[j]);
				goto error_skip;
			}
		}

		if (h->fn)
			res = h->fn(state, lex,
				    (const struct yangkheg_token **)args,
				    cblocks, i);

		for (size_t j = 0; j < i; j++)
			yk_token_put(&args[j]);

		if (res == H_OK)
			continue;

error_skip:
		error_skip(lex);
		close_token = NULL;
done_up:
		for (stack = state->stack;
		     stack && stack != state->stacktop;
		     stack = state->stack) {
			stacknext = stack->parent;

			if (stack->close)
				stack->close(state, close_token);
			/* TODO: free(stack) */

			state->stack = stacknext;
		}
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
handler_prototype(handle_import);
handler_prototype(handle_emit);
handler_prototype(handle_trace);
handler_prototype(handle_template);

handler_prototype(handle_nodeval);
handler_prototype(handle_lval);
handler_prototype(handle_first_next);

handler_prototype(handle_type);
handler_prototype(handle_dflt);
handler_prototype(handle_kind);
handler_prototype(handle_lyd_value);

handler_prototype(handle_key_input);
handler_prototype(handle_json_output);

static const struct yangkheg_handler h_root[] = {
	{ { YK_PATH, },		0,		handle_path },
	{ { YK_IMPLEMENTS, },	H_STANDALONE,	handle_implements },
	{ { YK_IMPORT, },	H_STANDALONE,	handle_import },
	{ { YK_EMIT, STRING, YKCC_OPEN },
				0,		handle_emit },
	{ { YK_TEMPLATE, STRING, YKCC_OPEN },
				0,		handle_template },
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

	{ { YK_FIRST, YKCC_OPEN },
				0,		handle_first_next },
	{ { YK_NEXT, YKCC_OPEN },
				0,		handle_first_next },

	{ { YK_TYPE, YK_PATH, YK_CTYPE, YKCC_OPEN },
				0,		handle_type },
	{ { YK_DEFAULT, },	0,		handle_dflt },
	{ { YK_KIND, ID, },	0,		handle_kind },
	{ { YK_LYD_VALUE, YKCC_OPEN, },
				0,		handle_lyd_value },

	{ { YK_KEY_INPUT, YKCC_OPEN, },
				0,		handle_key_input },
	{ { YK_JSON_OUTPUT, YKCC_OPEN, },
				0,		handle_json_output },
	{ },
};

static struct yang_prefix *yang_prefix_find_name(struct yangkheg_state *state,
						 const char *name)
{
	struct yang_prefix ref = { .prefix = name };

	while (state->parent)
		state = state->parent;

	return yang_prefix_find(state->fs->pfxs, &ref);
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
	if (!yn->priv) {
		struct yk_nodeinfo *nodeinfo;

		nodeinfo = XCALLOC(MTYPE_TMP, sizeof(*nodeinfo));
		nodeinfo->node = yn;
		((struct lysc_node *)yn)->priv = nodeinfo;
	}

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
	struct yk_nodeinfo *nodeinfo;

	if (!stk) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "no path to bind here");
		return H_ERROR;
	}

	nodeinfo = stk->lysc_node->priv;
	assert(nodeinfo);

	if (nodeinfo->nodeval) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "duplicate nodeval");
		return H_OK;
	}

	nodeinfo->nodeval = cblocks[1];
	return H_OK;
}

#if 0
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

static const struct render_fn render_fns[] = {
	{ "debug_show_type", render_debug_show_type },
	{ },
};
#endif

void ykat_debug_show_type(struct yk_crender_ctx *ctx, struct yk_citem *item,
			  const char *xpath)
{
	struct yangkheg_state *state = ctx->state;
	struct yangkheg_stack *stk = ctx->stk;
	struct ly_set *set = NULL;
	const struct lysc_node *node = stk ? stk->lysc_node : NULL;
	LY_ERR err;

	err = lys_find_xpath(state->fs->ly_ctx, node, xpath,
			     0, &set);
	if (err != LY_SUCCESS) {
		fprintf(stderr, "xpath error\n");
		return;
	}

	fprintfrr(stderr, "debug_show_type(%s@%pLYCN) => (%u)\n", xpath, node, set->count);
	for (size_t i = 0; i < set->count; i++) {
		const struct lysc_node *node = set->snodes[i];

		fprintf(stderr, "[%zu] %s {%s}%s\n", i,
			lys_nodetype2str(node->nodetype), node->module->name,
			node->name);

		struct lysc_ext_instance *ext;

		LY_ARRAY_FOR(node->exts, struct lysc_ext_instance, ext) {
			fprintfrr(stderr, "\text {%s}%s %pSQq\n",
				 ext->def->module->name, ext->def->name,
				 ext->argument);
		}

		if (node->nodetype == LYS_LIST) {
			const struct lysc_node_list *list =
				container_of(node, struct lysc_node_list, node);
			fprintfrr(stderr, "\tlist\n");
			continue;
		}

		if (node->nodetype != LYS_LEAF) {
			fprintfrr(stderr, "\tnot a leaf\n");
			continue;
		}

		const struct lysc_node_leaf *leaf =
			container_of(node, struct lysc_node_leaf, node);
		const struct lysc_type *typ;
		const struct lysc_typeinfo *ti;

		for (typ = leaf->type; typ && (ti = lysc_typeinfo(typ));
		     typ = ti ? ti->base : NULL) {
			fprintfrr(stderr, "\ttype: %p {%s}%s %p\n", typ,
				 ti->mod ? ti->mod->name : "BUILTIN",
				 ti->name, ti->base);

			LY_ARRAY_FOR(typ->exts, struct lysc_ext_instance, ext) {
				fprintfrr(stderr, "\text {%s}%s %pSQq\n",
					 ext->def->module->name, ext->def->name,
					 ext->argument);
			}
		}
	}

	ly_set_free(set, NULL);
}

static enum handler_res handle_emit(struct yangkheg_state *state,
				    struct yangkheg_lexer *lex,
				    const struct yangkheg_token *tokens[],
				    struct yk_cblock *cblocks[],
				    size_t tokenc)
{
	struct yangkheg_stack *stk = state->stack;
	struct yk_crender_ctx ctx = { .state = state, .stk = stk };
	const char *outname;
	FILE *out;

	outname = tokens[1]->cooked;

	if (!strcmp(outname, "")) {
		out = stdout;
		yk_token_diag(DIAG_TRACE, tokens[0], "rendering to stdout");
	} else {
		out = fopen(outname, "w");
		if (!out) {
			perror(outname);
			exit(1);
		}
	}

	yk_crender_init(&ctx, out);
	yk_cblock_render(&ctx, cblocks[2]);
	yk_crender_fini(&ctx);

	if (out != stdout)
		fclose(out);
	else
		yk_token_diag(DIAG_TRACE, tokens[0], "end of render");
	return H_OK;
}

static int yk_template_cmp(const struct yk_template *a,
			   const struct yk_template *b)
{
	return strcmp(a->name, b->name);
}

static uint32_t yk_template_hash(const struct yk_template *a)
{
	return jhash(a->name, strlen(a->name), 0xd1044749);
}

DECLARE_HASH(yk_templates, struct yk_template, item, yk_template_cmp,
	     yk_template_hash);

static struct yk_templates_head yk_templates[1] = {
	INIT_HASH(yk_templates[0]),
};

static enum handler_res handle_template(struct yangkheg_state *state,
					struct yangkheg_lexer *lex,
					const struct yangkheg_token *tokens[],
					struct yk_cblock *cblocks[],
					size_t tokenc)
{
	struct yk_template *tpl, ref;

	ref.name = tokens[1]->cooked;
	tpl = yk_templates_find(yk_templates, &ref);

	if (tpl) {
		yk_token_diag(DIAG_ERR, tokens[1], "template already exists");
		yk_token_diag(DIAG_ERR, tpl->loc_name, "previously defined here");
		return H_ERROR;
	}

	tpl = XCALLOC(MTYPE_TMP, sizeof(*tpl));
	tpl->loc_name = yk_token_get(tokens[1]);
	tpl->name = tpl->loc_name->cooked;
	tpl->cblock = cblocks[2];
	yk_templates_add(yk_templates, tpl);

	yk_token_diag(DIAG_TRACE, tokens[0], "template %pSQq defined",
		      tpl->name);
	return H_OK;
}

static const char *ykgen_ext_val(const struct lysc_node *node,
				 const char *extname)
{
	struct lysc_ext_instance *ext;

	LY_ARRAY_FOR(node->exts, struct lysc_ext_instance, ext) {
		if (strcmp(ext->def->module->name, "frr-codegen"))
			continue;
		if (strcmp(ext->def->name, extname))
			continue;
		return ext->argument;
	}

	return NULL;
}

static void ykat_render_setup_list(struct yk_crender_ctx *subctx,
				   const struct lysc_node_list *node_list)
{
	yk_crender_arg_set(subctx, "is_container", "");
	yk_crender_arg_set(subctx, "is_list", "true");
}

static void ykat_implement_container(struct yk_crender_ctx *ctx,
				     const struct lysc_node *node )
{
	struct yk_template *tpl, ref;
	const struct lysc_node *parent;
	struct yk_nodeinfo *nodeinfo = node->priv;
	const char *ctxtype;
	const char *bname, *parentbname, *inheritbname;

	ref.name = "dispatch";
	tpl = yk_templates_find(yk_templates, &ref);

	if (!tpl) {
		fprintf(stderr, "cannot find \"dispatch\" template\n");
		return;
	}

	struct yk_crender_ctx subctx = {
		.node = node,
		.state = ctx->state,
		.stk = ctx->stk,
	};

	yk_crender_init(&subctx, ctx->out);

	bname = ykgen_ext_val(node, "brief-name");
	if (!bname) {
		fprintf(stderr, "no brief-name for container with type\n");
		return;
	}
	yk_crender_arg_set(&subctx, "", bname);

	if (node->parent)
		parentbname = ykgen_ext_val(node->parent, "brief-name");
	else
		parentbname = "root";
	if (!parentbname) {
		fprintf(stderr, "no brief-name for container parent\n");
		return;
	}
	yk_crender_arg_set(&subctx, "parent", parentbname);

	switch (node->nodetype) {
	case LYS_CONTAINER:
		yk_crender_arg_set(&subctx, "is_container", "true");
		yk_crender_arg_set(&subctx, "is_list", "");
		break;
	case LYS_LIST:
		ykat_render_setup_list(&subctx,
			container_of(node, struct lysc_node_list, node));
		break;
	}

	for (parent = node->parent; parent; parent = parent->parent) {
		inheritbname = ykgen_ext_val(parent, "brief-name");
		if (inheritbname && ykgen_ext_val(parent, "context-type"))
			break;
	}
	if (!parent)
		inheritbname = "root";
	yk_crender_arg_set(&subctx, "ctx_parent", inheritbname);

	ctxtype = ykgen_ext_val(node, "context-type");
	if (ctxtype && nodeinfo->nodeval) {
		yk_crender_arg_set(&subctx, "this_ctxname", yk_cblock_typename(nodeinfo->nodeval));
		yk_crender_arg_set(&subctx, "this_ctxtype", ctxtype);
		yk_crender_arg_set(&subctx, "ctx_this", bname);
	} else
		yk_crender_arg_set(&subctx, "ctx_this", inheritbname);

	char namebuf[256];

	if (node->parent && node->module == node->parent->module)
		snprintfrr(namebuf, sizeof(namebuf), "%s", node->name);
	else
		snprintfrr(namebuf, sizeof(namebuf), "%s:%s",
			   node->module->prefix, node->name);
	yk_crender_arg_set(&subctx, "nodename", namebuf);

	yk_cblock_render_template(&subctx, tpl);
	yk_crender_fini(&subctx);
}

static void ykat_implement_leaf(struct yk_crender_ctx *ctx,
				const struct lysc_node *node )
{
	struct yk_template *tpl, ref;
	const struct lysc_node *parent;
	struct yk_nodeinfo *nodeinfo = node->priv;
	const char *parentbname, *inheritbname;
	const char *ctxtype;

	const struct lysc_node_leaf *leaf;
	const struct lysc_type *typ;
	const struct lysc_typeinfo *ti;

	ref.name = "leaf";
	tpl = yk_templates_find(yk_templates, &ref);

	if (!tpl) {
		fprintf(stderr, "cannot find \"leaf\" template\n");
		return;
	}
	if (!nodeinfo) {
		fprintf(stderr, "leaf missing node details\n");
		return;
	}

	struct yk_crender_ctx subctx = {
		.node = node,
		.state = ctx->state,
		.stk = ctx->stk,
	};

	yk_crender_init(&subctx, ctx->out);

	yk_crender_arg_set(&subctx, "", node->name);
	if (nodeinfo->lval)
		yk_crender_arg_cblock(&subctx, "lval", nodeinfo->lval);

	if (node->parent)
		parentbname = ykgen_ext_val(node->parent, "brief-name");
	else
		parentbname = "root";
	if (!parentbname) {
		fprintf(stderr, "parent missing brief-name\n");
		return;
	}
	yk_crender_arg_set(&subctx, "parent", parentbname);

	for (parent = node->parent; parent; parent = parent->parent) {
		inheritbname = ykgen_ext_val(parent, "brief-name");
		ctxtype = ykgen_ext_val(parent, "context-type");
		if (inheritbname && ctxtype)
			break;
	}
	if (!parent) {
		inheritbname = "root";
		ctxtype = NULL;
	}
	yk_crender_arg_set(&subctx, "ctx_parent", inheritbname);

	if (ctxtype) {
		struct yk_nodeinfo *parentinfo = parent->priv;
		yk_crender_arg_set(&subctx, "this_ctxname",
				   yk_cblock_typename(parentinfo->nodeval));
		yk_crender_arg_set(&subctx, "this_ctxtype", ctxtype);
	}

	char namebuf[256];

	if (node->parent && node->module == node->parent->module)
		snprintfrr(namebuf, sizeof(namebuf), "%s", node->name);
	else
		snprintfrr(namebuf, sizeof(namebuf), "%s:%s",
			   node->module->prefix, node->name);
	yk_crender_arg_set(&subctx, "nodename", namebuf);

	leaf = container_of(node, struct lysc_node_leaf, node);

	struct yk_yangtype *yktyp = NULL;

	for (typ = leaf->type; typ && (ti = lysc_typeinfo(typ));
	     typ = ti ? ti->base : NULL) {
		struct yk_yangtype ref;

		ref.mod = ti->mod;
		ref.name = ti->name;
		yktyp = yk_yangtypes_find(types, &ref);
		if (yktyp)
			break;
	}

	if (!yktyp) {
		fprintf(stderr, "unknown type to implement\n");
	} else {
		subctx.typ = yktyp;
		subctx.cmap = yktyp->dflt;

		if (subctx.cmap)
			yk_crender_arg_set(&subctx, "leaftype", subctx.cmap->name);

		yk_cblock_render_template(&subctx, tpl);
	}
	yk_crender_fini(&subctx);
}

void ykat_implement(struct ykat_ctx *at_ctx, const char *xpath)
{
	struct yk_crender_ctx *ctx = at_ctx->ctx;
	struct yangkheg_state *state = ctx->state;
	struct yangkheg_stack *stk = ctx->stk;
	struct ly_set *set = NULL;
	const struct lysc_node *node = stk ? stk->lysc_node : NULL;
	LY_ERR err;

	err = lys_find_xpath(state->fs->ly_ctx, node, xpath, 0, &set);
	if (err != LY_SUCCESS) {
		fprintf(stderr, "xpath error\n");
		return;
	}

	for (size_t i = 0; i < set->count; i++) {
		const struct lysc_node *node = set->snodes[i];

		fprintf(stderr, "[%zu] %s {%s}%s\n", i,
			lys_nodetype2str(node->nodetype), node->module->name,
			node->name);

		switch (node->nodetype) {
		case LYS_CONTAINER:
		case LYS_LIST:
			ykat_implement_container(ctx, node);
			break;
		case LYS_LEAF:
			ykat_implement_leaf(ctx, node);
			break;
		default:
			fprintf(stderr, "\tnode type %s not implemented!\n",
				lys_nodetype2str(node->nodetype));
		}
	}

	ly_set_free(set, NULL);
}

void ykat_template_call(struct ykat_ctx *at_ctx, const char *name)
{
	struct yk_template *tpl, ref;

	ref.name = name;
	tpl = yk_templates_find(yk_templates, &ref);

	if (!tpl) {
		struct yangkheg_token *pos;

		pos = yk_ctokens_first(at_ctx->item->tokens);
		pos = yk_ctokens_next(at_ctx->item->tokens, pos) ?: pos;
		pos = yk_ctokens_next(at_ctx->item->tokens, pos) ?: pos;

		yk_token_diag(DIAG_ERR, pos,
			      "invoked template %pSQq not found", name);
		return;
	}

	yk_cblock_render_template(at_ctx->ctx, tpl);
}

void ykat_json_output(struct ykat_ctx *at_ctx)
{
	struct yk_cmap *cmap = at_ctx->ctx->cmap;

	if (cmap)
		yk_cblock_render(at_ctx->ctx, cmap->json_output);
	else {
		struct yangkheg_token *pos;
		pos = yk_ctokens_first(at_ctx->item->tokens);

		yk_token_diag(DIAG_ERR, pos,
			      "no C type mapping available");
	}
}

static enum handler_res handle_lval(struct yangkheg_state *state,
				    struct yangkheg_lexer *lex,
				    const struct yangkheg_token *tokens[],
				    struct yk_cblock *cblocks[],
				    size_t tokenc)
{
	struct yangkheg_stack *stk = state->stack;
	struct yk_nodeinfo *nodeinfo;

	if (!stk) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "no path to bind here");
		return H_ERROR;
	}

	nodeinfo = stk->lysc_node->priv;
	assert(nodeinfo);

	if (nodeinfo->lval) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "duplicate nodeval");
		return H_OK;
	}

	nodeinfo->lval = cblocks[1];
	return H_OK;
}

static enum handler_res handle_first_next(struct yangkheg_state *state,
					  struct yangkheg_lexer *lex,
					  const struct yangkheg_token *tokens[],
					  struct yk_cblock *cblocks[],
					  size_t tokenc)
{
	struct yangkheg_stack *stk = state->stack;
	struct yk_nodeinfo *nodeinfo;
	struct yk_cblock **which;

	if (!stk) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "no path to bind here");
		return H_ERROR;
	}

	nodeinfo = stk->lysc_node->priv;
	assert(nodeinfo);

	switch (tokens[0]->token) {
	case YK_FIRST:
		which = &nodeinfo->first;
		break;
	case YK_NEXT:
		which = &nodeinfo->next;
		break;
	}

	if (*which) {
		yk_token_diag(DIAG_ERR, tokens[0], "duplicate handler");
		return H_OK;
	}

	*which = cblocks[1];
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

		if (i_state->open_at) {
			const struct lysc_node *child;

			yk_token_diag(DIAG_TRACE, i_state->open_at,
				      "trace! - block opened here.  nodes:");

			for (child = lysc_node_child(i_state->stacktop->lysc_node);
			     child; child = child->next)
				yk_token_diag(DIAG_TRACE, i_state->open_at,
				      "trace! -   %pLYCN", child);
		} else
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

	if (state->fs->lys_module) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "duplicate 'implements' statement");
		return H_ERROR;
	}

	fd = open(model, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		perror(model);
		exit(1);
	}

	err = lys_parse_fd(state->fs->ly_ctx, fd, LYS_IN_YANG,
			   &state->fs->lys_module);
	if (err) {
		fprintf(stderr, "YANG load failed\n");
		return 1;
	}
	close(fd);

	const struct lys_module *m = state->fs->lys_module;
	struct lysp_import *imp;
	struct yang_prefix *yp;

	yp = calloc(sizeof(*yp), 1);
	yp->prefix = m->prefix;
	yp->name = m->name;
	yp->module = m;

	yang_prefix_add(state->fs->pfxs, yp);

	LY_ARRAY_FOR(m->parsed->imports, struct lysp_import, imp) {
		yp = calloc(sizeof(*yp), 1);
		yp->prefix = imp->prefix;
		yp->name = imp->name;
		yp->module = imp->module;

		yang_prefix_add(state->fs->pfxs, yp);
	}

	yk_token_diag(DIAG_TRACE, tokens[0], "implementing %pSQq rev %pSE %d",
		      m->name, m->revision, m->implemented);

	return H_OK;
}

static enum handler_res handle_import(struct yangkheg_state *state,
				      struct yangkheg_lexer *lex,
				      const struct yangkheg_token *tokens[],
				      struct yk_cblock *cblocks[],
				      size_t tokenc)
{
	struct yangkheg_file file[1];
	struct yangkheg_lexer *imp_lex;
	struct yangkheg_file_state imp_file_state = {
		.parent = state->fs,
		.ly_ctx = state->fs->ly_ctx,
	};

	file->filename = yangkheg_pull_str(lex, STRING);
	file->fd = fopen(file->filename, "r");
	if (!file->fd) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "failed to open %pSQq: %m", file->filename);
		return H_ERROR;
	}
	//yangkheg_pull(lex, ';');

	if (state->parent) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "'import' statement must be used at top level");
		return H_ERROR;
	}

	yk_token_diag(DIAG_TRACE, tokens[0], "starting %pSQq", file->filename);

	imp_lex = yangkheg_begin(file);
	yangkheg_process(&imp_file_state, imp_lex, h_root);
	yangkheg_end(imp_lex);

	yk_token_diag(DIAG_TRACE, tokens[0], "finished %pSQq", file->filename);
	return H_OK;
}

DEFINE_MTYPE_STATIC(YANGKHEG, YANGTYPE, "YANG type information");
DEFINE_MTYPE_STATIC(YANGKHEG, CMAP,     "YANG type to C mapping");

static void close_type(struct yangkheg_state *state,
		       struct yangkheg_token *token)
{
	struct yk_cmap *cmap;

	if (!token)
		return;

	assert(state->stack && state->stack->cmap);
	cmap = state->stack->cmap;

	if (!cmap->kind) {
		yk_token_diag(DIAG_ERR, token,
			      "missing `kind` for type %pLYCT (%s)",
			      cmap->yangtype->lysc_type, cmap->name);
		return;
	}

	switch (cmap->kind) {
	case CMAP_SIMPLE_VALUE:
		if (!cmap->lyd_value) {
			yk_token_diag(DIAG_WARN, token,
				      "missing `lyd-value` for type %pLYCT (%s)",
				      cmap->yangtype->lysc_type, cmap->name);
			return;
		}
		return;

	case CMAP_ALLOC_POINTER:
		if (!cmap->lyd_value) {
			yk_token_diag(DIAG_WARN, token,
				      "missing `lyd-value` for type %pLYCT (%s)",
				      cmap->yangtype->lysc_type, cmap->name);
			return;
		}
		return;
	}
}

handler_prototype(handle_type)
{
	struct yangkheg_stack *stack;

	char *freeme, *item, *colon, *pfx = NULL;
	const struct lys_module *mod;
	struct lysp_module *modp;
	struct lysp_tpdf *tpdf;
	struct lysc_type *typec;

	freeme = item = strdup(tokens[1]->text);
	colon = strchr(item, ':');
	if (colon) {
		*colon++ = '\0';

		item = colon;
		pfx = freeme;
	}

	if (pfx) {
		struct yang_prefix *pfxres;

		pfxres = yang_prefix_find_name(state, pfx);
		if (!pfxres) {
			yk_token_diag(DIAG_ERR, tokens[1],
				      "invalid prefix %pSQq", pfx);
			return H_ERROR;
		}
		mod = pfxres->module;

		yk_token_diag(DIAG_TRACE, tokens[1], "looking for %pSQq in %pLYM",
			      item, mod);

		modp = mod->parsed;

		LY_ARRAY_FOR(modp->typedefs, struct lysp_tpdf, tpdf)
			if (!strcmp(tpdf->name, item))
				break;

		if (!tpdf) {
			yk_token_diag(DIAG_ERR, tokens[1],
				      "cannot find type %pSQq in %pLYM", item, mod);
			free(freeme);
			return H_ERROR;
		}
		if (!tpdf->type.compiled) {
			yk_token_diag(DIAG_TRACE, tokens[1],
				      "ignoring unused type %pSQs in %pLYM", item, mod);
			free(freeme);
			return H_OK;
		}

		typec = tpdf->type.compiled;
	} else {
		yk_token_diag(DIAG_TRACE, tokens[1], "implementing built-in %pSQq",
			      item);

		mod = NULL;
		typec = NULL;
	}

	struct yk_yangtype ref, *yktyp;

	ref.mod = mod;
	ref.name = item;
	yktyp = yk_yangtypes_find(types, &ref);

	if (!yktyp && !mod) {
		yk_token_diag(DIAG_ERR, tokens[1], "refusing to create built-in %pSQq",
			      item);
		free(freeme);
		return H_ERROR;
	} else if (!yktyp) {
		yk_token_diag(DIAG_TRACE, tokens[1], "new type %pLYCT", typec);

		yktyp = XCALLOC(MTYPE_YANGTYPE, sizeof(*yktyp));
		yk_cmaps_init(yktyp->cmaps);
		yktyp->mod = mod;
		yktyp->name = tpdf->name;	/* will stay alive */
		yktyp->lysc_type = typec;

		yk_yangtypes_add(types, yktyp);
	} else {
		yk_token_diag(DIAG_TRACE, tokens[1], "extending %pLYCT", typec);
		assert(yktyp->lysc_type == typec);
	}

	struct yk_cmap *cmap;

	cmap = XCALLOC(MTYPE_CMAP, sizeof(*cmap));
	cmap->yangtype = yktyp;
	cmap->name = yk_cblock_typename(cblocks[3]);
	cmap->origin_loc = yk_token_get(tokens[1]);

	yk_cmaps_add_tail(yktyp->cmaps, cmap);

	stack = XCALLOC(MTYPE_YK_STACK, sizeof(*stack));
	stack->cmap = cmap;
	stack->parent = state->stack;
	stack->close = close_type;
	state->stack = stack;

	free(freeme);
	return H_OK;
}

handler_prototype(handle_dflt)
{
	struct yangkheg_stack *stk = state->stack;
	struct yk_cmap *cmap;
	struct yk_yangtype *yangtype;

	if (!stk || !stk->cmap) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "`default` keyword without a type to apply to");
		return H_ERROR;
	}

	cmap = stk->cmap;
	yangtype = cmap->yangtype;

	if (yangtype->dflt) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "type %pLYCT already has a default ctype (%s)",
			      yangtype->lysc_type, yangtype->dflt->name);
		yk_token_diag(DIAG_WARN, yangtype->dflt->origin_loc,
			      "previous definition was here");
		return H_ERROR;
	}
	cmap->dflt = true;
	yangtype->dflt = cmap;

	return H_OK;
}

handler_prototype(handle_kind)
{
	struct yangkheg_stack *stk = state->stack;
	struct yk_cmap *cmap;

	if (!stk || !stk->cmap) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "`kind` keyword without a type to apply to");
		return H_ERROR;
	}

	cmap = stk->cmap;
	if (cmap->kind) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "`kind` already specified for this type");
		return H_ERROR;
	}

	if (!strcmp(tokens[1]->text, "simple-value"))
		cmap->kind = CMAP_SIMPLE_VALUE;
	else if (!strcmp(tokens[1]->text, "alloc-pointer"))
		cmap->kind = CMAP_ALLOC_POINTER;
	else {
		yk_token_diag(DIAG_ERR, tokens[1],
			      "unrecognized `kind` for type");
		return H_ERROR;
	}
	return H_OK;
}

handler_prototype(handle_lyd_value)
{
	struct yangkheg_stack *stk = state->stack;
	struct yk_cmap *cmap;

	if (!stk || !stk->cmap) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "`lyd-value` keyword without a type to apply to");
		return H_ERROR;
	}

	cmap = stk->cmap;
	if (cmap->lyd_value) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "`lyd-value` already specified for this type");
		return H_ERROR;
	}

	cmap->lyd_value = cblocks[1];
	return H_OK;
}

handler_prototype(handle_key_input)
{
	struct yangkheg_stack *stk = state->stack;
	struct yk_cmap *cmap;

	if (!stk || !stk->cmap) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "`key-input` keyword without a type to apply to");
		return H_ERROR;
	}

	cmap = stk->cmap;
	if (cmap->key_input) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "`key-input` already specified for this type");
		return H_ERROR;
	}

	cmap->key_input = cblocks[1];
	return H_OK;
}

handler_prototype(handle_json_output)
{
	struct yangkheg_stack *stk = state->stack;
	struct yk_cmap *cmap;

	if (!stk || !stk->cmap) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "`json-output` keyword without a type to apply to");
		return H_ERROR;
	}

	cmap = stk->cmap;
	if (cmap->json_output) {
		yk_token_diag(DIAG_ERR, tokens[0],
			      "`json-output` already specified for this type");
		return H_ERROR;
	}

	cmap->json_output = cblocks[1];
	return H_OK;
}

static void ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
	if (path)
		fprintf(stderr, "ly<%d>%s %pSQq\n", level, msg, path);
	else
		fprintf(stderr, "ly<%d>%s\n", level, msg);
}

static struct yk_yangtype builtin_types[] = {
#define type_int_uint(len)                                                     \
	{                                                                      \
		.name = "uint" #len,                                           \
		.basetype = LY_TYPE_UINT ## len,                               \
	},                                                                     \
	{                                                                      \
		.name = "int" #len,                                            \
		.basetype = LY_TYPE_INT ## len,                                \
	}                                                                      \
	/* end */

	type_int_uint(8),
	type_int_uint(16),
	type_int_uint(32),
	type_int_uint(64),

	{
		.name = "boolean",
		.basetype = LY_TYPE_BOOL,
	},
	{
		.name = "string",
		.basetype = LY_TYPE_STRING,
	},
};

bool f_no_line_numbers;

int main(int argc, char **argv)
{
	struct yangkheg_lexer *lex;
	struct yangkheg_file_state file_state = { };
	LY_ERR err;

	struct yangkheg_file file[1];
	const char *yang_models_path = "yang/";

	ykat_mktab();
	yk_yangtypes_init(types);

	for (size_t i = 0; i < array_size(builtin_types); i++) {
		yk_cmaps_init(builtin_types[i].cmaps);
		yk_yangtypes_add(types, &builtin_types[i]);
	}

	char *filename = NULL;

	argc--, argv++;

	while (argc--) {
		char *arg = *argv++;

		if (!strcmp(arg, "--")) {
			argc--, argv++;
			assert(argc == 1 && !filename);
			filename = argv[0];
			break;
		}

		if (arg[0] != '-') {
			assert(!filename);
			filename = arg;
			continue;
		}

		if (!strcmp(arg, "-fno-line-numbers")) {
			f_no_line_numbers = true;
			continue;
		}

		fprintf(stderr, "invalid argument: %s\n", arg);
		exit(1);
	}

	if (!filename) {
		fprintf(stderr, "no filename given\n");
		exit(1);
	}

	file->filename = filename;
	file->fd = fopen(filename, "r");
	if (!file->fd) {
		perror("fopen");
		return 1;
	}

	ly_set_log_clb(ly_log_cb, 1);
	ly_log_options(LY_LOLOG | LY_LOSTORE);

	uint options = LY_CTX_NO_YANGLIBRARY | LY_CTX_DISABLE_SEARCHDIR_CWD;
	err = ly_ctx_new(yang_models_path, options, &file_state.ly_ctx);
	if (err) {
		fprintf(stderr, "YANG initialization failed\n");
		return 1;
	}

	lex = yangkheg_begin(file);
	yangkheg_process(&file_state, lex, h_root);
	yangkheg_end(lex);

	return 0;
}
