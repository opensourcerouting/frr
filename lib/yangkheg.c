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

static const struct yangkheg_token *
yangkheg_pull(struct yangkheg_lexer *lex, int expect)
{
	const struct yangkheg_token *token;

	token = yangkheg_next(lex);
	if (token->token != expect) {
		fprintf(stderr, "%d:%d: unexpected token %d\n",
			token->line, token->col, token->token);
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
	H_CONTINUE = 0,
	H_RETURN,
};

struct yangkheg_stack;

struct yangkheg_handler {
	int token;
	enum handler_res (*fn)(struct yangkheg_stack *stk,
			       struct yangkheg_lexer *lex,
			       const struct yangkheg_token *token);
};

static void yangkheg_handle(struct yangkheg_stack *stk,
			    struct yangkheg_lexer *lex,
			    const struct yangkheg_handler *htab)
{
	const struct yangkheg_token *token;
	const struct yangkheg_handler *h;

	while ((token = yangkheg_next(lex))) {
		for (h = htab; h->token; h++) {
			if (h->token == token->token) {
				enum handler_res res = H_CONTINUE;

				if (h->fn)
					res = h->fn(stk, lex, token);
				if (res == H_RETURN)
					return;
				break;
			}
		}
		if (!h->token) {
			fprintf(stderr, "%d:%d: unhandled token %d\n",
				token->line, token->col, token->token);
			exit(1);
		}
	}

	if (!token)
		return;

	fprintf(stderr, "%d:%d: unexpected token %d\n",
		token->line, token->col, token->token);
	exit(1);
}

struct yangkheg_stack {
	struct yangkheg_stack *parent;

	struct ly_ctx *ly_ctx;
	const struct lys_module *lys_module;
	const struct lysc_node *lysc_node;

	struct yang_prefix_head pfxs[1];
};

static enum handler_res handle_path(struct yangkheg_stack *stk,
				    struct yangkheg_lexer *lex,
				    const struct yangkheg_token *token);
static enum handler_res handle_bind(struct yangkheg_stack *stk,
				    struct yangkheg_lexer *lex,
				    const struct yangkheg_token *token);
static enum handler_res handle_implements(struct yangkheg_stack *stk,
					  struct yangkheg_lexer *lex,
					  const struct yangkheg_token *token);
static enum handler_res handle_blk_begin(struct yangkheg_stack *stk,
					 struct yangkheg_lexer *lex,
					 const struct yangkheg_token *token);
static enum handler_res handle_blk_end(struct yangkheg_stack *stk,
				       struct yangkheg_lexer *lex,
				       const struct yangkheg_token *token);


static const struct yangkheg_handler h_root[] = {
	{ COMMENT,		NULL },
	{ YK_IMPLEMENTS,	handle_implements },
	{ YK_PATH,		handle_path },
	{ 0, NULL },
};

static const struct yangkheg_handler h_path[] = {
	{ COMMENT,		NULL },
	{ YK_PATH,		handle_path },
	{ YKCC_OPEN,		handle_bind },
	{ '{',			handle_blk_begin },
	{ 0, NULL },
};

static const struct yangkheg_handler h_blk[] = {
	{ COMMENT,		NULL },
	{ YK_PATH,		handle_path },
	{ '}',			handle_blk_end },
	{ 0, NULL },
};


static enum handler_res handle_path(struct yangkheg_stack *stk,
				    struct yangkheg_lexer *lex,
				    const struct yangkheg_token *token)
{
	struct yangkheg_stack nextstk;
	char *freeme, *item, *pfx = NULL, *colon;
	const struct lysc_node *yn;
	const struct lys_module *mod;
	struct lysc_ext_instance *ext;

	nextstk = *stk;
	nextstk.parent = stk;

	freeme = item = strdup(token->text);

	colon = strchr(item, ':');
	if (colon) {
		pfx = item;
		*colon++ = '\0';
		item = colon;
	}
	if (pfx) {
		struct yang_prefix *pfxres, ref;

		ref.prefix = pfx;
		pfxres = yang_prefix_find(stk->pfxs, &ref);
		if (!pfxres) {
			fprintf(stderr, "invalid prefix %s\n", pfx);
			exit(1);
		}
		mod = pfxres->module;
	} else if (stk && stk->lysc_node) {
		mod = stk->lysc_node->module;
	} else {
		abort();
	}

	yn = lys_find_child(stk->lysc_node, mod, item, strlen(item),
			    0, 0);
	nextstk.lysc_node = yn;

	printfrr("path: {%s}%s\n", yn->module->name, yn->name);

	LY_ARRAY_FOR(yn->exts, struct lysc_ext_instance, ext) {
		printfrr("\text {%s}%s %pSQq\n", ext->def->module->name,
			 ext->def->name, ext->argument);
	}

	free(freeme);

	yangkheg_handle(&nextstk, lex, h_path);
	return H_RETURN;
}

static enum handler_res handle_bind(struct yangkheg_stack *stk,
				    struct yangkheg_lexer *lex,
				    const struct yangkheg_token *token)
{
	const struct yangkheg_token *ntoken;
	const char *varname = NULL;

	while ((ntoken = yangkheg_next(lex))
	       && (ntoken->token != YKCC_CLOSE)) {
		switch (ntoken->token) {
		case YKCC_WSP:
		case COMMENT:
			continue;
		case YKCC_ID:
			if (varname) {
				fprintf(stderr,
					"bind requires single C token\n");
				exit(1);
			}
			varname = strdup(ntoken->text);
			continue;
		}
		fprintf(stderr, "unexpected %d (%s) in C code\n",
			ntoken->token, ntoken->text);
	}
	if (!varname) {
		fprintf(stderr, "no bind name?\n");
		exit(1);
	}

	printf("\tbind to %s\n", varname);
	return H_CONTINUE;
}

static enum handler_res handle_blk_begin(struct yangkheg_stack *stk,
					 struct yangkheg_lexer *lex,
					 const struct yangkheg_token *token)
{
	yangkheg_handle(stk, lex, h_blk);
	return H_RETURN;
}

static enum handler_res handle_blk_end(struct yangkheg_stack *stk,
				       struct yangkheg_lexer *lex,
				       const struct yangkheg_token *token)
{
	return H_RETURN;
}

static enum handler_res handle_implements(struct yangkheg_stack *stk,
					  struct yangkheg_lexer *lex,
					  const struct yangkheg_token *token)
{
	char *model;
	LY_ERR err;
	int fd;

	model = yangkheg_pull_str(lex, STRING);
	yangkheg_pull(lex, ';');

	if (stk->lys_module) {
		fprintf(stderr, "duplicate 'implements' statement\n");
		exit(1);
	}

	fd = open(model, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		perror(model);
		exit(1);
	}

	err = lys_parse_fd(stk->ly_ctx, fd, LYS_IN_YANG, &stk->lys_module);
	if (err) {
		fprintf(stderr, "YANG load failed\n");
		return 1;
	}
	close(fd);

	yang_prefix_init(stk->pfxs);

	const struct lys_module *m = stk->lys_module;
	struct lysp_import *imp;
	struct yang_prefix *yp;

	yp = calloc(sizeof(*yp), 1);
	yp->prefix = m->prefix;
	yp->name = m->name;
	yp->module = m;

	yang_prefix_add(stk->pfxs, yp);

	LY_ARRAY_FOR(m->parsed->imports, struct lysp_import, imp) {
		yp = calloc(sizeof(*yp), 1);
		yp->prefix = imp->prefix;
		yp->name = imp->name;
		yp->module = imp->module;

		yang_prefix_add(stk->pfxs, yp);
	}

	printfrr("implementing %pSQq rev %pSQq %d\n", m->name, m->revision,
		 m->implemented);

	return H_CONTINUE;
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
	struct yangkheg_stack stk = { };
	LY_ERR err;

	FILE *fd;
	const char *yang_models_path = "yang/";

	fd = fopen(argv[1], "r");
	if (!fd) {
		perror("fopen");
		return 1;
	}

	ly_set_log_clb(ly_log_cb, 1);
	ly_log_options(LY_LOLOG | LY_LOSTORE);

	uint options = LY_CTX_NO_YANGLIBRARY | LY_CTX_DISABLE_SEARCHDIR_CWD;
	err = ly_ctx_new(yang_models_path, options, &stk.ly_ctx);
	if (err) {
		fprintf(stderr, "YANG initialization failed\n");
		return 1;
	}

	lex = yangkheg_begin(fd);
	yangkheg_handle(&stk, lex, h_root);
	yangkheg_end(lex);

	return 0;
}
