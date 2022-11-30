%{
#define YYDEBUG 1
%}

%locations
/* define parse.error verbose */
%define api.pure full
/* define api.prefix {ykat_} */
%token-table

%defines "lib/yangkheg-yk_atexpr_eval.h"
%output  "lib/yangkheg-yk_atexpr_eval.c"

/* note: code blocks are output in order, to both .c and .h:
 *  1. %code requires
 *  2. %union + bison forward decls
 *  3. %code provides
 */
%code requires {
  #include "config.h"

  #include <stdbool.h>
  #include <stdlib.h>
  #include <string.h>
  #include <ctype.h>

  #include "yangkheg.h"

#define YKAT_LTYPE		struct ykat_loc
#define YYLOCATION_PRINT	ykat_locprint
#define YYLLOC_DEFAULT(cur, rhs, n)                                            \
	do {                                                                   \
		if (n) {                                                       \
			(cur).first = YYRHSLOC(rhs, 1).first;                  \
			(cur).last = YYRHSLOC(rhs, n).last;                    \
		} else {                                                       \
			(cur).first = YYRHSLOC(rhs, 0).last;                   \
			(cur).last = YYRHSLOC(rhs, 0).last;                    \
		}                                                              \
	} while (0)

}

%union {
  struct yangkheg_token *token;
  intmax_t number;
  const char *string;
}

%code provides {
extern int ykat_lex(YKAT_STYPE *val, YKAT_LTYPE *loc, struct ykat_ctx *ctx);
extern int ykat_error(YKAT_LTYPE *loc, struct ykat_ctx *ctx, const char *msg);
extern int ykat_locprint(FILE *fd, const YKAT_LTYPE *loc);
}

/* union types for lexed tokens */
%token <token>	YKAT_ID
%token <token>	YKAT_STRING

%type <string>	strexpr

%code {

}

%lex-param	{struct ykat_ctx *ctx}
%parse-param	{struct ykat_ctx *ctx}

/* called automatically before yyparse */
%initial-action {
}

%%

start:
	'@' {
		printf("bison: @@\n");
	}
|
	YKAT_ID '@' {
		printf("bison: @%s@\n", $1->text);
	}
|
	"debug_show_type" '(' strexpr ')' {
		printf("bison: dst(%s)\n", $3);
	}
;

strexpr:
	YKAT_STRING {
		$$ = $1->text;
	}
;

%%

#include "typesafe.h"
#include "jhash.h"

PREDECL_HASH(ykat_ids);

struct ykat_id {
	struct ykat_ids_item itm;
	const char *text;
	int value;
};

static inline int ykat_cmp(const struct ykat_id *a, const struct ykat_id *b)
{
	return strcmp(a->text, b->text);
}

static inline uint32_t ykat_hash(const struct ykat_id *i)
{
	return jhash(i->text, strlen(i->text), 0xc5793144);
}

DECLARE_HASH(ykat_ids, struct ykat_id, itm, ykat_cmp, ykat_hash);

static struct ykat_id identry[array_size(yytname)];
static struct ykat_ids_head ids[1];

void ykat_mktab(void)
{
	int token = 254;

	ykat_ids_init(ids);

	for (size_t i = 0; i < array_size(identry); i++) {
		identry[i].value = token++;
		identry[i].text = yytname[i];
		if (yytname[i])
			ykat_ids_add(ids, &identry[i]);
	}
}

int ykat_find_id_token(const char *text)
{
	struct ykat_id ref = { .text = text }, *res;

	res = ykat_ids_find(ids, &ref);
	return res ? res->value : -1;
}
