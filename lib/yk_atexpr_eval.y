%{
#define YYDEBUG 1
%}

%locations
/* define parse.error verbose */
%define api.pure full
/* define api.prefix {ykat_} */

%defines "lib/yangkheg-yk_atexpr_eval.h"
%output  "lib/yangkheg-yk_atexpr_eval.c"

/* note: code blocks are output in order, to both .c and .h:
 *  1. %code requires
 *  2. %union + bison forward decls
 *  3. %code provides
 * command_lex.h needs to be included at 3.; it needs the union and YYSTYPE.
 * struct parser_ctx is needed for the bison forward decls.
 */
%code requires {
  #include "config.h"

  #include <stdbool.h>
  #include <stdlib.h>
  #include <string.h>
  #include <ctype.h>

  #include "yangkheg.h"

/*
  #define YYSTYPE CMD_YYSTYPE
  #define YYLTYPE CMD_YYLTYPE
  struct parser_ctx;
 */
}

%union {
  struct yangkheg_token *token;
  intmax_t number;
  char *string;
}

%code provides {
}

/* union types for lexed tokens */
%token <token>  YKAT_ID
%token <token>  YKAT_AT

%code {

}

/* yyparse parameters */
%lex-param {struct ykat_ctx *ctx}
%parse-param {struct ykat_ctx *ctx}

/* called automatically before yyparse */
%initial-action {
}

%%

start:
	YKAT_ID {
	}
;

%%

