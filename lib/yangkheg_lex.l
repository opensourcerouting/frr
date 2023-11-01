#line 1 "lib/yangkheg_lex.l"
/*
 * clippy (CLI preparator in python) C pseudo-lexer
 * Copyright (C) 2016-2017  David Lamparter for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* This is just enough of a lexer to make rough sense of a C source file.
 * It handles C preprocessor directives, strings, and looks for FRR-specific
 * idioms (aka DEFUN).
 *
 * There is some preliminary support for documentation comments for DEFUNs.
 * They would look like this (note the ~):  (replace \ by /)
 *
 * \*~  documentation for foobar_cmd
 *  *   parameter does xyz
 *  *\
 * DEFUN(foobar_cmd, ...)
 *
 * This is intended for user documentation / command reference.  Don't put
 * code documentation in it.
 */

%top{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
}
%{
/* ignore harmless bugs in old versions of flex */
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-value"

#include "yangkheg.h"

#include <string.h>
#include <stdlib.h>
#include "printfrr.h"

struct yangkheg_lexer {
	yyscan_t scn;

	int comment_link;
	int preproc_link;
	int string_link;

	char string_end;
	int code_depth;

	size_t bytepos;

	struct yangkheg_file *file;
	struct yangkheg_token *tkn;
};

static void set_start(struct yangkheg_lexer *lex);
static void feed_pos(struct yangkheg_lexer *lex, const char *text);

static void extendbuf(char **what, const char *arg)
{
	if (!*what)
		*what = strdup(arg);
	else {
		size_t vall = strlen(*what), argl = strlen(arg);
		*what = realloc(*what, vall + argl + 1);
		memcpy(*what + vall, arg, argl);
		(*what)[vall + argl] = '\0';
	}
}
#define extendr(x) extendbuf(&yyextra->tkn->raw, x)
#define extendc(x) extendbuf(&yyextra->tkn->cooked, x)

#define YY_USER_ACTION                                                         \
	feed_pos(yyextra, yytext);                                             \
	/* end */

#ifndef __clang_analyzer__
%}

CID		[A-Za-z_][A-Za-z0-9_]*
YID		[A-Za-z_][A-Za-z0-9_-]*
OPERATOR	[!%&/\[\]()=?:^|\*.,;><~'\\+-]

%pointer
%option warn 8bit noinput nounput noyywrap
%option reentrant
%option debug

%option yylineno
%option outfile="lib/yangkheg_lex.c"
%option header-file="lib/yangkheg_lex.h"
%option prefix="kheg_yy"
%option extra-type="struct yangkheg_lexer *"

%s c_code

%x comment
%x linecomment
%x rstring
%x preproc

%%
				/* comments */
<INITIAL,preproc,c_code>"/*"	{
					yyextra->comment_link = YY_START;
					extendr(yytext);
					BEGIN(comment);
				}
<comment>[^*\n]*		extendr(yytext);
<comment>"*"+[^*/\n]*		extendr(yytext);
<comment>\n			extendr(yytext);
<comment>"*"+"/"		{
					extendr(yytext);
					BEGIN(yyextra->comment_link);
					return COMMENT;
				}

				/* line comments */
"//"				extendr(yytext); yyextra->comment_link = YY_START; BEGIN(linecomment);
<preproc>"//"			extendr(yytext); yyextra->comment_link = yyextra->preproc_link; BEGIN(linecomment);
<linecomment>[^\n]*		extendr(yytext);
<linecomment>\n			BEGIN(yyextra->comment_link); return COMMENT;

				/* #preproc */
#				{
					if (yycolumn != 0)
						return '#';
					else {
						yyextra->preproc_link = YY_START;
						extendr("#");
						BEGIN(preproc);
					}
				}
<preproc>[^\n\\]+		extendr(yytext);
<preproc>\\\n			extendr(yytext);
<preproc>\\+[^\n]		extendr(yytext);
<preproc>\n			BEGIN(yyextra->preproc_link); return PREPROC;

				/* "strings" and 'strings' */
[\"\']				{
					yyextra->string_end = yytext[0];
					extendr(yytext);
					yyextra->tkn->cooked = strdup("");
					yyextra->string_link = YY_START;
					BEGIN(rstring);
				}
<rstring>[\"\']			{
					extendr(yytext);
					if (yytext[0] == yyextra->string_end) {
						BEGIN(yyextra->string_link);
						return STRING;
					}
				}
<rstring>\\\n			/* ignore */
<rstring>\\n			extendr(yytext); extendc("\n");
<rstring>\\t			extendr(yytext); extendc("\t");
<rstring>\\e			extendr(yytext); extendc("\e");
<rstring>\\.			extendr(yytext); extendc(yytext + 1);
<rstring>[^\\\"\']+		extendr(yytext); extendc(yytext);

<INITIAL>"${"			yyextra->code_depth = 0; BEGIN(c_code); return YKCC_OPEN;

<c_code>[ \t\n]+		yyextra->tkn->raw = strdup(yytext); return YKCC_WSP;
<c_code>{CID}			yyextra->tkn->raw = strdup(yytext); return YKCC_ID;
<c_code>"{"			yyextra->tkn->raw = strdup(yytext); yyextra->code_depth++; return '{';
<c_code>"}"			{
					if (!yyextra->code_depth) {
						BEGIN(INITIAL);
						return YKCC_CLOSE;
					}
					yyextra->tkn->raw = strdup(yytext);
					yyextra->code_depth--;
					return '}';
				}
<c_code>@			yyextra->tkn->text = "@"; return YKCC_AT;
<c_code>.			return yytext[0];

<INITIAL>"implements"		return YK_IMPLEMENTS;
<INITIAL>"import"		return YK_IMPORT;
<INITIAL>"emit"			return YK_EMIT;
<INITIAL>"trace!"		return YK_TRACE;
<INITIAL>"template"		return YK_TEMPLATE;

<INITIAL>"noop"			return YK_NOOP;
<INITIAL>"nodeval"		return YK_NODEVAL;
<INITIAL>"lval"			return YK_LVAL;

<INITIAL>"create"		return YK_CREATE;
<INITIAL>"modify"		return YK_MODIFY;
<INITIAL>"destroy"		return YK_DESTROY;
<INITIAL>"first"		return YK_FIRST;
<INITIAL>"next"			return YK_NEXT;

<INITIAL>"type"			return YK_TYPE;
<INITIAL>"ctype"		return YK_CTYPE;
<INITIAL>"default"		return YK_DEFAULT;
<INITIAL>"kind"			return YK_KIND;
<INITIAL>"lyd-value"		return YK_LYD_VALUE;
<INITIAL>"key-input"		return YK_KEY_INPUT;
<INITIAL>"json-input"		return YK_JSON_INPUT;
<INITIAL>"json-output"		return YK_JSON_OUTPUT;

<INITIAL>"{"			return '{';
<INITIAL>"}"			return '}';
<INITIAL>";"			return ';';

<INITIAL>[ \t\n]+		set_start(yyextra);
<INITIAL>\/[a-zA-Z_][a-zA-Z0-9_.-]*(:[a-zA-Z_][a-zA-Z0-9_.-]*)? {
					BEGIN(INITIAL);
					/* exclude starting / */
					yyextra->tkn->raw = strdup(yytext + 1);
					return YK_PATH;
				}


<INITIAL>{YID}			yyextra->tkn->raw = strdup(yytext); return ID;

	/* {OPERATOR}			yyextra->value = strdup(yytext); return YKCCOPERATOR; */

.				return yytext[0];

%%

#endif /* __clang_analyzer__ */

struct yangkheg_lexer *yangkheg_begin(struct yangkheg_file *file)
{
	struct yangkheg_lexer *lex = calloc(1, sizeof(*lex));

	lex->file = file;

	kheg_yylex_init_extra(lex, &lex->scn);
	kheg_yyset_in(file->fd, lex->scn);
	return lex;
}

static void set_start(struct yangkheg_lexer *lex)
{
	lex->tkn->file = lex->file;
	lex->tkn->line_s = kheg_yyget_lineno(lex->scn);
	lex->tkn->col_s = kheg_yyget_column(lex->scn);
	lex->tkn->byte_s = lex->bytepos;
}

static void feed_pos(struct yangkheg_lexer *lex, const char *text)
{
	int col = kheg_yyget_column(lex->scn);

	for (; text && *text; text++) {
		lex->bytepos++;

		if (*text == '\n')
			col = 0;
		else
			col++;
	}

	kheg_yyset_column(col, lex->scn);
}

struct yangkheg_token *yangkheg_next(struct yangkheg_lexer *lex)
{
	yk_token_put(&lex->tkn);

	lex->tkn = yk_token_create();
	set_start(lex);

	lex->tkn->token = kheg_yylex(lex->scn);

	if (lex->tkn->token == YY_NULL)
		return NULL;

	if (!lex->tkn->text)
		lex->tkn->text = lex->tkn->raw;
	lex->tkn->line_e = kheg_yyget_lineno(lex->scn);
	lex->tkn->col_e = kheg_yyget_column(lex->scn);

	return lex->tkn;
}

void yangkheg_end(struct yangkheg_lexer *lex)
{
	yk_token_put(&lex->tkn);
	kheg_yylex_destroy(lex->scn);
	free(lex);
}
