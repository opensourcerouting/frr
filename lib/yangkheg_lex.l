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

	struct yangkheg_token tkn;
};

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
#define extendr(x) extendbuf(&yyextra->tkn.raw, x)
#define extendc(x) extendbuf(&yyextra->tkn.cooked, x)

#ifndef __clang_analyzer__
%}

ID		[A-Za-z0-9_]+
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

/* option bison-bridge */
/* option bison-locations */

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
					yyextra->tkn.cooked = strdup("");
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

<c_code>[ \t\n]+		yyextra->tkn.text = yytext; return YKCC_WSP;
<c_code>{ID}			yyextra->tkn.text = yytext; return YKCC_ID;
<c_code>"{"			yyextra->tkn.text = yytext; yyextra->code_depth++; return YKCC_OPERATOR;
<c_code>"}"			{
					if (!yyextra->code_depth) {
						BEGIN(INITIAL);
						return YKCC_CLOSE;
					}
					yyextra->tkn.text = yytext;
					yyextra->code_depth--;
					return YKCC_OPERATOR;
				}
<c_code>.			return yytext[0];

<INITIAL>"implements"		return YK_IMPLEMENTS;
<INITIAL>"bind"			return YK_BIND;
<INITIAL>"create"		return YK_CREATE;
<INITIAL>"modify"		return YK_MODIFY;
<INITIAL>"destroy"		return YK_DESTROY;
<INITIAL>"{"			return '{';
<INITIAL>"}"			return '}';
<INITIAL>";"			return ';';

<INITIAL>[ \t\n]+		/* ignore */
<INITIAL>\/[a-zA-Z_][a-zA-Z_.-]*(:[a-zA-Z_][a-zA-Z_.-]*)? {
					BEGIN(INITIAL);
					/* exclude starting / */
					yyextra->tkn.text = yytext + 1;
					return YK_PATH;
				}


{ID}				yyextra->tkn.text = yytext; return ID;

	/* {OPERATOR}			yyextra->value = strdup(yytext); return YKCCOPERATOR; */

.				return yytext[0];

%%

#endif /* __clang_analyzer__ */

struct yangkheg_lexer *yangkheg_begin(FILE *fd)
{
	struct yangkheg_lexer *lex = malloc(sizeof(*lex));

	kheg_yylex_init_extra(lex, &lex->scn);
	kheg_yyset_in(fd, lex->scn);

	return lex;
}

const struct yangkheg_token *yangkheg_next(struct yangkheg_lexer *lex)
{
	free(lex->tkn.raw);
	free(lex->tkn.cooked);

	memset(&lex->tkn, 0, sizeof(lex->tkn));

	lex->tkn.token = kheg_yylex(lex->scn);
	if (lex->tkn.token == YY_NULL)
		return NULL;

	if (!lex->tkn.text)
		lex->tkn.text = lex->tkn.raw;
	lex->tkn.line = kheg_yyget_lineno(lex->scn);
	lex->tkn.col = kheg_yyget_column(lex->scn);

	return &lex->tkn;
}

void yangkheg_end(struct yangkheg_lexer *lex)
{
	free(lex->tkn.raw);
	free(lex->tkn.cooked);

	kheg_yylex_destroy(lex->scn);
	free(lex);
}

#if 0
static int kheg_yylex_clr(yyscan_t scn, char **retbuf, char **cooked)
{
	struct yangkheg_lexer *state;
	state = kheg_yyget_extra(scn);
	*retbuf = state->tkn.raw;
	state->tkn.raw = NULL;
	*cooked = state->tkn.cooked;
	state->tkn.cooked = NULL;
	return rv;
}

void yangkheg_dump(const char *filename);

void yangkheg_dump(const char *filename)
{

	while ((token = kheg_yylex_clr(scn, &tval, &tcook)) != YY_NULL) {
                int lineno = ;
		const char *ttype = "*";

		if (token < 256) {
			printfrr("%4d: char %c\n", lineno, token);

			continue;
		}

		switch (token) {
#define t(name) case name: ttype = #name; break
		t(ID);
		t(PREPROC);
		t(STRING);
		t(YK_PATH);
		t(YK_IMPLEMENTS);
		t(YK_BIND);
		t(YK_CREATE);
		t(YK_MODIFY);
		t(YK_DESTROY);
		t(YKCC_OPEN);
		t(YKCC_CLOSE);
		t(YKCC_WSP);
		t(YKCC_ID);
		t(YKCC_OPERATOR);
		t(COMMENT);
		}

		printfrr("%4d:TOKEN %s/%d %pSQq %pSQq\n", lineno, ttype, token, tval, tcook);
		free(tval);
		free(tcook);

	}

	puts("");
	kheg_yylex_destroy(scn);
	fclose(fd);
}

#endif
