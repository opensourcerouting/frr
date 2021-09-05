#ifndef _YANGKHEG_H
#define _YANGKHEG_H

#include <stdio.h>

enum yangkheg_tokens {
	ID = 258,
	PREPROC,
	STRING,
	COMMENT,

	YK_PATH,	/* 262 */
	YK_IMPLEMENTS,
	YK_BIND,
	YK_CREATE,
	YK_MODIFY,
	YK_DESTROY,

	YKCC_OPEN,	/* 268 */
	YKCC_CLOSE,
	YKCC_WSP,
	YKCC_ID,
	YKCC_OPERATOR,
};

struct yangkheg_token {
	int token;

	const char *text;
	char *raw, *cooked;

	int line, col;
};

struct yangkheg_lexer;

extern struct yangkheg_lexer *yangkheg_begin(FILE *fd);
extern const struct yangkheg_token *yangkheg_next(struct yangkheg_lexer *lex);
extern void yangkheg_end(struct yangkheg_lexer *lex);

#endif /* _YANGKHEG_H */
