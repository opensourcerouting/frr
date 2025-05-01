// SPDX-License-Identifier: NONE
/*
 * This is part of the libb64 project, and has been placed in the public domain.
 * For details, see http://sourceforge.net/projects/libb64
 */

#ifndef _BASE64_H_
#define _BASE64_H_

#include <stdlib.h>

enum base64_encodestep {
	step_A, step_B, step_C
};

struct base64_encodestate {
	enum base64_encodestep step;
	char result;
};

void base64_init_encodestate(struct base64_encodestate *state_in);

char base64_encode_value(char value_in);

int base64_encode_block(const char *plaintext_in, int length_in, char *code_out,
			struct base64_encodestate *state_in);

int base64_encode_blockend(char *code_out, struct base64_encodestate *state_in);

static inline size_t base64_encoded_length(size_t raw_len)
{
	return (raw_len + 2) / 3 * 4;
}

enum base64_decodestep {
	step_a, step_b, step_c, step_d
};

struct base64_decodestate {
	enum base64_decodestep step;
	char plainchar;
};

void base64_init_decodestate(struct base64_decodestate *state_in);

signed char base64_decode_value(signed char value_in);

int base64_decode_block(const char *code_in, int length_in, char *plaintext_out,
			struct base64_decodestate *state_in);

static inline size_t base64_decoded_max_length(size_t base64_len)
{
	return (base64_len * 3) / 4;
}

#endif /* _BASE64_H_ */
