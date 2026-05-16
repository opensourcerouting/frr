// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2026  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_PRIVSEP_CORE_H
#define _FRR_PRIVSEP_CORE_H

#include <stddef.h>
#include <stdint.h>

#include "lib/compiler.h"

/* "descriptor" for privilege-separated function */
struct privsep_op {
	int32_t opcode;

	size_t in_size, out_size;
	unsigned n_in_fds, n_out_fds;

	int (*impl)(const void *input, void *output, const int in_fds[], int out_fds[]);

	const char *opname;
	const unsigned *capabilities;

	/* these two may optionally be used to perform additional setup,
	 * before the privsep process drops into its main event loop
	 */
	void (*init_highpriv)(void);
	void (*init_lowpriv)(void);
};

struct ps_nothing {
	/* empty output arg */
};

/* this needs to be called for any function that a daemon wants to use.
 * calling multiple times is fine.  modules and libraries may also use this.
 *
 * The calls MUST be before privsep_fork(), it is not possible to enable privsep
 * functions afterwards.
 */
extern void privsep_need(const struct privsep_op *op);

/* main entry, use the wrappers provided by the macros below */
extern int privsep_call(const struct privsep_op *op, const void *input, void *output,
			const int in_fds[], int out_fds[]);

/* only libfrr.c should call this
 * log_sock is a unix datagram socket to carry log messages back from privsep to main
 */
extern void privsep_fork(int *log_sock);

/* opens an additional privsetp control socket and returns it.
 * must be used to give each thread its own socket, otherwise they'll trample on each other
 */
extern int psep_extra_socket(void);
extern const struct privsep_op _psep_extra_socket[1];

/* notes for the following 3 macros:
 *
 * - the name must match along the functions, struct, and whatnot.  It is not possible to deviate
 *   from the naming scheme.
 * - do not include psep_ or privsep_ in name
 *
 * - in_type: should be "struct ps_in_name"
 * - out_type: should be "struct ps_out_name", or if you don't need it use _NOOUT below
 *
 * - n_in_fds & n_out_fds: number of file descriptors to pass in each direction.
 *   NB on file descriptors:
 *   - all FDs must always be used, they are not optional
 *   - when changing an existing FD (e.g. setsockopt), only pass it "in".  it is not necessary
 *     to "give it back" after changing it, it's the same FD.
 *   - the privsep side automatically closes all file descriptors after a call completes,
 *     don't close anything manually
 *
 * - capabs: a brace-enclosed list of Linux capabilities with a trailing comma at the end, e.g.
 *     (CAP_NET_ADMIN, ) or (CAP_NET_RAW, CAP_NET_ADMIN, )
 *
 * - varargs: other fields to set in struct privsep_op (e.g. .init)
 */
#define DEFINE_PRIVSEP_CALL_COMMON(name, in_type, out_type, n_in_fds_, n_out_fds_, capabs, ...)   \
	/* ESC strips the () that capabs comes with, ~0U is then the terminator */                \
	const unsigned _psep_##name##_caps[] = { ESC capabs ~0U };                                \
	const struct privsep_op _psep_##name[1] = { {                                             \
		.opcode = PRIVSEP_##name,                                                         \
		.in_size = sizeof(in_type),                                                       \
		.out_size = sizeof(out_type),                                                     \
		.n_in_fds = n_in_fds_,                                                            \
		.n_out_fds = n_out_fds_,                                                          \
		.impl = _psep_##name##_wrap,                                                      \
		.opname = #name,                                                                  \
		.capabilities = _psep_##name##_caps,                                              \
		##__VA_ARGS__,                                                                    \
	} };                                                                                      \
	MACRO_REQUIRE_SEMICOLON()

/* "full" variant with {data,fd} {in,out}.  cf. variant without data out below. */
#define DEFINE_PRIVSEP_CALL(name, in_type, out_type, n_in_fds, n_out_fds, capabs, ...)            \
	static int privsep_impl_##name(const in_type *input, out_type *output,                    \
				       const int in_fds[n_in_fds], int out_fds[n_out_fds]);       \
	static int _psep_##name##_wrap(const void *input, void *output, const int in_fds[],       \
				       int out_fds[])                                             \
	{                                                                                         \
		return privsep_impl_##name(input, output, in_fds, out_fds);                       \
	}                                                                                         \
                                                                                                  \
	DEFINE_PRIVSEP_CALL_COMMON(name, in_type, out_type, n_in_fds, n_out_fds, capabs,          \
				   __VA_ARGS__);                                                  \
                                                                                                  \
	static inline int privsep_##name(const in_type *input, out_type *output,                  \
					 const int in_fds[n_in_fds], int out_fds[n_out_fds])      \
	{                                                                                         \
		return privsep_call(&_psep_##name, input, output, in_fds, out_fds);               \
	}                                                                                         \
                                                                                                  \
	MACRO_REQUIRE_SEMICOLON()

/* same as above, but no "output" struct
 * most privsep functions don't use the output struct; the return value and out_fds still works.
 */
#define DEFINE_PRIVSEP_CALL_NOOUT(name, in_type, n_in_fds, n_out_fds, capabs, ...)                \
	static int privsep_impl_##name(const in_type *input, const int in_fds[n_in_fds],          \
				       int out_fds[n_out_fds]);                                   \
	static int _psep_##name##_wrap(const void *input, void *output, const int in_fds[],       \
				       int out_fds[])                                             \
	{                                                                                         \
		return privsep_impl_##name(input, in_fds, out_fds);                               \
	}                                                                                         \
                                                                                                  \
	DEFINE_PRIVSEP_CALL_COMMON(name, in_type, struct ps_nothing, n_in_fds, n_out_fds, capabs, \
				   __VA_ARGS__);                                                  \
                                                                                                  \
	static inline int privsep_##name(const in_type *input, const int in_fds[n_in_fds],        \
					 int out_fds[n_out_fds])                                  \
	{                                                                                         \
		return privsep_call(&_psep_##name, input, NULL, in_fds, out_fds);                 \
	}                                                                                         \
                                                                                                  \
	MACRO_REQUIRE_SEMICOLON()

/* all exported calls must be listed here.  They can be implemented whereever.  Or not. */
enum privsep_ops {
	PRIVSEP_extra_socket = 1,
	PRIVSEP_netns_socket,
	PRIVSEP_setsockopt_int,
	PRIVSEP_bind,
	PRIVSEP_getaddrinfo,
	PRIVSEP_netns_create,
	PRIVSEP_netns_destroy,

	_PRIVSEP_COUNT,
};

#endif /* _FRR_PRIVSEP_CORE_H */
