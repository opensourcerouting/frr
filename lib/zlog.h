/*
 * Copyright (c) 2015-19  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _FRR_ZLOG_H
#define _FRR_ZLOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/uio.h>

#include "atomlist.h"
#include "frrcu.h"
#include "memory.h"
#include "hook.h"
#include "typesafe.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MGROUP(LOG)

extern char zlog_prefix[];
extern size_t zlog_prefixsz;
extern int zlog_tmpdirfd;

PREDECL_RBTREE_UNIQ(zlog_debugflags)

enum {
	ZDF_CONFIG = (1 << 0),
	ZDF_EPHEMERAL = (1 << 1),
};

struct zlog_debugflag {
	atomic_uint_fast32_t enable;

	const char *code_name;
	const char *cli_name;

	struct zlog_debugflags_item zdf_item;
};

extern void zlog_debugflag_register(struct zlog_debugflag *zdf);

#define DECLARE_DEBUGFLAG(name) \
	extern struct zlog_debugflag name[1];
#define DEFINE_DEBUGFLAG(name, cli_name_) \
	struct zlog_debugflag name[1] = { { \
		.code_name = #name, \
		.cli_name = cli_name_, \
	} }; \
	static void _zdfinit_##name(void) __attribute__((_CONSTRUCTOR(1200))); \
	static void _zdfinit_##name(void) \
	{ \
		zlog_debugflag_register(name); \
	}; \
	/* end */

struct vty;
struct cmd_token;

extern int zlog_debugflag_cli(struct zlog_debugflag *zdf, struct vty *vty,
			       int argc, struct cmd_token *argv[]);

struct xref_logmsg {
	struct xref xref;

	const char *fmtstring;
	uint32_t priority;
	uint32_t ec;
};

struct xrefdata_logmsg {
	struct xrefdata xrefdata;

	/* nothing more here right now */
};

struct xref_logdebug {
	union {
		/* make xref directly accessible */
		struct xref xref;
		struct xref_logmsg logmsg;
	};

	struct zlog_debugflag *debugflag;
};

/* These functions are set up to write to stdout/stderr without explicit
 * initialization and/or before config load.  There is no need to call e.g.
 * fprintf(stderr, ...) just because it's "too early" at startup.  Depending
 * on context, it may still be the right thing to use fprintf though -- try to
 * determine wether something is a log message or something else.
 */

extern void vzlogx(const struct xref_logmsg *xref, int prio,
		   const char *fmt, va_list ap);
#define vzlog(prio, ...) vzlogx(NULL, prio, __VA_ARGS__)

extern void vzlogdbg(const struct xref_logdebug *xref, int prio, const char *fmt, va_list ap);

PRINTFRR(2, 3)
static inline void zlog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vzlog(prio, fmt, ap);
	va_end(ap);
}

PRINTFRR(2, 3)
static inline void zlog_ref(const struct xref_logmsg *xref,
			    const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vzlogx(xref, xref->priority, fmt, ap);
	va_end(ap);
}

PRINTFRR(2, 3)
static inline void zlog_dbgxref(const struct xref_logdebug *xref, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vzlogdbg(xref, LOG_DEBUG, fmt, ap);
	va_end(ap);
}

#define _zlog_ref(prio, msg, ...) do {                                         \
		static struct xrefdata _xrefdata = {                           \
			.hashstr = (msg),                                      \
			.hashu32 = { (prio), 0 },                              \
		};                                                             \
		static const struct xref_logmsg _xref __attribute__((used)) = {\
			.xref = XREF_INIT(XREFT_LOGMSG, &_xrefdata, __func__), \
			.fmtstring = (msg),                                    \
			.priority = (prio),                                    \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		zlog_ref(&_xref, (msg), ## __VA_ARGS__);                       \
	} while (0)

#define zlog_err(...)    _zlog_ref(LOG_ERR, __VA_ARGS__)
#define zlog_warn(...)   _zlog_ref(LOG_WARNING, __VA_ARGS__)
#define zlog_info(...)   _zlog_ref(LOG_INFO, __VA_ARGS__)
#define zlog_notice(...) _zlog_ref(LOG_NOTICE, __VA_ARGS__)
#define zlog_debug(...)  _zlog_ref(LOG_DEBUG, __VA_ARGS__)

#define zlog_debugif(zdf, msg, ...) do {                                       \
		static struct xrefdata _xrefdata = {                           \
			.hashstr = (msg),                                      \
			.hashu32 = { LOG_DEBUG, 0 },                           \
		};                                                             \
		static const struct xref_logdebug _xref                        \
				__attribute__((used)) = {                      \
			.logmsg = {                                            \
				.xref = XREF_INIT(XREFT_LOGMSG, &_xrefdata,    \
						  __func__),                   \
				.fmtstring = (msg),                            \
				.priority = LOG_DEBUG,                         \
			},                                                     \
			.debugflag = (zdf),                                    \
		};                                                             \
		XREF_LINK(_xref.logmsg.xref);                                  \
		zlog_dbgxref(&_xref, (msg), ## __VA_ARGS__);                   \
	} while (0)


#define _zlog_ecref(ec_, prio, msg, ...) do {                                  \
		static struct xrefdata _xrefdata = {                           \
			.hashstr = (msg),                                      \
			.hashu32 = { (prio), (ec_) },                          \
		};                                                             \
		static const struct xref_logmsg _xref __attribute__((used)) = {\
			.xref = XREF_INIT(XREFT_LOGMSG, &_xrefdata, __func__), \
			.fmtstring = (msg),                                    \
			.priority = (prio),                                    \
			.ec = (ec_),                                           \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		zlog_ref(&_xref, "[EC %u] " msg, ec_, ## __VA_ARGS__);         \
	} while (0)

#define flog_err(ferr_id, format, ...)                                         \
	_zlog_ecref(ferr_id, LOG_ERR, format, ## __VA_ARGS__)
#define flog_warn(ferr_id, format, ...)                                        \
	_zlog_ecref(ferr_id, LOG_WARNING, format, ## __VA_ARGS__)

#define flog_err_sys(ferr_id, format, ...)                                     \
	flog_err(ferr_id, format, ##__VA_ARGS__)
#define flog(priority, ferr_id, format, ...)                                   \
	zlog(priority, "[EC %u] " format, ferr_id, ##__VA_ARGS__)

extern void zlog_sigsafe(const char *text, size_t len);

/* extra priority value to disable a target without deleting it */
#define ZLOG_DISABLED	(LOG_EMERG-1)

/* zlog_msg encapsulates a particular logging call from somewhere in the code.
 * The same struct is passed around to all zlog_targets.
 *
 * This is used to defer formatting the log message until it is actually
 * requested by one of the targets.  If none of the targets needs the message
 * formatted, the formatting call is avoided entirely.
 *
 * This struct is opaque / private to the core zlog code.  Logging targets
 * should use zlog_msg_* functions to get text / timestamps / ... for a
 * message.
 */

struct zlog_msg;

extern int zlog_msg_prio(struct zlog_msg *msg);
extern const struct xref_logmsg *zlog_msg_xref(struct zlog_msg *msg);

/* pass NULL as textlen if you don't need it. */
extern const char *zlog_msg_text(struct zlog_msg *msg, size_t *textlen);

struct zlog_kw_frame;
extern const struct zlog_kw_frame *zlog_msg_frame(struct zlog_msg *msg);

/* timestamp formatting control flags */

/* sub-second digit count */
#define ZLOG_TS_PREC		0xfU

/* 8601:   0000-00-00T00:00:00Z      (if used with ZLOG_TS_UTC)
 *         0000-00-00T00:00:00+00:00 (otherwise)
 * Legacy: 0000/00/00 00:00:00       (no TZ indicated!)
 */
#define ZLOG_TS_ISO8601		(1 << 8)
#define ZLOG_TS_LEGACY		(1 << 9)

/* default is local time zone */
#define ZLOG_TS_UTC		(1 << 10)

extern size_t zlog_msg_ts(struct zlog_msg *msg, char *out, size_t outsz,
			  uint32_t flags);
extern void zlog_msg_tsraw(struct zlog_msg *msg, struct timespec *ts);
extern int zlog_msg_prio(struct zlog_msg *msg);

/* This list & struct implements the actual logging targets.  It is accessed
 * lock-free from all threads, and thus MUST only be changed atomically, i.e.
 * RCU.
 *
 * Since there's no atomic replace, the replacement action is an add followed
 * by a delete.  This means that during logging config changes, log messages
 * may be duplicated in the log target that is being changed.  The old entry
 * being changed MUST also at the very least not crash or do other stupid
 * things.
 *
 * This list and struct are NOT related to config.  Logging config is kept
 * separately, and results in creating appropriate zlog_target(s) to realize
 * the config.  Log targets may also be created from varying sources, e.g.
 * command line options, or VTY commands ("log monitor").
 *
 * struct zlog_target is intended to be embedded into a larger structure that
 * contains additional field for the specific logging target, e.g. an fd or
 * additional options.  It MUST be the first field in that larger struct.
 */

PREDECL_ATOMLIST(zlog_targets)
struct zlog_target {
	struct zlog_targets_item head;

	int prio_min;

	void (*logfn)(struct zlog_target *zt, struct zlog_msg *msg[],
		      size_t nmsgs);

	/* for crash handlers, set to NULL if log target can't write crash logs
	 * without possibly deadlocking (AS-Safe)
	 *
	 * text is not \0 terminated & split up into lines (e.g. no \n)
	 */
	void (*logfn_sigsafe)(struct zlog_target *zt, const char *text,
			      size_t len);

	struct rcu_head rcu_head;
};

/* make a copy for RCUpdating.  oldzt may be NULL to allocate a fresh one. */
extern struct zlog_target *zlog_target_clone(struct memtype *mt,
					     struct zlog_target *oldzt,
					     size_t size);

/* update the zlog_targets list;  both oldzt and newzt may be NULL.  You
 * still need to zlog_target_free() the old target afterwards if it wasn't
 * NULL.
 *
 * Returns oldzt so you can zlog_target_free(zlog_target_replace(old, new));
 * (Some log targets may need extra cleanup inbetween, but remember the old
 * target MUST remain functional until the end of the current RCU cycle.)
 */
extern struct zlog_target *zlog_target_replace(struct zlog_target *oldzt,
					       struct zlog_target *newzt);

/* Mostly for symmetry for zlog_target_clone(), just rcu_free() internally. */
#define zlog_target_free(mt, zt) \
	rcu_free(mt, zt, rcu_head)

extern void zlog_init(const char *progname, const char *protoname,
		      unsigned short instance, uid_t uid, gid_t gid);
DECLARE_HOOK(zlog_init, (const char *progname, const char *protoname,
			 unsigned short instance, uid_t uid, gid_t gid),
			(progname, protoname, instance, uid, gid))

extern void zlog_fini(void);
DECLARE_KOOH(zlog_fini, (), ())

/* for tools & test programs, i.e. anything not a daemon.
 * (no cleanup needed at exit)
 */
extern void zlog_aux_init(const char *prefix, int prio_min);
DECLARE_HOOK(zlog_aux_init, (const char *prefix, int prio_min),
			    (prefix, prio_min))

extern void zlog_startup_end(void);

extern void zlog_tls_buffer_init(void);
extern void zlog_tls_buffer_flush(void);
extern void zlog_tls_buffer_fini(void);

#ifdef __cplusplus
}
#endif

struct zlog_kw {
	const char *name;
};

/* used to mark overwritten keys */
extern struct zlog_kw zlkw_INVALID[1];

extern struct zlog_kw zlkw_VRF[1];
extern struct zlog_kw zlkw_INTERFACE[1];
extern struct zlog_kw zlkw_NEIGHBOR[1];
extern struct zlog_kw zlkw_R_PREFIX[1];
extern struct zlog_kw zlkw_NH_ADDRESS[1];
extern struct zlog_kw zlkw_NH_INTERFACE[1];

struct zlog_kw_val {
	struct zlog_kw *key;
	const struct xref *origin;
	unsigned start, end;
};

struct zlog_kw_heap {
	unsigned refcount;
	unsigned n_keywords;

	struct zlog_kw_val keywords[0];
};

struct zlog_kw_frame {
	struct zlog_kw_frame *up;
	struct zlog_kw_heap *heapcopy;

	unsigned n_alloc, n_used;
	struct zlog_kw_val keywords[0];
};

struct zlog_kw_state; /* private */

#define ZLOG_KW_FRAME(state, max_local_kws)                                    \
	unsigned _prev_kw_count = zlog_kw_count();                             \
	struct {                                                               \
		struct zlog_kw_frame frame;                                    \
		struct zlog_kw_val keywords[_prev_kw_count + max_local_kws];   \
	} _zlog_kw_frame_var;                                                  \
	struct zlog_kw_state *state __attribute__((                            \
			cleanup(_zlog_kw_frame_fini))) =                       \
		_zlog_kw_frame_init(&_zlog_kw_frame_var.frame,                 \
				    _prev_kw_count + max_local_kws)            \
	/* end */

#define ZLOG_KW_FRAME_LOAD_SAVED(state, heapkws, add_local_kws)                \
	ZLOG_KW_FRAME(state, ((heapkws) ? (heapkws)->n_keywords : 0)           \
				+ add_local_kws);                              \
	zlog_kw_apply(state, heapkws);                                         \
	/* end */

extern struct zlog_kw_state *_zlog_kw_frame_init(struct zlog_kw_frame *fvar,
						 unsigned size);
extern void _zlog_kw_frame_fini(struct zlog_kw_state **statep);

extern void _zlog_kw_push(struct zlog_kw_state *state, const struct xref *xref,
			  struct zlog_kw *key, const char *fmt, ...);

#define zlog_kw_push(state, key, fmt, ...)                                     \
	do {                                                                   \
		static const struct xref _xref __attribute__((used)) =         \
			XREF_INIT(XREFT_KWPUSH, NULL, __func__);               \
		XREF_LINK(_xref);                                              \
		_zlog_kw_push(state, &_xref, key, fmt, ## __VA_ARGS__);        \
	} while (0)                                                            \
	/* end */

extern void zlog_kw_revert(struct zlog_kw_state *state);
extern void zlog_kw_clear(struct zlog_kw_state *state);

extern unsigned zlog_kw_count(void);
extern const char *zlog_kw_get(struct zlog_kw *kw);
extern void zlog_kw_dump(void);

extern struct zlog_kw_heap *zlog_kw_save(void);
extern void zlog_kw_apply(struct zlog_kw_state *state,
			  struct zlog_kw_heap *heapkw);

extern struct zlog_kw_heap *zlog_kw_ref(struct zlog_kw_heap *heapkw);
extern void zlog_kw_unref(struct zlog_kw_heap **heapkw);

extern size_t zlog_kw_frame_count(const struct zlog_kw_frame *frame);
extern const struct zlog_kw_val *zlog_kw_frame_vals_next(
	const struct zlog_kw_frame *frame, const struct zlog_kw_val *prev);
extern const struct zlog_kw_val *zlog_kw_frame_vals_first(
	const struct zlog_kw_frame *frame);
extern const char *zlog_kw_frame_val_str(const struct zlog_kw_val *val);

#endif /* _FRR_ZLOG_H */
