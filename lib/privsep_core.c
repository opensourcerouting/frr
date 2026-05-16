// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2026  David Lamparter, for NetDEF, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <pthread.h>
#ifdef __linux__
#include <linux/capability.h>
#include <cap-ng.h>
#endif

#include "lib/memory.h"
#include "lib/zlog.h"
#include "lib/network.h"
#include "lib/privsep_core.h"

/* this won't ever be seen in "show memory" */
DEFINE_MTYPE_STATIC(LIB, PRIVSEP_POLL, "privsep poll block");

static pid_t ps_child = -1;

static size_t n_ps_sockets;
static struct pollfd *ps_poll;

struct ps_message {
	_Alignas(uint64_t) int32_t opcode;
	uint32_t operr;

	char payload[];
};

static int privsep_fd_get(void);
static bool privsep_send(int fd, const struct ps_message *hdr, const void *msg, size_t msgsize,
			 const int *out_fds, size_t n_out_fds);

/* privsep_socket()
 *
 * in_fds: netns
 * out_fds: newly created socket
 */
struct ps_in_extra_socket {
	unsigned flags;
};

DEFINE_PRIVSEP_CALL_NOOUT(extra_socket, struct ps_in_extra_socket, 0, 1, ());

static int privsep_impl_extra_socket(const struct ps_in_extra_socket *args, const int in_fds[0],
				     int out_fds[1])
{
	int pair[2], ret;
	size_t i;

	ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair);
	if (ret)
		return -1;

	i = n_ps_sockets++;

	ps_poll = XREALLOC(MTYPE_PRIVSEP_POLL, ps_poll, sizeof(ps_poll[0]) * n_ps_sockets);
	ps_poll[i].fd = pair[1];
	ps_poll[i].events = POLLIN;
	ps_poll[i].revents = 0;

	out_fds[0] = pair[0];
	return 0;
}

int psep_extra_socket(void)
{
	int out_fd[1], rv;

	rv = privsep_extra_socket(&(struct ps_in_extra_socket){}, NULL, out_fd);
	return rv ? -1 : out_fd[0];
}

#if 0
/* setsockopt_int()
 *
 * in_fds: socket
 * out_fds: none
 */
struct ps_in_setsockopt_int {
	unsigned flags;

	int level, optname, optval;
};

DEFINE_PRIVSEP_CALL(setsockopt_int, struct ps_in_setsockopt_int, struct ps_nothing, 1, 0,
		    (CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN, ));

/* bind()
 *
 * in_fds: socket
 * out_fds: none
 */

struct ps_in_bind {
	unsigned flags;

	struct sockaddr_storage sa;
	socklen_t sa_len;
};

DEFINE_PRIVSEP_CALL(bind, struct ps_in_bind, struct ps_nothing, 1, 0, (CAP_NET_BIND, ));
#endif

static const struct privsep_op *privsep_ops[_PRIVSEP_COUNT];

void privsep_need(const struct privsep_op *op)
{
	assertf((size_t)op->opcode < _PRIVSEP_COUNT, "%u", op->opcode);
	assertf(privsep_ops[op->opcode] == op || !privsep_ops[op->opcode], "%u", op->opcode);

	privsep_ops[op->opcode] = op;
}

int privsep_call(const struct privsep_op *op, const void *input, void *output, const int in_fds[],
		 int out_fds[])
{
	struct ps_message txhdr = {
		.opcode = op->opcode,
	};
	struct ps_message rxhdr;
	struct iovec iov[2] = {
		{ .iov_base = &rxhdr, .iov_len = sizeof(rxhdr) },
		{ .iov_base = output, .iov_len = op->out_size },
	};
	struct msghdr mh[1] = { {
		.msg_iov = iov,
		.msg_iovlen = array_size(iov),
	} };
	int fd;
	bool ok;
	ssize_t rxlen;

	assertf(ps_child == -1, "attempting to make privsep call from privsep process");
	fd = privsep_fd_get();

	ok = privsep_send(fd, &txhdr, input, op->in_size, in_fds, op->n_in_fds);
	assert(ok);

	memset(output, 0, op->out_size);
	for (size_t i = 0; i < op->n_out_fds; i++)
		out_fds[i] = -1;

	if (op->n_out_fds) {
		mh->msg_controllen = CMSG_SPACE(sizeof(int) * (op->n_out_fds + 1));
		mh->msg_control = alloca(mh->msg_controllen);
	}
	rxlen = recvmsg(fd, mh, 0);

	if (rxhdr.operr) {
		assertf(rxlen == sizeof(struct ps_message), "%zd", rxlen);
		errno = rxhdr.operr;
		return rxhdr.opcode;
	}

	assertf((size_t)rxlen == sizeof(struct ps_message) + op->out_size, "%zd", rxlen);

	if (op->n_out_fds) {
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(mh);
		size_t expect_cmsg_size = sizeof(*cmsg) + op->n_out_fds * sizeof(int);

		assert(cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS);
		assertf(cmsg->cmsg_len == expect_cmsg_size, "%zu != %zu", expect_cmsg_size,
			(size_t)cmsg->cmsg_len);

		memcpy(out_fds, CMSG_DATA(cmsg), op->n_out_fds * sizeof(int));
	}
	return rxhdr.opcode;
}

static void sigchld(int sig)
{
	pid_t pid;
	int status;

	pid = waitpid(-1, &status, WNOHANG);
	if (pid == -1)
		_zlog_ecref(0, LOG_CRIT, "SIGCHLD but no child in privsep (%m)!");
	else if (WIFSTOPPED(status) || WIFCONTINUED(status))
		return;
	else if (WIFEXITED(status)) {
		zlog_info("privsep child exited (status %d)", WEXITSTATUS(status));
		exit(WEXITSTATUS(status));
	} else if (WIFSIGNALED(status))
		zlog_err("privsep child exited (%s)", strsignal(WTERMSIG(status)));
	else
		zlog_err("privsep child exited (unknown status)");

	exit(121);
}

FRR_NORETURN
static void privsep_fault(const char *msg)
{
	_zlog_ecref(0, LOG_CRIT, "privilege separation fault: %s (errno: %m), aborting", msg);

	for (int i = 0; i < 5; i++) {
		if (kill(ps_child, SIGABRT))
			if (errno == ESRCH)
				exit(121);

		/* SIGCHLD handler will exit */
		sleep(1);
	}
	kill(ps_child, SIGKILL);

	exit(121);
}

static void privsep_close(int fd)
{
	/* TODO */
}

/* used on both sides of the socket */
static bool privsep_send(int fd, const struct ps_message *hdr, const void *msg, size_t msgsize,
			 const int *out_fds, size_t n_out_fds)
{
	char cmsgbuf[CMSG_SPACE(sizeof(int) * n_out_fds)];
	struct iovec iov[2] = {
		{ .iov_base = (void *)hdr, .iov_len = sizeof(*hdr) },
		{ .iov_base = (void *)msg, .iov_len = msgsize },
	};
	struct msghdr mh[1] = { {
		.msg_iov = iov,
		.msg_iovlen = array_size(iov),
	} };
	ssize_t send_rv;

	if (!hdr) {
		iov[0].iov_len = 0;
		mh->msg_iov++;
		mh->msg_iovlen--;
	}

	if (out_fds) {
		struct cmsghdr *cmsg;

		mh->msg_control = cmsgbuf;
		mh->msg_controllen = sizeof(cmsgbuf);

		cmsg = CMSG_FIRSTHDR(mh);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int) * n_out_fds);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmsg), out_fds, sizeof(int) * n_out_fds);
	}

	send_rv = sendmsg(fd, mh, 0);
	return (size_t)send_rv == iov[0].iov_len + iov[1].iov_len;
}

static void privsep_exec(int fd, const struct privsep_op *op, struct msghdr *mh)
{
	int ret;
	int in_fds[op->n_in_fds];
	int out_fds[op->n_out_fds];
	struct {
		struct ps_message hdr;
		char payload[op->out_size];
	} outbuf;
	struct ps_message *inbuf = mh->msg_iov->iov_base;
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(mh);

	assert(!cmsg || (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS));

	if (op->n_in_fds && !cmsg)
		privsep_fault("invalid call (missing input FDs)");
	if (cmsg && !op->n_in_fds)
		privsep_fault("invalid call (unexpected input FDs)");
	if (op->n_in_fds) {
		size_t expect_cmsg_size = sizeof(*cmsg) + op->n_in_fds * sizeof(int);

		if (cmsg->cmsg_len != expect_cmsg_size)
			privsep_fault("invalid call (wrong number of input FDs)");
		memcpy(in_fds, CMSG_DATA(cmsg), op->n_in_fds * sizeof(int));
	}

	errno = 0;
	memset(&outbuf, 0, sizeof(outbuf));
	for (size_t i = 0; i < op->n_out_fds; i++)
		out_fds[i] = -1;

	ret = op->impl(inbuf->payload, outbuf.payload, in_fds, out_fds);
	outbuf.hdr.opcode = ret;
	if (ret < 0) {
		outbuf.hdr.operr = errno;
		if (!privsep_send(fd, NULL, &outbuf, sizeof(outbuf.hdr), NULL, 0))
			privsep_fault("failed to send call error result");
	} else {
		if (!privsep_send(fd, NULL, &outbuf, sizeof(outbuf.hdr), out_fds, op->n_out_fds))
			privsep_fault("failed to send call result");
	}

	for (size_t i = 0; i < op->n_in_fds; i++)
		close(in_fds[i]);
	for (size_t i = 0; i < op->n_out_fds; i++)
		close(out_fds[i]);
}

static void privsep_handle(int fd)
{
	struct ps_message hdr[1];
	const struct privsep_op *op;
	ssize_t msgsize, actual;
	struct iovec iov[1];
	struct msghdr mh[1] = { {
		.msg_iov = iov,
		.msg_iovlen = array_size(iov),
	} };

	msgsize = recv(fd, hdr, sizeof(*hdr), MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
	if (msgsize < 0 && ERRNO_IO_RETRY(errno))
		return;
	if (msgsize <= 0) {
		if (msgsize < 0)
			zlog_err("privilege separation socket error: %m");
		privsep_close(fd);
		return;
	}
	if ((size_t)msgsize < sizeof(hdr))
		privsep_fault("invalid call (too short)");
	if ((size_t)hdr->opcode >= array_size(privsep_ops))
		privsep_fault("invalid call (invalid op)");
	op = privsep_ops[hdr->opcode];
	if (!op)
		privsep_fault("invalid call (op not enabled)");
	if ((size_t)msgsize != sizeof(hdr) + op->in_size)
		privsep_fault("invalid call (wrong size)");

	iov->iov_len = sizeof(hdr) + op->in_size;
	iov->iov_base = alloca(iov->iov_len);
	mh->msg_controllen = CMSG_SPACE(sizeof(int) * (op->n_in_fds + 1));
	mh->msg_control = alloca(mh->msg_controllen);

	actual = recvmsg(fd, mh, MSG_DONTWAIT);
	if (actual != msgsize) {
		if (actual < 0)
			zlog_err("privilege separation socket error: %m");
		else
			zlog_err("privilege separation socket weirdness");
		privsep_close(fd);
		return;
	}

	privsep_exec(fd, op, mh);
}

static void privsep_main(void)
{
	const struct sigaction sa = {
		.sa_handler = sigchld,
	};
	int n_ready;
	sigset_t sigmask[1];

	if (sigaction(SIGCHLD, &sa, NULL))
		privsep_fault("could not register SIGCHLD handler");
	/* TODO: forward signals */

	sigemptyset(sigmask);
	do {
		n_ready = ppoll(ps_poll, n_ps_sockets, NULL, sigmask);
		if (n_ready < 0 && ERRNO_IO_RETRY(errno))
			continue;

		for (size_t i = 0; n_ready && i < n_ps_sockets; i++) {
			if (!ps_poll[i].revents)
				continue;

			ps_poll[i].revents = 0;
			privsep_handle(ps_poll[i].fd);
			n_ready--;
		}
	} while (n_ps_sockets);
}

static pthread_key_t ps_fd_key;

static int privsep_fd_get(void)
{
	void *ptr = pthread_getspecific(ps_fd_key);
	intptr_t fd = (intptr_t)ptr;

	/* TODO */
	assert(fd != 0);
	return fd;
}

static void privsep_fd_cleanup(void *ptr)
{
	intptr_t fd = (intptr_t)ptr;

	if (fd && fd != -1)
		close(fd);
}

__attribute__((constructor(400))) static void privsep_tls_setup(void)
{
	pthread_key_create(&ps_fd_key, privsep_fd_cleanup);
}

void privsep_fork(int *log_sock)
{
	pid_t rv;
	int ps_fd;

	if (privsep_impl_extra_socket(NULL, NULL, &ps_fd)) {
		zlog_err("failed to set up privilege separation socket: %m");
		exit(120);
	}

	rv = fork();
	if (rv == -1) {
		zlog_err("failed to fork() for privilege separation: %m");
		exit(120);
	}
	if (rv == 0) {
		pthread_setspecific(ps_fd_key, (void *)(intptr_t)ps_fd);
		close(ps_poll[0].fd);
		XFREE(MTYPE_PRIVSEP_POLL, ps_poll);
		return;
	}

	ps_child = rv;
	close(ps_fd);

#ifdef __linux__
	prctl(PR_SET_NAME, "[frr:privsep]");

	capng_clear(CAPNG_SELECT_ALL);
	/* for killing the child process on faults
	 *
	 * maybe we just exit instead and leave it to crash?
	 */
	capng_update(CAPNG_ADD, CAPNG_PERMITTED, CAP_KILL);
	capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, CAP_KILL);

	for (size_t i = 0; i < array_size(privsep_ops); i++) {
		if (!privsep_ops[i])
			continue;

		for (const unsigned *cap = privsep_ops[i]->capabilities; *cap != ~0U; cap++) {
			capng_update(CAPNG_ADD, CAPNG_PERMITTED, *cap);
			capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, *cap);
		}
	}

	capng_apply((capng_select_t)CAPNG_PERMITTED);
	capng_apply((capng_select_t)CAPNG_EFFECTIVE);
	/* TODO: what user/group to use? */
	capng_change_id(65534, 65534, CAPNG_DROP_SUPP_GRP);
	capng_lock();
#endif

	privsep_main();
	exit(0);
}
