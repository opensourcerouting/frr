// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM southbound implementation.
 *
 * Copyright (C) 2021-2026 Network Education Foundation
 *                         Rafael Zalamena
 */

#ifndef _PIM_SOUTHBOUND_
#define _PIM_SOUTHBOUND_

#include <netinet/in.h>

#include <stdbool.h>
#include <stdint.h>

#include "pimd/pim_addr.h"

/* Forward declarations */
struct zclient;
struct igmp_source;
struct igmp_group;
struct pim_instance;

/** Default TCP listening port. */
#if PIM_IPV == 4
#define PIMSB_DEFAULT_PORT 2650
#else
#define PIMSB_DEFAULT_PORT 2651
#endif /* PIM_IPV == 6 */

/** pimreg interface index value for southbound. */
#define PIM_REG_IF_IDX 0x7FFF0000

/*
 * PIM southbound.
 */
enum multicast_event_type {
	MRT_EVENT_DATA_START,
	MRT_EVENT_DATA_STOP,
	MRT_EVENT_WRONG_IF,
	MRT_EVENT_JOIN_SPT,
	MRT_EVENT_DATA_PACKET,
};

/** PIM southbound message version. */
#define MRE_VERSION_V1 0x01

struct mroute_event_header {
	/** Protocol message version. */
	uint8_t version;
	/** Multicast route event. \see enum multicast_event_type. */
	uint8_t type;
	/** Message length. */
	uint16_t length;
};

struct mroute_event {
	/** Event header. */
	struct mroute_event_header header;
	/** Event flags. \see MRE_FLAG_* definitions. */
	uint32_t flags;
	/** Input interface index. */
	int32_t iif_idx;
	/** Source address. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} source;
	/** Group address. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} group;
};


/*
 * FPM southbound.
 */
/** Tell data plane that SPT switch over is allowed. */
#define MRT_FLAG_JOIN_SPT_ALLOWED 0x0001
/** Ask data plane to tell us when the data flow stops. */
#define MRT_FLAG_RESTART_DL_TIMER 0x0002
/** Flag IPv6 addresses for the data plane. */
#define MRT_FLAG_ADDR_TYPE_V6 0x0008
/** Blackhole multicast packets. */
#define MRT_FLAG_DUMMY 0x0020
/** Used with dummy to remove blackhole after a time. */
#define MRT_FLAG_DL_TIMER 0x0040

struct pimsb_mroute_args {
	struct channel_oil *oil;
	struct mfcctl_vendor *mfcc;
	union {
		struct in_addr v4;
		struct in_addr v6;
	} local;
	union {
		struct in_addr v4;
		struct in_addr v6;
	} remote;
};

/*
 * PIM southbound.
 */

/* Forward declaration */
struct pim_interface;

/** Send PIM packet parameters. */
struct pimsb_pim_args {
	/** Source address. */
	uint32_t source;
	/** Destination address. */
	uint32_t destination;
	/** Selected interface. */
	int32_t ifindex;

	/** Data pointer. */
	uint8_t *data;
	/** Data amount. */
	size_t datalen;
};

extern void pimsb_socket_init(const struct sockaddr_storage *ss, socklen_t sslen, bool client);

void pimsb_packet_read(int sock);
ssize_t pimsb_igmp_sendto(const char *ifname, const void *data, size_t datalen,
			  struct sockaddr *sa, socklen_t salen);

/** Removes a multicast group/source from being announced. */
extern void pimsb_gm_leave(const struct interface *interface, const pim_addr *source,
			   const pim_addr *group);

/**
 * Generate multicast join for currently configured groups/source in
 * interface.
 */
extern void pimsb_gm_join(const struct interface *interface);

int pim_socket_get(void);
int pimsb_socket_bind(int fd, pim_addr address);

void pimsb_init(struct zclient *zc);
void pimsb_shutdown(void);
int pimsb_mroute_socket_enable(struct pim_instance *pim);

void pimsb_socket_parse(const char *arg);

#if PIM_IPV == 4
void pimsb_msg_send_frame(const struct interface *ifp, const struct ip *ip, const void *msg,
			  const size_t msglen);
#else
void pimsb_msg_send_frame(const pim_addr *src, const pim_addr *dst, const struct interface *ifp,
			  struct iovec *iov, int fd);

struct gm_if;
int pimsb_send_query(const struct gm_if *gm_ifp, struct msghdr *msg, struct in6_pktinfo *ipi6,
		     int proto);
#endif

void pimsb_show_state(struct vty *vty, struct pim_instance *pim, const char *src_grp,
		      const char *grp, bool json_output);
void pimsb_show_state_json(struct vty *vty, struct pim_instance *pim, const char *src_grp,
			   const char *grp, struct json_object *json);
void pimsb_show_mroute(struct vty *vty, struct pim_instance *pim, const pim_sgaddr *sg, bool fill,
		       bool json);
void pimsb_show_mroute_json(struct vty *vty, struct pim_instance *pim, const pim_sgaddr *sg,
			    struct json_object *json);

void pimsb_mroute_do(struct channel_oil *oil, bool install);
int pimsb_mroute_add(struct channel_oil *c_oil, const char *name);
int pimsb_mroute_del(struct channel_oil *c_oil, const char *name);

#endif /* _PIM_SOUTHBOUND_ */
