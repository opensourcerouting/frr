// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Flowspec header . private structs and defines
 * Copyright (C) 2018 6WIND
 */

#ifndef _FRR_BGP_FLOWSPEC_PRIVATE_H
#define _FRR_BGP_FLOWSPEC_PRIVATE_H

#define FLOWSPEC_NLRI_SIZELIMIT			240

/* Flowspec raffic action bit*/
#define FLOWSPEC_TRAFFIC_ACTION_TERMINAL	1
#define FLOWSPEC_TRAFFIC_ACTION_SAMPLE		0
#define FLOWSPEC_TRAFFIC_ACTION_DISTRIBUTE	1

/* Flow Spec Component Types */
#define NUM_OF_FLOWSPEC_MATCH_TYPES		12
#define FLOWSPEC_DEST_PREFIX		1
#define FLOWSPEC_SRC_PREFIX		2
#define FLOWSPEC_IP_PROTOCOL		3
#define FLOWSPEC_PORT			4
#define FLOWSPEC_DEST_PORT		5
#define FLOWSPEC_SRC_PORT		6
#define FLOWSPEC_ICMP_TYPE		7
#define FLOWSPEC_ICMP_CODE		8
#define FLOWSPEC_TCP_FLAGS		9
#define FLOWSPEC_PKT_LEN		10
#define FLOWSPEC_DSCP			11
#define FLOWSPEC_FRAGMENT		12
#define FLOWSPEC_FLOW_LABEL		13 /* For IPv6 only */

#endif /* _FRR_BGP_FLOWSPEC_PRIVATE_H */
