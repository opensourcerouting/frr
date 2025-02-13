/*
 * WPA Supplicant - Layer2 packet interface definition
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file defines an interface for layer 2 (link layer) packet sending and
 * receiving. l2_packet_linux.c is one implementation for such a layer 2
 * implementation using Linux packet sockets and l2_packet_pcap.c another one
 * using libpcap and libdnet. When porting %wpa_supplicant to other operating
 * systems, a new l2_packet implementation may need to be added.
 */

#ifndef LLDP_PACKET_H
#define LLDP_PACKET_H

#ifndef ETH_P_LLDP
#define ETH_P_LLDP 0x88cc
#endif
#ifndef ETH_P_SLLDP
#define ETH_P_SLLDP 0xaaaa
#endif


extern int lldp_write_packet(int fd, struct interface *ifp, struct stream *obuf);
extern struct stream *lldp_recv_packet(int fd, struct interface **ifp, struct stream *ibuf);
extern int lldp_interface_socket_init(struct interface *ifp);


#endif /* L2_PACKET_H */
