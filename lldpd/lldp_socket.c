/*
 * WPA Supplicant - Layer2 packet handling with Linux packet sockets
 * Copyright (c) 2003-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "sockopt.h"
#include "zclient.h"

#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "lldpd.h"
#include "lldp_interface.h"
//#include "lldp_db.h"
#include "lldp_packet.h"
#include "lldp_socket.h"

extern struct zebra_privs_t lldp_privs;

static int lldp_socket_promisc(int fd, struct interface *ifp)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifp->name);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		if (lldp_privs.change(ZPRIVS_LOWER))
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		zlog_err("%s: get flags: %s", __func__, strerror(errno));
		close(fd);
		return -1;
	}
	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		if (lldp_privs.change(ZPRIVS_LOWER))
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		zlog_err("%s: setting promisc mode: %s", __func__, strerror(errno));
		close(fd);
		return -1;
	}
	return CMD_SUCCESS;
}
struct stream *lldp_recv_packet(int fd, struct interface **ifp, struct stream *ibuf)
{
	int ret;
	unsigned int ifindex = 0;
	struct iovec iov;
	/* Header and data both require alignment. */
	char buff[CMSG_SPACE(SOPT_SIZE_CMSG_IFINDEX_IPV4())];
	struct msghdr msgh;

	memset(&msgh, 0, sizeof(struct msghdr));
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = (caddr_t)buff;
	msgh.msg_controllen = sizeof(buff);

	ret = stream_recvmsg(ibuf, fd, &msgh, 0, LLDP_MAX_PACKET_SIZE + 1);
	if (ret < 0) {
		zlog_warn("stream_recvmsg failed: %s", safe_strerror(errno));
		return NULL;
	}

	ifindex = getsockopt_ifindex(AF_INET, &msgh);
	*ifp = if_lookup_by_index(ifindex);
	return ibuf;
}

int lldp_write_packet(int fd, struct interface *ifp, struct stream *obuf)
{
	int ret = 0;
	struct sockaddr_ll ll;
	struct lldp_interface *lifp = ifp->info;

	if (ifp == NULL || obuf == NULL)
		return -1;
	lifp = ifp->info;
	if (lifp == NULL)
		return -1;

	memset(&ll, 0, sizeof(ll));

	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifp->ifindex;
	ll.sll_protocol = htons(ETH_P_8021Q | ETH_P_LLDP);
	ll.sll_halen = ETH_ALEN;
	memcpy(ll.sll_addr, lifp->own_mac, ETH_ALEN);
	errno = 0;
	ret = sendto(lifp->sock, STREAM_DATA(obuf), stream_get_endp(obuf), 0,
		     (struct sockaddr *)&ll, sizeof(ll));
	if (ret < 0) {
		LLDP_DEBUG_LOG("error sendto %x - %d: %s\n", lifp->dst_mac[5], lifp->sock,
			       strerror(errno));
		errno = 0;
		return -1;
	}
	lifp->sen_pkts++;
	LLDP_DEBUG_LOG("sendto %x - %d: %s\n", lifp->dst_mac[5], lifp->sock, strerror(errno));
	return ret;
}

int lldp_interface_socket_init(struct interface *ifp)
{
	int sock = 0;
	struct ifreq ifr;
	struct sockaddr_ll ll;
	struct lldp_interface *lifp = ifp->info;

	if (lldp_privs.change(ZPRIVS_RAISE))
		zlog_err("%s: could not raise privs, %s", __func__, safe_strerror(errno));

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_8021Q | ETH_P_LLDP));
	if (sock < 0) {
		if (lldp_privs.change(ZPRIVS_LOWER))
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		LLDP_DEBUG_LOG("%s: socket: %s", __func__, strerror(errno));
		return -1;
	}
	//memset(&ll, 0, sizeof(ll));
	//LLDP_DEBUG_LOG("get %s %d %d",ifp->name,ifp->ifindex,ifr.ifr_ifindex);

	/*
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifp->name);
	 if ( ioctl( sock, SIOCGIFFLAGS, &ifr ) < 0 )
	  {
			if (lldp_privs.change (ZPRIVS_LOWER))
				zlog_err ("%s: could not lower privs, %s",__func__,safe_strerror (errno) );
			zlog_err( "%s: get flags: %s",__func__, strerror(errno));
			close(sock);
			return -1;
	  }
	 ifr.ifr_flags |= IFF_PROMISC;
	 if ( ioctl( sock, SIOCSIFFLAGS, &ifr ) < 0 )
	  {
			if (lldp_privs.change (ZPRIVS_LOWER))
				zlog_err ("%s: could not lower privs, %s",__func__,safe_strerror (errno) );
			zlog_err( "%s: setting promisc mode: %s",__func__, strerror(errno));
			close(sock);
			return -1;
	  }
	 */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifp->name);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		if (lldp_privs.change(ZPRIVS_LOWER))
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		LLDP_DEBUG_LOG("%s: ioctl[SIOCGIFHWADDR]: %s", __func__, strerror(errno));
		close(sock);
		return -1;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_halen = ETH_ALEN;
	ll.sll_ifindex = ifp->ifindex;
	ll.sll_protocol = htons(ETH_P_8021Q | ETH_P_LLDP);
	memcpy(ll.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (bind(sock, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
		if (lldp_privs.change(ZPRIVS_LOWER))
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		LLDP_DEBUG_LOG("%s: bind[PF_PACKET]: %s", __func__, strerror(errno));
		close(sock);
		return -1;
	}

	if (lldp_privs.change(ZPRIVS_LOWER)) {
		LLDP_DEBUG_LOG("%s: could not lower privs, %s", __func__, safe_strerror(errno));
	}

	memcpy(lifp->own_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	LLDP_DEBUG_LOG("%s:%s get mac %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, ifp->name,
		       lifp->own_mac[0], lifp->own_mac[1], lifp->own_mac[2], lifp->own_mac[3],
		       lifp->own_mac[4], lifp->own_mac[5]);

	//if(lifp->mode & LLDP_READ_MODE)
	//	lifp->t_read = thread_add_read (master, lldp_read_packet, ifp, sock);
	//lifp->ibuf = stream_new (LLDP_PACKET_MAX_SIZE);
	//lifp->obuf = stream_new (LLDP_PACKET_MAX_SIZE);
	//lifp->outbuf = XMALLOC (MTYPE_STREAM_DATA, LLDP_PACKET_MAX_SIZE);
	lifp->sock = sock;
	return sock;
}

/****************************************************************************************/
#ifdef LLDP_DEBUG_TEST
//only test
//ETH_P_ALL
int lldp_send_debug_test(int ifindex, struct lldp_interface *lifp)
{
	unsigned char l2_hdr[4096];
	struct ethhdr *eth_hdr = (struct ethhdr *)l2_hdr;
	struct sockaddr_ll ll;

	if (lifp == NULL)
		return -1;

	//lifp->obuf = stream_new (LLDP_PACKET_MAX_SIZE);
	if (lifp->ifp && lifp->obuf) {
		LLDP_DEBUG_LOG("lldp_make_hello and lldp_write_packet");
		lldp_make_lldp_pdu(lifp->ifp);
		//lldp_end_format_tlv(lifp->obuf);
		lldp_write_packet(lifp->sock, lifp->ifp, lifp->obuf);
		//lldp_write_packet (int fd, struct interface *ifp, struct stream *obuf);
		if (lifp->obuf)
			stream_free(lifp->ibuf);
	}
	memset(l2_hdr, 0, sizeof(l2_hdr));

	memcpy(eth_hdr->h_dest, lifp->dst_mac, ETH_ALEN);
	memcpy(eth_hdr->h_source, lifp->own_mac, ETH_ALEN);

	eth_hdr->h_proto = htons(ETH_P_LLDP);


	memset(&ll, 0, sizeof(ll));

	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = lifp->ifp->ifindex;
	ll.sll_protocol = htons(ETH_P_8021Q | ETH_P_LLDP);
	ll.sll_halen = ETH_ALEN;
	memcpy(ll.sll_addr, lifp->own_mac, ETH_ALEN);
	errno = 0;
	sendto(lifp->sock, l2_hdr, 64, 0, (struct sockaddr *)&ll, sizeof(ll));
	close(lifp->sock);
	LLDP_DEBUG_LOG("sendto %x - %d: %s\n", lifp->dst_mac[5], lifp->sock, strerror(errno));
}
static int lld_raw_test(char *name)
{
	int sock;
	int n_write;
	int n_res;
	struct interface *ifp;
	struct lldp_interface *lifp;
	struct sockaddr_ll sll;
	struct ifreq ifstruct;

	char buffer[1024];
	char MAC_BUFFER[ETH_ALEN] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
	char TYPE_BUFFER[2] = { 0x88, 0xcc };

	printf("Date:%s || Time:%s \n", __DATE__, __TIME__);
	if (lldp_privs.change(ZPRIVS_RAISE))
		zlog_err("%s: could not raise privs, %s", __func__, safe_strerror(errno));

	if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_8021Q | ETH_P_LLDP))) < 0) {
		fprintf(stdout, "create socket error\n");
		if (lldp_privs.change(ZPRIVS_LOWER)) {
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		}
		return -1;
	}
	n_res = 0;
	n_write = 0;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(ETH_P_8021Q | ETH_P_LLDP);

	strcpy(ifstruct.ifr_name, name);
	ioctl(sock, SIOCGIFINDEX, &ifstruct);
	sll.sll_ifindex = ifstruct.ifr_ifindex;

	strcpy(ifstruct.ifr_name, name);
	ioctl(sock, SIOCGIFHWADDR, &ifstruct);
	memcpy(sll.sll_addr, ifstruct.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
	sll.sll_halen = ETH_ALEN;

	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
		printf("bind:   ERROR\n");
		if (lldp_privs.change(ZPRIVS_LOWER)) {
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		}
		return -1;
	}
	memset(&ifstruct, 0, sizeof(ifstruct));
	strcpy(ifstruct.ifr_name, name);
	if (ioctl(sock, SIOCGIFFLAGS, &ifstruct) == -1) {
		perror("iotcl()\n");
		printf("Fun:%s Line:%d\n", __func__, __LINE__);
		if (lldp_privs.change(ZPRIVS_LOWER)) {
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		}
		return -1;
	}
	ifstruct.ifr_flags |= IFF_PROMISC;
	if (ioctl(sock, SIOCSIFFLAGS, &ifstruct) == -1) {
		perror("iotcl()\n");
		printf("Fun:%s Line:%d\n", __func__, __LINE__);
		if (lldp_privs.change(ZPRIVS_LOWER)) {
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		}
		return -1;
	}
	memcpy(buffer, MAC_BUFFER, ETH_ALEN);
	memcpy(buffer + 6, sll.sll_addr, ETH_ALEN);
	memcpy(buffer + 12, TYPE_BUFFER, 2);

	ifp = if_lookup_by_name("eno16777736");
	//ifp->ifindex = sll.sll_ifindex;
	lifp = ifp->info;
	//memcpy(lifp->dst_mac, sll.sll_addr,ETH_ALEN);
	memcpy(lifp->own_mac, sll.sll_addr, ETH_ALEN);
	lifp->sock = sock;

	lldp_send_debug_test(ifp->ifindex, lifp);

	//while (1)
	{
		n_res = sendto(sock, buffer, 1024, 0, (struct sockaddr *)&sll, sizeof(sll));

		if (n_res < 0) {
			if (lldp_privs.change(ZPRIVS_LOWER)) {
				zlog_err("%s: could not lower privs, %s", __func__,
					 safe_strerror(errno));
			}
			perror("sendto()\n");
			return -1;
		}
	}
	if (lldp_privs.change(ZPRIVS_LOWER)) {
		zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
	}
	close(lifp->sock);
	return 0;
}

static int lldp_raw_socket_init(struct interface *ifp)
{
	int sock = 0;
	struct ifreq ifr;
	struct sockaddr_ll ll;
	struct lldp_interface *lifp = ifp->info;

	if (lldp_privs.change(ZPRIVS_RAISE))
		zlog_err("%s: could not raise privs, %s", __func__, safe_strerror(errno));

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_8021Q | ETH_P_LLDP));
	if (sock < 0) {
		if (lldp_privs.change(ZPRIVS_LOWER))
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		zlog_err("%s: socket: %s", __func__, strerror(errno));
		return -1;
	}
	memset(&ll, 0, sizeof(ll));
	LLDP_DEBUG_LOG("get %s %d %d", ifp->name, ifp->ifindex, ifr.ifr_ifindex);
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifp->name);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		if (lldp_privs.change(ZPRIVS_LOWER))
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		zlog_err("%s: get flags: %s", __func__, strerror(errno));
		close(sock);
		return -1;
	}
	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		if (lldp_privs.change(ZPRIVS_LOWER))
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		zlog_err("%s: setting promisc mode: %s", __func__, strerror(errno));
		close(sock);
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifp->name);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		if (lldp_privs.change(ZPRIVS_LOWER))
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		zlog_err("%s: ioctl[SIOCGIFHWADDR]: %s", __func__, strerror(errno));
		close(sock);
		return -1;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_halen = ETH_ALEN;
	ll.sll_ifindex = ifp->ifindex;
	ll.sll_protocol = htons(ETH_P_8021Q | ETH_P_LLDP);
	memcpy(ll.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (bind(sock, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
		if (lldp_privs.change(ZPRIVS_LOWER))
			zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
		zlog_err("%s: bind[PF_PACKET]: %s", __func__, strerror(errno));
		close(sock);
		return -1;
	}

	if (lldp_privs.change(ZPRIVS_LOWER)) {
		zlog_err("%s: could not lower privs, %s", __func__, safe_strerror(errno));
	}

	memcpy(lifp->own_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	LLDP_DEBUG_LOG("%s:%s get mac %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, ifp->name,
		       lifp->own_mac[0], lifp->own_mac[1], lifp->own_mac[2], lifp->own_mac[3],
		       lifp->own_mac[4], lifp->own_mac[5]);

	//if(lifp->mode & LLDP_READ_MODE)
	//	lifp->t_read = thread_add_read (master, lldp_read_packet, ifp, sock);
	//lifp->ibuf = stream_new (LLDP_PACKET_MAX_SIZE);
	//lifp->obuf = stream_new (LLDP_PACKET_MAX_SIZE);
	//lifp->outbuf = XMALLOC (MTYPE_STREAM_DATA, LLDP_PACKET_MAX_SIZE);
	lifp->sock = sock;
	return sock;
}
static int lldp_raw_write(struct thread *thread)
{
	int sock;
	struct interface *ifp = if_lookup_by_name("eno16777736");
	//int sock = THREAD_FD (thread);
	//sock = lldp_raw_socket_init(ifp);
	lldp_interface_socket_init(ifp);
	//if(sock)
	{
		lldp_send_debug_test(ifp->ifindex, ifp->info);

		//close(sock);
	}
	//lld_raw_test("eno16777736");
	return CMD_SUCCESS;
}
int aaa_test()
{
	thread_add_timer(master, lldp_raw_write, NULL, 5);
}
#endif
