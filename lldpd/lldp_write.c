/*
 * lldp_write.c
 *
 *  Created on: Oct 25, 2016
 *      Author: zhurish
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

#include "lldpd.h"
#include "lldp_interface.h"
#include "lldp_neighbor.h"
//#include "lldp_db.h"
#include "lldp_packet.h"
#include "lldp_socket.h"


int lldp_write(struct thread *thread)
{
	int sock;
	struct interface *ifp;
	struct lldp_interface *lifp;
	ifp = THREAD_ARG(thread);
	sock = THREAD_FD(thread);
	lifp = ifp->info;
	lldp_make_lldp_pdu(ifp);
	return lldp_write_packet(sock, ifp, lifp->obuf);
}

int lldp_timer(struct thread *thread)
{
	struct interface *ifp;
	struct lldp_interface *lifp;
	ifp = THREAD_ARG(thread);
	//sock = THREAD_FD (thread);
	lifp = (struct lldp_interface *)ifp->info;
	if (lifp) {
		if (lifp->mode != LLDP_DISABLE) {
			//lldp_make_lldp_pdu(ifp);

			lifp->t_time = thread_add_timer(master, lldp_timer, ifp, lifp->lldp_timer);

			//LLDP_DEBUG_LOG("aaaaaaaaaaaaa:%s size=%d\n",ifp->name,(int)stream_get_endp(lifp->obuf));

			LLDP_DEBUG_LOG("%s:%s\n", __func__, ifp->name);
			//lldp_write_debug(ifp);
			//lldp_write_packet (lifp->sock, ifp, lifp->obuf);
			if (lldpd_config && lldpd_config->lldp_enable == 1)
				lifp->t_write = thread_add_write(master, lldp_write, ifp,
								 lifp->sock);
		}
	}
	return CMD_SUCCESS;
}
