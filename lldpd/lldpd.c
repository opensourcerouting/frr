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
#include "lldp_db.h"
#include "lldp_packet.h"
#include "lldp_socket.h"


struct lldpd *lldpd_config;


int lldp_interface_enable(struct interface *ifp)
{
	int ret = 0;
	struct lldp_interface *lifp;

	if (ifp == NULL)
		return CMD_WARNING;

	lifp = (struct lldp_interface *)ifp->info;

	if (lifp == NULL)
		return CMD_WARNING;

	ret = lldp_interface_socket_init(ifp);

	if (ret <= 0) {
		lifp->mode = LLDP_DISABLE;
		zlog_debug("Can't enable lldp on interface %s (create socket error)", ifp->name);
		return CMD_WARNING;
	}
	lifp->ibuf = stream_new(LLDP_PACKET_MAX_SIZE);
	lifp->obuf = stream_new(LLDP_PACKET_MAX_SIZE);

	LLDP_DEBUG_LOG("%s:%s\n", __func__, ifp->name);

	if (lifp->mode & LLDP_WRITE_MODE)
		lifp->t_time = thread_add_timer(master, lldp_timer, ifp, lifp->lldp_timer);

	if (lifp->mode & LLDP_READ_MODE)
		lifp->t_read = thread_add_read(master, lldp_read, ifp, lifp->sock);

	return CMD_SUCCESS;
}


int lldp_interface_disable(struct interface *ifp)
{
	struct lldp_interface *lifp;
	if (ifp == NULL)
		return -1;
	lifp = (struct lldp_interface *)ifp->info;
	if (lifp == NULL)
		return -1;
	if (lifp->sock <= 0)
		return CMD_SUCCESS;
	if (lifp->mode == LLDP_DISABLE) {
		if (lifp->t_read)
			thread_cancel(lifp->t_read);
		if (lifp->t_write)
			thread_cancel(lifp->t_write);
		if (lifp->t_time)
			thread_cancel(lifp->t_time);
		if (lifp->ibuf)
			stream_free(lifp->ibuf);
		if (lifp->obuf)
			stream_free(lifp->ibuf);
	}
	return CMD_SUCCESS;
}


int lldp_interface_transmit_enable(struct interface *ifp)
{
	struct lldp_interface *lifp;
	if (ifp == NULL)
		return -1;
	lifp = (struct lldp_interface *)ifp->info;
	if (lifp == NULL)
		return -1;
	if (lifp->sock <= 0)
		return CMD_SUCCESS;
	if (lifp->mode == LLDP_DISABLE) {
		if (lifp->t_write)
			thread_cancel(lifp->t_write);
		if (lifp->t_time)
			thread_cancel(lifp->t_time);
		if (lifp->obuf)
			stream_free(lifp->ibuf);
	}
	if (lifp->mode & LLDP_WRITE_MODE) {
		if (lifp->t_write)
			thread_cancel(lifp->t_write);
		//参数变更立即更新数据
		lifp->t_write = thread_add_write(master, lldp_write, ifp, lifp->sock);

		if (lifp->t_time)
			thread_cancel(lifp->t_time);
		lifp->t_time = thread_add_timer(master, lldp_timer, ifp, lifp->lldp_timer);
	}
	return CMD_SUCCESS;
}


int lldp_interface_receive_enable(struct interface *ifp)
{
	struct lldp_interface *lifp;
	if (ifp == NULL)
		return -1;
	lifp = (struct lldp_interface *)ifp->info;
	if (lifp == NULL)
		return -1;
	if (lifp->sock <= 0)
		return CMD_SUCCESS;
	if (lifp->mode == LLDP_DISABLE) {
		if (lifp->t_read)
			thread_cancel(lifp->t_read);
		if (lifp->ibuf)
			stream_free(lifp->ibuf);
	}
	if (lifp->mode & LLDP_READ_MODE) {
		if (lifp->t_read)
			thread_cancel(lifp->t_read);
		lifp->t_read = thread_add_read(master, lldp_read, ifp, lifp->sock);
	}
	return CMD_SUCCESS;
}


int lldp_check_timer(struct thread *thread)
{
	int local_change = 0;
	struct lldpd *config;
	struct listnode *node;
	struct interface *ifp;
	struct lldp_interface *lifp;
	config = THREAD_ARG(thread);
	if (config) {
		if (lldpd_config->lldp_enable == 0)
			return CMD_SUCCESS;
		//初始化本地数据库/获取本地数据库并检测是否发生变化
		local_change = lldp_local_db_init();
		//检测本地信息是否发生变化
		//检测本地信息发生变化,触发发送LLDP更新报文
		for (ALL_LIST_ELEMENTS_RO(iflist, node, ifp)) {
			lifp = ifp->info;
			if (lifp == NULL)
				continue;
			if ((lifp->Changed || local_change) &&
			    (lifp->mode & LLDP_WRITE_MODE)) //端口数据发生变化，或者是系统发生变化
			{
				if (lifp->t_time)
					thread_cancel(lifp->t_time);
				lifp->t_time = thread_add_timer(master, lldp_timer, ifp, 2);
				lifp->Changed = 0;
			}
		}
		config->t_ckeck_time = thread_add_timer(master, lldp_check_timer, config,
							config->lldp_check_interval);
	}
	return CMD_SUCCESS;
}


int lldp_change_event(void)
{
	if (lldpd_config->t_ckeck_time)
		thread_cancel(lldpd_config->t_ckeck_time);
	lldpd_config->t_ckeck_time = thread_add_event(master, lldp_check_timer, lldpd_config, 0);
	//lldpd_config->t_ckeck_time = thread_add_timer(master, lldp_check_timer, lldpd_config, lldpd_config->lldp_check_interval);
	return 0;
}


DEFUN (lldpd_admin_enable,
		lldpd_admin_enable_cmd,
	    "lldp admin enable",
		LLDP_STR
		"admin status\n"
		"enable lldp\n")
{
	if (lldpd_config == NULL)
		return CMD_WARNING;
	if (lldpd_config->lldp_enable)
		return CMD_SUCCESS;
	lldpd_config->lldp_enable = 1;
	if (lldpd_config->t_ckeck_time)
		THREAD_TIMER_ON(master, lldpd_config->t_ckeck_time, lldp_check_timer, lldpd_config,
				lldpd_config->lldp_check_interval);
	else
		THREAD_TIMER_ON(master, lldpd_config->t_ckeck_time, lldp_check_timer, lldpd_config,
				1);
	return CMD_SUCCESS;
}


DEFUN (no_lldpd_admin_enable,
		no_lldpd_admin_enable_cmd,
	    "no lldp admin enable",
		NO_STR
		LLDP_STR
		"admin status\n"
		"enable lldp\n")
{
	if (lldpd_config == NULL)
		return CMD_WARNING;
	if (lldpd_config->lldp_enable == 0)
		return CMD_SUCCESS;
	lldpd_config->lldp_enable = 0;
	if (lldpd_config->t_ckeck_time)
		THREAD_TIMER_OFF(lldpd_config->t_ckeck_time);
	lldpd_config->t_ckeck_time = NULL;
	return CMD_SUCCESS;
}


DEFUN (lldpd_check_interval,
		lldpd_check_interval_cmd,
	    "lldp check-interval <1-600>",
		LLDP_STR
		"lldpd check interval\n"
		"time value (sec)\n")
{
	if (argv[0]) {
		int value = atoi(argv[0]);
		if (value < 1 || value > 600) {
			vty_out(vty, "Invalid input sec value ,you may input 1 - 600%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		if (lldpd_config && lldpd_config->lldp_check_interval != value) {
			lldpd_config->lldp_check_interval = value;
			if (lldpd_config->t_ckeck_time)
				THREAD_TIMER_OFF(lldpd_config->t_ckeck_time);
			THREAD_TIMER_ON(master, lldpd_config->t_ckeck_time, lldp_check_timer,
					lldpd_config, lldpd_config->lldp_check_interval);
		}
		return CMD_SUCCESS;
	}
	return CMD_WARNING;
}


DEFUN (no_lldpd_check_interval,
		no_lldpd_check_interval_cmd,
	    "no lldp check-interval",
		NO_STR
		LLDP_STR
		"lldpd check interval\n"
		"time value (sec)\n")
{
	if (lldpd_config && lldpd_config->lldp_check_interval != LLDP_CHECK_TIME_DEFAULT) {
		lldpd_config->lldp_check_interval = LLDP_CHECK_TIME_DEFAULT;
		if (lldpd_config->t_ckeck_time)
			THREAD_TIMER_OFF(lldpd_config->t_ckeck_time);
		THREAD_TIMER_ON(master, lldpd_config->t_ckeck_time, lldp_check_timer, lldpd_config,
				lldpd_config->lldp_check_interval);
	}
	return CMD_SUCCESS;
}


static int lldp_config_write(struct vty *vty)
{
	if (!lldpd_config || !lldpd_config->lldp_enable)
		return CMD_SUCCESS;
	if (lldpd_config->lldp_enable)
		vty_out(vty, "lldp admin enable%s", VTY_NEWLINE);
	//if(lldpd_config->lldp_tlv_select != LLDP_HOLD_TIME_DEFAULT)
	//	vty_out (vty, "lldp hold-time %d %s",lifp->lldp_holdtime, VTY_NEWLINE);
	if (lldpd_config->lldp_check_interval != LLDP_CHECK_TIME_DEFAULT)
		vty_out(vty, "lldp check-interval %d %s", lldpd_config->lldp_check_interval,
			VTY_NEWLINE);

	vty_out(vty, "!%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}


static struct cmd_node lldp_node = {
	LLDP_NODE,
	"%s(config)# ",
	1,
};


int lldp_config_init(void)
{
	lldpd_config = XMALLOC(MTYPE_LLDP, sizeof(struct lldpd));
	//lldpd_config->system_name = strdup("route-platform");

	lldpd_config->lldp_enable = 0;
	lldpd_config->version = LLDP_VERSION;
	lldpd_config->lldp_check_interval = LLDP_CHECK_TIME_DEFAULT;
	lldpd_config->lldp_tlv_select = 0xffffff;

	//lldpd_config->tlv_db = XMALLOC (MTYPE_TMP, sizeof(struct lldp_neighbor));

#ifdef LLDP_DEBUG_TEST
	extern int aaa_test();
	aaa_test();
#endif
	install_node(&lldp_node, lldp_config_write);

	install_default(LLDP_NODE);

	install_element(CONFIG_NODE, &lldpd_admin_enable_cmd);
	install_element(CONFIG_NODE, &no_lldpd_admin_enable_cmd);

	install_element(CONFIG_NODE, &lldpd_check_interval_cmd);
	install_element(CONFIG_NODE, &no_lldpd_check_interval_cmd);

	return 0;
}
