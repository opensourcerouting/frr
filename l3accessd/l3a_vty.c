#include "lib/zebra.h"

#include "lib/command.h"
#include "lib/vty.h"

#include "l3a.h"

#include "l3a_vty_clippy.c"

DEFPY(l3a_route_main,
      l3a_route_cmd,
      "ipv6 l3access route X:X::X:X/M lifetime (0-4294967295) via X:X::X:X interface IFNAME",
      IPV6_STR
      "L3 access protocols\n"
      "Set up route\n"
      "Prefix\n"
      "Lifetime\n"
      "Lifetime (milliseconds)\n"
      "Nexthop\n"
      "Nexthop\n"
      "Interface\n"
      "Interface\n")
{
	union g_addr nexthop;
	nexthop.ipv6 = via;

	l3a_route_update(route, lifetime, &nexthop, ifname, NULL, 0);
	return CMD_SUCCESS;
}

DEFPY(l3a_dhcpv6_main,
      l3a_dhcpv6_cmd,
      "ipv6 l3access dhcp-snoop IFNAME",
      IPV6_STR
      "L3 access protocols\n"
      "DHCPv6 snooping\n"
      "Interface\n")
{
	struct l3a_if *l3a_if = l3a_if_get_byname(ifname);
	l3a_if->snoop = true;
	l3a_dhcpv6_snoop(l3a_if);
	return CMD_SUCCESS;
}

DEFPY(l3a_arp_main,
      l3a_arp_cmd,
      "ip l3access arp-snoop IFNAME",
      IP_STR
      "L3 access protocols\n"
      "ARP snooping\n"
      "Interface\n")
{
	struct l3a_if *l3a_if = l3a_if_get_byname(ifname);
	l3a_if->arp_snoop = true;
	l3a_arp_snoop(l3a_if);
	return CMD_SUCCESS;
}

DEFPY(l3a_dhcpv6_show_main,
      l3a_dhcpv6_show_cmd,
      "show ipv6 l3access dhcp-snoop",
      SHOW_STR
      IPV6_STR
      "L3 access protocols\n"
      "DHCPv6 snooping\n")
{
	l3a_dhcpv6_show(vty);
	return CMD_SUCCESS;
}

DEFPY(l3a_dhcpv6_db_main,
      l3a_dhcpv6_db_cmd,
      "ipv6 l3access dhcp-db DBNAME",
      IPV6_STR
      "L3 access protocols\n"
      "DHCPv6 snooping database\n"
      "Filename\n")
{
	l3a_dhcpv6_db(dbname);
	return CMD_SUCCESS;
}

static struct cmd_node l3a_interface_node = {
	INTERFACE_NODE,
	"%s(config-if)# ",
	1
};

void l3a_vty_init(void)
{
	install_node(&l3a_interface_node, NULL);
	if_cmd_init();

	install_element(ENABLE_NODE, &l3a_route_cmd);
	install_element(ENABLE_NODE, &l3a_dhcpv6_show_cmd);

	install_element(CONFIG_NODE, &l3a_arp_cmd);
	install_element(CONFIG_NODE, &l3a_dhcpv6_cmd);
	install_element(CONFIG_NODE, &l3a_dhcpv6_db_cmd);
}
