# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Tsen Chee Vincent LEUNG YIN KO

"""
Test if BGP community alias is visible in CLI outputs.
"""

__topotests_file__ = "bgp_community_alias/test_bgp-community-alias.py"
__topotests_gitrev__ = "a53c08bc131c02f4a20931d7aa9f974194ab16e7"

from topotato import *


@topology_fixture()
def allproto_topo(topo):
    """
    [ r1 ]
       |
    { s1 }
       |
    [ r2 ]
    """
    topo.router("r2").lo_ip4.append("172.16.16.1/32")
    topo.router("r2").lo_ip4.append("172.16.16.2/32")
    topo.router("r2").lo_ip4.append("172.16.16.3/32")


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%  if router.name == 'r2'
    interface lo
     ip address {{ routers.r2.lo_ip4[0] }}
     ip address {{ routers.r2.lo_ip4[1] }}
     ip address {{ routers.r2.lo_ip4[2] }}
    !
    #%  endif
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }}
    !
    #%   endfor
    #% endblock
    """

    bgpd = """
    #% block main
        #%  if router.name == 'r1'
        !
        bgp send-extra-data zebra
        !
        bgp community alias 65001:1 community-r2-1
        bgp community alias 65002:2 community-r2-2
        bgp community alias 65001:1:1 large-community-r2-1
        !
        bgp large-community-list expanded r2 seq 5 permit _65001:1:1_
        !
        router bgp 65001
            no bgp ebgp-requires-policy
            neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as external
            address-family ipv4 unicast
                redistribute connected
                neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} route-map r2 in
        exit-address-family
        !
        route-map r2 permit 10
            match alias community-r2-1
            set tag 10
        route-map r2 permit 20
            match alias community-r2-2
            set tag 20
        route-map r2 permit 30
            set tag 100
        !
        #%   elif router.name == 'r2'
        !
        bgp send-extra-data zebra
        !
        router bgp 65002
            no bgp ebgp-requires-policy
            neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as external
            address-family ipv4 unicast
                redistribute connected
                neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} route-map r1 out
        exit-address-family
        !
        ip prefix-list p1 permit {{ routers.r2.lo_ip4[0] }}
        ip prefix-list p2 permit {{ routers.r2.lo_ip4[1] }}
        ip prefix-list p3 permit {{ routers.r2.lo_ip4[2] }}
        !
        route-map r1 permit 10
            match ip address prefix-list p1
            set community 65001:1 65001:2
            set large-community 65001:1:1 65001:1:2
        route-map r1 permit 20
            match ip address prefix-list p2
            set community 65002:1 65002:2
        route-map r1 permit 30
            match ip address prefix-list p3
        !
        #%   endif
    #% endblock
    """


@config_fixture(Configs)
def configs(config, allproto_topo):
    return


@instance_fixture()
def testenv(configs):
    return FRRNetworkInstance(configs.topology, configs).prepare()


class BGPCommunityAliasTest(TestBase):
    instancefn = testenv

    @topotatofunc
    def _bgp_converge(self, topo, r1, r2):
        expected = {
            str(r2.lo_ip4[0]): [
                {
                    "tag": 10,
                    "communities": "community-r2-1 65001:2",
                    "largeCommunities": "large-community-r2-1 65001:1:2",
                }
            ],
            str(r2.lo_ip4[1]): [
                {
                    "tag": 20,
                    "communities": "65002:1 community-r2-2",
                    "largeCommunities": "",
                }
            ],
            str(r2.lo_ip4[2]): [
                {
                    "tag": 100,
                    "communities": "",
                    "largeCommunities": "",
                }
            ],
        }

        yield from AssertVtysh.make(
            r1,
            "zebra",
            f"show ip route json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def _bgp_show_prefixes_by_alias(self, topo, r1, r2):
        expected = {
            "routes": {
                str(r2.lo_ip4[0]): [
                    {
                        "community": {"string": "community-r2-1 65001:2"},
                        "largeCommunity": {"string": "large-community-r2-1 65001:1:2"},
                    }
                ]
            }
        }

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast alias large-community-r2-1 json detail",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def _bgp_show_prefixes_by_large_community_list(self, topo, r1, r2):
        expected = {"routes": {str(r2.lo_ip4[0]): [{"valid": True}]}}

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast large-community-list r2 json",
            maxwait=5.0,
            compare=expected,
        )
