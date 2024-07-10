#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if Opaque Data is accessable from other daemons in Zebra
"""

__topotests_file__ = "zebra_opaque/test_zebra_opaque.py"
__topotests_gitrev__ = "77e3d82167b97a1ff4abe59d6e4f12086a61d9f9"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }  [ r3 ]
      |       |
    [ r2 ]  { s2 }
              |
            [ r4 ]
    """


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }}
     ipv6 address {{ iface.ip6[0] }}
    !
    #%   endfor
    ip forwarding
    !
    #% endblock
    """

    bgpd = """
    #% block main
    #%   if router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
     address-family ipv4 unicast
      redistribute connected
      neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} route-map r1 out
     exit-address-family
    !
    route-map r1 permit 10
     set community 65002:1 65002:2
     set large-community 65002:1:1 65002:2:1
    !
    #%   endif
    #% endblock
    """

    ospf6d = """
    #% block main
    #%   if router.name == 'r3'
    interface r3-eth0
     ipv6 ospf6 area 0
     ipv6 ospf6 hello-interval 2
     ipv6 ospf6 dead-interval 10
    !
    router ospf6
     ospf6 send-extra-data zebra
    !
    #%   elif router.name == 'r4'
    interface r4-eth0
     ipv6 ospf6 area 0
     ipv6 ospf6 hello-interval 2
     ipv6 ospf6 dead-interval 10
    !
    router ospf6
     ospf6 send-extra-data zebra
    !
    #%   endif
    #% endblock
    """

    ospfd = """
    #% block main
    #%   if router.name == 'r3'
    interface r3-eth0
     ip ospf area 0
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    router ospf
     ospf send-extra-data zebra
    !
    #%   elif router.name == 'r4'
    interface r4-eth0
     ip ospf area 0
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    router ospf
     ospf send-extra-data zebra
    !
    #%   endif
    #% endblock
    """


class ZebraOpaque(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, _, r1, r3, r2):
        expected = {
            str(r1.lo_ip4[0].ip): [
                {
                    "communities": "65002:1 65002:2",
                    "largeCommunities": "65002:1:1 65002:2:1",
                }
            ]
        }
        yield from AssertVtysh.make(
            r1,
            "vtysh",
            f"show ip route {r1.lo_ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )

    # @topotatofunc
    # def ospf_converge(self, _, r1, r3):
    #     expected = {
    #         str(r1.lo_ip4[0].ip): [
    #             {
    #                 "ospfPathType": "Intra-Area",
    #                 "ospfAreaId": "0.0.0.0",
    #             }
    #         ]
    #     }
    #     yield from AssertVtysh.make(
    #         r3,
    #         "zebra",
    #         f"show ip route {r1.lo_ip4[0].ip} json",
    #         maxwait=5.0,
    #         compare=expected,
    #     )
