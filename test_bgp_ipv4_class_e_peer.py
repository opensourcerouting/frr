# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Check if the peering works by using IPv4 Class E IP ranges, and if
we don't treat next-hop as martian in such a case.
"""

__topotests_file__ = "bgp_ipv4_class_e_peer/test_bgp_ipv4_class_e_peer.py"
__topotests_gitrev__ = "acddc0ed3ce0833490b7ef38ed000d54388ebea4"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }
      |
    [ r2 ]

    """
    # Support for E-Class IPs needs to be enabled beforehand

    topo.router("r1").lo_ip4.append("172.16.255.1/32")
    topo.router("r1").iface_to("s1").ip4.append("240.0.0.1/24")
    topo.router("r2").iface_to("s1").ip4.append("240.0.0.2/24")


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }}
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
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers connect 1
     address-family ipv4
      redistribute connected
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers connect 1
    !
    #%   endif
    #% endblock
    """


class BGPIpv4ClassEPeer(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, r1, r2):
        expected = {
            str(r1.iface_to("s1").ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r1.iface_to('s1').ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_next_hop_ipv4_class_e(self, r1, r2):
        expected = {
            "paths": [
                {
                    "valid": True,
                    "nexthops": [
                        {
                            "ip": str(r1.iface_to("s1").ip4[0].ip),
                            "accessible": True,
                        }
                    ],
                }
            ]
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show bgp ipv4 unicast {r1.lo_ip4[0]} json",
            maxwait=5.0,
            compare=expected,
        )
