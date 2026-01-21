# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if r1 can announce only static routes to r2, and only connected
routes to r3 using `match source-protocol` with route-maps.
"""


__topotests_file__ = (
    "bgp_route_map_match_source_protocol/test_bgp_route_map_match_source_protocol.py"
)
__topotests_gitrev__ = "9c3ffc80db2ef0445ab6d8dabf6b5f696cbd0470"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]--{ s2 }
      |       |
    { s1 }--[ r3 ]
      |
    [ r2 ]
    """

    topo.router("r1").lo_ip4.append("172.16.255.1/32")
    topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")
    topo.router("r1").iface_to("s2").ip4.append("192.168.2.1/24")
    topo.router("r3").iface_to("s1").ip4.append("192.168.2.2/24")


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }}
    !
    #%   endfor
    #% endblock
    """

    staticd = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    ip route 10.10.10.10/32 192.168.2.2
    #%   endif
    #% endblock
    """

    bgpd = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers connect 1
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} timers connect 1
     address-family ipv4
      redistribute connected
      redistribute static
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} route-map r2 out
      neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} route-map r3 out
     exit-address-family
    !
    route-map r2 permit 10
     match source-protocol static
    route-map r3 permit 10
     match source-protocol connected
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers connect 1
    !
    #%   elif router.name == 'r3'
    router bgp 65003
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s2').ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.iface_to('s2').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.iface_to('s2').ip4[0].ip }} timers connect 1
    !
    #%   endif
    #% endblock
    """


class BGPRouteMapMatchSourceProtocol(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def bgp_check_advertised_routes_r2(self, _, r1, r2):
        expected = {
            "advertisedRoutes": {
                "10.10.10.10/32": {
                    "valid": True,
                }
            },
            "totalPrefixCounter": 1,
        }

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast neighbors {r2.iface_to('s1').ip4[0].ip} advertised-routes json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_advertised_routes_r3(self, _, r1, r3):
        expected = {
            "advertisedRoutes": {
                "192.168.1.0/24": {
                    "valid": True,
                },
                "192.168.2.0/24": {
                    "valid": True,
                },
                "172.16.255.1/32": {
                    "valid": True,
                },
            },
            "totalPrefixCounter": 3,
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast neighbors {r3.iface_to('s1').ip4[0].ip} advertised-routes json",
            maxwait=5.0,
            compare=expected,
        )
