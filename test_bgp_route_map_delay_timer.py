# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""

"""

__topotests_file__ = "bgp_route_map_delay_timer/test_bgp_route_map_delay_timer.py"
__topotests_gitrev__ = "4d8e44c7538c6479ac99ec842bebc42a1e6b2ebc"

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
    #% endblock
    """

    bgpd = """
    #% block main
    #%   if router.name == 'r1'
    !
    !debug bgp updates
    !debug bgp neighbor
    !
    bgp route-map delay-timer 5
    !
    router bgp 65001
     no bgp ebgp-requires-policy
     no bgp network import-check
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
     address-family ipv4 unicast
      network 10.10.10.1/32
      network 10.10.10.2/32
      network 10.10.10.3/32
      aggregate-address 10.10.10.0/24 summary-only
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} unsuppress-map r2
    exit-address-family
    !
    ip prefix-list r1 seq 5 permit 10.10.10.1/32
    ip prefix-list r1 seq 10 permit 10.10.10.2/32
    !
    route-map r2 permit 10
     match ip address prefix-list r1
    exit
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
    !
    #%   endif
    #% endblock
    """


class BGPRouteMapDelayTimer(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge_1(self, r1, r2):
        expected = {
            "advertisedRoutes": {
                "10.10.10.0/24": {},
                "10.10.10.1/32": {},
                "10.10.10.2/32": {},
                "10.10.10.3/32": None,
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast neighbor {r2.iface_to('s1').ip4[0].ip} advertised-routes json",
            maxwait=5.0,
            compare=expected,
        )

    # This bit does not work. Work in Progress.
    @topotatofunc
    def bgp_converge_2(self, r1, r2):
        expected = {
            "advertisedRoutes": {
                "10.10.10.0/24": {},
                "10.10.10.1/32": {},
                "10.10.10.2/32": None,
                "10.10.10.3/32": None,
            }
        }

        yield from AssertVtysh.make(
            r2,
            "vtysh",
            """
            configure terminal
            bgp route-map delay-timer 600
            no ip prefix-list r1 seq 10 permit 10.10.10.2/32
            exit
            """,
            compare="",
        )

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast neighbor {r2.iface_to('s1').ip4[0].ip} advertised-routes json",
            maxwait=5.0,
            compare=expected,
        )
