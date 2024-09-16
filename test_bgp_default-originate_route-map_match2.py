# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if default-originate works with conditional match.
If 10.0.0.0/22 is recived from r2, then we announce 0.0.0.0/0
to r2.
"""


__topotests_file__ = (
    "bgp_default_route_route_map_match2/test_bgp_default-originate_route-map_match2.py"
)
__topotests_gitrev__ = "acddc0ed3ce0833490b7ef38ed000d54388ebea4"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

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

    topo.router("r1").iface_to("s1").ip4.append("192.168.255.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.255.2/24")


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
    router bgp 65000
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as 65001
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} default-originate route-map default
     exit-address-family
    !
    ip prefix-list r2 permit 10.0.0.0/22
    !
    route-map default permit 10
     match ip address prefix-list r2
    !
    #%   elif router.name == 'r2'    
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as 65000
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      redistribute connected
     exit-address-family
    !
    #%   endif
    #% endblock
    """


class BGPDefaultOriginateRouteMap(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def bgp_converge(self, _, r1, r2):
        expected = {
            str(r1.iface_to("s1").ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 0}},
            }
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor 192.168.255.1 json",
            maxwait=10.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_default_route_is_valid_1(self, _, r2):
        expected = {"paths": [{"valid": True}]}

        yield from AssertVtysh.make(
            r2,
            "vtysh",
            """
            configure terminal
            router bgp
            address-family ipv4
             no redistribute connected
            exit 
            """,
            compare="",
        )

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp 0.0.0.0/0 json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_default_route_is_valid_2(self, _, r2):
        expected = {"paths": [{"valid": True}]}

        yield from AssertVtysh.make(
            r2,
            "vtysh",
            """
            configure terminal
            router bgp
            address-family ipv4
             no redistribute connected
            exit 
            """,
            compare="",
        )

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp 0.0.0.0/0 json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_default_route_is_valid_3(self, _, r2):
        expected = {"paths": [{"valid": True}]}

        yield from AssertVtysh.make(
            r2,
            "vtysh",
            """
            configure terminal
            router bgp
            address-family ipv4
             no redistribute connected
            exit 
            """,
            compare="",
        )

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp 0.0.0.0/0 json",
            maxwait=5.0,
            compare=expected,
        )
