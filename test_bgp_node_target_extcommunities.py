# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if Node Target Extended Communities works.

At r1 we set NT to 192.168.1.3 and 192.168.1.4 (this is the R3/R4 router-id),
and that means 10.10.10.10/32 MUST be installed on R3 and R4, but not on R2,
because this route does not have NT:192.168.1.2.
"""


__topotests_file__ = (
    "bgp_node_target_extcommunities/test_bgp_node_target_extcommunities.py"
)
__topotests_gitrev__ = "068c4dfe0b8196e6f67d1211e492f5d265801c9e"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

from topotato import *


@topology_fixture()
def topology(topo):
    """
            [ r1 ]
              |
    [ r4 ]--{ s1 }--[ r3 ]
              |
            [ r2 ]

    """

    # topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    # topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")
    # topo.router("r3").iface_to("s1").ip4.append("192.168.1.3/24")
    # topo.router("r4").iface_to("s1").ip4.append("192.168.1.4/24")


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3", "r4"]

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
     bgp router-id {{ routers.r1.iface_to('s1').ip4[0].ip }}
     no bgp ebgp-requires-policy
     no bgp network import-check
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r4.iface_to('s1').ip4[0].ip }} remote-as external
     address-family ipv4 unicast
      network 10.10.10.10/32
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} route-map rmap out
      neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} route-map rmap out
      neighbor {{ routers.r4.iface_to('s1').ip4[0].ip }} route-map rmap out
     exit-address-family
    !
    route-map rmap permit 10
     set extcommunity nt {{ routers.r3.iface_to('s1').ip4[0].ip }}:0 {{ routers.r4.iface_to('s1').ip4[0].ip }}:0
    exit
    #%   elif router.name == 'r2'
    router bgp 65002
     bgp router-id {{ routers.r2.iface_to('s1').ip4[0].ip }}
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
    !
    #%   elif router.name == 'r3'
    router bgp 65003
     bgp router-id {{ routers.r3.iface_to('s1').ip4[0].ip }}
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
    !
    #%   elif router.name == 'r4'
    router bgp 65004
     bgp router-id {{ routers.r4.iface_to('s1').ip4[0].ip }}
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
    !
    #%   endif
    #% endblock
    """


class BGPNodeTargetExtendedCommunities(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def bgp_converge(self, _, r1, r2, r3, r4):
        expected = {
            "ipv4Unicast": {
                "peers": {
                    str(r2.iface_to("s1").ip4[0].ip): {
                        "pfxSnt": 1,
                        "state": "Established",
                    },
                    str(r3.iface_to("s1").ip4[0].ip): {
                        "pfxSnt": 1,
                        "state": "Established",
                    },
                    str(r4.iface_to("s1").ip4[0].ip): {
                        "pfxSnt": 1,
                        "state": "Established",
                    },
                }
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp summary json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_route_r2(self, _, r2):
        expected = {
            "routes": {
                "10.10.10.10/32": None,
            }
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show bgp ipv4 unicast json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_route_r3(self, _, r3):
        expected = {
            "routes": {
                "10.10.10.10/32": [
                    {
                        "valid": True,
                    }
                ]
            }
        }
        yield from AssertVtysh.make(
            r3,
            "bgpd",
            f"show bgp ipv4 unicast json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_route_r4(self, _, r4):
        expected = {
            "routes": {
                "10.10.10.10/32": [
                    {
                        "valid": True,
                    }
                ]
            }
        }
        yield from AssertVtysh.make(
            r4,
            "bgpd",
            f"show bgp ipv4 unicast json",
            maxwait=5.0,
            compare=expected,
        )
