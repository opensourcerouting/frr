# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
test_bgp_color_extcommunity.py: Test the FRR BGP color extented
community feature
"""

__topotests_file__ = "bgp_color_extcommunities/test_bgp_color_extcommunities.py"
__topotests_gitrev__ = "9ec092c6a278d98dc5f36e8e8b2e04f3a9c3fd70"

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
     address-family ipv4 unicast
      network 10.10.10.10/24 route-map rmap
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} route-map rmap out
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} activate
     exit-address-family
    !
    route-map rmap permit 10
     set extcommunity color 1
     set extcommunity rt 80:987
     set extcommunity color 100 55555 200
    exit 
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     bgp router-id {{ routers.r2.iface_to('s1').ip4[0].ip }}
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
    !
    #%   endif
    #% endblock
    """


class BGPColorExtendedCommunities(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def bgp_converge(self, r1, r2):
        expected = {
            "ipv4Unicast": {
                "peers": {
                    str(r2.iface_to("s1").ip4[0].ip): {
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
    def bgp_check_route(self, r1, r2):
        expected = {
            "prefix": "10.10.10.0/24",
            "paths": [
                {
                    "valid": True,
                    "extendedCommunity": {
                        "string": "RT:80:987 Color:100 Color:200 Color:55555"
                    },
                }
            ],
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast 10.10.10.10 json",
            maxwait=5.0,
            compare=expected,
        )
