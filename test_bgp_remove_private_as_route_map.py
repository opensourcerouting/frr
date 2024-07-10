# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if private AS is removed from AS_PATH attribute when route-map is used (prepend).
"""

__topotests_replaces__ = {
    "bgp_remove_private_as_route_map/": "adb1c9aa519c80880635b57124fbda97062572d8",
}

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument, attribute-defined-outside-init
from topotato.v1 import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    [ r2 ]

    """


class Configs(FRRConfigs):
    zebra = """
    #% extends "boilerplate.conf"
    ## nothing needed
    """

    bgpd = """
    #% block main
    #%   if router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers 1 3
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers connect 1
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers connect 1
     address-family ipv4 unicast
      redistribute connected
      neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} route-map r1 out
      neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remove-private-AS all
     exit-address-family
    !
    route-map r1 permit 10
     set as-path prepend 65123 4200000001
    !
    #%   endif
    #% endblock
    """


class BGP_Remove_Private_AS_Route_Map(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def check_routes(self, r1, r2):
        expected = {
            "routes": {
                "10.255.0.2/32": [
                    {
                        "valid": True,
                        "path": "65002",
                    }
                ]
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast json",
            maxwait=5.0,
            compare=expected,
        )
