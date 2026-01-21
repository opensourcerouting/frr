# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if local-preference is passed between different EBGP peers when
EBGP-OAD is configured.
"""

__topotests_replaces__ = {
    "bgp_oad/": "ba67eb6bd090c78bc9eb0b4bb11ecc0c30661c1a",
}

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument, attribute-defined-outside-init
from topotato.v1 import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    [ r2 ]
      |
    [ r3 ]

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
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} oad
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers connect 1
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} oad
     neighbor {{ routers.r3.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r3.ifaces[0].ip4[0].ip }} timers 1 3
     neighbor {{ routers.r3.ifaces[0].ip4[0].ip }} timers connect 1
     neighbor {{ routers.r3.ifaces[0].ip4[0].ip }} oad
    !
    #%   elif router.name == 'r3'
    router bgp 65003
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.ifaces[1].ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.ifaces[1].ip4[0].ip }} timers 1 3
     neighbor {{ routers.r2.ifaces[1].ip4[0].ip }} timers connect 1
     neighbor {{ routers.r2.ifaces[1].ip4[0].ip }} oad
     address-family ipv4 unicast
      redistribute connected route-map connected
     exit-address-family
    !
    route-map connected permit 10
     set local-preference 123
     set metric 123
    !
    #%   endif
    #% endblock
    """


class BGP_OAD(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, r1, r2, r3):
        expected = {
            "paths": [
                {
                    "aspath": {"string": "65002 65003"},
                    "metric": 123,
                    "locPrf": 123,
                }
            ]
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast {r3.lo_ip4[0].ip} json",
            maxwait=7.0,
            compare=expected,
        )
