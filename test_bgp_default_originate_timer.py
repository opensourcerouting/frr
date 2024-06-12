# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Check if `bgp default-originate timer` commands takes an effect:
1. Set bgp default-originate timer 3600
2. No default route is advertised because the timer is running for 3600 seconds
3. We reduce it to 10 seconds
4. Default route is advertised
"""


__topotests_replaces__ = {
    "bgp_default_originate_timer/": "1bfbdc17f20fe4e9d66c9adcbfa48b7a7adfdc29",
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
    routers = ["r1", "r2", "r3"]

    zebra = """
    #% extends "boilerplate.conf"
    ## nothing needed
    """

    bgpd = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     bgp default-originate timer 3600
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers 1 3
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers connect 1
     neighbor {{ routers.r3.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r3.ifaces[0].ip4[0].ip }} timers 1 3
     neighbor {{ routers.r3.ifaces[0].ip4[0].ip }} timers connect 1
     address-family ipv4
      neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} default-originate route-map default
     exit-address-family
    !
    bgp community-list standard r3 seq 5 permit 65003:1
    !
    route-map default permit 10
     match community r3
    exit
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers connect 1
    !
    #%   elif router.name == 'r3'
    router bgp 65003
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers connect 1
     address-family ipv4 unicast
      redistribute connected route-map r1
     exit-address-family
    !
    route-map r1 permit 10
     set community 65003:1
    exit
    #%   endif
    #% endblock
    """


class BGPDefaultOriginateTimer(TestBase, AutoFixture, topo=topology, configs=Configs):
    # Negative check function not yet implemented
    #
    # @topotatofunc
    # def bgp_default_received_from_r1(self, _, r1, r2):
    #     expected = {
    #         "paths": [
    #             {
    #                 "nexthops": [
    #                     {
    #                         "hostname": "r1",
    #                         "ip": str(r1.iface_to("s1").ip4[0].ip),
    #                     }
    #                 ],
    #             }
    #         ],
    #     }

    #     yield from AssertVtysh.make(
    #         r2,
    #         "bgpd",
    #         f"show bgp ipv4 unicast 0.0.0.0/0 json",
    #         maxwait=30.0,
    #         compare=expected,
    #     )

    @topotatofunc
    def bgp_default_received_from_r1_2(self, _, r1, r2, r3):
        expected = {
            "paths": [
                {
                    "nexthops": [
                        {
                            "hostname": "r1",
                            "ip": str(r1.ifaces[0].ip4[0].ip),
                        }
                    ],
                }
            ],
        }

        yield from ReconfigureFRR.make(
            r1,
            "bgpd",
            """
            router bgp
                bgp default-originate timer 10
            """,
            compare="",
        )

        yield from ReconfigureFRR.make(
            r3,
            "bgpd",
            """
            route-map r1 permit 10
                set metric 1
            """,
            compare="",
        )

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show bgp ipv4 unicast 0.0.0.0/0 json",
            maxwait=20.0,
            compare=expected,
        )
