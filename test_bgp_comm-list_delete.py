# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if works the following commands:
route-map test permit 10
  set comm-list <arg> delete
"""

__topotests_replaces__ = {
    "bgp_comm_list_delete/": "4953ca977f3a5de8109ee6353ad07f816ca1774c",
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
    #% if router.name == 'r1'
    router bgp 65000
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as 65001
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      redistribute connected route-map r2-out
    !
    route-map r2-out permit 10
     set community 111:111 222:222 333:333 444:444
    !
    #% elif router.name == 'r2'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as 65000
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} timers 3 10
     address-family ipv4
      neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} route-map r1-in in
    !
    bgp community-list standard r1 permit 333:333
    !
    route-map r1-in permit 10
     set comm-list r1 delete
    !
    #% endif
    #% endblock
    """


class BGPCommListDeleteTest(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, topo, r1, r2):
        expected = {
            str(r1.ifaces[0].ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 2,
                    }
                },
            }
        }

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor { r1.ifaces[0].ip4[0].ip } json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_comm_list_delete(self, topo, r1, r2):
        expected = {
            "paths": [{"community": {"list": ["111:111", "222:222", "444:444"]}}]
        }

        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp { r1.lo_ip4[0] } json",
            maxwait=5.0,
            compare=expected,
        )
