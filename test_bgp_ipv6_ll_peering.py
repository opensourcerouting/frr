# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Check if IPv6 Link-Local BGP peering works fine.
"""

__topotests_file__ = "bgp_ipv6_ll_peering/test_bgp_ipv6_ll_peering.py"
__topotests_gitrev__ = "0f4a09ac25d42601f42d37e044f8630ec7d31507"

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
    #%   if router.name == 'r1'
    interface eth0
     ipv6 address {{ routers.r1.iface_to('s1').ip6[0] }}
    !
    #%   endif
    #%   if router.name == 'r2'
    interface eth0
     ipv6 address {{ routers.r2.iface_to('s1').ip6[0] }}
    !
    #%   endif
    #% endblock
    """

    bgpd = """
    #% block main
    #%   if router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip6[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s1').ip6[0].ip }} timers 3 10
     neighbor {{ routers.r2.iface_to('s1').ip6[0].ip }} interface {{ routers.r1.iface_to('s1').ifname }}
    ! 
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip6[0].ip }} remote-as external
     neighbor {{ routers.r1.iface_to('s1').ip6[0].ip }} timers 3 10
     neighbor {{ routers.r1.iface_to('s1').ip6[0].ip }} interface {{ routers.r2.iface_to('s1').ifname }}
    ! 
    #%   endif
    #% endblock
    """


class BGPIPv6LinkLocalPeering(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_check_advertised_routes(self, r1, r2):
        expected = {
            "ipv4Unicast": {
                "peers": {
                    str(r2.iface_to("s1").ip6[0].ip): {
                        "state": "Established",
                    }
                }
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp summary json",
            maxwait=3.0,
            compare=expected,
        )
