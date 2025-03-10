#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2023  Bruno Bernard.
"""
Test if an aggregated route with AS_SET is not sent to peers.
Addressing draft-ietf-idr-deprecate-as-set-confed-set recommendations.

BGP speakers conforming to this document (i.e., conformant BGP
   speakers) MUST NOT locally generate BGP UPDATE messages containing
   AS_SET or AS_CONFED_SET.  Conformant BGP speakers SHOULD NOT send BGP
   UPDATE messages containing AS_SET or AS_CONFED_SET.  Upon receipt of
   such messages, conformant BGP speakers SHOULD use the "Treat-as-
   withdraw" error handling behavior as per [RFC7606].
"""

from topotato.v1 import *


__topotests_file__ = "bgp_reject_as_sets/test_bgp_reject_as_sets.py"
__topotests_gitrev__ = "acddc0ed3ce0833490b7ef38ed000d54388ebea4"

@topology_fixture()
def topology(topo):
    """
    [ r2 ]--{ s1 }--[ r1 ]
      |
      |
    { s2 }--[ r3 ]
    """

    topo.router("r1").lo_ip4.append("172.16.255.254/30")
    topo.router("r3").lo_ip4.append("172.16.254.254/32")


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    ! exit1
    #%   elif router.name == 'r2'
    ! spine
    #%   elif router.name == 'r3'
    ! exit2
    #%   endif
    #%   if router.name in ['r1', 'r3']
    interface lo
     ip address {{ router.lo_ip4[0] }}
    !
    #%   endif
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
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    ! exit1
    router bgp 65001
      no bgp ebgp-requires-policy
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as 65002
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
      address-family ipv4 unicast
        redistribute connected
      exit-address-family
      !
    !
    #%   elif router.name == 'r2'
    ! spine
    router bgp 65002
      bgp reject-as-sets
      no bgp ebgp-requires-policy
      neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as 65001
      neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
      neighbor {{ routers.r3.iface_to('s2').ip4[0].ip }} remote-as 65003
      neighbor {{ routers.r3.iface_to('s2').ip4[0].ip }} timers 3 10
      address-family ipv4 unicast
        aggregate-address 172.16.0.0/16 as-set summary-only
      exit-address-family
      !
    !
    #%   elif router.name == 'r3'
    ! exit2
    router bgp 65003
      no bgp ebgp-requires-policy
      neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} remote-as 65002
      neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} timers 3 10
      address-family ipv4 unicast
        neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} allowas-in
        redistribute connected
      exit-address-family
      !
    !
    #%   endif
    #% endblock
    """

class BGPRejectAsSetsTest(TestBase, AutoFixture, topo=topology, configs=Configs):

    @topotatofunc
    def test_bgp_converge(self, r1, r2):
      expected = {
            str(r1.iface_to('s1').ip4[0].ip): {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
      }

      yield from AssertVtysh.make(
            r2, "bgpd", f"show ip bgp neighbor {r1.iface_to('s1').ip4[0].ip} json", maxwait=5.0, compare=expected
      )


    @topotatofunc
    def test_bgp_has_aggregated_route_with_stripped_as_set(self, r2):
      expected = {
            "paths": [{"aspath": {"string": "Local", "segments": [], "length": 0}}]
      }

      yield from AssertVtysh.make(
            r2, "bgpd", "show ip bgp 172.16.0.0/16 json",  maxwait=5.0, compare=expected
      )


    @topotatofunc
    def test_bgp_announce_route_without_as_sets(self, topo, r1, r2, r3):
      expected = {
            "advertisedRoutes": {
                "172.16.0.0/16": {"path": ""},
                str(r3.iface_to('s2').ip4[0].network): {"path": "65003"},
                str(r1.iface_to('s1').ip4[0].network): {"path": "65001"},
            },
            "totalPrefixCounter": 3,
      }

      yield from AssertVtysh.make(
            r2, "bgpd", f"show ip bgp neighbor {r3.iface_to('s2').ip4[0].ip} advertised-routes json",  maxwait=5.0, compare=expected
      )
