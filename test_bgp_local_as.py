#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Bruno Bernard

"""
Test if iBGP is functioning correctly when the local AS is the same as the remote AS,
by verifying the propagation of BGP prefixes between routers.
"""

__topotests_file__ = "bgp_local_as/test_bgp_local_as.py"
__topotests_gitrev__ = "68d4b72ff37eb2d6d851b0dcd9e69e7a248b6cec"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation

from topotato import *


@topology_fixture()
def topology(_):
    """
    [ r1 ]---{ s1 }---[ r2 ]
      |
    { s2 }
      |
    [ r3 ]

    """


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    interface lo
     ip address {{ routers.r1.lo_ip4[0] }}
    !
    #%   endif
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
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }}  remote-as 65002
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} local-as 65002
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers connect 1
     neighbor PG peer-group
     neighbor PG remote-as 65003
     neighbor PG local-as 65003
     neighbor {{ routers.r3.iface_to('s2').ip4[0].ip }} peer-group PG
     address-family ipv4
      redistribute connected
    exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as internal
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers connect 1
    !
    #%   elif router.name == 'r3'
    router bgp 65003
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s2').ip4[0].ip }} remote-as internal
     neighbor {{ routers.r1.iface_to('s2').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.iface_to('s2').ip4[0].ip }} timers connect 1
    !
    #%   endif
    #% endblock
    """


class BGPLocalAs(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def test_gp_check_local_as_same_remote_as(self, _, r1, r2):
        expected = {
            "paths": [
                {
                    "valid": True,
                    "aspath": {"string": "Local"},
                    "nexthops": [{"ip": str(r1.iface_to('s1').ip4[0].ip), "hostname": "r1"}],
                }
            ]
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show bgp ipv4 unicast {r1.lo_ip4[0]} json",
            maxwait=3.0,
            compare=expected,
        )
        
        
    @topotatofunc
    def test_bgp_peer_group_local_as_same_remote_as(self, _, r1, r3):
        expected = {
            "paths": [
                {
                    "valid": True,
                    "aspath": {"string": "Local"},
                    "nexthops": [{"ip": str(r1.iface_to('s2').ip4[0].ip), "hostname": "r1"}],
                }
            ]
        }
        yield from AssertVtysh.make(
            r3,
            "bgpd",
            f"show bgp ipv4 unicast {r1.lo_ip4[0]} json",
            maxwait=3.0,
            compare=expected,
        )