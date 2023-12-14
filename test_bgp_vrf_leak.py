# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Bruno Bernard for NetDEF, Inc.

"""
Test basic vrf route leaking
"""
# pylint: disable=wildcard-import, unused-wildcard-import, trailing-whitespace

from topotato.v1 import *

__topotests_replaces__ = {
    "bgp_vrf_route_leak_basic/test_bgp-vrf-route-leak-basic.py": "acddc0ed3ce0833490b7ef38ed000d54388ebea4",
}


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
    """


class Configs(FRRConfigs):
    routers = ["r1"]

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
     hostname r1

     int dummy1
     ip address 10.0.0.1/24
     no shut
     !
     int dummy2
     ip address 10.0.1.1/24
     no shut
     !
     int dummy3
     ip address 10.0.2.1/24
     no shut
     !
     int dummy4
     ip address 10.0.3.1/24
     no shut
     !
    #% endblock
    """

    bgpd = """
    #% block main
     hostname r1
     router bgp 99 vrf DONNA
     no bgp ebgp-requires-policy
     address-family ipv4 unicast
         redistribute connected
         import vrf EVA
     !
     !
     router bgp 99 vrf EVA
     no bgp ebgp-requires-policy
     address-family ipv4 unicast
         redistribute connected
         import vrf DONNA
     !
     !
    #% endblock
    """


class TestBGPVRFLeak(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def prepare(self, r1):
        commands = [
            "ip link add DONNA type vrf table 1001",
            "ip link add EVA type vrf table 1002",
            "ip link add dummy1 type dummy",
            "ip link add dummy2 type dummy",
            "ip link add dummy3 type dummy",
            "ip link add dummy4 type dummy",
            "ip link set dummy1 master DONNA",
            "ip link set dummy2 master EVA",
            "ip link set dummy3 master DONNA",
            "ip link set dummy4 master EVA",
        ]

        for lines in commands:
            cmd = BackgroundCommand(r1, lines)
            yield from cmd.start()
            yield from cmd.wait()

    @topotatofunc
    def test_donna_vrf_route_leak(self, r1):
        # Check DONNA VRF routes
        expect = {
            "10.0.0.0/24": [
                {
                    "protocol": "connected",
                }
            ],
            "10.0.1.0/24": [
                {"protocol": "bgp", "selected": True, "nexthops": [{"fib": True}]}
            ],
            "10.0.2.0/24": [{"protocol": "connected"}],
            "10.0.3.0/24": [
                {"protocol": "bgp", "selected": True, "nexthops": [{"fib": True}]}
            ],
        }

        yield from AssertVtysh.make(
            r1, "zebra", "show ip route vrf DONNA json", maxwait=5, compare=expect
        )

    @topotatofunc
    def test_eva_vrf_route_leak(self, topo, r1):
        # Check EVA VRF routes
        expect = {
            "10.0.0.0/24": [
                {"protocol": "bgp", "selected": True, "nexthops": [{"fib": True}]}
            ],
            "10.0.1.0/24": [
                {
                    "protocol": "connected",
                }
            ],
            "10.0.2.0/24": [
                {"protocol": "bgp", "selected": True, "nexthops": [{"fib": True}]}
            ],
            "10.0.3.0/24": [
                {
                    "protocol": "connected",
                }
            ],
        }
        yield from AssertVtysh.make(
            r1, "zebra", "show ip route vrf EVA json", maxwait=5, compare=expect
        )
