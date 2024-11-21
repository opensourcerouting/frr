# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test some bgp interface based issues that show up
"""

__topotests_file__ = "bgp_unnumbered/test_bgp_unnumbered.py"
__topotests_gitrev__ = "acddc0ed3ce0833490b7ef38ed000d54388ebea4"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

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
     timers bgp 1 9
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} interface remote-as external
     address-family ipv4 unicast
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp network import-check
     no bgp ebgp-requires-policy
     timers bgp 1 9
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} interface remote-as external
     address-family ipv4 uni
        network 172.16.255.254/32
    !
    #%   endif
    #% endblock
  """


class BGPUnnumberedRemoval(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, _, r1):
        expected = {"prefix": "172.16.255.254/32"}
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show ip bgp 172.16.255.254/32 json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def shutdown_interface_r1_eth0(self, _, r1):
        yield from AssertVtysh.make(
            r1,
            "zebra",
            """
            enable
            configure
            int r1-eth0
             shutdown
            """,
            compare="",
        )

    @topotatofunc
    def remove_neighbor_from_r1(self, _, r1):
        yield from AssertVtysh.make(
            r1,
            "zebra",
            """
            enable
            configure
            router bgp
             no neighbor r1-eth0 interface remote-as external
            """,
            compare="",
        )

    @topotatofunc
    def bgp_nexthop_cache(self, _, r1):
        expected = "Current BGP nexthop cache:\n"
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp nexthop",
            maxwait=5.0,
            compare=expected,
        )
