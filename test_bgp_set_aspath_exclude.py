# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if `set as-path exclude` is working correctly for route-maps.
"""

__topotests_file__ = "bgp_set_aspath_exclude/test_bgp_set_aspath_exclude.py"
__topotests_gitrev__ = "92550adfc77d9d01a2d7a96d67d8a5d27f7b6877"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }--[ r3 ]
      |       |
    [ r2 ]--{ s2 }
    """

    topo.router("r3").lo_ip4.append("172.16.255.31/32")
    topo.router("r3").lo_ip4.append("172.16.255.32/32")
    topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")
    topo.router("r2").iface_to("s2").ip4.append("192.168.2.2/24")
    topo.router("r3").iface_to("s1").ip4.append("192.168.2.1/24")


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3"]

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
    !
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} route-map r2 in
     exit-address-family
    !
    ip prefix-list p1 seq 5 permit {{ routers.r3.lo_ip4[0] }}
    !
    route-map r2 permit 10
     match ip address prefix-list p1
     set as-path exclude 65003
    route-map r2 permit 20
     set as-path exclude 65002 65003
    !
    #%   elif router.name == 'r2'
    !
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r3.iface_to('s1').ip4[0].ip }} timers 3 10
    !
    #%   elif router.name == 'r3'
    !
    router bgp 65003
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s2').ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      redistribute connected
     exit-address-family
    !
    #%   endif
    #% endblock
    """


class BGPSetAspathExclude(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, r1, r3):
        expected = {
            "routes": {
                str(r3.lo_ip4[0]): [{"path": "65002"}],
                str(r3.lo_ip4[1]): [{"path": ""}],
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast json",
            maxwait=5.0,
            compare=expected,
        )
