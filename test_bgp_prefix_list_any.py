# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if route-map works correctly when modifying prefix-list
from deny to permit with any, and vice-versa.
"""

__topotests_replaces__ = {
    "bgp_prefix_list_any/": "d8986f0134887f5d8916e71993ab378efaee4306",
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
     no bgp network import-check
     neighbor {{ routers.r2.ifaces[0].ip4[0].ip }} remote-as external
     neighbor 2001:db8:1::1 remote-as external
     address-family ipv4 unicast
      network 192.168.0.1/32
      no neighbor 2001:db8:1::2 activate
     exit-address-family
     address-family ipv6 unicast
      neighbor 2001:db8:1::2 activate
      network 2001:db8::1/128
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     no bgp network import-check
     neighbor {{ routers.r1.ifaces[0].ip4[0].ip }} remote-as external
     neighbor 2001:db8:1::1 remote-as external
     address-family ipv4 unicast
      network 10.10.10.1/32
      network 10.10.10.2/32
      network 10.10.10.3/32
      network 10.10.10.10/32
      no neighbor 2001:db8:1::1 activate
      neighbor 192.168.1.1 route-map r1-v4 out
     exit-address-family
     address-family ipv6 unicast
      network 2001:db8:10::1/128
      network 2001:db8:10::2/128
      network 2001:db8:10::3/128
      network 2001:db8:10::10/128
      neighbor 2001:db8:1::1 activate
      neighbor 2001:db8:1::1 route-map r1-v6 out
     exit-address-family
    !
    ip prefix-list r1-1 seq 5 permit 10.10.10.1/32
    ip prefix-list r1-1 seq 10 permit 10.10.10.2/32
    ip prefix-list r1-1 seq 15 permit 10.10.10.3/32
    ip prefix-list r1-2 seq 5 permit 10.10.10.10/32
    !
    ipv6 prefix-list r1-1 seq 5 permit 2001:db8:10::1/128
    ipv6 prefix-list r1-1 seq 10 permit 2001:db8:10::2/128
    ipv6 prefix-list r1-1 seq 15 permit 2001:db8:10::3/128
    ipv6 prefix-list r1-2 seq 5 permit 2001:db8:10::10/128
    !
    route-map r1-v4 permit 10
     match ip address prefix-list r1-1
    exit
    !
    route-map r1-v4 permit 20
     match ip address prefix-list r1-2
    exit
    !
    route-map r1-v6 permit 10
     match ipv6 address prefix-list r1-1
    exit
    !
    route-map r1-v6 permit 20
     match ipv6 address prefix-list r1-2
    exit
    #%   endif
    #% endblock
    """


class BGP_Prefix_List_Any(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def check_routes(self, r1, r2):
        count = 60
        expected = {
            "ipv4Unicast": {
                "peers": {
                    str(r1.ifaces[0].ip4[0].ip): {
                        "pfxSnt": count,
                        "state": "Established",
                    }
                }
            },
            "ipv6Unicast": {
                "peers": {
                    "2001:db8:1::1": {
                        "pfxSnt": count,
                        "state": "Established",
                    }
                }
            },
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show bgp summary json",
            maxwait=5.0,
            compare=expected,
        )
