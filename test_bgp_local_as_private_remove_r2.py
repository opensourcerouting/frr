# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar for NetDEF, Inc.

"""
Test if AddPath RX direction is not negotiated via AddPath capability for r2.
"""

__topotests_replaces__ = {
    "bgp_local_as_private_remove/": "acddc0ed3ce0833490b7ef38ed000d54388ebea4",
}

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument, attribute-defined-outside-init
from topotato.v1 import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]--{ s1 }--[ r2 ]
    """


class Configs(FRRConfigs):
    routers = ["r1", "r2"]

    zebra = """
    #% extends "boilerplate.conf"
    ## nothing needed
    """

    bgpd = """
    #% block main
    #%   if router.name == 'r1'
    router bgp 65000
    no bgp ebgp-requires-policy
    neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as 1000
    neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
    neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} local-as 500
    address-family ipv4 unicast
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remove-private-AS
     redistribute connected
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 1000
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as 500
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
    !
    #%   endif
    #% endblock
    """


class BGPLocalAsPrivateRemoveR2(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, _, r1, r2):
        expected = {
            str(r1.iface_to("s1").ip4[0].ip): {
                "bgpState": "Established",
            }
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r1.iface_to('s1').ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_as_path_r2(self, _, r1, r2):
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "500",
                        "length": 1,
                    }
                }
            ]
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp {r1.lo_ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )
