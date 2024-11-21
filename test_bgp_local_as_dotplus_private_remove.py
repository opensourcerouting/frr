# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
bgp_local_as_private_remove.py:
Test if primary AS number is not removed in cases when `local-as`
used together with `remove-private-AS`.
"""

__topotests_file__ = (
    "bgp_local_as_dotplus_private_remove/test_bgp_local_as_dotplus_private_remove.py"
)
__topotests_gitrev__ = "d1e16777d5073071f36659a5231be8d9d9226aa0"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }  [ r3 ]
      |       |
    [ r2 ]--{ s2 }
              |
            [ r4 ]
    """


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3", "r4"]

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
    router bgp 0.65000 as-notation dot+
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as 0.1000
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} local-as 0.500
     address-family ipv4 unicast
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remove-private-AS
      redistribute connected
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 0.1000 as-notation dot+
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as 0.500
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
    !
    #%   elif router.name == 'r3'
    router bgp 3000
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as 1000
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} local-as 500
     address-family ipv4 unicast
      neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remove-private-AS
      redistribute connected
     exit-address-family
    !
    #%   elif router.name == 'r4'
    router bgp 0.1000 as-notation dot+
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as 0.500
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
    !
    #%   endif
    #% endblock
    """


class BGPLocalASDotplusPrivateRemove(
    TestBase, AutoFixture, topo=topology, configs=Configs
):
    @topotatofunc
    def bgp_converge(self, r1, r2):
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
    def bgp_as_path_r2(self, r2, r3):
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "0.500",
                        "length": 1,
                    }
                }
            ]
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp {r3.lo_ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_as_path_r4(self, r3, r4):
        expected = {
            "paths": [
                {
                    "aspath": {
                        "string": "0.500 0.3000",
                        "length": 2,
                    }
                }
            ]
        }
        yield from AssertVtysh.make(
            r4,
            "bgpd",
            f"show ip bgp {r3.lo_ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )
