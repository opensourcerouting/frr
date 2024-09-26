# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if role capability is exchanged dynamically.
"""

__topotests_file__ = "bgp_dynamic_capability/test_bgp_dynamic_capability_role.py"
__topotests_gitrev__ = "2b5236dbb3f41a397a6add688e8a4e8ce8c717e8"

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

    topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")


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
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers connect 1
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} capability dynamic
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as external
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 1 3
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers connect 1
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} capability dynamic
    !
    #%   endif
    #% endblock
    """


class BGPDynamicCapabilityRole(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, r1, r2):
        expected = {
            str(r2.iface_to("s1").ip4[0].ip): {
                "bgpState": "Established",
                "localRole": "undefined",
                "remoteRole": "undefined",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                },
                "connectionsEstablished": 1,
                "connectionsDropped": 0,
            }
        }

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp neighbor json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_if_session_not_reset(self, r1, r2):
        expected = {
            str(r2.iface_to("s1").ip4[0].ip): {
                "bgpState": "Established",
                "localRole": "customer",
                "remoteRole": "provider",
                "neighborCapabilities": {
                    "dynamic": "advertisedAndReceived",
                    "role": "advertisedAndReceived",
                },
                "connectionsEstablished": 1,
                "connectionsDropped": 0,
            }
        }

        yield from AssertVtysh.make(
            r1,
            "vtysh",
            """
            configure terminal
            router bgp
             neighbor 192.168.1.2 local-role customer

            """,
            compare="",
        )

        yield from AssertVtysh.make(
            r2,
            "vtysh",
            """
            configure terminal
            router bgp
             neighbor 192.168.1.1 local-role customer

            """,
            compare="",
        )

        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp neighbor json",
            maxwait=5.0,
            compare=expected,
        )
