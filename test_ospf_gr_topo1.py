#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2023  Bruno Bernard for NetDEF, Inc.
"""
Test Grace-LSA from the router performing a graceful restart.
"""

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation


__topotests_file__ = "ospf_gr_topo1/test_ospf_gr_topo1.py"
__topotests_gitrev__ = "4953ca977f3a5de8109ee6353ad07f816ca1774c"

from topotato.v1 import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s1 }
      |
    [ r2 ]

    """
    topo.router("r1").lo_ip4.append("1.1.1.1/32")
    topo.router("r2").lo_ip4.append("2.2.2.2/32")


class Configs(FRRConfigs):

    zebra = """
    #% extends "boilerplate.conf"
    #% block main
    interface lo
     ip address {{ router.lo_ip4[0] }}
    !
    #%   for iface in router.ifaces
    interface {{ iface.ifname }}
     ip address {{ iface.ip4[0] }}
    !
    #%   endfor
    ip forwarding
    !
    #% endblock
    """

    ospfd = """
    #% block main
    #%   if router.name == 'r1'
    interface lo
    ip ospf area 1
    !
    interface {{ router.ifaces[0].ifname }}
    ip ospf network point-to-point
    ip ospf area 1
    ip ospf hello-interval 3
    ip ospf dead-interval 9
    !
    router ospf
    router-id {{ router.lo_ip4[0].ip }}
    capability opaque
    redistribute connected
    graceful-restart grace-period 120
    graceful-restart helper enable
    !

    #%   endif
    #%   if router.name == 'r2'
    interface lo
    ip ospf area 0
    !
    interface {{ router.ifaces[0].ifname }}
    ip ospf network point-to-point
    ip ospf area 1
    ip ospf hello-interval 3
    ip ospf dead-interval 9
    !
    router ospf
    router-id {{ router.lo_ip4[0].ip }}
    capability opaque
    graceful-restart grace-period 120
    graceful-restart helper enable
    !
    #%   endif
    #% endblock
    """


class GracefulRestartTest(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def check_routers(self, r1, r2):

        expected = {
            str(r1.lo_ip4[0]): [
                {
                    "prefix": str(r1.lo_ip4[0]),
                    "protocol":"ospf",
                    "distance":110,
                    "metric":0,
                    "nexthops":[
                        {
                            "directlyConnected": True,
                            "interfaceName": "lo"
                        }
                    ]
                }
            ],
            str(r2.lo_ip4[0]): [
                {
                    "prefix": str(r2.lo_ip4[0]),
                    "protocol":"ospf",
                    "distance":110,
                    "metric":10,
                }
            ],
        }

        yield from AssertVtysh.make(r1, 'zebra', "show ip route json", compare=expected)
