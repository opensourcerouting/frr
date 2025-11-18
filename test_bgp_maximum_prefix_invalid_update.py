# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
bgp_maximum_prefix_invalid_update.py:
Test if unnecesarry UPDATE message like below:

[Error] Error parsing NLRI
%NOTIFICATION: sent to neighbor X.X.X.X 3/10 (UPDATE Message Error/Invalid Network Field) 0 bytes

is not sent if maximum-prefix count is overflow.
"""

__topotests_file__ = (
    "bgp_maximum_prefix_invalid_update/test_bgp_maximum_prefix_invalid_update.py"
)
__topotests_gitrev__ = "acddc0ed3ce0833490b7ef38ed000d54388ebea4"

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

    topo.router("r1").lo_ip4.append("172.16.255.254/32")
    topo.router("r1").lo_ip4.append("172.16.255.253/32")


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
    router bgp 65000
     no bgp ebgp-requires-policy
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} remote-as 65001
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} timers 3 10
     address-family ipv4 unicast
      redistribute connected
     exit-address-family
     !
    !
    ip prefix-list r2 seq 5 permit {{ routers.r1.lo_ip4[0] }}
    ip prefix-list r2 seq 10 permit {{ routers.r1.lo_ip4[0] }}
    !
    #%   elif router.name == 'r2'
    router bgp 65001
     no bgp ebgp-requires-policy
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} remote-as 65000
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} timers 3 10
     address-family ipv4
      neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} maximum-prefix 1
     exit-address-family
     !
    !
    #%   endif
    #% endblock
    """


class BGPIpv4ClassEPeer(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_parsing_nlri(self, r1, r2):
        expected = {
            str(r1.iface_to("s1").ip4[0].ip): {
                "lastNotificationReason": "Cease/Maximum Number of Prefixes Reached",
                "lastResetDueTo": "BGP Notification send",
            }
        }
        yield from AssertVtysh.make(
            r2,
            "bgpd",
            f"show ip bgp neighbor {r1.iface_to('s1').ip4[0].ip} json",
            maxwait=5.0,
            compare=expected,
        )
