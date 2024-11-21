#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
Test if BGP confederation works properly when using
remote-as internal/external.

Also, check if the same works with peer-groups as well.
"""

__topotests_file__ = "bgp_confederation_astype/test_bgp_confederation_astype.py"
__topotests_gitrev__ = "caf65e4a27539b1ecc0f6820994d36278c0e63e6"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r3 ]--{ s2 }
              |
    { s1 }--[ r1 ]
      |
    [ r2 ]

    """

    # topo.router("r1").lo_ip4.append("172.16.255.254/32")
    # topo.router("r3").lo_ip4.append("172.16.255.32/32")

    topo.router("r2").lo_ip4.append("172.16.255.254/32")
    # topo.router("r3").lo_ip4.append("172.16.255.254/32")

    topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    topo.router("r1").iface_to("s2").ip4.append("192.168.2.1/24")

    topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")

    topo.router("r3").iface_to("s2").ip4.append("192.168.2.2/24")


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
    #% endblock
    """

    # There seems to be an issue with the R1 config. R1 is blocking any packets it receives for some reason.

    bgpd = """
    #% block main
    #%   if router.name == 'r1'
    router bgp 65001
     no bgp ebgp-requires-policy
     bgp confederation identifier 65300
     bgp confederation peers 65002 65003
     neighbor fabric peer-group
     neighbor fabric remote-as external
     neighbor {{ routers.r2.iface_to('s1').ip4[0].ip }} peer-group fabric
     neighbor {{ routers.r3.iface_to('s2').ip4[0].ip }} remote-as external
     address-family ipv4 unicast
      neighbor fabric soft-reconfiguration inbound
      neighbor fabric activate
      neighbor {{ routers.r3.iface_to('s2').ip4[0].ip }} soft-reconfiguration inbound
     exit-address-family
    !
    #%   elif router.name == 'r2'
    router bgp 65002
     no bgp ebgp-requires-policy
     no bgp network import-check
     bgp confederation identifier 65300
     bgp confederation peers 65001
     neighbor fabric peer-group
     neighbor fabric remote-as external
     neighbor {{ routers.r1.iface_to('s1').ip4[0].ip }} peer-group fabric
     address-family ipv4 unicast
      network {{ routers.r2.lo_ip4[0] }}
      neighbor fabric activate
     exit-address-family
    !
    #%   elif router.name == 'r3'
    router bgp 65003
     no bgp ebgp-requires-policy
     no bgp network import-check
     bgp confederation identifier 65300
     bgp confederation peers 65001 
     neighbor {{ routers.r1.iface_to('s2').ip4[0].ip }} remote-as external
     address-family ipv4 unicast
      network {{ routers.r2.lo_ip4[0] }}
     exit-address-family
    !
    #%   endif
    #% endblock
    """


class BGPConfederationAstype(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def bgp_converge(self, _, r1, r2, r3):
        expected = {
            "ipv4Unicast": {
                "peerCount": 2,
                "peers": {
                    str(r2.iface_to("s1").ip4[0].ip): {
                        "hostname": "r2",
                        "remoteAs": 65002,
                        "localAs": 65001,
                        "pfxRcd": 1,
                        "state": "Established",
                    },
                    str(r3.iface_to("s2").ip4[0].ip): {
                        "hostname": "r3",
                        "remoteAs": 65003,
                        "localAs": 65001,
                        "pfxRcd": 1,
                        "state": "Established",
                    },
                },
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp summary json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_neighbors(self, _, r1, r3, r2):
        expected = {
            str(r2.iface_to("s1").ip4[0].ip): {
                "nbrCommonAdmin": True,
                "nbrConfedExternalLink": True,
                "hostname": "r2",
            },
            str(r3.iface_to("s2").ip4[0].ip): {
                "nbrCommonAdmin": True,
                "nbrConfedExternalLink": True,
                "hostname": "r3",
            },
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp neighbors json",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def bgp_check_routes(self, _, r1, r2):
        expected = {
            "routes": {
                str(r2.lo_ip4[0]): [
                    {
                        "valid": True,
                        "pathFrom": "external",
                        "path": "(65003)",
                    },
                    {
                        "valid": True,
                        "pathFrom": "external",
                        "path": "(65002)",
                    },
                ]
            }
        }
        yield from AssertVtysh.make(
            r1,
            "bgpd",
            f"show bgp ipv4 unicast json",
            maxwait=5.0,
            compare=expected,
        )
