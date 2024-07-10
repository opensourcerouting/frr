# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar

"""
test_ospf_unnumbered.py: Test the OSPF unnumbered.
"""

__topotests_file__ = "ospf_unnumbered/test_ospf_unnumbered.py"
__topotests_gitrev__ = "acddc0ed3ce0833490b7ef38ed000d54388ebea4"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods, unused-argument

from topotato import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]--[ r2 ]--{ s3 }
      |       |
    { s1 }--{ s2 }

    """
    topo.router("r1").iface_to("s1").ip4.append("10.0.1.1/32")
    topo.router("r1").iface_to("s2").ip4.append("10.0.3.4/32")
    topo.router("r2").iface_to("s1").ip4.append("10.0.20.1/32")
    topo.router("r2").iface_to("s2").ip4.append("10.0.3.2/32")


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
    #% endblock
    """

    ospfd = """
    #% block main
    #%   if router.name == 'r1'
    interface r1-eth1
     ip ospf network point-to-point
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    router ospf
     ospf router-id 10.0.255.1
     redistribute kernel
     redistribute connected
     redistribute static
     network 0.0.0.0/0 area 0
    !
    #%   elif router.name == 'r2'
    interface r2-eth1
     ip ospf network point-to-point
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    router ospf
     ospf router-id 10.0.255.2
     redistribute kernel
     redistribute connected
     redistribute static
     network 0.0.0.0/0 area 0
    !
    #%   endif
    #% endblock
    """


class OSPFUnnumbered(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def test_ospf_convergence_r1(self, r1, r2):
        expected = {
            "10.0.1.1\/32": {
                "routeType": "N",
                "cost": 10,
                "area": "0.0.0.0",
                "nexthops": [{"ip": " ", "directlyAttachedTo": "r1-eth0"}],
            },
            "10.0.20.1\/32": {
                "routeType": "N",
                "cost": 20,
                "area": "0.0.0.0",
                "nexthops": [{"ip": "10.0.3.2", "via": "r1-eth1"}],
            },
            "10.0.255.2": {
                "routeType": "R ",
                "cost": 10,
                "area": "0.0.0.0",
                "routerType": "asbr",
                "nexthops": [{"ip": "10.0.3.2", "via": "r1-eth1"}],
            },
        }

        yield from AssertVtysh.make(
            r1,
            "ospfd",
            f"show ip ospf route json",
            maxwait=15.0,
            compare=expected,
        )

    @topotatofunc
    def test_ospf_convergence_r2(self, r1, r2):
        expected = {
            "10.0.1.1\/32": {
                "routeType": "N",
                "cost": 20,
                "area": "0.0.0.0",
                "nexthops": [{"ip": "10.0.3.4", "via": "r2-eth1"}],
            },
            "10.0.20.1\/32": {
                "routeType": "N",
                "cost": 10,
                "area": "0.0.0.0",
                "nexthops": [{"ip": " ", "directlyAttachedTo": "r2-eth0"}],
            },
            "10.0.255.1": {
                "routeType": "R ",
                "cost": 10,
                "area": "0.0.0.0",
                "routerType": "asbr",
                "nexthops": [{"ip": "10.0.3.4", "via": "r2-eth1"}],
            },
        }

        yield from AssertVtysh.make(
            r2,
            "ospfd",
            f"show ip ospf route json",
            maxwait=15.0,
            compare=expected,
        )

    @topotatofunc
    def test_ospf_kernel_route_r1(self, r1, r2):
        expected = {
            "10.0.1.1\/32": [
                {
                    "prefix": "10.0.1.1\/32",
                    "protocol": "ospf",
                    "distance": 110,
                    "metric": 10,
                    "table": 254,
                    "nexthops": [
                        {
                            "flags": 9,
                            "ip": "0.0.0.0",
                            "afi": "ipv4",
                            "interfaceName": "r1-eth0",
                            "active": true,
                            "onLink": true,
                        }
                    ],
                },
                {
                    "prefix": "10.0.1.1\/32",
                    "protocol": "connected",
                    "selected": true,
                    "destSelected": true,
                    "distance": 0,
                    "metric": 0,
                    "installed": true,
                    "table": 254,
                    "nexthops": [
                        {
                            "flags": 3,
                            "fib": true,
                            "directlyConnected": true,
                            "interfaceName": "r1-eth0",
                            "active": true,
                        }
                    ],
                },
            ],
            "10.0.3.4\/32": [
                {
                    "prefix": "10.0.3.4\/32",
                    "protocol": "connected",
                    "selected": true,
                    "destSelected": true,
                    "distance": 0,
                    "metric": 0,
                    "installed": true,
                    "table": 254,
                    "nexthops": [
                        {
                            "flags": 3,
                            "fib": true,
                            "directlyConnected": true,
                            "interfaceName": "r1-eth1",
                            "active": true,
                        }
                    ],
                }
            ],
            "10.0.20.1\/32": [
                {
                    "prefix": "10.0.20.1\/32",
                    "protocol": "ospf",
                    "selected": true,
                    "destSelected": true,
                    "distance": 110,
                    "metric": 20,
                    "installed": true,
                    "table": 254,
                    "nexthops": [
                        {
                            "flags": 11,
                            "fib": true,
                            "ip": "10.0.3.2",
                            "afi": "ipv4",
                            "interfaceName": "r1-eth1",
                            "active": true,
                            "onLink": true,
                        }
                    ],
                }
            ],
        }

        yield from AssertVtysh.make(
            r1,
            "ospfd",
            f"show ip route json",
            maxwait=15.0,
            compare=expected,
        )

    @topotatofunc
    def test_ospf_kernel_route_r2(self, r1, r2):
        expected = {
            "10.0.1.1\/32": [
                {
                    "prefix": "10.0.1.1\/32",
                    "protocol": "ospf",
                    "distance": 110,
                    "metric": 10,
                    "table": 254,
                    "nexthops": [
                        {
                            "flags": 9,
                            "ip": "0.0.0.0",
                            "afi": "ipv4",
                            "interfaceName": "r1-eth0",
                            "active": true,
                            "onLink": true,
                        }
                    ],
                },
                {
                    "prefix": "10.0.1.1\/32",
                    "protocol": "connected",
                    "selected": true,
                    "destSelected": true,
                    "distance": 0,
                    "metric": 0,
                    "installed": true,
                    "table": 254,
                    "nexthops": [
                        {
                            "flags": 3,
                            "fib": true,
                            "directlyConnected": true,
                            "interfaceName": "r1-eth0",
                            "active": true,
                        }
                    ],
                },
            ],
            "10.0.3.4\/32": [
                {
                    "prefix": "10.0.3.4\/32",
                    "protocol": "connected",
                    "selected": true,
                    "destSelected": true,
                    "distance": 0,
                    "metric": 0,
                    "installed": true,
                    "table": 254,
                    "nexthops": [
                        {
                            "flags": 3,
                            "fib": true,
                            "directlyConnected": true,
                            "interfaceName": "r1-eth1",
                            "active": true,
                        }
                    ],
                }
            ],
            "10.0.20.1\/32": [
                {
                    "prefix": "10.0.20.1\/32",
                    "protocol": "ospf",
                    "selected": true,
                    "destSelected": true,
                    "distance": 110,
                    "metric": 20,
                    "installed": true,
                    "table": 254,
                    "nexthops": [
                        {
                            "flags": 11,
                            "fib": true,
                            "ip": "10.0.3.2",
                            "afi": "ipv4",
                            "interfaceName": "r1-eth1",
                            "active": true,
                            "onLink": true,
                        }
                    ],
                }
            ],
        }

        yield from AssertVtysh.make(
            r2,
            "ospfd",
            f"show ip route json",
            maxwait=15.0,
            compare=expected,
        )
