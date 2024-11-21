# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023 Nathan Mangar


__topotests_file__ = "bgp_rfapi_basic_sanity/test_bgp_rfapi_basic_sanity.py"
__topotests_gitrev__ = "acddc0ed3ce0833490b7ef38ed000d54388ebea4"

# pylint: disable=invalid-name, missing-class-docstring, missing-function-docstring, line-too-long, consider-using-f-string, wildcard-import, unused-wildcard-import, f-string-without-interpolation, too-few-public-methods

from topotato.v1 import *


@topology_fixture()
def topology(topo):
    """
    [ r1 ]
      |
    { s0 }
      |
    [ r2 ]--{ s1 }--[ r4 ]
      |
    { s2 }--[ r3 ]
    """

    # topo.router("r1").lo_ip4.append("172.16.255.1/32")
    # topo.router("r1").iface_to("s1").ip4.append("192.168.1.1/24")
    # topo.router("r2").iface_to("s1").ip4.append("192.168.1.2/24")
    # topo.router("r1").iface_to("s2").ip4.append("192.168.2.1/24")
    # topo.router("r3").iface_to("s1").ip4.append("192.168.2.2/24")


class Configs(FRRConfigs):
    routers = ["r1", "r2", "r3", "r4"]

    zebra = """
    #% extends "boilerplate.conf"
    ## nothing needed
    """

    bgpd = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    frr defaults traditional
    !
    hostname r1
    password zebra
    log stdout notifications
    log commands
    router bgp 5226
     bgp router-id 1.1.1.1
     bgp cluster-id 1.1.1.1
     no bgp ebgp-requires-policy
     neighbor 2.2.2.2 remote-as 5226
     neighbor 2.2.2.2 timers 3 10
     neighbor 2.2.2.2 update-source 1.1.1.1
    !
    address-family ipv4 unicast
     redistribute vnc-direct
     no neighbor 2.2.2.2 activate
    !
    address-family ipv4 vpn
     neighbor 2.2.2.2 activate
    !
    rfp holddown-factor 0
    !
    vnc defaults
     rd auto:vn:123
     response-lifetime 45
     rt both 1000:1 1000:2
    exit-vnc
    !
    vnc nve-group red
     prefix vn 10.0.0.0/8
     rd auto:vn:10
     rt both 1000:10
    exit-vnc
    !
    vnc nve-group blue
     prefix vn 20.0.0.0/8
     rd auto:vn:20
     rt both 1000:20
    exit-vnc
    !
    vnc nve-group green
     prefix vn 30.0.0.0/8
     rd auto:vn:20
     rt both 1000:30
    exit-vnc
    !
    end
    #%   elif router.name == 'r2'
    frr defaults traditional
    !
    hostname r2
    password zebra
    log stdout notifications
    log commands
    router bgp 5226
     bgp router-id 2.2.2.2
     bgp cluster-id 2.2.2.2
     no bgp ebgp-requires-policy
     neighbor 1.1.1.1 remote-as 5226
     neighbor 1.1.1.1 timers 3 10
     neighbor 1.1.1.1 update-source 2.2.2.2
     neighbor 3.3.3.3 remote-as 5226
     neighbor 3.3.3.3 timers 3 10
     neighbor 3.3.3.3 update-source 2.2.2.2
     neighbor 4.4.4.4 remote-as 5226
     neighbor 4.4.4.4 timers 3 10
     neighbor 4.4.4.4 update-source 2.2.2.2
     address-family ipv4 unicast
      no neighbor 1.1.1.1 activate
      no neighbor 3.3.3.3 activate
      no neighbor 4.4.4.4 activate
     address-family ipv4 vpn
      neighbor 1.1.1.1 activate
      neighbor 1.1.1.1 route-reflector-client
      neighbor 3.3.3.3 activate
      neighbor 3.3.3.3 route-reflector-client
      neighbor 4.4.4.4 activate
      neighbor 4.4.4.4 route-reflector-client
    end
    #%   elif router.name == 'r3'
    frr defaults traditional
    !
    hostname r3
    password zebra
    log stdout notifications
    log commands
    router bgp 5226
     bgp router-id 3.3.3.3
     bgp cluster-id 3.3.3.3
     no bgp ebgp-requires-policy
     neighbor 2.2.2.2 remote-as 5226
     neighbor 2.2.2.2 timers 3 10
     neighbor 2.2.2.2 update-source 3.3.3.3
    !
    address-family ipv4 unicast
     no neighbor 2.2.2.2 activate
    address-family ipv4 vpn
     neighbor 2.2.2.2 activate
    !
    rfp holddown-factor 0
    !
    vnc defaults
     rd auto:vn:123
     response-lifetime 45
     rt both 1000:1 1000:2
    exit-vnc
    !
    vnc nve-group red
     prefix vn 10.0.0.0/8
     rd auto:vn:10
     rt both 1000:10
    exit-vnc
    !
    vnc nve-group blue
     prefix vn 20.0.0.0/8
     rd auto:vn:20
     rt both 1000:20
    exit-vnc
    !
    vnc nve-group green
     prefix vn 30.0.0.0/8
     rd auto:vn:20
     rt both 1000:30
    exit-vnc
    !
    end
    #%   elif router.name == 'r4'
    frr defaults traditional
    !
    hostname r4
    password zebra
    log stdout notifications
    log commands
    router bgp 5226
     bgp router-id 4.4.4.4
     bgp cluster-id 4.4.4.4
     no bgp ebgp-requires-policy
     neighbor 2.2.2.2 remote-as 5226
     neighbor 2.2.2.2 timers 3 10
     neighbor 2.2.2.2 update-source 4.4.4.4
    !
    address-family ipv4 unicast
        no neighbor 2.2.2.2 activate
    !
    address-family ipv4 vpn
        neighbor 2.2.2.2 activate
    !
    rfp holddown-factor 0
    !
    vnc defaults
     rd auto:vn:123
     response-lifetime 45
     rt both 1000:1 1000:2
    exit-vnc
    !
    vnc nve-group red
     prefix vn 10.0.0.0/8
     rd auto:vn:10
     rt both 1000:10
    exit-vnc
    !
    vnc nve-group blue
     prefix vn 20.0.0.0/8
     rd auto:vn:20
     rt both 1000:20
    exit-vnc
    !
    vnc nve-group green
     prefix vn 30.0.0.0/8
     rd auto:vn:20
     rt both 1000:30
    exit-vnc
    !
    end
    #%   endif
    #% endblock
    """

    ospfd = """
    #% extends "boilerplate.conf"
    #% block main
    #%   if router.name == 'r1'
    hostname r1
    log file ospfd.log
    !
    router ospf
     router-id 1.1.1.1
     network 0.0.0.0/4 area 0
     redistribute static
    !
    int r1-eth0
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    #%   elif router.name == 'r2'
    hostname r2
    log file ospfd.log
    !
    router ospf
     router-id 2.2.2.2
     network 0.0.0.0/0 area 0
    !
    int r2-eth0
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    int r2-eth1
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    int r2-eth2
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    #%   elif router.name == 'r3'
    hostname r3
    password 1
    log file ospfd.log
    !
    router ospf
     router-id 3.3.3.3
     network 0.0.0.0/4 area 0
     redistribute static
    !
    int r3-eth0
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    int r3-eth1
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    #%   elif router.name == 'r4'
    hostname r4
    log file ospfd.log
    !
    router ospf
     router-id 4.4.4.4
     network 0.0.0.0/4 area 0
    redistribute static
    !
    int r4-eth0
     ip ospf hello-interval 2
     ip ospf dead-interval 10
    !
    #%   endif
    #% endblock
    """


class BGPRfapiBasicSanity(TestBase, AutoFixture, topo=topology, configs=Configs):
    @topotatofunc
    def add_routes_holddown_factor_set(self, _, r1):
        expected = "rfp holddown-factor"

        yield from AssertVtysh.make(
            r1,
            "vtysh",
            f"show running",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def add_routes_opened_rfapi_r1(self, _, r1):
        expected = "rfapi_set_response_cb: status 0"

        yield from AssertVtysh.make(
            r1,
            "vtysh",
            f"debug rfapi-dev open vn 10.0.0.1 un 1.1.1.1",
            maxwait=5.0,
            compare=expected,
        )

    @topotatofunc
    def add_routes_clean_query_r1(self, _, r1):
        expected = "rfp holddown-factor"

        yield from AssertVtysh.make(
            r1,
            "vtysh",
            f"debug rfapi-dev query vn 10.0.0.1 un 1.1.1.1 target 11.11.11.11",
            maxwait=5.0,
            compare=expected,
        )

    # @topotatofunc
    # def add_routes_prefix_registered_r1(self, _, r1):
    #     expected = "rfp holddown-factor"

    #     yield from AssertVtysh.make(
    #         r1,
    #         "vtysh",
    #         f"debug rfapi-dev register vn 10.0.0.1 un 1.1.1.1 prefix 11.11.11.0/24 lifetime {}",
    #         maxwait=5.0,
    #         compare=expected,
    #     )

    @topotatofunc
    def add_routes_local_registration_r1(self, _, r1):
        expected = "rfp holddown-factor"

        yield from AssertVtysh.make(
            r1,
            "vtysh",
            f"show vnc registrations local",
            maxwait=5.0,
            compare=expected,
        )
