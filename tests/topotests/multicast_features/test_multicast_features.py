#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_multicast_features.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_multicast_features.py: Test the FRR PIM multicast features.
"""

import os
import sys
import json
from functools import partial
import re
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from lib.pim import McastTesterHelper

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

app_helper = McastTesterHelper()


def build_topo(tgen):
    """
    +----+     +----+     +----+     +----+
    | h1 | <-> | r1 | <-> | r2 | <-> | h2 |
    +----+     +----+     +----+     +----+
                 ^
                 |
                 v
               +----+
               | r3 |
               +----+
    """

    # Create 3 routers
    for routern in range(1, 4):
        tgen.add_router(f"r{routern}")

    # R1 interface eth0 and R2 interface eth0
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # R1 interface eth1
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # R1 interface eth2
    switch = tgen.add_switch("s3")
    tgen.add_host("h1", "192.168.100.100/24", "via 192.168.100.1")
    tgen.add_host("h3", "192.168.100.101/24", "via 192.168.100.1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])
    switch.add_link(tgen.gears["h3"])

    # R2 interface eth1
    switch = tgen.add_switch("s4")
    tgen.add_host("h2", "192.168.101.100/24", "via 192.168.101.1")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["h2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, f"{router.name}/frr.conf"))

    # Initialize all routers.
    tgen.start_router()

    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def test_bgp_convergence():
    "Wait for BGP protocol convergence"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_loopback_route(router, iptype, route, proto):
        "Wait until route is present on RIB for protocol."
        logger.info(f"waiting route {route} in {router}")
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            f"show {iptype} route json",
            {route: [{"protocol": proto}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    # Wait for R1
    expect_loopback_route("r1", "ip", "10.254.254.2/32", "bgp")
    expect_loopback_route("r1", "ip", "10.254.254.3/32", "bgp")
    expect_loopback_route("r1", "ipv6", "2001:db8:ffff::2/128", "bgp")
    expect_loopback_route("r1", "ipv6", "2001:db8:ffff::3/128", "bgp")

    # Wait for R2
    expect_loopback_route("r2", "ip", "10.254.254.1/32", "bgp")
    expect_loopback_route("r2", "ip", "10.254.254.3/32", "bgp")
    expect_loopback_route("r2", "ipv6", "2001:db8:ffff::1/128", "bgp")
    expect_loopback_route("r2", "ipv6", "2001:db8:ffff::3/128", "bgp")

    # Wait for R3
    expect_loopback_route("r3", "ip", "10.254.254.1/32", "bgp")
    expect_loopback_route("r3", "ip", "10.254.254.2/32", "bgp")
    expect_loopback_route("r3", "ipv6", "2001:db8:ffff::1/128", "bgp")
    expect_loopback_route("r3", "ipv6", "2001:db8:ffff::2/128", "bgp")


def test_pim_convergence():
    "Wait for PIM peers find each other."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def expect_pim_peer(router, iptype, interface, peer):
        "Wait until peer is present."
        logger.info(f"waiting peer {peer} in {router}")
        expected = {interface: {peer: {"upTime": "*"}}}

        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            f"show {iptype} pim neighbor json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
        assertmsg = f'"{router}" convergence failure'
        assert result is None, assertmsg

    expect_pim_peer("r1", "ip", "r1-eth0", "192.168.1.2")
    expect_pim_peer("r2", "ip", "r2-eth0", "192.168.1.1")
    expect_pim_peer("r1", "ip", "r1-eth1", "192.168.2.2")

    #
    # IPv6 part
    #
    out = tgen.gears["r1"].vtysh_cmd("show interface r1-eth0 json", True)
    r1_r2_link_address = out["r1-eth0"]["ipAddresses"][1]["address"].split('/')[0]
    out = tgen.gears["r1"].vtysh_cmd("show interface r1-eth1 json", True)
    r1_r3_link_address = out["r1-eth1"]["ipAddresses"][1]["address"].split('/')[0]
    out = tgen.gears["r2"].vtysh_cmd("show interface r2-eth0 json", True)
    r2_link_address = out["r2-eth0"]["ipAddresses"][1]["address"].split('/')[0]
    out = tgen.gears["r3"].vtysh_cmd("show interface r3-eth0 json", True)
    r3_link_address = out["r3-eth0"]["ipAddresses"][1]["address"].split('/')[0]

    expect_pim_peer("r1", "ipv6", "r1-eth0", r2_link_address)
    expect_pim_peer("r2", "ipv6", "r2-eth0", r1_r2_link_address)
    expect_pim_peer("r1", "ipv6", "r1-eth1", r3_link_address)


def host_send_igmp_packet(host, script, type, source, group, router_alert=True):
    "Sends packet using specified script from host."
    command = f"python3 {CWD}/../../packets/{script}"
    command += f" --src_ip={source} --gaddr={group}"
    command += f" --iface={host}-eth0 --type={type}"
    if router_alert:
        command += f" --enable_router_alert"

    tgen = get_topogen()
    tgen.gears[host].run(command)


def host_send_igmpv3_packet(host, source, group, router_alert=True):
    "Sends packet using specified script from host."
    command = f"python3 {CWD}/../../packets/igmp/igmp_v3.py"
    command += f" --src_ip={source} --gaddr=224.0.0.22"
    command += f" --iface={host}-eth0 --type=0x22"
    command += f" --record={group} "
    if router_alert:
        command += f" --enable_router_alert"

    tgen = get_topogen()
    tgen.gears[host].run(command)

def expect_igmp_group(router, interface, group):
    tgen = get_topogen()
    igmp_groups = tgen.gears[router].vtysh_cmd("show ip igmp groups json", isjson=True)
    try:
        for group in igmp_groups[interface]["groups"]:
            if group["group"] == group:
                return True

        return False
    except KeyError:
        return False


def test_igmp_router_alert():
    "Test IGMP router alert check feature."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    source = "192.168.100.100"
    group = "224.100.10.10"
    host_send_igmp_packet("h1", "igmp/igmp_v1.py", 0x12, source, group, router_alert=False)
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    topotest.run_and_expect(test_func, True, count=10, wait=2)

    group = "224.100.10.11"
    host_send_igmp_packet("h1", "igmp/igmp_v2.py", 0x16, source, group, router_alert=False)
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    topotest.run_and_expect(test_func, True, count=10, wait=2)

    group = "224.100.10.12"
    host_send_igmp_packet("h1", "igmp/igmp_v2.py", 0x16, source, group, router_alert=False)
    test_func = partial(expect_igmp_group, "r1", "r1-eth2", group)
    topotest.run_and_expect(test_func, True, count=10, wait=2)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
