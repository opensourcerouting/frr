#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by wangdan1323
#
# Test BGP confederation identifier behavior:
# 1. Initial confederation ID shows correctly
# 2. Changing confederation ID does not reset BGP session
# 3. Deleting confederation ID multiple times does not reset session repeatedly
#

import os
import sys
import json
import time
import pytest
import functools

pytestmark = pytest.mark.bgpd

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname in router_list:
        router = tgen.gears[rname]
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def get_bgp_confederation_id(router):
    """Get confederation identifier from router"""
    output = router.vtysh_cmd("show running-config | include bgp confederation identifier")
    if "bgp confederation identifier" in output:
        # Parse "bgp confederation identifier 65536" -> "65536"
        parts = output.strip().split()
        return parts[-1]
    return ""


def get_bgp_peer_uptime(router, peer_ip="10.0.0.2"):
    """Get BGP peer uptime in seconds"""
    output = json.loads(router.vtysh_cmd("show bgp summary json"))
    peers = output.get("peers", {})
    for peer, info in peers.items():
        if peer_ip in peer:
            return info.get("uptime", 0)
    return 0


def get_bgp_peer_state(router, peer_ip="10.0.0.2"):
    """Get BGP peer state"""
    output = json.loads(router.vtysh_cmd("show bgp summary json"))
    peers = output.get("peers", {})
    for peer, info in peers.items():
        if peer_ip in peer:
            return info.get("state", "")
    return ""


def test_bgp_confederation_id_unchanged(request):
    """
    Test that BGP session is not reset when confederation ID is:
    1. Initially configured correctly
    2. Changed to a different value (session uptime continues)
    3. Deleted multiple times (session uptime continues)
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    # Test point 1: Initial confederation ID shows correctly
    def _check_initial_confed_id(router):
        confed_id = get_bgp_confederation_id(router)
        return confed_id == "65536"

    test_func = functools.partial(_check_initial_confed_id, router1)
    success, result = topotest.run_and_expect(test_func, True, count=10, wait=1)
    assert success, "Initial confederation ID should be 65536, got: {}".format(result)

    # Wait for BGP to establish
    def _bgp_established(router):
        state = get_bgp_peer_state(router)
        return state == "Established"

    test_func = functools.partial(_bgp_established, router1)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "BGP session not established on r1"

    # Record initial uptime
    initial_uptime = get_bgp_peer_uptime(router1)
    assert initial_uptime > 0, "Initial uptime should be > 0, got: {}".format(initial_uptime)

    time.sleep(2)

    # Test point 2: Change confederation ID to 1.0
    router1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 64512\n"
        "bgp confederation identifier 1.0\n"
        "end\n"
    )

    # Wait a bit for any potential reset
    time.sleep(5)

    # Check confederation ID changed to 1.0
    def _check_changed_confed_id(router):
        confed_id = get_bgp_confederation_id(router)
        return confed_id == "1.0"

    test_func = functools.partial(_check_changed_confed_id, router1)
    success, result = topotest.run_and_expect(test_func, True, count=10, wait=1)
    assert success, "Confederation ID should be 1.0, got: {}".format(result)

    # Check session is still established
    assert get_bgp_peer_state(router1) == "Established", "BGP session should be established"

    # Check uptime continued (not reset) - uptime should be >= initial_uptime
    new_uptime = get_bgp_peer_uptime(router1)
    assert new_uptime >= initial_uptime - 1, \
        "Session uptime reset! initial={}, new={}".format(initial_uptime, new_uptime)

    time.sleep(2)

    # Test point 3: Delete confederation ID
    router1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 64512\n"
        "no bgp confederation identifier\n"
        "end\n"
    )

    time.sleep(5)

    # Record uptime after first delete
    uptime_after_first_delete = get_bgp_peer_uptime(router1)
    assert get_bgp_peer_state(router1) == "Established", "Session should be established"

    # Delete again (should not reset session)
    router1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 64512\n"
        "no bgp confederation identifier\n"
        "end\n"
    )

    time.sleep(3)

    # Check confederation ID is gone or 0
    def _check_confed_id_deleted(router):
        output = router.vtysh_cmd("show running-config | include bgp confederation identifier")
        return "bgp confederation identifier" not in output

    test_func = functools.partial(_check_confed_id_deleted, router1)
    success, _ = topotest.run_and_expect(test_func, True, count=5, wait=1)
    assert success, "Confederation ID should be deleted from config"

    # Check session still established
    assert get_bgp_peer_state(router1) == "Established", "Session should still be established"

    # Check uptime continued after second delete (t2 == t2 condition)
    uptime_after_second_delete = get_bgp_peer_uptime(router1)
    assert uptime_after_second_delete >= uptime_after_first_delete - 1, \
        "Second delete caused session reset! uptime before second delete={}, after={}".format(
            uptime_after_first_delete, uptime_after_second_delete
        )


def test_bgp_confederation_id_on_both_routers(request):
    """
    Test that changing confederation ID on one router doesn't affect
    the other router's session uptime (the session is shared).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]

    # Ensure BGP is established
    def _bgp_established(router):
        state = get_bgp_peer_state(router)
        return state == "Established"

    test_func = functools.partial(_bgp_established, router1)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, "BGP session not established on r1"

    # Record uptime on both routers
    uptime_r1_before = get_bgp_peer_uptime(router1, "10.0.0.2")
    uptime_r2_before = get_bgp_peer_uptime(router2, "10.0.0.1")
    assert uptime_r1_before > 0
    assert uptime_r2_before > 0

    time.sleep(2)

    # Change confederation ID on r2
    router2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 64512\n"
        "bgp confederation identifier 1.0\n"
        "end\n"
    )

    time.sleep(5)

    # Check session still established on both
    assert get_bgp_peer_state(router1) == "Established"
    assert get_bgp_peer_state(router2) == "Established"

    # Check uptime continued on both
    uptime_r1_after = get_bgp_peer_uptime(router1, "10.0.0.2")
    uptime_r2_after = get_bgp_peer_uptime(router2, "10.0.0.1")

    assert uptime_r1_after >= uptime_r1_before - 1
    assert uptime_r2_after >= uptime_r2_before - 1


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))