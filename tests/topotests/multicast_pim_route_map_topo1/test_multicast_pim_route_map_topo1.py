#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_multicast_pim_route_map_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_multicast_pim_route_map_topo1.py: Test the FRR PIM multicast route map.
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
    +----+     +----+
    | r1 | <-> | r2 |
    +----+     +----+
    """

    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.gears["r1"].load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.start_router()
    tgen.gears["r2"].load_frr_config(os.path.join(CWD, "r2/frr.conf"))
    tgen.start_router()

    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def test_pim_route_map():
    "Test IGMP route map filtering"
    MULTICAST_STATES = [
        {
            "source": "*",
            "group": "225.0.0.100",
            "filtered": False,
        },
        {
            "source": "*",
            "group": "225.0.1.100",
            "filtered": True,
        },
        {
            "source": "192.168.100.110",
            "group": "232.0.0.123",
            "filtered": False,
        },
        {
            "source": "192.168.100.110",
            "group": "232.0.1.123",
            "filtered": True,
        },
        {
            "source": "*",
            "group": "226.0.0.1",
            "filtered": False,
        },
        {
            "source": "192.168.100.200",
            "group": "232.0.0.1",
            "filtered": True,
        },
        {
            "source": "*",
            "group": "227.0.0.1",
            "filtered": True,
        },
    ]

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for state in MULTICAST_STATES:
        if state["source"] == "*":
            app_helper.run("h1", [state["group"], "h1-eth0"])
        else:
            app_helper.run("h1", [state["group"], f"--source={state['source']}", "h1-eth0"])

    app_helper.run("h2", ["227.0.0.1", "h2-eth0"])

    for state in MULTICAST_STATES:
        expect_igmp_state("r1", state["source"], state["group"], "r1-eth0", missing=state["filtered"])

    logger.info(f"waiting multicast state SG(*, 227.0.0.1) in r1 interface r1-eth1")
    expect_igmp_state("r1", "*", "227.0.0.1", "r1-eth1")

    app_helper.stop_all_hosts()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
