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

pytestmark = [pytest.mark.pimd]


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


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_pim_route_map():
    "Test IGMP route map filtering"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    assert False


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
