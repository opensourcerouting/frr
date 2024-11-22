#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import sys
import json
import pytest
import functools
import time

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen, TopoRouter
from lib.common_config import stop_router, start_router

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("c1", "r1"), "s2": ("r1", "r2"), "s3": ("r2", "c2"), "s4": ("r1")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    tgen.net["r1"].cmd(
        """
ip link add vxlan10 type vxlan id 10 dstport 4789 local 10.10.10.1 nolearning
ip link add name br10 type bridge
ip link set br10 master red addrgenmode none
ip link set dev vxlan10 master br10
ip link set dev r1-eth0 master br10
ip link set up dev br10
ip link set up dev vxlan10
ip link add name red type vrf table 10
ip link set r1-eth2 master red
ip link set br10 master red addrgenmode none
ip link set br10 addr aa:bb:cc:00:00:64
ip link set dev red up"""
    )

    tgen.net["r2"].cmd(
        """
ip link add vxlan10 type vxlan id 10 dstport 4789 local 10.10.10.2 nolearning
ip link add name br10 type bridge
ip link set dev vxlan10 master br10
ip link set dev r2-eth1 master br10
ip link set up dev br10
ip link set up dev vxlan10"""
    )

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_evpn_frr_reload():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    net = get_topogen().net
    #net["r1"].cmd("/usr/lib/frr/frr-reload.py --debug --reload ../../../tests/topotests/bgp_evpn_frr_reload/r1/new.conf")

    tgen.mininet_cli()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
