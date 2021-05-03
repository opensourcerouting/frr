#!/usr/bin/env python

#
# test_pim_vrf.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_pim_vrf.py: Test various BGP features.
"""

import json
import functools
import os
import sys
import pytest
import re
import time
from time import sleep
import socket

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

pytestmark = [pytest.mark.pimd]


#
# Test global variables:
# They are used to handle communicating with external application.
#
APP_SOCK_PATH = '/tmp/topotests/apps.sock'
HELPER_APP_PATH = os.path.join(CWD, "../lib/mcast-tester.py")
app_listener = None
app_clients = {}

def listen_to_applications():
    "Start listening socket to connect with applications."
    # Remove old socket.
    try:
        os.unlink(APP_SOCK_PATH)
    except OSError:
        pass

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    sock.bind(APP_SOCK_PATH)
    sock.listen(10)
    global app_listener
    app_listener = sock

def accept_host(host):
    "Accept connection from application running in hosts."
    global app_listener, app_clients
    conn = app_listener.accept()
    app_clients[host] = {
        'fd': conn[0],
        'address': conn[1]
    }

def close_applications():
    "Signal applications to stop and close all sockets."
    global app_listener, app_clients

    if app_listener:
        # Close listening socket.
        app_listener.close()

        # Remove old socket.
        try:
            os.unlink(APP_SOCK_PATH)
        except OSError:
            pass

    # Close all host connections.
    for host in ["h1", "h2"]:
        if app_clients.get(host) is None:
            continue
        app_clients[host]["fd"].close()

    # Reset listener and clients data struct
    app_listener = None
    app_clients = {}


class PIMVRFTopo(Topo):
    "PIM VRF Test Topology"

    def build(self):
        tgen = get_topogen(self)

        # Create the hosts
        for hostNum in range(1,3):
            tgen.add_router("h{}".format(hostNum))

        # Create the main router - without VRF
        tgen.add_router("r1")
        # Create the 2nd main router - with VRF
        tgen.add_router("r2")

        # Create the PIM RP routers
        for rtrNum in range(11, 16):
            tgen.add_router("r{}".format(rtrNum))

        # Setup Switches and connections
        for swNum in range(1, 5):
            tgen.add_switch("sw{}".format(swNum))

        
        ################
        # 1st set of connections to routers without VRF
        ################

        # Add connections H1 to R1 switch sw1
        tgen.gears["h1"].add_link(tgen.gears["sw1"])
        tgen.gears["r1"].add_link(tgen.gears["sw1"])

        # Add connections R1 to R1x switch sw2
        tgen.gears["r1"].add_link(tgen.gears["sw2"])
        tgen.gears["h2"].add_link(tgen.gears["sw2"])
        tgen.gears["r11"].add_link(tgen.gears["sw2"])
        tgen.gears["r12"].add_link(tgen.gears["sw2"])
        tgen.gears["r13"].add_link(tgen.gears["sw2"])
        tgen.gears["r14"].add_link(tgen.gears["sw2"])
        tgen.gears["r15"].add_link(tgen.gears["sw2"])

        ################
        # 2nd set of connections to routers without VRF
        ################

        # Add connections H1 to R1 switch sw1
        tgen.gears["h1"].add_link(tgen.gears["sw3"])
        tgen.gears["r1"].add_link(tgen.gears["sw3"])

        # Add connections R1 to R1x switch sw2
        tgen.gears["r1"].add_link(tgen.gears["sw4"])
        tgen.gears["h2"].add_link(tgen.gears["sw4"])
        tgen.gears["r11"].add_link(tgen.gears["sw4"])
        tgen.gears["r12"].add_link(tgen.gears["sw4"])
        tgen.gears["r13"].add_link(tgen.gears["sw4"])
        tgen.gears["r14"].add_link(tgen.gears["sw4"])
        tgen.gears["r15"].add_link(tgen.gears["sw4"])


#####################################################
#
#   Tests starting
#
#####################################################

def setup_module(module):
    tgen = Topogen(PIMVRFTopo, module.__name__)
    tgen.start_topology()

    vrf_setup_cmds = [
        "ip link add {0}-cust1 type vrf table 1001",
        "ip link add loop1 type dummy",
        "ip link set {0}-eth0 master {0}-cust1",
        "ip link set {0}-eth1 master {0}-cust1",
    ]

    # Starting Routers
    router_list = tgen.routers()

    # Create VRF on r2 first and add it's interfaces
    for cmd in cmds:
        tgen.net["r2"].cmd(cmd.format(rname))
    # adjust handling of vrf traffic
    adjust_router_l3mdev(tgen, "r2")

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        if rname[0] != 'h':
            # Only load ospf on routers, not on end hosts
            router.load_config(
                TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
            )
            router.load_config(
                TopoRouter.RD_PIM, os.path.join(CWD, "{}/pimd.conf".format(rname))
            )
    tgen.start_router()


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()
    close_applications()


def test_ospf_convergence():
    "Test for OSPFv2 convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking OSPFv2 convergence on router r1")

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/ospf_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip ospf neighbor json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "OSPF router R1 did not converge"
    assert res is None, assertmsg


def test_pim_convergence():
    "Test for PIM convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking PIM convergence on router r1")

    tgen.mininet_cli()

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/pim_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip pim neighbor json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "PIM router R1 did not converge"
    assert res is None, assertmsg


# def test_dummy():
#     "Dummy Test with CLI"
#     tgen = get_topogen()

#     # Skip if previous fatal error condition is raised
#     if tgen.routers_have_failure():
#         pytest.skip(tgen.errors)

#     logger.info("Dummy Test started");
#     tgen.mininet_cli()

#     tgen.gears["h2"].run("{} --send='0.7' '{}' '{}' '{}' &".format(
#         HELPER_APP_PATH, APP_SOCK_PATH, '239.100.0.17', 'h2-eth0'))
#     accept_host("h2")

#     tgen.gears["h1"].run("{} '{}' '{}' '{}' &".format(
#         HELPER_APP_PATH, APP_SOCK_PATH, '239.100.0.17', 'h1-eth0'))
#     accept_host("h1")

#     logger.info("join issued")
#     tgen.mininet_cli()


##################################
###  Test PIM RP Access-Lists
##################################

def check_mcast_entry(entry, mcastaddr, pimrp):
    "Helper function to check RP"
    tgen = get_topogen()

    logger.info("Testing PIM RP selection for ACL {} entry using {}".format(entry, mcastaddr));

    # Start applications socket.
    listen_to_applications()

    tgen.gears["h2"].run("{} --send='0.7' '{}' '{}' '{}' &".format(
        HELPER_APP_PATH, APP_SOCK_PATH, mcastaddr, 'h2-eth0'))
    accept_host("h2")

    tgen.gears["h1"].run("{} '{}' '{}' '{}' &".format(
        HELPER_APP_PATH, APP_SOCK_PATH, mcastaddr, 'h1-eth0'))
    accept_host("h1")

    logger.info("mcast join and source for {} started".format(mcastaddr))

    # tgen.mininet_cli()

    router = tgen.gears["r1"]
    reffile = os.path.join(CWD, "r1/acl_{}_pim_join.json".format(entry))
    expected = json.loads(open(reffile).read())

    logger.info("verifying pim join on r1 for {}".format(mcastaddr))
    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip pim join json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "PIM router r1 did not show join status"
    assert res is None, assertmsg

    logger.info("verifying pim join on PIM RP {} for {}".format(pimrp, mcastaddr))
    router = tgen.gears[pimrp]
    reffile = os.path.join(CWD, "{}/acl_{}_pim_join.json".format(pimrp, entry))
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp, router, "show ip pim join json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=60, wait=2)
    assertmsg = "PIM router {} did not get selected as the PIM RP".format(pimrp)
    assert res is None, assertmsg

    close_applications()
    return


def test_mcast_acl_1():
    "Test 1st ACL entry 239.100.0.0/28 with 239.100.0.1"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(1, '239.100.0.1', 'r11')


def test_mcast_acl_2():
    "Test 2nd ACL entry 239.100.0.17/32 with 239.100.0.17"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(2, '239.100.0.17', 'r12')


def test_mcast_acl_3():
    "Test 3rd ACL entry 239.100.0.32/27 with 239.100.0.32"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(3, '239.100.0.32', 'r13')


def test_mcast_acl_4():
    "Test 4th ACL entry 239.100.0.128/25 with 239.100.0.255"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(4, '239.100.0.255', 'r14')


def test_mcast_acl_5():
    "Test 5th ACL entry 239.100.0.96/28 with 239.100.0.97"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(5, '239.100.0.97', 'r14')


def test_mcast_acl_6():
    "Test 5th ACL entry 239.100.0.64/28 with 239.100.0.70"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_mcast_entry(6, '239.100.0.70', 'r15')




if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
