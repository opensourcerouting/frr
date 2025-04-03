#!/usr/bin/env python
# SPDX-License-Identifier: ISC

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_pan_654():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "10.0.0.2": {"state": "Established"},
                    "10.0.13.2": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge"

    import time
    time.sleep(5)

    r1.vtysh_cmd(
        """
config terminal
route-map 1735210719119015328 permit 10
 set local-preference 100
do clear ip bgp vrf default 10.0.13.2 soft
    """
    )
    
    time.sleep(0.3)

    r1.vtysh_cmd("""
    configure terminal
    no route-map 1735210719119015328
    """)

    time.sleep(0.3)

    r1.vtysh_cmd("""
    configure terminal
    route-map 1735210719119015328 permit 10
     set local-preference 100
    """)

    time.sleep(0.3)

    r1.vtysh_cmd("""
    configure terminal
    no route-map 1735210719119015328
    """)

    time.sleep(0.3)

    r1.vtysh_cmd("""
    configure terminal
    route-map 1735210719119015328 permit 10
     set local-preference 100
    """)

    time.sleep(0.3)

    r1.vtysh_cmd("""
    configure terminal
    no route-map 1735210719119015328
    """)

    time.sleep(0.3)

    r1.vtysh_cmd("""
    clear ip bgp vrf default 10.0.13.2 soft
    """)

    r1.vtysh_cmd("""
    configure terminal
    route-map 1735210719119015328 permit 10
     set local-preference 100
    """)

    time.sleep(0.3)

    r1.vtysh_cmd("""
    configure terminal
    no route-map 1735210719119015328
    """)

    time.sleep(0.3)

    r1.vtysh_cmd("""
    configure terminal
    route-map 1735210719119015328 permit 10
     set local-preference 100
    """)

    time.sleep(0.3)

    r1.vtysh_cmd("""
    configure terminal
    no route-map 1735210719119015328
    """)

    time.sleep(5)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
