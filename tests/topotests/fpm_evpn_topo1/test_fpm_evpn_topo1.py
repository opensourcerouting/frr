#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_fpm_evpn_topo1.py: Test the EVPN entries zebra sends to the FPM.

Topology:

    peer1
      |  s1
    r1 ---- r2 ---- h2
    r1 ---- r2  s2
       s3

r1 and r2 are EVPN VTEPs (iBGP, VTEP IPs on the s1 link) with a VLAN
aware bridge, the L2VNI 1000 on VLAN 10 and the L3VNI 4001 (VRF vrf1)
on VLAN 100. h2 is a host in the VNI 1000 behind r2. The s3 link carries
an unnumbered (IPv6 link local) IPv4 unicast session, for which zebra
installs the 169.254.0.1 neighbor. peer1 is an ExaBGP EVPN peer of r1
playing a third VTEP of the VNI 1000, whose flood mode the test changes.

r1's zebra runs the FPM module connected to fpm_listener. The test
checks that the listener receives the entries r1 installs for r2's
routes, both when they are learnt and when zebra replays them on a new
FPM connection:

- the flood list entry (type-3) of r2, with its VNI and VLAN;
- the remote MAC (type-2) of h2;
- the remote neighbor (type-2 with IP) of h2 on the VNI SVI;
- the router MAC of r2 (type-5);
- the L3VNI next hop of r2 on the L3VNI SVI.

It also checks that:

- they are removed when r2's routes are withdrawn;
- the flood list entry of a remote VTEP no longer asking for head-end
  replication is removed, and installed again when it asks again;
- an access VLAN change moves the flood list and remote MAC entries to
  the new VLAN, without removing the kernel flood entry;
- the bridge coming up again without VLAN filtering moves the flood list
  entry to no VLAN, without removing the kernel flood entry;
- the 169.254.0.1 neighbor of the unnumbered session (not an EVPN
  entry) is never sent to the FPM.
"""

import os
import platform
import re
import subprocess
import sys
import time
from functools import partial

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn, pytest.mark.fpm]

R1_VTEP = "192.168.1.1"
R2_VTEP = "192.168.1.2"
PEER1_VTEP = "192.168.1.3"
R2_RMAC = "02:00:00:00:00:02"
H2_MAC = "02:00:00:00:00:64"
H2_IP = "10.10.10.100"
L2VNI = 1000
L2VNI_VLAN = 10
L2VNI_NEW_VLAN = 20
L3VNI = 4001
L3VNI_VLAN = 100
IPV4_LL = "169.254.0.1"

# Neighbor flags (linux/neighbour.h)
NTF_SELF = 0x02
NTF_MASTER = 0x04
NTF_EXT_LEARNED = 0x10


def build_topo(tgen):
    "Build function"

    for name in ["r1", "r2", "h2"]:
        tgen.add_router(name)

    # r1-eth0 <-> r2-eth0
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # peer1-eth0 on s1: ExaBGP EVPN peer of r1
    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="{}/24".format(PEER1_VTEP), defaultRoute="via 192.168.1.1"
    )
    switch.add_link(peer1)

    # r2-eth1 <-> h2-eth0
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["h2"])

    # r1-eth1 <-> r2-eth2: unnumbered IPv4 unicast session
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def _setup_vtep(router, num):
    "Create the VRF, VLAN aware bridge, VXLAN interfaces and SVIs of a VTEP"

    router.cmd_raises(
        """
ip link add vrf1 type vrf table 1001
ip link set vrf1 up
ip link add br0 address 02:00:00:00:00:{num:02x} type bridge vlan_filtering 1 stp_state 0
bridge vlan add vid {l2vlan} dev br0 self
bridge vlan add vid {l3vlan} dev br0 self
ip link set br0 up
ip link add lo1 type dummy
ip link set lo1 master vrf1
ip addr add 10.100.0.{num}/32 dev lo1
ip link set lo1 up
""".format(
            num=num, l2vlan=L2VNI_VLAN, l3vlan=L3VNI_VLAN
        )
    )

    for vni, vlan in [(L2VNI, L2VNI_VLAN), (L3VNI, L3VNI_VLAN)]:
        router.cmd_raises(
            """
ip link add vxlan{vni} type vxlan id {vni} dstport 4789 local 192.168.1.{num} nolearning
ip link set vxlan{vni} master br0
bridge vlan del vid 1 dev vxlan{vni}
bridge vlan add vid {vlan} dev vxlan{vni} pvid untagged
bridge link set dev vxlan{vni} learning off
ip link set vxlan{vni} up
ip link add link br0 name vlan{vlan} type vlan id {vlan}
ip link set vlan{vlan} master vrf1
ip link set vlan{vlan} up
""".format(
                vni=vni, vlan=vlan, num=num
            )
        )

    router.cmd_raises("ip addr add 10.10.10.{}/24 dev vlan{}".format(num, L2VNI_VLAN))


def setup_module(mod):
    "Sets up the pytest environment"

    if not topotest.platform_has_vrf():
        pytest.skip("platform does not support VRF")

    if not topotest.platform_has_evpn():
        pytest.skip("platform does not support EVPN")

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        pytest.skip('EVPN tests need kernel 4.18 or newer (have "{}")'.format(krel))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    h2 = tgen.gears["h2"]

    _setup_vtep(r1, 1)
    _setup_vtep(r2, 2)

    # h2 is connected to an access port of r2's bridge in the VNI VLAN.
    r2.cmd_raises(
        """
ip link set r2-eth1 master br0
bridge vlan del vid 1 dev r2-eth1
bridge vlan add vid {vlan} dev r2-eth1 pvid untagged
ip link set r2-eth1 up
""".format(
            vlan=L2VNI_VLAN
        )
    )
    h2.cmd_raises("ip link set h2-eth0 address {}".format(H2_MAC))

    r1.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        extra_daemons=[
            ("zebra", "-M dplane_fpm_nl"),
            (
                TopoRouter.RD_FPM_LISTENER,
                "-z {} -o {}".format(_fpm_dump_path(r1), _fpm_log_path(r1)),
            ),
        ],
    )
    r2.load_frr_config(os.path.join(CWD, "r2/frr.conf"))
    h2.load_frr_config(os.path.join(CWD, "h2/frr.conf"), daemons=["zebra"])

    tgen.start_router()

    tgen.gears["peer1"].start(
        os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env")
    )

    r1.vtysh_cmd(
        """
configure terminal
 fpm address 127.0.0.1
"""
    )


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


#
# FPM listener helpers
#


def _fpm_dump_path(router):
    return os.path.join(router.gearlogdir, "fpm_test.data")


def _fpm_log_path(router):
    "The log of every message fpm_listener received"
    return os.path.join(router.gearlogdir, "fpm_listener.log")


def _fpm_listener_dump(router):
    """
    Make fpm_listener dump its tables and return the dump as a string, or
    None when no dump was produced (see the same helper in
    fpm_testing_topo1).
    """
    pid_file = os.path.join(router.gearlogdir, "fpm_listener.pid")
    dump_file = _fpm_dump_path(router)

    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
    except (OSError, ValueError) as error:
        logger.info("fpm_listener pid file is not usable: {}".format(error))
        return None

    try:
        os.unlink(dump_file)
    except FileNotFoundError:
        pass

    rc, _, err = router.net.cmd_status("kill -USR1 {}".format(pid), warn=False)
    if rc:
        logger.info("fpm_listener (pid {}) not signalled: {}".format(pid, err.strip()))
        return None

    for _ in range(20):
        try:
            with open(dump_file, "r") as f:
                return f.read()
        except FileNotFoundError:
            time.sleep(0.1)

    logger.info("fpm_listener (pid {}) did not write {}".format(pid, dump_file))
    return None


def _fpm_neighbors(router):
    """
    Return the neighbor table of the fpm_listener dump as
    {"connection": <FPM connection number>, "neighbors": [<entry>, ...]},
    each entry being a dict of the "Key: value" pairs the listener prints
    (see fpm_neigh_snprint() in zebra/fpm_listener.c), or None when there
    is no dump.
    """
    dump = _fpm_listener_dump(router)
    if dump is None:
        return None

    parts = dump.split("=== Neighbor Table Dump ===", 1)
    if len(parts) != 2:
        return None
    section = parts[1].split("=====================", 1)[0]

    connection = re.search(r"^Connection: (\d+)$", section, re.MULTILINE)
    if connection is None:
        return None

    neighbors = []
    for line in section.splitlines():
        line = line.strip()
        if line.startswith("Neigh: "):
            neighbors.append(
                dict(re.findall(r"(\w+): ([^,]+)", line[len("Neigh: ") :]))
            )

    return {"connection": int(connection.group(1)), "neighbors": neighbors}


def _ifindex(router, ifname):
    return int(router.run("cat /sys/class/net/{}/ifindex".format(ifname)).strip())


def _evpn_entries(router, l2vni_vlan=L2VNI_VLAN):
    """
    The FPM entries r1 installs for r2's EVPN routes, by description. The
    "Flags" value lists the neighbor flags that must be set.
    """
    vxlan_l2 = _ifindex(router, "vxlan{}".format(L2VNI))
    vxlan_l3 = _ifindex(router, "vxlan{}".format(L3VNI))
    bridge = _ifindex(router, "br0")

    return {
        "flood list entry (type-3)": {
            "Family": "bridge",
            "Ifindex": vxlan_l2,
            "Lladdr": "00:00:00:00:00:00",
            "Dst": R2_VTEP,
            "Vlan": l2vni_vlan,
            "Vni": L2VNI,
        },
        "remote MAC (type-2)": {
            "Family": "bridge",
            "Ifindex": vxlan_l2,
            "Lladdr": H2_MAC,
            "Dst": R2_VTEP,
            "Vlan": l2vni_vlan,
            "Vni": L2VNI,
            "Master": bridge,
            "Flags": NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED,
        },
        "remote neighbor (type-2)": {
            "Family": "inet",
            "Ifindex": _ifindex(router, "vlan{}".format(L2VNI_VLAN)),
            "Lladdr": H2_MAC,
            "Dst": H2_IP,
            "Flags": NTF_EXT_LEARNED,
        },
        "router MAC (type-5)": {
            "Family": "bridge",
            "Ifindex": vxlan_l3,
            "Lladdr": R2_RMAC,
            "Dst": R2_VTEP,
            "Vlan": L3VNI_VLAN,
            "Vni": L3VNI,
            "Master": bridge,
            "Flags": NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED,
        },
        "L3VNI next hop (type-5)": {
            "Family": "inet",
            "Ifindex": _ifindex(router, "vlan{}".format(L3VNI_VLAN)),
            "Lladdr": R2_RMAC,
            "Dst": R2_VTEP,
            "Flags": NTF_EXT_LEARNED,
        },
    }


def _entry_matches(neighbor, expected):
    for key, value in expected.items():
        if key not in neighbor:
            return False
        if key == "Flags":
            if int(neighbor[key], 16) & value != value:
                return False
        elif neighbor[key] != str(value):
            return False
    return True


def _check_fpm_entries(router, present, absent=None, min_connection=0):
    """
    Return a description of what does not match yet, or None when the
    listener has all the `present` entries and none of the `absent` ones,
    on a connection numbered `min_connection` or more.
    """
    table = _fpm_neighbors(router)
    if table is None:
        return "no fpm_listener dump"

    if table["connection"] < min_connection:
        return "still on FPM connection {}, waiting for {}".format(
            table["connection"], min_connection
        )

    errors = []
    for name, expected in present.items():
        if not any(_entry_matches(n, expected) for n in table["neighbors"]):
            errors.append("missing {}: {}".format(name, expected))
    for name, expected in (absent or {}).items():
        if any(_entry_matches(n, expected) for n in table["neighbors"]):
            errors.append("unexpected {}: {}".format(name, expected))

    if not errors:
        return None

    return "{}\nFPM neighbors (connection {}):\n{}".format(
        "\n".join(errors),
        table["connection"],
        "\n".join(str(n) for n in table["neighbors"]),
    )


def _wait_fpm_entries(router, present, absent=None, min_connection=0, what=""):
    test_func = partial(_check_fpm_entries, router, present, absent, min_connection)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "{}:\n{}".format(what, result)


def _fpm_reconnect(router):
    """
    Make zebra connect again to the FPM, which sends the whole state again,
    and return the connection number the listener will report then.
    """
    table = _fpm_neighbors(router)
    assert table is not None, "no fpm_listener dump"

    router.vtysh_cmd(
        """
configure terminal
 fpm address 127.0.0.1
"""
    )

    return table["connection"] + 1


def _h2_traffic():
    "Make r2 learn h2's MAC and IP address (again)"
    tgen = get_topogen()
    tgen.gears["h2"].run("ping -c 2 -W 1 10.10.10.2")


def _wait_bgp_evpn(router):
    "Wait for the EVPN session between r1 and r2"
    expected = {"peers": {R2_VTEP: {"state": "Established"}}}
    test_func = partial(
        topotest.router_json_cmp, router, "show bgp l2vpn evpn summary json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 EVPN session to r2 is not up"


def _wait_bgp_peer1(router):
    "Wait for the EVPN session between r1 and peer1"
    expected = {"peers": {PEER1_VTEP: {"state": "Established"}}}
    test_func = partial(
        topotest.router_json_cmp, router, "show bgp l2vpn evpn summary json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 EVPN session to peer1 is not up"


def _peer1_flood_mode(mode):
    "Make peer1 advertise its type-3 route with the flood mode `mode`"
    peer1 = get_topogen().gears["peer1"]
    peer1.cmd_raises(
        "echo {0} > /etc/exabgp/flood-mode && chmod 644 /etc/exabgp/flood-mode".format(
            mode
        )
    )


def _remote_vtep_flood(router, vtep):
    "The flood mode zebra has for the remote VTEP `vtep`, or None"
    output = router.vtysh_cmd("show evpn vni {} json".format(L2VNI), isjson=True)
    for remote in output.get("remoteVteps", []):
        if remote.get("ip") == vtep:
            return remote.get("flood")
    return None


def _kernel_flood_entry(router, vtep):
    "If the kernel has the flood list entry of `vtep`"
    output = router.run("bridge fdb show dev vxlan{}".format(L2VNI))
    return (
        re.search(r"^00:00:00:00:00:00 dst {} ".format(vtep), output, re.MULTILINE)
        is not None
    )


def _kernel_flood_monitor_start(router):
    "Start recording the kernel FDB updates"
    proc = router.popen(
        ["bridge", "monitor", "fdb"],
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    # Give the monitor the time to subscribe before anything changes.
    time.sleep(1)
    return proc


def _kernel_flood_monitor_check(router, proc):
    """
    Stop recording and check that the kernel flood entry of r2 was never
    removed: moving it to another VLAN only concerns the FPM.
    """
    proc.terminate()
    output, _ = proc.communicate(timeout=10)
    deleted = [
        line
        for line in output.splitlines()
        if re.match(
            r"Deleted 00:00:00:00:00:00 dev vxlan{} .*dst {}\b".format(L2VNI, R2_VTEP),
            line,
        )
    ]
    assert not deleted, "kernel flood entry of r2 was removed:\n{}".format(
        "\n".join(deleted)
    )

    entry = router.run("bridge fdb show dev vxlan{}".format(L2VNI))
    assert re.search(
        r"^00:00:00:00:00:00 dst {} ".format(R2_VTEP), entry, re.MULTILINE
    ), "kernel flood entry of r2 is missing:\n{}".format(entry)


#
# Tests
#


def test_bgp_evpn_converge():
    "Wait for the EVPN session between r1 and r2"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _wait_bgp_evpn(tgen.gears["r1"])


def test_fpm_evpn_entries():
    "The FPM gets the EVPN entries as they are installed"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    _h2_traffic()
    _wait_fpm_entries(
        r1, _evpn_entries(r1), what="FPM did not get the EVPN entries of r2"
    )


def test_fpm_evpn_entries_replay():
    "A new FPM connection gets the EVPN entries again"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    connection = _fpm_reconnect(r1)
    _wait_fpm_entries(
        r1,
        _evpn_entries(r1),
        min_connection=connection,
        what="FPM did not get the EVPN entries of r2 on a new connection",
    )


def test_fpm_evpn_entries_withdraw():
    "The FPM entries are removed when r2's routes are withdrawn"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    entries = _evpn_entries(r1)

    r1.vtysh_cmd(
        """
configure terminal
 router bgp 65000
  neighbor {} shutdown
""".format(
            R2_VTEP
        )
    )
    _wait_fpm_entries(
        r1, {}, absent=entries, what="FPM kept EVPN entries of r2 after withdraw"
    )

    r1.vtysh_cmd(
        """
configure terminal
 router bgp 65000
  no neighbor {} shutdown
""".format(
            R2_VTEP
        )
    )
    _wait_bgp_evpn(r1)
    _h2_traffic()
    _wait_fpm_entries(r1, entries, what="FPM did not get the EVPN entries of r2 back")


def test_fpm_evpn_flood_mode_change():
    """
    The flood list entry of a remote VTEP no longer asking for head-end
    replication (PMSI tunnel type) is removed, from the kernel and the FPM,
    and installed again when it asks for it again. FRR always advertises
    ingress replication, so the remote VTEP is the ExaBGP peer.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    flood_entry = {
        "Family": "bridge",
        "Ifindex": _ifindex(r1, "vxlan{}".format(L2VNI)),
        "Lladdr": "00:00:00:00:00:00",
        "Dst": PEER1_VTEP,
        "Vni": L2VNI,
    }
    entry = {"peer1 flood list entry (type-3)": flood_entry}

    _wait_bgp_peer1(r1)

    # (peer1 advertisement, zebra flood mode, flood list entry installed)
    steps = [
        ("ingress-replication", "HER", True),
        ("no-tunnel", "-", False),
        ("ingress-replication", "HER", True),
    ]
    for mode, flood, installed in steps:
        _peer1_flood_mode(mode)

        test_func = partial(_remote_vtep_flood, r1, PEER1_VTEP)
        _, result = topotest.run_and_expect(test_func, flood, count=30, wait=1)
        assert result == flood, "peer1 VTEP flood mode is {}, not {}".format(
            result, flood
        )

        if installed:
            _wait_fpm_entries(
                r1, entry, what="FPM did not get the flood list entry of peer1"
            )
        else:
            _wait_fpm_entries(
                r1,
                {},
                absent=entry,
                what="FPM kept the flood list entry of peer1 not using HER",
            )

        test_func = partial(_kernel_flood_entry, r1, PEER1_VTEP)
        _, result = topotest.run_and_expect(test_func, installed, count=30, wait=1)
        assert result == installed, "kernel flood list entry of peer1 is {}".format(
            "missing" if installed else "still installed"
        )

    # The VTEP is removed with its route.
    _peer1_flood_mode("withdraw")
    test_func = partial(_remote_vtep_flood, r1, PEER1_VTEP)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "peer1 VTEP was not removed"
    _wait_fpm_entries(
        r1, {}, absent=entry, what="FPM kept the flood list entry of peer1"
    )
    assert not _kernel_flood_entry(r1, PEER1_VTEP), "kernel kept peer1 flood entry"


def test_fpm_evpn_access_vlan_change():
    """
    An access VLAN change of the L2VNI moves its flood list and remote MAC
    entries to the new VLAN, live and on a new FPM connection.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    l2_entries = ["flood list entry (type-3)", "remote MAC (type-2)"]
    old_entries = _evpn_entries(r1)
    new_entries = _evpn_entries(r1, L2VNI_NEW_VLAN)
    old = {name: old_entries[name] for name in l2_entries}
    new = {name: new_entries[name] for name in l2_entries}

    monitor = _kernel_flood_monitor_start(r1)
    r1.cmd_raises(
        """
bridge vlan add vid {new} dev br0 self
bridge vlan add vid {new} dev vxlan{vni} pvid untagged
bridge vlan del vid {old} dev vxlan{vni}
""".format(
            new=L2VNI_NEW_VLAN, old=L2VNI_VLAN, vni=L2VNI
        )
    )
    _wait_fpm_entries(
        r1, new, absent=old, what="FPM entries did not move to the new access VLAN"
    )
    _kernel_flood_monitor_check(r1, monitor)

    connection = _fpm_reconnect(r1)
    _wait_fpm_entries(
        r1,
        new,
        absent=old,
        min_connection=connection,
        what="FPM did not get the new access VLAN entries on a new connection",
    )


def test_fpm_evpn_bridge_vlan_filtering_change():
    """
    The bridge coming up again without VLAN filtering moves the flood list
    entry to no VLAN, live and on a new FPM connection.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    name = "flood list entry (type-3)"
    old = {name: _evpn_entries(r1, L2VNI_NEW_VLAN)[name]}
    new = {name: _evpn_entries(r1, 0)[name]}

    monitor = _kernel_flood_monitor_start(r1)
    r1.cmd_raises(
        """
ip link set br0 down
ip link set br0 type bridge vlan_filtering 0
ip link set br0 up
"""
    )
    _wait_fpm_entries(
        r1, new, absent=old, what="FPM flood list entry did not move to no VLAN"
    )
    _kernel_flood_monitor_check(r1, monitor)

    connection = _fpm_reconnect(r1)
    _wait_fpm_entries(
        r1,
        new,
        absent=old,
        min_connection=connection,
        what="FPM did not get the flood list entry without VLAN on a new connection",
    )


def _wait_bgp_unnumbered(router):
    "Wait for the unnumbered session between r1 and r2"
    expected = {"ipv4Unicast": {"peers": {"r1-eth1": {"state": "Established"}}}}
    test_func = partial(
        topotest.router_json_cmp, router, "show bgp summary json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 unnumbered session to r2 is not up"


def test_fpm_no_link_local_neighbor():
    """
    The 169.254.0.1 neighbor zebra installs for the unnumbered session is
    not an EVPN entry: the FPM never gets it, nor its removal (zebra
    removes it and installs it again when the kernel marks it invalid).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    _wait_bgp_unnumbered(r1)

    # The FPM must be connected to get the updates, if they were sent.
    def _fpm_connected():
        table = _fpm_neighbors(r1)
        return table is not None and len(table["neighbors"]) > 0

    _, result = topotest.run_and_expect(_fpm_connected, True, count=60, wait=1)
    assert result, "FPM did not get any entry"

    # A removal only goes on to the FPM when the kernel removal succeeds:
    # make sure the kernel has the entry before marking it invalid.
    r2_mac = r2.run("cat /sys/class/net/r2-eth2/address").strip()
    r1.cmd_raises(
        "ip neigh replace {} lladdr {} dev r1-eth1 nud permanent".format(
            IPV4_LL, r2_mac
        )
    )
    r1.cmd_raises("ip neigh replace {} dev r1-eth1 nud incomplete".format(IPV4_LL))

    def _reinstalled():
        output = r1.run("ip -4 neigh show {} dev r1-eth1".format(IPV4_LL))
        return "INCOMPLETE" not in output

    _, result = topotest.run_and_expect(_reinstalled, True, count=30, wait=1)
    assert result, "zebra did not install the {} neighbor again".format(IPV4_LL)

    # The FPM gets the dataplane updates right after the kernel: give it
    # some time and check nothing about the neighbor ever reached it.
    for _ in range(3):
        time.sleep(1)
        with open(_fpm_log_path(r1), "r") as f:
            lines = [line for line in f if "Dst: {},".format(IPV4_LL) in line]
        assert not lines, "FPM got the {} neighbor:\n{}".format(IPV4_LL, "".join(lines))


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
