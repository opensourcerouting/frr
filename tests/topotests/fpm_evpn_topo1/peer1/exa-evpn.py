#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
exa-evpn.py: advertise the EVPN type-3 (IMET) route of the VTEP 192.168.1.3
for the VNI 1000, with the flood mode (PMSI tunnel type) the test asks for.

ExaBGP has no syntax for EVPN routes: the route is encoded here in a
MP_REACH_NLRI (or MP_UNREACH_NLRI) generic attribute, which goes, with
the PMSI tunnel generic attribute, in the update of a dummy IPv4 route.

The test writes the state to advertise in /etc/exabgp/flood-mode:

- "ingress-replication": PMSI tunnel type ingress replication;
- "no-tunnel": PMSI tunnel type "no tunnel information present";
- "withdraw": the route is withdrawn.
"""

import socket
import struct
import sys
import time

VTEP = "192.168.1.3"
VNI = 1000
ROUTE_TARGET = "target:65000:{}".format(VNI)
DUMMY_ROUTE = "192.0.2.3/32"
MODE_FILE = "/etc/exabgp/flood-mode"

AFI_L2VPN = 25
SAFI_EVPN = 70
EVPN_IMET_ROUTE = 3
PMSI_NO_TUNNEL = 0
PMSI_INGRESS_REPLICATION = 6

ATTR_MP_REACH_NLRI = 0x0E
ATTR_MP_UNREACH_NLRI = 0x0F
ATTR_PMSI_TUNNEL = 0x16
FLAG_OPTIONAL = 0x80
FLAG_TRANSITIVE = 0x40


def imet_nlri():
    "EVPN type-3 route: RD (type 1), Ethernet tag 0 and the VTEP address"
    vtep = socket.inet_aton(VTEP)
    rd = struct.pack("!H", 1) + vtep + struct.pack("!H", VNI)
    value = rd + struct.pack("!IB", 0, 32) + vtep
    return struct.pack("!BB", EVPN_IMET_ROUTE, len(value)) + value


def mp_reach_nlri():
    nexthop = socket.inet_aton(VTEP)
    return (
        struct.pack("!HBB", AFI_L2VPN, SAFI_EVPN, len(nexthop))
        + nexthop
        + b"\x00"
        + imet_nlri()
    )


def mp_unreach_nlri():
    return struct.pack("!HB", AFI_L2VPN, SAFI_EVPN) + imet_nlri()


def pmsi_tunnel(tunnel_type):
    # Flags, tunnel type and the VNI in the MPLS label field (RFC 8365).
    value = struct.pack("!BB", 0, tunnel_type) + struct.pack("!I", VNI)[1:]
    if tunnel_type == PMSI_INGRESS_REPLICATION:
        value += socket.inet_aton(VTEP)
    return value


def generic(code, flags, value):
    return "attribute [ 0x{:02x} 0x{:02x} 0x{} ]".format(code, flags, value.hex())


def command(mode):
    announce = "announce route {} next-hop {}".format(DUMMY_ROUTE, VTEP)
    if mode == "withdraw":
        return "{} {}".format(
            announce, generic(ATTR_MP_UNREACH_NLRI, FLAG_OPTIONAL, mp_unreach_nlri())
        )

    tunnel_type = {
        "ingress-replication": PMSI_INGRESS_REPLICATION,
        "no-tunnel": PMSI_NO_TUNNEL,
    }[mode]
    return "{} extended-community [ {} ] {} {}".format(
        announce,
        ROUTE_TARGET,
        generic(ATTR_MP_REACH_NLRI, FLAG_OPTIONAL, mp_reach_nlri()),
        generic(
            ATTR_PMSI_TUNNEL, FLAG_OPTIONAL | FLAG_TRANSITIVE, pmsi_tunnel(tunnel_type)
        ),
    )


def read_mode():
    try:
        with open(MODE_FILE, "r") as f:
            return f.read().strip()
    except OSError:
        return None


current = None
while True:
    mode = read_mode()
    if mode and mode != current:
        sys.stdout.write(command(mode) + "\n")
        sys.stdout.flush()
        current = mode
    time.sleep(0.5)
