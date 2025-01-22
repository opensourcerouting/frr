#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  igmp_v1.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#

"""
IGMPv1 Packet Class

This module defines the IGMPv1 class, which represents an IGMPv1 packet. The class is built using the Scapy library and allows for the creation and manipulation of IGMPv1 packets, including the optional addition of a Router Alert field.

Classes:
    IGMPv1: Represents an IGMPv1 packet.

Usage Example:
    from scapy.all import sendp
    from igmp_v1 import IGMPv1

    # Create an IGMPv1 packet without Router Alert
    igmp_packet = IGMPv1(gaddr="224.0.0.1")
    igmp_packet.show()

    # Enable Router Alert
    igmp_packet.enable_router_alert()
    igmp_packet.show()

    # Send the packet on the network interface (e.g., eth0)
    sendp(igmp_packet, iface="eth0")
"""

from scapy.all import Packet, ByteField, ShortField, IPField, ConditionalField
from scapy.sendrecv import sendp


class IGMPv1(Packet):
    """
    Represents an IGMPv1 packet.

    Attributes:
        type (int): The type of the IGMP message (default is 0x11).
        max_resp_time (int): The maximum response time (default is 0).
        checksum (int): The checksum of the packet (default is None).
        gaddr (str): The group address (default is "0.0.0.0").
        router_alert (int): The Router Alert field (default is 0x0, conditional).

    Methods:
        enable_router_alert(value=0x94):
            Enables the Router Alert field with the specified value.
    """

    name = "IGMPv1"
    fields_desc = [
        ByteField("type", 0x11),
        ByteField("max_resp_time", 0),
        ShortField("checksum", None),
        IPField("gaddr", "0.0.0.0"),
        ConditionalField(ByteField("router_alert", 0x0), lambda pkt: hasattr(pkt, 'router_alert_enabled') and pkt.router_alert_enabled)
    ]

    def enable_router_alert(self, value=0x9404):
        """
        Enables the Router Alert field with the specified value.

        Args:
            value (int): The value to set for the Router Alert field (default is 0x9404).
        """
        self.router_alert = value
        self.router_alert_enabled = True

    def send(self, interval=0, count=1, iface="eth0"):
        sendp(self, inter=int(interval), iface=iface, count=int(count))