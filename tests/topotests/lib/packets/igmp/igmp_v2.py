#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  imgp_v2.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#

"""
IGMPv2 Packet Class

This module defines the IGMPv2 class, which represents an IGMPv2 packet. The class is built using the Scapy library and allows for the creation and manipulation of IGMPv2 packets, including the optional addition of a Router Alert field.

Classes:
    IGMPv2: Represents an IGMPv2 packet.

Usage Example:
    from scapy.all import sendp
    from igmp_v2 import IGMPv2

    # Create an IGMPv2 packet without Router Alert
    igmp_packet = IGMPv2(gaddr="224.0.0.1")
    igmp_packet.show()

    # Enable Router Alert
    igmp_packet.enable_router_alert()
    igmp_packet.show()

    # Send the packet on the network interface (e.g., eth0)
    sendp(igmp_packet, iface="eth0")
"""

from scapy.all import Packet, ByteField, ShortField, IPField, ConditionalField


class IGMPv2(Packet):
    """
    Represents an IGMPv2 packet.

    Attributes:
        type (int): The type of the IGMP message (default is 0x16).
        max_resp_time (int): The maximum response time (default is 10).
        checksum (int): The checksum of the packet (default is None).
        gaddr (str): The group address (default is "0.0.0.0").
        router_alert (int): The Router Alert field (default is 0x0, conditional).

    Methods:
        enable_router_alert(value=0x94):
            Enables the Router Alert field with the specified value.
    """

    name = "IGMPv2"
    fields_desc = [
        ByteField("type", 0x16),
        ByteField("max_resp_time", 10),
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
