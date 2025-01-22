#!/usr/bin/env python
#
#  SPDX-License-Identifier: BSD-2-Clause
#
#  mld_v1.py
#  Part of NetDEF CI System
#
#  Copyright (c) 2025 by
#  Network Device Education Foundation, Inc. ("NetDEF")
#

"""
MLDv1 Packet Class

This module defines the MLDv1 class, which represents an MLDv1 packet. The class is built using the Scapy library and allows for the creation and manipulation of MLDv1 packets, including the optional addition of a Router Alert field.

Classes:
    MLDv1: Represents an MLDv1 packet.

Usage Example:
    from scapy.all import sendp
    from mld_v1 import MLDv1

    # Create an MLDv1 packet without Router Alert
    mld_packet = MLDv1(gaddr="ff02::1")
    mld_packet.show()

    # Enable Router Alert
    mld_packet.enable_router_alert()
    mld_packet.show()

    # Send the packet on the network interface (e.g., eth0)
    sendp(mld_packet, iface="eth0")
"""

from scapy.all import Packet, ByteField, ShortField, IP6Field, ConditionalField

class MLDv1(Packet):
    """
    Represents an MLDv1 packet.

    Attributes:
        type (int): The type of the MLD message (default is 0x82).
        max_resp_time (int): The maximum response time (default is 0).
        checksum (int): The checksum of the packet (default is None).
        gaddr (str): The group address (default is "ff02::1").
        router_alert (int): The Router Alert field (default is 0x0, conditional).

    Methods:
        enable_router_alert(value=0x94):
            Enables the Router Alert field with the specified value.
    """
    name = "MLDv1"
    fields_desc = [
        ByteField("type", 0x82),
        ByteField("max_resp_time", 0),
        ShortField("checksum", None),
        IP6Field("gaddr", "ff02::1"),
        ConditionalField(ByteField("router_alert", 0x0), lambda pkt: hasattr(pkt, 'router_alert_enabled') and pkt.router_alert_enabled)
    ]

    def enable_router_alert(self, value=0x05):
        """
        Enables the Router Alert field with the specified value.

        Args:
            value (int): The value to set for the Router Alert field (default is 0x05).
        """
        self.router_alert = value
        self.router_alert_enabled = True