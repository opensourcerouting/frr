#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023  David Lamparter for NetDEF, Inc.
"""
Test network for topotato.
"""

import logging
import typing
from typing import (
    Any,
    Dict,
    Callable,
    List,
    Optional,
    Tuple,
)

from .timeline import Timeline
from .osdep import NetworkInstance

if typing.TYPE_CHECKING:
    from . import toponom
    from .types import ISession
    from .frr.core import FRRSetup


_logger = logging.getLogger(__name__)


class TopotatoNetwork(NetworkInstance):
    """
    Main network representation & interface.

    This class is not used directly;  each test (or multiple tests if they are
    very similar) create subclasses of it.  The topotato machinery then creates
    an instance of the subclass to run a particular test class against.

    System names referenced in the topology are looked up directly in the class
    namespace to get the "system type" (a subclass of
    :py:class:`NetworkInstance.RouterNS`) for each system.  For example, for
    ``[ h1 ]---[ h2 ]``, "h1" and "h2" should be class variables on the
    subclass like this::

        class TestSetup(TopotatoNetwork, topo=topology):
            h1: Host
            h2: Host

    (where :py:class:`Host` refers to the class defined below.)

    Note that the test only defines the subclass but does not create an
    instance of it, that only happens when topotato actually runs the test.
    """

    timeline: Timeline
    session: "ISession"

    def make(self, name):
        return self.__class__.__annotations__[name](self, name, self.session)

    def __init__(self, network: "toponom.Network", session: "ISession"):
        super().__init__(network)
        self.session = session
        self.timeline = Timeline()

    @classmethod
    def __init_subclass__(cls, /, topo=None, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.topo = topo


class TopotatoNetworkCompat(TopotatoNetwork):
    """
    This subclass is used for the previous style with a FRR config class.
    """

    router_factories: Dict[str, Callable[[str], NetworkInstance.RouterNS]]

    def make(self, name):
        return self.router_factories.get(name, super().make)(name)

    def __init__(self, network: "toponom.Network", session: "ISession"):
        super().__init__(network, session)
        self.router_factories = {}


class Host(TopotatoNetwork.RouterNS):
    def __init__(self, instance: TopotatoNetwork, name: str, frr):
        super().__init__(instance, name)
        _ = frr  # FIXME: remove arg / rework FRR specific setup

    def interactive_state(self) -> Dict[str, Any]:
        return {}

    def report_state(self) -> Optional[Dict[str, Any]]:
        return None

    def start_post(self, timeline, failed: List[Tuple[str, str]]):
        pass