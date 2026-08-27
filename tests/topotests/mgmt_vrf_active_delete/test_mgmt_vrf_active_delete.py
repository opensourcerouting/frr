# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026, NetDEF, Inc.
#
"""
Regression: a rejected delete of an *active* VRF must not wedge mgmtd's
candidate datastore.

Scenario (matches the customer report, FRR 10.4.3; still reproduces on master):

  1. Vrf_1 is active (a kernel VRF device exists) and is configured, so it is
     present in both the running and candidate datastores.
  2. A `vtysh -f` apply contains `no vrf Vrf_1`. mgmtd removes Vrf_1 from the
     candidate, then the commit's running->candidate diff produces a *delete* of
     Vrf_1. The northbound validator (lib/vrf.c lib_vrf_destroy, NB_EV_VALIDATE)
     correctly rejects deleting an active VRF:
         "Only inactive VRFs can be deleted"
     and the whole commit is aborted.
  3. BUG: on this batched / file-lock (non-implicit, unlock=false) path the
     candidate is NOT restored from running. It is left missing Vrf_1, while
     running still has it. Every subsequent commit re-diffs running->candidate,
     re-emits the phantom Vrf_1 delete, and fails -- including completely
     unrelated config -- until FRR is restarted.

This test asserts the CORRECT behavior, so it is expected to FAIL on buggy FRR
(both stable/10.4 and current master) and to PASS once the candidate datastore
is re-synced from running on a failed file-lock commit. The two assertions
marked "BUG" below are the ones that fail today.

See: post-mortem.md, fix-proposal.md, upstream-report.md
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter

pytestmark = [pytest.mark.mgmtd, pytest.mark.staticd]

VRF = "Vrf_1"
VRF_TABLE = "1001"
REJECT_MSG = "Only inactive VRFs can be deleted"


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]

    # Create the kernel VRF device *before* FRR starts so zebra marks the VRF
    # active (VRF_ACTIVE) -- this is what makes the delete illegal.
    r1.cmd_raises("ip link add {} type vrf table {}".format(VRF, VRF_TABLE))
    r1.cmd_raises("ip link set {} up".format(VRF))

    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"))

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def _vrf_names(r1, datastore):
    "Return the set of VRF names present in the given mgmtd datastore."
    out = r1.vtysh_cmd(
        "show mgmt get-data /frr-vrf:lib/vrf datastore {} only-config".format(datastore)
    )
    data = json.loads(out) if out.strip() else {}
    return {v["name"] for v in data.get("frr-vrf:lib", {}).get("vrf", [])}


def _apply_file(r1, conf):
    "Load a config snippet via 'vtysh -f' and return the combined output."
    return r1.cmd("vtysh -f {} 2>&1".format(os.path.join(CWD, "r1", conf)))


def test_step1_baseline_and_active_vrf_delete_is_rejected(tgen):
    """Trigger: deleting the active VRF via 'vtysh -f' is (correctly) rejected.

    This step PASSES on buggy and fixed FRR alike -- refusing to delete an
    active VRF is correct. It leaves the candidate datastore in the diverged
    state that steps 2 and 3 then observe.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Baseline: {} is active and present in candidate + running".format(VRF))
    assert VRF in r1.vtysh_cmd("show vrf"), "{} is not active".format(VRF)
    assert VRF in _vrf_names(r1, "running"), "{} missing from running DS".format(VRF)
    assert VRF in _vrf_names(r1, "candidate"), "{} missing from candidate DS".format(VRF)

    step("Apply 'no {}' via vtysh -f; the active-VRF delete must be rejected".format(VRF))
    out = _apply_file(r1, "del_active_vrf.conf")
    assert REJECT_MSG in out, (
        "expected the active-VRF delete to be rejected with %r, got:\n%s"
        % (REJECT_MSG, out)
    )


def test_step2_candidate_not_left_diverged(tgen):
    """BUG #1: after the rejected delete the candidate must be re-synced to
    running. On buggy FRR (master + 10.4.x) the candidate is left missing the
    VRF -- this step FAILS until the candidate-resync fix lands."""
    # No routers_have_failure() guard: the previous step's intentional non-zero
    # 'vtysh -f' exit (the rejected commit) trips it, but the router is healthy
    # and we want this assertion to run.
    r1 = tgen.gears["r1"]
    cand = _vrf_names(r1, "candidate")
    assert VRF in cand, (
        "candidate datastore left diverged after a rejected delete: "
        "{} is missing from candidate (got {}). running still has it, so the "
        "stale candidate poisons every subsequent commit until FRR restarts.".format(
            VRF, sorted(cand)
        )
    )


def test_step3_unrelated_apply_not_blocked(tgen):
    """BUG #2: with the candidate wedged, a completely unrelated config apply
    (a prefix-list) re-emits the phantom active-VRF delete and fails. This is
    the customer-visible symptom. FAILS until the fix lands."""
    # No routers_have_failure() guard (see step2).
    r1 = tgen.gears["r1"]
    step("Unrelated prefix-list apply via vtysh -f must succeed")
    out = _apply_file(r1, "unrelated_change.conf")
    assert REJECT_MSG not in out, (
        "unrelated config apply was blocked by the wedged candidate "
        "(phantom delete of active {} re-emitted):\n{}".format(VRF, out)
    )
    assert "test-wedge" in r1.vtysh_cmd("show running-config"), (
        "unrelated prefix-list was not applied -- the commit did not succeed"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
