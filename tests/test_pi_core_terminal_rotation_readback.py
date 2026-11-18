"""Compose grant rotation and root readback on owned files; not a live sample."""

import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest import mock

from aragorn import pi_core_request_recovery as recovery
from aragorn import pi_core_service_lifecycle as lifecycle
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests.test_runtime_action_broker import _write_control
from tests.test_runtime_action_broker_v4 import _fixture, _replacement


class TerminalRotationReadbackTests(unittest.TestCase):
    def setUp(self):
        # Keep the real protected-ancestry check, including the temp parent.
        parent = Path(__file__).resolve().parents[1] / ".aragorn"
        recovery.broker._require_protected_ancestry(parent, os.geteuid())
        root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=parent,
            prefix="pi-rotation-readback-"))).resolve()
        os.chown(root, -1, os.getegid(), follow_symlinks=False)
        self.fixture, self.old, self.issued = _fixture(root)
        self.next = _replacement(self.old)
        self.fixture.control.chmod(0o710)
        self.fixture.protected.chmod(0o710)
        self.enterContext(mock.patch.object(lifecycle.entry, "EFFECT_ROOT", root))
        self.enterContext(mock.patch.object(time, "time", return_value=100))
        self.configs = {"action": {"identities": {"action": {"uid": os.geteuid(), "gid": os.getegid()}},
                                   "capability_grant": json.loads(self.next.capability_grant)}}
        self.deadline = time.monotonic() + 5

    def test_new_grant_readback_after_consumed_preserves_both_raw_archives(self):
        # Seed only terminal metadata. No action, runtime, approval or service is run.
        grant = json.loads(self.old.capability_grant)
        submission = self.issued["profiled_submission"]
        attribution = submission["runtime_attribution"]
        claim = recovery.grants._build_claim(grant, self.issued["lease"], submission, attribution,
                                              canonical_digest(submission), 100)
        profile = claim["profile_claim"]
        blocked = recovery.broker._result(request_digest=profile["request_digest"],
            observation_digest=canonical_digest(self.fixture.observation), target_name=profile["target_name"],
            verdict="BLOCK", reason_codes=["BROKER_REPLAY_BLOCKED"], effect_status="NOT_PERFORMED", decision=None)
        receipt = {"schema": "aragorn/runtime-process-profile-receipt/v1",
            "authority": "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
            "submission_digest": profile["submission_digest"], "runtime_attribution": attribution,
            "runtime_attribution_digest": canonical_digest(attribution),
            "broker_result": blocked, "broker_result_digest": canonical_digest(blocked)}
        old_pin = canonical_digest(grant)
        consumed = {"schema": "aragorn/runtime-capability-grant-state/v1",
            "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": old_pin, "status": "CONSUMED", "claim": claim,
            "result": recovery._result_record(claim, receipt)}
        _write_control(self.old.grant_state_path, consumed)
        _write_control(self.old.broker.profile_receipt_path, receipt)
        original = {"state": self.old.grant_state_path.read_bytes(),
                    "profile-receipt": self.old.broker.profile_receipt_path.read_bytes()}

        prepared = recovery.initialize_pi_runtime_capability_grant(self.next, deadline_monotonic=self.deadline)
        readback = lifecycle._broker_control_snapshot(self.configs, self.deadline, require_available=True)
        self.assertEqual(readback["status"], "AVAILABLE_READBACK")
        self.assertTrue(readback["read_only"] and readback["owned_handles_closed"])
        self.assertEqual((prepared["status"], prepared["grant_digest"]),
                         ("AVAILABLE", canonical_digest(self.configs["action"]["capability_grant"])))
        self.assertNotEqual(prepared["grant_digest"], old_pin)
        self.assertEqual(readback["grant_state"], prepared)
        self.assertEqual(readback["state_digest"], canonical_digest(prepared))
        self.assertEqual(self.next.grant_state_path.read_bytes(), canonical_json(prepared))
        self.assertFalse(self.next.broker.profile_receipt_path.exists() or self.next.broker.profile_pending_path.exists())
        for kind, raw in original.items():
            archive = self.fixture.control / recovery.grants._archive_name(kind, old_pin)
            self.assertEqual(archive.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o400)

    def test_readback_refuses_and_preserves_foreign_current_receipt(self):
        # The positive test covers rotation. Here the reader alone must neither
        # repair a foreign fixed alias nor change the already AVAILABLE state.
        available = {"schema": "aragorn/runtime-capability-grant-state/v1",
            "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": canonical_digest(self.configs["action"]["capability_grant"]),
            "status": "AVAILABLE", "claim": None, "result": None}
        _write_control(self.next.grant_state_path, available)
        residue = self.next.broker.profile_receipt_path
        _write_control(residue, {"foreign": "not this grant"})
        before = residue.read_bytes(), recovery.broker._file_identity(residue.stat())
        with self.assertRaisesRegex(lifecycle.PiServiceLifecycleError, "pending, receipt or archived") as failure:
            lifecycle._broker_control_snapshot(self.configs, self.deadline, require_available=True)
        self.assertEqual((residue.read_bytes(), recovery.broker._file_identity(residue.stat())), before)
        self.assertEqual(self.next.grant_state_path.read_bytes(), canonical_json(available))
        self.assertTrue(failure.exception.pi_broker_control_snapshot["owned_handles_closed"])
