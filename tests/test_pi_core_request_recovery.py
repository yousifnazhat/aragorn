"""Only new Pi recovery checks; durable I/O is an inert in-memory file table.

Real grant/claim/state/receipt codecs and frozen transition helpers are reused.
No file, socket, process, effect, activation or native recovery is executed.
"""

from contextlib import ExitStack
import copy
from dataclasses import replace
import json
import linecache
import os
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_request_recovery as subject
from aragorn import runtime_action_broker_v3 as leases
from aragorn import runtime_capability_grant as capabilities
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_runtime_capability_grant as fixtures


class PiRequestRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # Python 3.14 imports os locally in linecache. Retain traceback file/line
        # diagnostics but omit source-text lookup while product I/O is trapped.
        self.stack.enter_context(mock.patch.object(linecache, "getlines", return_value=[]))
        self.stack.enter_context(mock.patch.object(linecache, "checkcache", return_value=None))
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (socket, "getaddrinfo"), (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        for name in ("open", "close", "stat", "lstat", "fstat", "read", "write", "link", "unlink", "fsync", "rename"):
            self.stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError("unmocked file operation")))
        self.stack.enter_context(mock.patch.object(os, "supports_dir_fd", {os.link, os.open, os.stat, os.unlink}))
        self.stack.enter_context(mock.patch.object(os, "supports_follow_symlinks", {os.link}))
        self.uid = self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=2201))
        self.mono = self.stack.enter_context(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.wall = self.stack.enter_context(mock.patch.object(subject.time, "time", return_value=102.0))
        self.stack.enter_context(mock.patch.object(capabilities.secrets, "token_hex", return_value="c" * 64))
        self.grant, submission = fixtures._grant(), fixtures._submission()
        issued = capabilities.issue_profiled_runtime_capability(submission, canonical_json(self.grant), 102)
        self.claim = subject.grants._build_claim(self.grant, issued["lease"], submission,
            submission["runtime_attribution"], canonical_digest(submission), 102)
        root = Path("/var/lib/aragorn/request-control")
        base = subject.broker.RuntimeActionBrokerConfig(root / "broker.sock", root / "instance.lock", root / "broker.lock",
            root, Path("/var/lib/aragorn/output"), Path("/var/lib/aragorn/staging"),
            *(root / (name + ".json") for name in ("policy", "revocations", "health", "observation", "state")),
            2201, 2202, 2202, self.grant["runtime_digest"], 12, 13)
        profiled = subject.profile.RuntimeActionBrokerV2Config(base, self.grant["runtime_profile_digest"],
            root / "profile-pending.json", root / "profile-receipt.json")
        self.config = subject.grants.RuntimeActionBrokerV4Config(profiled, canonical_json(self.grant),
            root / "capability-grant-state.json")
        self.files = {"state.json": canonical_json({"schema": "aragorn/runtime-action-broker-state/v2",
            "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY", "minimum_revocation_generation": 1,
            "minimum_mediator_health_epoch": 1, "consumed": [], "effect_journal": None})}
        self.events, self.held = [], False
        self.fail_publish = self.fail_archive = self.fail_sync = self.fail_cleanup = False
        self.before_lock = lambda: None
        self.after_archive = lambda name: None

        def locked(config, deadline, operation):
            self.assertIs(config, self.config.broker)
            self.assertEqual(deadline, 100.5)
            self.before_lock()
            self.held = True
            self.events.append("lock")
            try:
                operation(77)
            finally:
                self.held = False
                self.events.append("close")
                if self.fail_cleanup:
                    raise subject.broker.RuntimeActionBrokerError("mock cleanup uncertainty")

        self.lock = self.stack.enter_context(mock.patch.object(subject.profile, "_with_profile_lock", side_effect=locked))

        def read(fd, name, **kwargs):
            self.assertTrue(self.held)
            self.assertEqual(fd, 77)
            self.assertEqual(kwargs["expected_uid"], 2201)
            self.assertEqual(kwargs.get("exact_mode", 0o400), 0o400)
            if name not in self.files:
                raise FileNotFoundError(name)
            raw = self.files[name]
            if len(raw) > kwargs["max_bytes"]:
                raise subject.broker.RuntimeActionBrokerError("mock read exceeded bound")
            return raw

        for owner in (subject.broker, subject.grants, leases):
            self.stack.enter_context(mock.patch.object(owner, "_read_owned_bytes_at", side_effect=read))
        self.stack.enter_context(mock.patch.object(subject.grants, "_read_immutable_archive_at", side_effect=read))

        def publish(fd, name, raw, **kwargs):
            self.assertTrue(self.held)
            self.assertEqual((fd, kwargs["expected_uid"]), (77, 2201))
            self.events.append(("publish", name))
            self.files[name] = raw
            if self.fail_publish:
                raise subject.broker.RuntimeActionBrokerError("mock publication uncertainty")

        self.publish = self.stack.enter_context(mock.patch.object(subject.grants, "_atomic_publish_at", side_effect=publish))

        def archive(fd, name, raw, config, label):
            self.assertTrue(self.held)
            self.events.append(("archive", name))
            if name in self.files and self.files[name] != raw:
                raise subject.broker.RuntimeActionBrokerError("mock immutable archive changed")
            self.files[name] = raw
            self.after_archive(name)
            if self.fail_archive:
                raise subject.broker.RuntimeActionBrokerError("mock archive uncertainty")

        self.archive = self.stack.enter_context(mock.patch.object(subject.grants, "_publish_immutable_at", side_effect=archive))

        def stat(name, *, dir_fd=None, follow_symlinks=True):
            self.assertTrue(self.held)
            self.assertEqual((dir_fd, follow_symlinks), (77, False))
            if name not in self.files:
                raise FileNotFoundError(name)
            return SimpleNamespace()

        self.stack.enter_context(mock.patch.object(os, "stat", side_effect=stat))
        # Rebind the supported-call set to the final inert stat implementation.
        self.stack.enter_context(mock.patch.object(os, "supports_dir_fd", {os.link, os.open, os.stat, os.unlink}))

        def unlink(name, *, dir_fd):
            self.assertTrue(self.held)
            self.assertEqual(dir_fd, 77)
            self.events.append(("unlink", name))
            del self.files[name]

        self.stack.enter_context(mock.patch.object(os, "unlink", side_effect=unlink))
        self.stack.enter_context(mock.patch.object(os, "supports_dir_fd", {os.link, os.open, os.stat, os.unlink}))

        def sync(fd):
            self.assertTrue(self.held)
            self.assertEqual(fd, 77)
            self.events.append("fsync")
            if self.fail_sync:
                raise OSError("mock fsync uncertainty")

        self.stack.enter_context(mock.patch.object(os, "fsync", side_effect=sync))
        for owner, name in ((subject.broker, "_recover_effect_journal"), (subject.broker, "_commit_state"),
                            (subject.pi, "mediate_pi_runtime_create"), (subject.grants, "mediate_granted_profiled_runtime_create")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("effect or implicit recovery forbidden")))

    def state(self):
        return json.loads(self.files[self.config.grant_state_path.name])

    def put_state(self, status="CLAIMED", result=None, claim=True):
        state = {"schema": "aragorn/runtime-capability-grant-state/v1",
            "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": canonical_digest(self.grant), "status": status,
            "claim": copy.deepcopy(self.claim) if claim else None, "result": result}
        self.files[self.config.grant_state_path.name] = canonical_json(state)
        return state

    def receipt(self, kind="effective", *, pending=False, consumed=False):
        claim = self.claim["profile_claim"]
        decision = {"schema": "aragorn/runtime-action-decision/v1",
            "authority": "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
            "request_digest": claim["request_digest"], "verdict": "ALLOW", "reason_codes": []}
        result = {"schema": "aragorn/runtime-action-broker-result/v1",
            "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "request_digest": claim["request_digest"], "observation_digest": "sha256:" + "d" * 64,
            "decision": decision, "verdict": "BLOCK", "reason_codes": ["BROKER_PI_REQUEST_REFUSED"],
            "effect_status": "NOT_PERFORMED", "target_name": claim["target_name"]}
        if kind == "replay":
            result.update(decision=None, reason_codes=["BROKER_REPLAY_BLOCKED"])
        elif kind == "created":
            result.update(verdict="ALLOW", reason_codes=[], effect_status="CREATED")
        elif kind == "policy":
            decision.update(verdict="BLOCK", reason_codes=["POLICY_DEFAULT_BLOCK"])
            result.update(reason_codes=["POLICY_DEFAULT_BLOCK"])
        receipt = {"schema": "aragorn/runtime-process-profile-receipt/v1",
            "authority": "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
            "submission_digest": claim["submission_digest"],
            "runtime_attribution": copy.deepcopy(claim["profile_pending"]["runtime_attribution"]),
            "runtime_attribution_digest": claim["runtime_attribution_digest"],
            "broker_result": result, "broker_result_digest": canonical_digest(result)}
        self.files["profile-receipt.json"] = canonical_json(receipt)
        record = subject._result_record(self.claim, receipt) if consumed else None
        self.put_state("CONSUMED" if consumed else "CLAIMED", record)
        if pending:
            self.files["profile-pending.json"] = canonical_json(claim["profile_pending"])
        return receipt

    def recover(self, config=None):
        return subject.recover_pi_runtime_capability_grant(config or self.config, deadline_monotonic=100.5)

    def initialize(self, config=None, now=102):
        return subject.initialize_pi_runtime_capability_grant(config or self.config,
            now_unix=now, deadline_monotonic=100.5)

    def replacement(self):
        return replace(self.config, capability_grant=canonical_json({**self.grant, "grant_id": "4" * 64}))

    def test_effective_block_recovers_without_rewriting_allow_policy(self):
        receipt = self.receipt()
        result = self.recover()
        self.assertEqual(result["status"], "CONSUMED")
        self.assertEqual(result["result"]["profile_result"]["verdict"], "BLOCK")
        self.assertEqual(json.loads(self.files["profile-receipt.json"]), receipt)
        self.assertEqual(receipt["broker_result"]["decision"]["verdict"], "ALLOW")

    def test_replay_without_new_policy_decision_recovers(self):
        self.receipt("replay")
        self.assertEqual(self.recover()["status"], "CONSUMED")

    def test_created_receipt_reuses_frozen_result_without_effect_retry(self):
        receipt = self.receipt("created")
        expected = subject.grants._result_record(self.claim, receipt)
        self.assertEqual(self.recover()["result"], expected)

    def test_policy_block_receipt_remains_distinct_from_broker_refusal(self):
        self.receipt("policy")
        self.assertEqual(self.recover()["result"]["profile_result"]["effect_status"], "NOT_PERFORMED")

    def test_exact_pending_removed_only_after_durable_consumed(self):
        self.receipt(pending=True)
        self.recover()
        self.assertLess(self.events.index(("publish", "capability-grant-state.json")),
                        self.events.index(("unlink", "profile-pending.json")))
        self.assertNotIn("profile-pending.json", self.files)

    def test_wrong_pending_holds_claim_before_any_mutation(self):
        self.receipt(pending=True)
        self.files["profile-pending.json"] = b"{}"
        before = copy.deepcopy(self.files)
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.recover()
        self.assertEqual(self.files, before)
        self.publish.assert_not_called()

    def test_claimed_missing_receipt_never_abandons_or_resets(self):
        self.put_state()
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.recover()
        self.assertEqual(self.state()["status"], "CLAIMED")
        self.publish.assert_not_called()

    def test_recovery_does_not_initialize_missing_grant_state(self):
        with self.assertRaises(FileNotFoundError): self.recover()
        self.publish.assert_not_called()

    def test_available_checks_journal_before_returning(self):
        self.put_state("AVAILABLE", claim=False)
        self.files["state.json"] = canonical_json({"invalid": True})
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.recover()
        self.publish.assert_not_called()

    def test_unresolved_effect_journal_blocks_both_entrypoints_without_recovery(self):
        self.receipt()
        with mock.patch.object(subject.broker, "_state", return_value={"effect_journal": {"status": "PENDING"}}), \
             mock.patch.object(subject.broker, "_load_control", return_value={"effect_journal": {"status": "PENDING"}}):
            for operation in (self.recover, self.initialize):
                with self.subTest(operation=operation), self.assertRaises(subject.broker.RuntimeActionBrokerError): operation()
        self.publish.assert_not_called()

    def test_legacy_broker_state_is_not_silently_migrated(self):
        value = json.loads(self.files["state.json"])
        value.update(schema="aragorn/runtime-action-broker-state/v1")
        value.pop("effect_journal")
        self.files["state.json"] = canonical_json(value)
        before = copy.deepcopy(self.files)
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.initialize()
        self.assertEqual(self.files, before)

    def test_mutated_receipt_digest_refuses_before_consumption(self):
        value = self.receipt()
        value["broker_result"]["target_name"] = "other.txt"
        self.files["profile-receipt.json"] = canonical_json(value)
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.recover()
        self.assertEqual(self.state()["status"], "CLAIMED")

    def test_rebound_receipt_target_still_refuses_exact_claim_join(self):
        value = self.receipt()
        value["broker_result"]["target_name"] = "other.txt"
        value["broker_result_digest"] = canonical_digest(value["broker_result"])
        self.files["profile-receipt.json"] = canonical_json(value)
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.recover()
        self.publish.assert_not_called()

    def test_unknown_effective_reason_cannot_gain_recovery_support(self):
        value = self.receipt()
        value["broker_result"]["reason_codes"] = ["BROKER_INVENTED_REASON"]
        value["broker_result_digest"] = canonical_digest(value["broker_result"])
        self.files["profile-receipt.json"] = canonical_json(value)
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.recover()

    def test_consumed_readback_revalidates_retained_receipt_without_new_write(self):
        self.receipt(consumed=True)
        expected = self.state()
        self.assertEqual(self.recover(), expected)
        self.publish.assert_not_called()

    def test_consumed_changed_result_refuses_without_archival(self):
        self.receipt(consumed=True)
        value = self.state()
        value["result"]["profile_result"]["broker_result_digest"] = "sha256:" + "e" * 64
        self.files["capability-grant-state.json"] = canonical_json(value)
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.recover()
        self.archive.assert_not_called()

    def test_publication_uncertainty_retains_consumed_and_pending(self):
        self.receipt(pending=True)
        self.fail_publish = True
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate): self.recover()
        self.assertEqual(self.state()["status"], "CONSUMED")
        self.assertIn("profile-pending.json", self.files)
        self.publish.assert_called_once()

    def test_pending_fsync_uncertainty_is_not_terminal_success(self):
        self.receipt(pending=True)
        self.fail_sync = True
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate): self.recover()
        self.assertEqual(self.state()["status"], "CONSUMED")

    def test_cleanup_failure_after_reconciliation_is_indeterminate(self):
        self.receipt()
        self.fail_cleanup = True
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate): self.recover()
        self.assertEqual(self.state()["status"], "CONSUMED")

    def test_initializer_is_only_explicit_missing_state_creator(self):
        observed = self.initialize()
        self.assertEqual(observed["status"], "AVAILABLE")
        self.assertEqual(self.recover(), observed)
        self.assertEqual(self.publish.call_count, 1)

    def test_missing_state_with_orphan_receipt_is_not_new_authority(self):
        self.files["profile-receipt.json"] = b"{}"
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.initialize()
        self.publish.assert_not_called()

    def test_missing_state_with_orphan_pending_is_not_new_authority(self):
        self.files["profile-pending.json"] = b"{}"
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.initialize()
        self.publish.assert_not_called()

    def test_fresh_grant_rotation_archives_receipt_then_state_before_available(self):
        receipt = self.receipt(consumed=True)
        original = self.state()
        observed = self.initialize(self.replacement())
        old = original["grant_digest"]
        receipt_name, state_name = (subject.grants._archive_name(kind, old) for kind in ("profile-receipt", "state"))
        self.assertEqual(json.loads(self.files[receipt_name]), receipt)
        self.assertEqual(json.loads(self.files[state_name]), original)
        self.assertEqual(observed["status"], "AVAILABLE")
        self.assertNotEqual(observed["grant_digest"], original["grant_digest"])
        self.assertLess(self.events.index(("archive", receipt_name)), self.events.index(("archive", state_name)))
        self.assertLess(self.events.index(("archive", state_name)), self.events.index(("publish", "capability-grant-state.json")))

    def test_same_grant_terminal_state_is_never_reset(self):
        self.receipt(consumed=True)
        expected = self.state()
        self.assertEqual(self.initialize(), expected)
        self.publish.assert_not_called()
        self.archive.assert_not_called()

    def test_claimed_never_rotates_even_with_a_fresh_grant(self):
        self.receipt()
        for config in (self.config, self.replacement()):
            with self.subTest(config=config), self.assertRaises(subject.broker.RuntimeActionBrokerError): self.initialize(config)
        self.assertEqual(self.state()["status"], "CLAIMED")
        self.archive.assert_not_called()

    def test_terminal_with_pending_requires_explicit_recovery_before_rotation(self):
        self.receipt(consumed=True, pending=True)
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.initialize(self.replacement())
        self.archive.assert_not_called()

    def test_old_archived_grant_cannot_be_reissued(self):
        self.receipt(consumed=True)
        old = self.state()
        self.initialize(self.replacement())
        self.files["capability-grant-state.json"] = canonical_json(old)
        self.files[subject.grants._archive_name("state", old["grant_digest"])] = canonical_json(old)
        self.files.pop("capability-grant-state.json")
        self.files.pop("profile-receipt.json")
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.initialize()
        self.assertNotIn("capability-grant-state.json", self.files)

    def test_restored_available_state_cannot_revive_archived_terminal_grant(self):
        self.receipt(consumed=True)
        terminal = self.state()
        self.files[subject.grants._archive_name("state", terminal["grant_digest"])] = canonical_json(terminal)
        restored = self.put_state("AVAILABLE", claim=False)
        before = copy.deepcopy(self.files)
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate): self.recover()
        self.assertEqual(self.state(), restored)
        self.assertEqual(self.files, before)
        self.publish.assert_not_called()

    def test_changed_immutable_archive_never_overwritten(self):
        self.receipt(consumed=True)
        before = self.state()
        name = subject.grants._archive_name("profile-receipt", before["grant_digest"])
        self.files[name] = b"retained other bytes"
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate): self.initialize(self.replacement())
        self.assertEqual(self.files[name], b"retained other bytes")
        self.assertEqual(self.state(), before)

    def test_archive_failure_retains_old_state_and_partial_evidence(self):
        self.receipt(consumed=True)
        before = self.state()
        self.fail_archive = True
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate): self.initialize(self.replacement())
        self.assertEqual(self.state(), before)
        self.assertIn(subject.grants._archive_name("profile-receipt", before["grant_digest"]), self.files)
        self.publish.assert_not_called()

    def test_post_archive_publication_uncertainty_never_rolls_back(self):
        self.receipt(consumed=True)
        before = self.state()
        self.fail_publish = True
        replacement = self.replacement()
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate): self.initialize(replacement)
        self.assertEqual(self.state()["grant_digest"], canonical_digest(json.loads(replacement.capability_grant)))
        self.assertIn(subject.grants._archive_name("state", before["grant_digest"]), self.files)

    def test_deadline_expiring_after_archive_never_publishes_new_authority(self):
        self.receipt(consumed=True)
        before = self.state()
        self.after_archive = lambda name: setattr(self.mono, "return_value", 100.5)
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate): self.initialize(self.replacement())
        self.assertEqual(self.state(), before)
        self.publish.assert_not_called()

    def test_expired_available_grant_terminalizes_without_effect(self):
        self.put_state("AVAILABLE", claim=False)
        self.wall.return_value = 110
        result = self.recover()
        self.assertEqual(result["status"], "EXPIRED")
        self.assertEqual(result["result"]["expires_at_unix"], 110)

    def test_initializer_does_not_renew_expired_grant(self):
        result = self.initialize(now=110)
        self.assertEqual(result["status"], "EXPIRED")
        self.assertEqual(self.initialize(now=111), result)

    def test_abandoned_terminal_can_rotate_but_never_become_available_again(self):
        result = {"schema": "aragorn/runtime-capability-grant-abandonment/v1",
            "authority": "BROKER_GRANT_ABANDONMENT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": self.claim["grant_digest"], "lease_digest": self.claim["lease_digest"],
            "failure_code": "KNOWN_NO_EFFECT_RUNTIME_BROKER_ERROR"}
        abandoned = self.put_state("ABANDONED", result)
        self.assertEqual(self.recover(), abandoned)
        self.assertEqual(self.initialize(), abandoned)
        self.assertEqual(self.initialize(self.replacement())["status"], "AVAILABLE")

    def test_unknown_deadline_types_expired_or_unbounded_refuse_before_lock(self):
        for deadline in (True, float("nan"), float("inf"), 100, 131, "100.5"):
            with self.subTest(deadline=deadline), self.assertRaises(subject.broker.RuntimeActionBrokerError):
                subject.recover_pi_runtime_capability_grant(self.config, deadline_monotonic=deadline)
        self.lock.assert_not_called()

    def test_original_deadline_checked_after_lock_acquisition(self):
        self.before_lock = lambda: setattr(self.mono, "return_value", 100.5)
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.initialize()
        self.publish.assert_not_called()

    def test_missing_state_publication_consuming_budget_is_indeterminate(self):
        original = self.publish.side_effect

        def delayed(*args, **kwargs):
            original(*args, **kwargs)
            self.mono.return_value = 100.5

        self.publish.side_effect = delayed
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate): self.initialize()
        self.assertEqual(self.state()["status"], "AVAILABLE")
        self.publish.assert_called_once()

    def test_wrong_broker_identity_refuses_before_lock(self):
        self.uid.return_value = 0
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.initialize()
        self.lock.assert_not_called()

    def test_initializer_rejects_boolean_time_and_future_grant(self):
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.initialize(now=True)
        with self.assertRaises(subject.broker.RuntimeActionBrokerError): self.initialize(now=89)
        self.publish.assert_not_called()

    def test_returned_state_is_detached_from_retained_bytes(self):
        self.receipt(consumed=True)
        observed = self.recover()
        observed["claim"]["profile_claim"]["target_name"] = "caller-change.txt"
        self.assertEqual(self.state()["claim"]["profile_claim"]["target_name"], "result.txt")


if __name__ == "__main__":
    unittest.main()
