"""New Pi mediation checks, confined to owned temporary files and mocked auth.

These run the real existing grant, snapshot, replay and atomic-create primitives.
Root/sensor provenance is mocked and is not deployment or kernel proof. No
socket, process, service, target runtime or network operation is permitted.
"""

from contextlib import ExitStack, contextmanager
import copy
from dataclasses import replace
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

from aragorn import pi_core_request_broker as pi
from aragorn import pi_core_request_handoff as handoff
from aragorn import pi_core_worker_identity as identity
from aragorn import runtime_action_broker as broker
from aragorn import runtime_action_broker_v2 as profile
from aragorn import runtime_action_broker_v4 as grants
from aragorn import runtime_action_broker_v5 as lineage
from aragorn import runtime_action_worker as worker
from aragorn.runtime_capability_grant import issue_profiled_runtime_capability
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests.test_runtime_action_broker_v4 import _fixture
from tests.test_runtime_action_broker import _write_control


class PiRequestBrokerTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # The pipeline omits TMPDIR, so the default /tmp ancestry is writable
        # by other users. Keep the real production ancestry guard intact.
        fixture_parent = Path(__file__).resolve().parents[1] / ".aragorn"
        broker._require_protected_ancestry(fixture_parent, os.geteuid())
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(
            prefix="pi-request-broker-", dir=fixture_parent))).resolve()
        # macOS temporary parents can carry a group different from getegid().
        # Normalize only this owned root before creating the fixture children.
        os.chown(self.root, -1, os.getegid(), follow_symlinks=False)
        self.fixture, self.grant_config, initial = _fixture(self.root)
        self.config = lineage.RuntimeActionBrokerV5Config(self.grant_config, self.root / "installed")
        self.grant = json.loads(self.grant_config.capability_grant)
        submission = copy.deepcopy(initial["profiled_submission"])
        correlation = {"session_id": "a" * 32, "run_id": "a" * 32, "tool_call_id": "sha256:" + "3" * 64}
        submission["envelope"]["request"].update(correlation)
        submission["measured_action"].update(correlation)
        submission["envelope_digest"] = canonical_digest(submission["envelope"])
        submission["request_digest"] = canonical_digest(submission["envelope"]["request"])
        self.issuance = issue_profiled_runtime_capability(submission, self.grant_config.capability_grant, 100)
        self.envelope = self.issuance["profiled_submission"]["envelope"]
        attribution = self.issuance["profiled_submission"]["runtime_attribution"]
        self.activation = {
            "schema": identity.ACTIVATION_SCHEMA, "authority": identity.ACTIVATION_AUTHORITY,
            "activation_id": "a" * 32, "session_id": "a" * 32, "run_id": "a" * 32,
            **{key: copy.deepcopy(attribution[key]) for key in (
                "pid", "uid", "gid", "start_time_ticks", "mount_namespace", "cgroup",
                "profile_digest", "runtime_digest", "executable_digest", "active_skill_digest")},
            "source_manifest_digest": self.grant["source_manifest_digest"],
            "install_context_digest": self.grant["install_context_digest"],
            "policy_digest": self.grant["policy_digest"], "tree_digest": "sha256:" + "d" * 64,
            "active_record_digest": "sha256:" + "e" * 64, "deployment_digest": "sha256:" + "f" * 64,
            "boot_id": "11111111-2222-3333-4444-555555555555", "expires_at_monotonic_ns": 1001_000_000_000,
        }
        self.worker_request = {
            "schema": "aragorn/runtime-action-worker-request/v1", "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "session_id": "a" * 32, "run_id": "a" * 32, "tool_call_digest": correlation["tool_call_id"],
            "target_name": self.envelope["effect"]["target_name"], "payload_base64": self.envelope["effect"]["payload_base64"],
        }
        self.live_lineage = {"active_record_digest": self.activation["active_record_digest"],
            "context_digest": self.activation["install_context_digest"],
            "manifest_digest": self.activation["source_manifest_digest"], "tree_digest": self.activation["tree_digest"]}
        self.value = {"schema": lineage.LINEAGE_ISSUANCE_SCHEMA, "authority": lineage.LINEAGE_ISSUANCE_AUTHORITY,
                      "lineage": copy.deepcopy(self.live_lineage), "issuance": self.issuance}
        self.holding = False
        self.used = False
        self.in_begin = False
        self.guard_count = 0
        self.guard_fail_at = None
        self.guard_events = []
        self.guard_hook = None
        self.authority = object.__new__(handoff.PiRequestAuthority)
        # Deliberately mock only this external authentication boundary. The exact
        # context type check is still exercised, and connected protocol tests
        # separately cover its origin; no test-made context is qualification.
        for name, getter in (("activation", lambda: copy.deepcopy(self.activation)),
                             ("worker_request", lambda: copy.deepcopy(self.worker_request)),
                             ("request_digest", lambda: canonical_digest(self.worker_request)),
                             ("deadline", lambda: 1000.5)):
            self.stack.enter_context(mock.patch.object(handoff.PiRequestAuthority, name,
                new_callable=mock.PropertyMock, side_effect=getter))
        self.begin_mock = self.stack.enter_context(mock.patch.object(handoff.PiRequestAuthority, "begin", side_effect=self.begin))
        self.guard_mock = self.stack.enter_context(mock.patch.object(handoff.PiRequestAuthority, "guard", side_effect=self.guard))
        self.local_live = self.stack.enter_context(mock.patch.object(handoff.PiRequestAuthority, "_live"))
        self.stack.enter_context(mock.patch.object(lineage, "hold_runtime_active_skill_lineage", side_effect=self.hold_lineage))
        self.mono = self.stack.enter_context(mock.patch.object(pi.time, "monotonic", return_value=1000.0))
        self.wall = self.stack.enter_context(mock.patch.object(pi.time, "time", return_value=100.0))
        self.stack.enter_context(mock.patch.object(pi.time, "monotonic_ns", return_value=1000_000_000_000))
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        self.legacy = self.stack.enter_context(mock.patch.object(lineage, "mediate_lineage_granted_profiled_runtime_create",
            side_effect=AssertionError("Pi cannot fall back to legacy mediation")))
        grants.initialize_runtime_capability_grant(self.grant_config, now_unix=100, deadline_monotonic=1000.5)

    @contextmanager
    def hold_lineage(self, *args, **kwargs):
        self.holding = True
        try:
            yield copy.deepcopy(self.live_lineage)
        finally:
            self.holding = False

    def begin(self):
        if self.used:
            raise RuntimeError("context consumed")
        self.used = True
        self.in_begin = True
        try:
            self.guard()
        finally:
            self.in_begin = False

    def guard(self):
        self.guard_count += 1
        state = self.fixture.load_state()
        self.guard_events.append((self.guard_count, state["effect_journal"], len(state["consumed"])))
        if not self.in_begin:
            self.assertTrue(self.holding)
            descriptor = os.open(self.fixture.lock_path, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(descriptor)
        if self.guard_hook:
            self.guard_hook(self.guard_count)
        if self.guard_count == self.guard_fail_at:
            raise RuntimeError("root authority withdrawn")

    def mediate(self, **options):
        return pi.mediate_pi_runtime_create(self.value, self.config,
            **{"authority": self.authority, "deadline_monotonic": 1000.5, **options})

    def grant_state(self):
        return json.loads(self.grant_config.grant_state_path.read_bytes())

    def absent(self):
        self.assertFalse(self.fixture.target.exists())
        self.legacy.assert_not_called()

    def pending_uncertainty(self):
        self.assertEqual(self.grant_state()["status"], "CLAIMED")
        self.assertTrue(self.grant_config.broker.profile_pending_path.exists())
        self.assertEqual(self.fixture.load_state()["effect_journal"]["status"], "PENDING")

    def frozen_reader_limits(self, result):
        binding = worker.RuntimeActionWorkerBinding(self.grant["runtime_digest"], self.grant["active_skill_digest"],
                                                    self.grant["policy_digest"], self.grant["policy_version"])
        self.assertEqual(worker._broker_result(result, self.envelope, binding), result)
        original = self.grant_state()
        observed = grants.initialize_runtime_capability_grant(self.grant_config, now_unix=100,
                                                               deadline_monotonic=1000.5)
        self.assertEqual(observed, original)  # Generic terminal readback accepts.
        names = {entry.name for entry in self.fixture.control.iterdir()}
        with self.assertRaisesRegex(broker.RuntimeActionBrokerError, "result is unbound"):
            grants.recover_runtime_capability_grant(self.grant_config)
        replacement = replace(self.grant_config, capability_grant=canonical_json({**self.grant, "grant_id": "4" * 64}))
        with self.assertRaisesRegex(broker.RuntimeActionBrokerError, "result is unbound"):
            grants.initialize_runtime_capability_grant(replacement, now_unix=100, deadline_monotonic=1000.5)
        self.assertEqual(self.grant_state(), original)
        self.assertEqual({entry.name for entry in self.fixture.control.iterdir()}, names)

    def test_authorized_tempfile_uses_real_grant_receipt_journal_and_serialized_guards(self):
        result = self.mediate()
        self.assertEqual((result["verdict"], result["effect_status"]), ("ALLOW", "CREATED"))
        self.assertEqual(self.fixture.target.read_bytes(), self.fixture.payload)
        self.assertEqual(self.grant_state()["status"], "CONSUMED")
        receipt = json.loads(self.grant_config.broker.profile_receipt_path.read_bytes())
        self.assertEqual(receipt["broker_result_digest"], canonical_digest(result))
        self.assertFalse(self.grant_config.broker.profile_pending_path.exists())
        self.assertIsNone(self.fixture.load_state()["effect_journal"])
        self.assertEqual([row[0] for row in self.guard_events], [1, 2, 3, 4])
        self.assertEqual(self.guard_events[-1][1]["status"], "PENDING")
        self.assertFalse(self.holding)
        self.local_live.assert_called_once()
        self.legacy.assert_not_called()

    def test_plain_json_or_callback_cannot_replace_authority(self):
        for value in (None, {}, lambda: True, mock.Mock(spec=handoff.PiRequestAuthority)):
            with self.subTest(value=type(value)), self.assertRaises(broker.RuntimeActionBrokerError):
                self.mediate(authority=value)
        self.begin_mock.assert_not_called()
        self.assertEqual(self.grant_state()["status"], "AVAILABLE")
        self.absent()

    def test_shortened_or_extended_or_nonfinite_deadline_refuses_before_begin(self):
        for value in (1000.4, 1000.6, 999, True, float("nan"), float("inf")):
            with self.subTest(deadline=value), self.assertRaises(broker.RuntimeActionBrokerError):
                self.mediate(deadline_monotonic=value)
        self.begin_mock.assert_not_called()
        self.absent()

    def test_used_context_cannot_start_second_mediation(self):
        self.mediate()
        with self.assertRaises(broker.RuntimeActionBrokerError):
            self.mediate()
        self.assertEqual(self.guard_count, 4)
        self.assertEqual(self.grant_state()["status"], "CONSUMED")

    def test_fresh_context_cannot_redeem_consumed_grant(self):
        self.mediate()
        self.used = False  # Independent mocked authentication, same durable grant.
        with self.assertRaises(broker.RuntimeActionBrokerError):
            self.mediate()
        self.assertEqual(self.grant_state()["status"], "CONSUMED")

    def test_root_withdrawal_at_begin_never_claims(self):
        self.guard_fail_at = 1
        with self.assertRaises(broker.RuntimeActionBrokerError):
            self.mediate()
        self.assertEqual(self.grant_state()["status"], "AVAILABLE")
        self.absent()

    def test_root_withdrawal_inside_claim_lock_never_claims(self):
        self.guard_fail_at = 2
        with self.assertRaises(broker.RuntimeActionBrokerError):
            self.mediate()
        self.assertEqual(self.grant_state()["status"], "AVAILABLE")
        self.absent()

    def test_root_withdrawal_before_journal_blocks_and_consumes_without_effect(self):
        self.guard_fail_at = 3
        result = self.mediate()
        self.assertEqual(result["reason_codes"], ["BROKER_PI_REQUEST_REFUSED"])
        self.assertEqual(result["effect_status"], "NOT_PERFORMED")
        self.assertEqual(result["decision"]["verdict"], "ALLOW")
        self.assertEqual(result["decision"]["reason_codes"], [])
        self.assertEqual(self.grant_state()["status"], "CONSUMED")
        self.assertIsNone(self.fixture.load_state()["effect_journal"])
        self.frozen_reader_limits(result)
        self.absent()

    def test_root_withdrawal_after_pending_retains_uncertain_records(self):
        self.guard_fail_at = 4
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.mediate()
        self.pending_uncertainty()
        self.assertTrue(list(self.fixture.staging.iterdir()))
        self.absent()

    def test_expiry_during_final_root_exchange_prevents_link(self):
        self.guard_hook = lambda number: setattr(self.mono, "return_value", 1001.0) if number == 4 else None
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.mediate()
        self.pending_uncertainty()
        self.absent()

    def test_wall_clock_expiry_during_final_root_exchange_prevents_link(self):
        self.guard_hook = lambda number: setattr(self.wall, "return_value", 104.0) if number == 4 else None
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.mediate()
        self.pending_uncertainty()
        self.absent()

    def test_pidfd_death_during_final_snapshot_reads_prevents_link(self):
        self.local_live.side_effect = RuntimeError("worker PIDFD exited during snapshot reads")
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.mediate()
        self.pending_uncertainty()
        self.absent()

    def test_wall_clock_rollback_after_pending_prevents_link(self):
        self.guard_hook = lambda number: setattr(self.wall, "return_value", 99.0) if number == 4 else None
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.mediate()
        self.pending_uncertainty()
        self.absent()

    def test_health_change_during_final_root_exchange_prevents_link(self):
        def change(number):
            if number == 4:
                health = {**self.fixture.health, "status": "unhealthy"}
                _write_control(self.fixture.paths["health"], health)
        self.guard_hook = change
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.mediate()
        self.pending_uncertainty()
        self.absent()

    def test_receipt_retains_final_valid_health_epoch_not_earlier_snapshot(self):
        self.guard_hook = lambda number: _write_control(self.fixture.paths["health"],
            {**self.fixture.health, "epoch": 5}) if number == 4 else None
        result = self.mediate()
        self.assertEqual(result["effect_status"], "CREATED")
        self.assertEqual(result["decision"]["mediator_health_epoch"], 5)
        receipt = json.loads(self.grant_config.broker.profile_receipt_path.read_bytes())
        self.assertEqual(receipt["broker_result"], result)

    def test_revocation_change_during_final_root_exchange_prevents_link(self):
        def change(number):
            if number == 4:
                record = {**self.fixture.revocations, "generation": 4,
                          "skill_digests": [self.activation["active_skill_digest"]]}
                _write_control(self.fixture.paths["revocations"], record)
        self.guard_hook = change
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.mediate()
        self.pending_uncertainty()
        self.absent()

    def test_policy_change_during_final_root_exchange_prevents_link(self):
        self.guard_hook = lambda number: _write_control(self.fixture.paths["policy"],
            {**self.fixture.policy, "version": 2, "allow": []}) if number == 4 else None
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.mediate()
        self.pending_uncertainty()
        self.absent()

    def test_changed_grant_claim_after_pending_prevents_link(self):
        def change(number):
            if number == 4:
                state = self.grant_state()
                state["claim"]["profile_claim"]["claimed_at_unix"] = 99
                _write_control(self.grant_config.grant_state_path, state)
        self.guard_hook = change
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.mediate()
        self.assertTrue(self.grant_config.broker.profile_pending_path.exists())
        self.absent()

    def test_activation_sensor_identity_fields_must_all_match(self):
        mutations = {"pid": 9999, "uid": 9999, "gid": 9999, "start_time_ticks": 9999,
            "mount_namespace": {"device": 9, "inode": 9}, "cgroup": "/different.service",
            "profile_digest": "sha256:" + "9" * 64, "runtime_digest": "sha256:" + "9" * 64,
            "executable_digest": "sha256:" + "9" * 64, "active_skill_digest": "sha256:" + "9" * 64}
        original = copy.deepcopy(self.activation)
        for field, value in mutations.items():
            self.activation = {**copy.deepcopy(original), field: value}
            self.used = False
            with self.subTest(field=field), self.assertRaises(broker.RuntimeActionBrokerError):
                self.mediate()
            self.assertEqual(self.grant_state()["status"], "AVAILABLE")
        self.absent()

    def test_source_manifest_or_install_context_mismatch_never_claims(self):
        for field in ("source_manifest_digest", "install_context_digest"):
            previous = self.activation[field]
            self.activation[field] = "sha256:" + "9" * 64
            self.used = False
            with self.subTest(field=field), self.assertRaises(broker.RuntimeActionBrokerError):
                self.mediate()
            self.activation[field] = previous
        self.assertEqual(self.grant_state()["status"], "AVAILABLE")
        self.absent()

    def test_worker_request_payload_target_and_correlation_are_exact(self):
        original = copy.deepcopy(self.worker_request)
        for field, value in (("target_name", "other.txt"), ("payload_base64", "eA=="),
                             ("session_id", "b" * 32), ("run_id", "b" * 32),
                             ("tool_call_digest", "sha256:" + "9" * 64)):
            self.worker_request = {**original, field: value}
            self.used = False
            with self.subTest(field=field), self.assertRaises(broker.RuntimeActionBrokerError):
                self.mediate()
        self.assertEqual(self.grant_state()["status"], "AVAILABLE")
        self.absent()

    def test_worker_policy_mismatch_never_claims(self):
        self.activation["policy_digest"] = "sha256:" + "9" * 64
        with self.assertRaises(broker.RuntimeActionBrokerError):
            self.mediate()
        self.assertEqual(self.grant_state()["status"], "AVAILABLE")
        self.absent()

    def test_lineage_snapshot_or_launch_lineage_mismatch_never_claims(self):
        for field in ("active_record_digest", "context_digest", "manifest_digest", "tree_digest"):
            original = self.live_lineage[field]
            self.live_lineage[field] = "sha256:" + "9" * 64
            self.value["lineage"] = copy.deepcopy(self.live_lineage)
            self.used = False
            with self.subTest(field=field), self.assertRaises(broker.RuntimeActionBrokerError):
                self.mediate()
            self.live_lineage[field] = original
        self.absent()

    def test_changed_supplied_lineage_refuses_before_claim(self):
        self.value["lineage"]["tree_digest"] = "sha256:" + "9" * 64
        with self.assertRaises(broker.RuntimeActionBrokerError):
            self.mediate()
        self.assertEqual(self.grant_state()["status"], "AVAILABLE")
        self.absent()

    def test_legacy_unwrapped_issuance_cannot_enter_pi_mediator(self):
        self.value = self.issuance
        with self.assertRaises(broker.RuntimeActionBrokerError):
            self.mediate()
        self.assertEqual(self.grant_state()["status"], "AVAILABLE")
        self.absent()

    def test_replay_ledger_remains_effect_authoritative(self):
        state = self.fixture.load_state()
        state["consumed"] = [{"request_digest": canonical_digest(self.envelope["request"]),
                              "observation_digest": "sha256:" + "9" * 64, "expires_at_unix": 103}]
        _write_control(self.fixture.paths["state"], state)
        result = self.mediate()
        self.assertEqual(result["reason_codes"], ["BROKER_REPLAY_BLOCKED"])
        self.assertIsNone(result["decision"])
        self.assertEqual(self.grant_state()["status"], "CONSUMED")
        self.frozen_reader_limits(result)
        self.absent()

    def test_effective_block_validator_rejects_unknown_or_forged_policy_reasons(self):
        self.guard_fail_at = 3
        self.mediate()
        claim = self.grant_state()["claim"]["profile_claim"]
        receipt = json.loads(self.grant_config.broker.profile_receipt_path.read_bytes())
        for mutation in ("unknown", "mixed", "policy", "absent"):
            changed = copy.deepcopy(receipt)
            result = changed["broker_result"]
            if mutation == "unknown":
                result["reason_codes"] = ["BROKER_FAKE_REASON"]
            elif mutation == "mixed":
                result["reason_codes"] += ["BROKER_DEADLINE_EXPIRED"]
            elif mutation == "policy":
                result["decision"].update(verdict="BLOCK", reason_codes=["BROKER_PI_REQUEST_REFUSED"])
            else:
                result["decision"] = None
            changed["broker_result_digest"] = canonical_digest(result)
            with self.subTest(mutation=mutation), self.assertRaises(broker.RuntimeActionBrokerError):
                pi._effective_profile_result(claim, changed)

    def test_effective_block_receipt_and_claim_joins_remain_exact(self):
        self.guard_fail_at = 3
        self.mediate()
        claim = self.grant_state()["claim"]["profile_claim"]
        receipt = json.loads(self.grant_config.broker.profile_receipt_path.read_bytes())
        for field in ("submission_digest", "runtime_attribution_digest", "broker_result_digest"):
            with self.subTest(field=field), self.assertRaises(broker.RuntimeActionBrokerError):
                pi._effective_profile_result(claim, {**receipt, field: "sha256:" + "9" * 64})
        changed = copy.deepcopy(receipt)
        changed["runtime_attribution"]["pid"] += 1
        with self.assertRaises(broker.RuntimeActionBrokerError):
            pi._effective_profile_result(claim, changed)

    def test_known_prejournal_failure_abandons_exact_claim_without_reset(self):
        with mock.patch.object(broker, "_open_broker_roots", side_effect=broker.RuntimeActionBrokerError("roots refused")):
            with self.assertRaises(broker.RuntimeActionBrokerError):
                self.mediate()
        self.assertEqual(self.grant_state()["status"], "ABANDONED")
        self.assertFalse(self.grant_config.broker.profile_pending_path.exists())
        self.absent()

    def test_profile_pending_write_uncertainty_retains_claim(self):
        with mock.patch.object(profile, "_create_profile_pending", side_effect=OSError("fsync uncertain")):
            with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
                self.mediate()
        self.assertEqual(self.grant_state()["status"], "CLAIMED")
        self.absent()

    def test_claim_publication_failure_preserves_durable_claim_and_no_effect(self):
        publish = grants._publish_state
        def uncertain(control, config, state):
            publish(control, config, state)
            if state["status"] == "CLAIMED":
                raise OSError("claim fsync uncertain")
        with mock.patch.object(grants, "_publish_state", side_effect=uncertain):
            with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
                self.mediate()
        self.assertEqual(self.grant_state()["status"], "CLAIMED")
        self.absent()

    def test_pre_effect_pending_cleanup_failure_is_not_plain_refusal(self):
        with mock.patch.object(broker, "_open_broker_roots", side_effect=broker.RuntimeActionBrokerError("roots refused")), \
             mock.patch.object(profile, "_discard_profile_pending", side_effect=OSError("pending cleanup uncertain")):
            with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
                self.mediate()
        self.assertEqual(self.grant_state()["status"], "CLAIMED")
        self.assertTrue(self.grant_config.broker.profile_pending_path.exists())
        self.absent()

    def test_pending_journal_fsync_uncertainty_retains_all_state(self):
        commit = broker._commit_state
        def uncertain(control, config, state):
            commit(control, config, state)
            if state["effect_journal"] and state["effect_journal"]["status"] == "PENDING":
                raise OSError("fsync uncertain")
        with mock.patch.object(broker, "_commit_state", side_effect=uncertain):
            with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
                self.mediate()
        self.pending_uncertainty()
        self.absent()

    def test_link_attempt_failure_is_indeterminate_and_never_retried(self):
        actual_link = broker.os.link
        with mock.patch.object(broker.os, "link", side_effect=OSError("link uncertain")) as link:
            # Preserve capability membership: production checks contain the real
            # built-in; only test-local mocked link gets equivalent support sets.
            with mock.patch.object(broker.os, "supports_dir_fd", os.supports_dir_fd | {link}), \
                 mock.patch.object(broker.os, "supports_follow_symlinks", os.supports_follow_symlinks | {link}):
                with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
                    self.mediate()
            link.assert_called_once()
        self.assertIs(broker.os.link, actual_link)
        self.pending_uncertainty()
        self.absent()

    def test_result_receipt_failure_never_resets_created_effect_grant(self):
        with mock.patch.object(profile, "_persist_profile_receipt", side_effect=OSError("receipt uncertain")):
            with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
                self.mediate()
        self.assertTrue(self.fixture.target.exists())
        self.assertEqual(self.grant_state()["status"], "CLAIMED")
        self.assertTrue(self.grant_config.broker.profile_pending_path.exists())

    def test_lineage_cleanup_cannot_downgrade_indeterminate_journal(self):
        @contextmanager
        def bad_cleanup(*args, **kwargs):
            self.holding = True
            try:
                yield copy.deepcopy(self.live_lineage)
            finally:
                self.holding = False
                raise lineage.RuntimeActionObservationPublisherError("lineage cleanup failed")
        self.guard_fail_at = 4
        with mock.patch.object(lineage, "hold_runtime_active_skill_lineage", side_effect=bad_cleanup):
            with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
                self.mediate()
        self.pending_uncertainty()
        self.absent()


if __name__ == "__main__":
    unittest.main()
