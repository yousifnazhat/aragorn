"""New native action retention checks with inert filesystem/process owners.

Existing request/grant/receipt codecs run unchanged. No services, effects,
networking, acquisition, source observer or qualification capture is performed.
"""

import base64
from contextlib import ExitStack, contextmanager
import copy
import hashlib
import json
import linecache
import os
from pathlib import Path
import socket
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_action_evidence as subject
from aragorn import pi_core_native_request as native
from aragorn import pi_core_native_provider as provider
from aragorn import pi_core_service_channels as channels
from aragorn import runtime_action_worker as worker
from aragorn import runtime_capability_grant as capabilities
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_runtime_capability_grant as fixtures


def metadata(inode, mode, uid=2201, gid=2202, size=0):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=gid,
        st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)


class InertStore:
    def __init__(self, events, activation):
        self.events, self.activation = events, activation
        self.references, self.values = [], []
        self.failure_kind = None
        self.closed, self.uncertain = False, False

    def retain(self, kind, value):
        self.events.append(("retain", kind))
        if kind == self.failure_kind:
            self.uncertain = True
            raise OSError("inert retention failure")
        detached = copy.deepcopy(value)
        self.values.append((kind, detached))
        reference = {"kind": kind, "digest": canonical_digest(detached), "bytes": len(canonical_json(detached))}
        self.references.append(reference)
        return copy.deepcopy(reference)

    @property
    def observation(self):
        return {"schema": subject.storage.ACTION_SCHEMA, "authority": subject.storage.AUTHORITY,
            "status": "CLEANUP_HOLD" if self.uncertain else "CLOSED" if self.closed else "OPEN",
            "activation_digest": canonical_digest(self.activation), "references": copy.deepcopy(self.references),
            "pending_reference": None, "index_digest": "sha256:" + "9" * 64,
            "index_bytes": 100, "index_status": "DURABLE_PREFIX", "owned_handles_closed": self.closed and not self.uncertain,
            "uncertainty": [], "phase3_eligible": False}


class NativeActionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(linecache, "getlines", return_value=[]))
        self.stack.enter_context(mock.patch.object(linecache, "checkcache", return_value=None))
        self.events, self.closed_fds = [], []
        self.locked, self.lock_failure, self.unlock_failure = False, None, None
        self.close_failure = self.store_close_failure = self.read_failure = self.open_failure = None
        self.named_root_changed = self.named_lock_changed = False
        self.after_read = lambda name: None
        self.grant, submission = fixtures._grant(), fixtures._submission()
        operation = canonical_digest({"schema": "aragorn/runtime-file-operation/v1", "operation": "create"})
        self.grant["operation_digest"] = operation
        request = submission["envelope"]["request"]
        request.update(session_id="a" * 32, run_id="a" * 32, tool_call_id="sha256:" + "c" * 64,
            operation_digest=operation, payload_digest="sha256:" + hashlib.sha256(b"payload").hexdigest())
        for name in ("session_id", "run_id", "tool_call_id", "operation_digest", "payload_digest"):
            submission["measured_action"][name] = request[name]
        submission["request_digest"] = canonical_digest(request)
        submission["envelope_digest"] = canonical_digest(submission["envelope"])
        with mock.patch.object(capabilities.secrets, "token_hex", return_value="d" * 64):
            issued = capabilities.issue_profiled_runtime_capability(submission, canonical_json(self.grant), 102)
        self.claim = subject.grants._build_claim(self.grant, issued["lease"], submission,
            submission["runtime_attribution"], canonical_digest(submission), 102)
        self.envelope = submission["envelope"]
        attribution = submission["runtime_attribution"]
        self.activation = {"schema": subject.identity.ACTIVATION_SCHEMA, "authority": subject.identity.ACTIVATION_AUTHORITY,
            "activation_id": "a" * 32, "session_id": "a" * 32, "run_id": "a" * 32,
            **{key: copy.deepcopy(attribution[key]) for key in (
                "pid", "uid", "gid", "start_time_ticks", "mount_namespace", "cgroup", "profile_digest",
                "runtime_digest", "executable_digest", "active_skill_digest")},
            "source_manifest_digest": self.grant["source_manifest_digest"],
            "install_context_digest": self.grant["install_context_digest"],
            "policy_digest": self.grant["policy_digest"], "tree_digest": "sha256:" + "d" * 64,
            "active_record_digest": "sha256:" + "e" * 64, "deployment_digest": "sha256:" + "f" * 64,
            "boot_id": "11111111-2222-3333-4444-555555555555", "expires_at_monotonic_ns": 1001_000_000_000}
        self.request = {"schema": "aragorn/runtime-action-worker-request/v1",
            "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY", "session_id": "a" * 32,
            "run_id": "a" * 32, "tool_call_digest": request["tool_call_id"], "target_name": "result.txt",
            "payload_base64": "cGF5bG9hZA=="}
        self.binding = worker.RuntimeActionWorkerBinding(self.grant["runtime_digest"], self.grant["active_skill_digest"],
            self.grant["policy_digest"], self.grant["policy_version"])
        self.configs = {"action": {"identities": {"action": {"uid": 2201, "gid": 2202}},
                                    "capability_grant": copy.deepcopy(self.grant)}}
        self.services = object.__new__(channels.PiServiceChannels)
        self.life = object.__new__(subject.lifecycle.PiServiceLifecycle)
        self.life.configuration = SimpleNamespace(configurations=self.configs)
        self.life._active, self.life._closed, self.life._channels = True, False, self.services
        self.services._lifecycle = self.life
        self.services._provider_retired, self.services._requests_retired = True, False
        self.request_channels = native.PiNativeRequestChannels(None, None, (8001, 2201, 2202),
            (8002, 2301, 2302), self.binding, self.services)
        self.services._request_channels = self.request_channels
        self.custody = object.__new__(native.PiNativeRequestCustody)
        self.custody._channels, self.custody._deadline = self.request_channels, 1000.5
        self.custody._activation = copy.deepcopy(self.activation)
        self.custody._dispatch, self.custody._owned = SimpleNamespace(grant=self.grant), SimpleNamespace()
        root = Path("/var/lib/aragorn/provider-control")
        self.config = subject.broker.RuntimeActionBrokerConfig(root / "broker.sock", root / "instance.lock",
            root / "broker.lock", root, Path("/var/lib/aragorn/output"), Path("/var/lib/aragorn/staging"),
            *(root / (name + ".json") for name in ("policy", "revocations", "health", "observation", "state")),
            0, 2301, 2302, self.grant["runtime_digest"], 12, 13)
        self.provider = object.__new__(provider.PiNativeProviderDispatch)
        self.provider.channels = provider.PiNativeProviderChannels(self.config, self.services)
        self.provider.grant = copy.deepcopy(self.grant)
        self.files = {"state.json": canonical_json({"schema": "aragorn/runtime-action-broker-state/v2",
            "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY", "minimum_revocation_generation": 1,
            "minimum_mediator_health_epoch": 1, "consumed": [], "effect_journal": None})}
        self.file_metadata = {}
        self.root_metadata = metadata(92, stat.S_IFDIR | 0o710)
        self.lock_metadata = metadata(93, stat.S_IFREG | 0o600)
        self.set_receipt("created")
        self.store = InertStore(self.events, self.activation)
        self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(os, "getegid", return_value=0))
        self.guard = self.stack.enter_context(mock.patch.object(native.PiNativeRequestCustody, "guard",
            side_effect=lambda: self.events.append("guard")))
        self.completed = self.stack.enter_context(mock.patch.object(provider.PiNativeProviderDispatch, "require_completed",
            side_effect=lambda **kwargs: self.events.append(("provider-completed", kwargs["deadline"]))))
        self.stack.enter_context(mock.patch.object(native, "_provider_dispatch", return_value=self.provider))
        self.deadline = self.stack.enter_context(mock.patch.object(subject.channel, "validate_deadline",
            side_effect=lambda value: self.assertEqual(value, 1000.5)))
        self.open_root = self.stack.enter_context(mock.patch.object(subject.broker, "_open_protected_directory",
            side_effect=self.open_control))
        self.stack.enter_context(mock.patch.object(subject.storage, "hold_action_evidence", side_effect=self.hold_store))
        self.read = self.stack.enter_context(mock.patch.object(subject.lifecycle, "_read_at", side_effect=self.read_at))
        self.stack.enter_context(mock.patch.object(os, "open", side_effect=self.open_at))
        self.stack.enter_context(mock.patch.object(os, "close", side_effect=self.close))
        self.stack.enter_context(mock.patch.object(os, "fstat", side_effect=self.fstat))
        self.stack.enter_context(mock.patch.object(os, "stat", side_effect=self.stat))
        self.stack.enter_context(mock.patch.object(os, "lstat", side_effect=self.lstat))
        self.flock = self.stack.enter_context(mock.patch.object(subject.fcntl, "flock", side_effect=self.lock))
        for component, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                                (subprocess, "Popen"), (subprocess, "run"), (os, "system"),
                                (os, "mkdir"), (os, "unlink"), (os, "write"), (os, "rename"), (os, "link")):
            self.stack.enter_context(mock.patch.object(component, name, side_effect=AssertionError("live/mutation forbidden")))
        for name in ("initialize_pi_runtime_capability_grant", "recover_pi_runtime_capability_grant"):
            self.stack.enter_context(mock.patch.object(subject.recovery, name, side_effect=AssertionError("no recovery")))

    def set_receipt(self, kind):
        claim = self.claim["profile_claim"]
        decision = {"schema": "aragorn/runtime-action-decision/v1",
            "authority": "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
            "request_digest": claim["request_digest"], "verdict": "ALLOW", "reason_codes": [],
            "policy_digest": self.grant["policy_digest"], "policy_version": self.grant["policy_version"],
            "active_context_digest": "sha256:" + "1" * 64, "measured_action_digest": "sha256:" + "2" * 64,
            "revocation_snapshot_digest": "sha256:" + "3" * 64, "mediator_health_digest": "sha256:" + "4" * 64,
            "evaluated_at_unix": 102, "revocation_generation": 1, "minimum_revocation_generation": 1,
            "mediator_health_epoch": 1, "minimum_mediator_health_epoch": 1}
        result = {"schema": "aragorn/runtime-action-broker-result/v1",
            "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "request_digest": claim["request_digest"], "observation_digest": "sha256:" + "d" * 64,
            "decision": decision, "verdict": "ALLOW", "reason_codes": [], "effect_status": "CREATED",
            "target_name": claim["target_name"]}
        if kind == "effective":
            result.update(verdict="BLOCK", reason_codes=["BROKER_PI_REQUEST_REFUSED"], effect_status="NOT_PERFORMED")
        if kind == "replay":
            result.update(verdict="BLOCK", decision=None, reason_codes=["BROKER_REPLAY_BLOCKED"], effect_status="NOT_PERFORMED")
        receipt = {"schema": "aragorn/runtime-process-profile-receipt/v1",
            "authority": "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
            "submission_digest": claim["submission_digest"], "runtime_attribution": claim["profile_pending"]["runtime_attribution"],
            "runtime_attribution_digest": claim["runtime_attribution_digest"], "broker_result": result,
            "broker_result_digest": canonical_digest(result)}
        state = {"schema": "aragorn/runtime-capability-grant-state/v1",
            "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": canonical_digest(self.grant), "status": "CONSUMED", "claim": copy.deepcopy(self.claim),
            "result": subject.recovery._result_record(self.claim, receipt)}
        self.files.update({"profile-receipt.json": canonical_json(receipt), "capability-grant-state.json": canonical_json(state)})
        self.result = worker._worker_result(canonical_digest(self.request), "COMPLETED", result)
        fields = {"nonce": "1" * 32, "activation_digest": canonical_digest(self.activation),
            "request_digest": canonical_digest(self.request), "deadline_ns": 1000_500_000_000}
        self.done = subject.handoff._packet("DONE", **fields, envelope=self.envelope, result=self.result, terminal_ack=True)
        self.sensor_done = subject.sensor._packet("DONE", nonce="2" * 32, request_digest=fields["request_digest"],
            deadline_ns=fields["deadline_ns"], broker_result_digest=canonical_digest(result), terminal_ack=True)
        self.context = {"schema": "aragorn/pi-core-action-context/v1", "request": self.request,
            "activation": self.activation, "measurement": {}, "lineage": {}, "grant": self.grant,
            "challenge": subject.handoff._packet("CHALLENGE", nonce=fields["nonce"], terminal_ack=True),
            "offer_intent": subject.handoff._packet("OFFER", **fields, activation=self.activation,
                worker_request=self.request, terminal_ack=True)}

    def open_control(self, path, uid, label):
        self.events.append(("open-root", str(path), uid))
        if self.open_failure is not None:
            raise self.open_failure
        if path == self.config.control_root:
            self.assertEqual(uid, 0)
            return 91
        self.assertEqual((path, uid), (subject.entry.EFFECT_ROOT / "control", 2201))
        return 92

    @contextmanager
    def hold_store(self, config, fd, *, activation, deadline):
        self.assertIs(config, self.config)
        self.assertEqual((fd, activation, deadline), (91, self.activation, 1000.5))
        self.events.append("store-open")
        try:
            yield self.store
        finally:
            self.store.closed = True
            self.events.append("store-close")
            if self.store_close_failure is not None:
                self.store.uncertain = True
                raise self.store_close_failure

    def open_at(self, name, flags, *, dir_fd):
        self.assertEqual((name, dir_fd), ("broker.lock", 92))
        self.assertTrue(flags & os.O_NOFOLLOW)
        return 93

    def close(self, fd):
        self.closed_fds.append(fd)
        self.events.append(("close", fd))
        if fd == self.close_failure:
            raise OSError("inert close uncertain")

    def fstat(self, fd):
        self.assertIn(fd, (92, 93))
        return self.root_metadata if fd == 92 else self.lock_metadata

    def stat(self, name, *, dir_fd, follow_symlinks):
        self.assertEqual((dir_fd, follow_symlinks), (92, False))
        if name == "broker.lock":
            if self.named_lock_changed:
                return metadata(999, stat.S_IFREG | 0o600)
            return self.lock_metadata
        if name not in self.files:
            raise FileNotFoundError(name)
        return self.file_metadata.get(name, metadata(100 + sorted(self.files).index(name),
            stat.S_IFREG | 0o400, size=len(self.files[name])))

    def lstat(self, path):
        self.assertEqual(path, subject.entry.EFFECT_ROOT / "control")
        if self.named_root_changed:
            return metadata(999, stat.S_IFDIR | 0o710)
        return self.root_metadata

    def lock(self, fd, operation):
        self.assertEqual(fd, 93)
        self.events.append(("lock", operation))
        if operation == subject.fcntl.LOCK_UN:
            self.locked = False
            if self.unlock_failure:
                raise self.unlock_failure
        else:
            self.assertEqual(operation, subject.fcntl.LOCK_EX | subject.fcntl.LOCK_NB)
            if self.lock_failure:
                raise self.lock_failure
            self.locked = True

    def read_at(self, fd, name, uid, deadline, *, maximum):
        self.assertEqual((fd, uid, deadline), (92, 2201, 1000.5))
        self.assertTrue(self.locked)
        self.events.append(("read", name))
        if self.read_failure:
            raise self.read_failure
        raw = self.files[name]
        self.assertLessEqual(len(raw), maximum)
        self.after_read(name)
        return raw

    def complete(self, owner):
        owner.retain("REQUEST_CONTEXT", self.context)
        # These B31 tests start at the authenticated terminal packets and exercise the
        # locked broker readback. B77 exercises the real preceding CHECK/CURRENT path.
        with mock.patch.object(owner, "_finish_current_sends"):
            owner.complete(done=self.done, sensor_done=self.sensor_done, result=self.result)

    def run_owner(self):
        with subject.hold_native_action_evidence(self.custody) as owner:
            self.complete(owner)
        return owner.observation

    def test_completed_allow_retains_original_records_and_closes_only_owned_handles(self):
        original = copy.deepcopy(self.files)
        record = self.run_owner()
        self.assertEqual((record["schema"], record["authority"], record["status"]),
                         (subject.SCHEMA, subject.AUTHORITY, "CLOSED"))
        self.assertTrue(record["receipt_join_verified"])
        self.assertTrue(record["owned_handles_closed"])
        self.assertEqual(self.closed_fds, [93, 92, 91])
        self.assertEqual(self.files, original)
        for flag in ("capture_complete", "effect_verified", "timing_verified", "health_verified", "phase3_exit_eligible"):
            self.assertIs(record[flag], False)

    def test_effective_block_keeps_allow_policy_and_original_terminal_receipt(self):
        self.set_receipt("effective")
        record = self.run_owner()
        retained = [value for kind, value in self.store.values if kind == "ACTION_RESULT"][0]
        self.assertEqual(retained["broker_result"]["decision"]["verdict"], "ALLOW")
        self.assertEqual(retained["broker_result"]["verdict"], "BLOCK")
        self.assertTrue(record["receipt_join_verified"])

    def test_exact_replay_block_does_not_invent_a_policy_decision(self):
        self.set_receipt("replay")
        self.assertTrue(self.run_owner()["receipt_join_verified"])
        self.assertIsNone(self.result["broker_result"]["decision"])

    def test_terminal_records_precede_locked_readback_and_store_closes_before_control(self):
        self.run_owner()
        first_read = self.events.index(("read", "state.json"))
        for kind in ("ACTION_DONE", "SENSOR_DONE", "ACTION_RESULT"):
            self.assertLess(self.events.index(("retain", kind)), first_read)
        self.assertLess(self.events.index("store-close"), self.events.index(("close", 91)))

    def test_existing_action_done_pin_avoids_duplicate_retention(self):
        with subject.hold_native_action_evidence(self.custody) as owner:
            owner.retain("ACTION_DONE", self.done)
            self.complete(owner)
        self.assertEqual([kind for kind, _ in self.store.values].count("ACTION_DONE"), 1)

    def test_changed_previously_retained_done_refuses_without_rewrite(self):
        with self.assertRaisesRegex(RuntimeError, "DONE_CHANGED"):
            with subject.hold_native_action_evidence(self.custody) as owner:
                owner.retain("ACTION_DONE", self.done)
                self.done = {**self.done, "nonce": "3" * 32}
                self.complete(owner)
        self.read.assert_not_called()

    def test_completion_is_one_shot(self):
        with self.assertRaisesRegex(RuntimeError, "ALREADY_ATTEMPTED"):
            with subject.hold_native_action_evidence(self.custody) as owner:
                self.complete(owner)
                owner.complete(done=self.done, sensor_done=self.sensor_done, result=self.result)

    def test_unknown_done_stays_retained_but_never_reaches_readback(self):
        self.result = worker._worker_result(canonical_digest(self.request), "INDETERMINATE", None)
        self.done = {**self.done, "result": self.result}
        with self.assertRaises(RuntimeError):
            self.run_owner()
        self.assertIn("ACTION_DONE", [kind for kind, _ in self.store.values])
        self.read.assert_not_called()

    def test_sensor_result_substitution_refuses_before_readback(self):
        self.sensor_done["broker_result_digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(RuntimeError, "TERMINAL_BINDINGS"):
            self.run_owner()
        self.read.assert_not_called()

    def test_missing_request_context_refuses(self):
        with self.assertRaisesRegex(RuntimeError, "REQUEST_CONTEXT"):
            with subject.hold_native_action_evidence(self.custody) as owner:
                owner.complete(done=self.done, sensor_done=self.sensor_done, result=self.result)

    def test_changed_offer_nonce_and_request_projection_refuse(self):
        self.context["offer_intent"]["nonce"] = "3" * 32
        with self.assertRaisesRegex(RuntimeError, "TERMINAL_OFFER"):
            self.run_owner()

    def test_factory_requires_actual_root_and_exact_native_type(self):
        for value in (None, SimpleNamespace(guard=lambda: None)):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                with subject.hold_native_action_evidence(value):
                    self.fail("foreign custody entered")
        with mock.patch.object(os, "geteuid", return_value=2201), self.assertRaises(RuntimeError):
            self.run_owner()
        self.open_root.assert_not_called()

    def test_exact_provider_and_same_captured_service_lease_required(self):
        self.provider.channels = provider.PiNativeProviderChannels(self.config, object())
        with self.assertRaisesRegex(RuntimeError, "COMPLETED_PROVIDER"):
            self.run_owner()
        self.open_root.assert_not_called()

    def test_provider_must_be_completed_and_retired(self):
        self.services._provider_retired = False
        with self.assertRaisesRegex(RuntimeError, "TERMINAL_ROLES"):
            self.run_owner()

    def test_already_retired_action_pair_refuses_new_store(self):
        self.services._requests_retired = True
        with self.assertRaisesRegex(RuntimeError, "TERMINAL_ROLES"):
            self.run_owner()
        self.open_root.assert_not_called()

    def test_action_grant_or_peer_identity_substitution_refuses(self):
        self.provider.grant["grant_id"] = "9" * 64
        with self.assertRaisesRegex(RuntimeError, "ACTION_GRANT_OR_OWNER"):
            self.run_owner()

    def test_changed_held_configuration_after_open_refuses(self):
        with self.assertRaisesRegex(RuntimeError, "HELD_INPUTS_CHANGED"):
            with subject.hold_native_action_evidence(self.custody) as owner:
                self.life.configuration.configurations = {"action": {}}
                owner.retain("CHECK", {})

    def test_root_control_acquisition_failure_has_no_guessed_close(self):
        original = self.open_failure = OSError("acquisition uncertain")
        with self.assertRaises(OSError) as caught:
            self.run_owner()
        self.assertIs(caught.exception, original)
        self.assertEqual(self.closed_fds, [])
        self.assertEqual(original.pi_native_action_evidence_observation["status"], "CLEANUP_HOLD")

    def test_action_root_and_lock_require_exact_owner_group_and_modes(self):
        self.root_metadata.st_gid = 999
        with self.assertRaisesRegex(RuntimeError, "CONTROL_ROOT_OWNER"):
            self.run_owner()
        self.read.assert_not_called()
        self.assertEqual(self.closed_fds, [92, 91])

    def test_lock_alias_metadata_refuses_without_lock_or_read(self):
        self.lock_metadata.st_nlink = 2
        with self.assertRaisesRegex(RuntimeError, "CONTROL_LOCK_UNSAFE"):
            self.run_owner()
        self.flock.assert_not_called()
        self.read.assert_not_called()

    def test_busy_lock_is_attempted_once_and_not_reported_as_cleanup_uncertainty(self):
        self.lock_failure = BlockingIOError("busy")
        with self.assertRaises(BlockingIOError) as caught:
            self.run_owner()
        self.assertEqual(self.flock.call_count, 1)
        record = caught.exception.pi_native_action_evidence_observation
        self.assertEqual(record["status"], "REFUSED")
        self.assertTrue(record["owned_handles_closed"])

    def test_original_raw_bytes_are_retained_before_canonical_parser_failure(self):
        self.files["state.json"] = b'{ "not": "canonical" }'
        with self.assertRaises(RuntimeError) as caught:
            self.run_owner()
        raw = [value for kind, value in self.store.values if kind == "CONTROL_READBACK" and value["phase"] == "FILE_BYTES"]
        self.assertEqual(base64.b64decode(raw[0]["bytes_base64"]), self.files["state.json"])
        self.assertEqual(caught.exception.pi_native_action_evidence_observation["status"], "REFUSED")

    def test_missing_receipt_retains_reached_state_without_invented_terminal_evidence(self):
        del self.files["profile-receipt.json"]
        with self.assertRaises(FileNotFoundError) as caught:
            self.run_owner()
        record = caught.exception.pi_native_action_evidence_observation
        self.assertIsNotNone(record["readback"]["files"]["capability-grant-state.json"]["digest"])
        self.assertFalse(record["receipt_join_verified"])
        self.assertTrue(record["owned_handles_closed"])

    def test_available_grant_is_not_falsely_accepted_as_completed_block(self):
        self.files["capability-grant-state.json"] = canonical_json({"schema": "aragorn/runtime-capability-grant-state/v1",
            "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": canonical_digest(self.grant), "status": "AVAILABLE", "claim": None, "result": None})
        with self.assertRaisesRegex(RuntimeError, "GRANT_NOT_CONSUMED"):
            self.run_owner()

    def test_pending_file_retained_as_presence_not_removed(self):
        self.files["profile-pending.json"] = b"{}"
        with self.assertRaisesRegex(RuntimeError, "PENDING_OR_ARCHIVED") as caught:
            self.run_owner()
        self.assertIs(caught.exception.pi_native_action_evidence_observation["readback"]["absence"]["profile-pending.json"], False)
        self.assertIn("profile-pending.json", self.files)

    def test_current_grant_archive_refuses_without_deletion(self):
        name = subject.grants._archive_name("state", canonical_digest(self.grant))
        self.files[name] = b"{}"
        with self.assertRaisesRegex(RuntimeError, "PENDING_OR_ARCHIVED"):
            self.run_owner()
        self.assertIn(name, self.files)

    def test_receipt_result_substitution_retains_bytes_but_refuses_join(self):
        receipt = json.loads(self.files["profile-receipt.json"])
        receipt["broker_result_digest"] = "sha256:" + "f" * 64
        self.files["profile-receipt.json"] = canonical_json(receipt)
        with self.assertRaises(RuntimeError) as caught:
            self.run_owner()
        self.assertFalse(caught.exception.pi_native_action_evidence_observation["receipt_join_verified"])

    def test_changed_named_root_or_lock_refuses_after_original_readback(self):
        self.named_root_changed = True
        with self.assertRaisesRegex(RuntimeError, "READBACK_CUSTODY_CHANGED"):
            self.run_owner()
        self.assertEqual(self.read.call_count, 3)

    def test_changed_file_group_prevents_unsafe_read(self):
        self.file_metadata["state.json"] = metadata(111, stat.S_IFREG | 0o400, gid=999, size=len(self.files["state.json"]))
        with self.assertRaisesRegex(RuntimeError, "CONTROL_FILE_OWNER"):
            self.run_owner()
        self.read.assert_not_called()

    def test_existing_reader_failure_preserves_original_and_unknown_cleanup(self):
        original = self.read_failure = OSError("reader failed during close")
        with self.assertRaises(OSError) as caught:
            self.run_owner()
        self.assertIs(caught.exception, original)
        record = original.pi_native_action_evidence_observation
        self.assertEqual(record["status"], "CLEANUP_HOLD")
        self.assertIn("READER_CLEANUP_UNCONFIRMED", record["readback"]["cleanup_uncertainty"])

    def test_storage_failure_before_readback_never_closes_borrowed_or_unknown_handles(self):
        self.store.failure_kind = "SENSOR_DONE"
        with self.assertRaises(OSError) as caught:
            self.run_owner()
        self.read.assert_not_called()
        self.assertEqual(self.closed_fds, [91])
        self.assertEqual(caught.exception.pi_native_action_evidence_observation["status"], "CLEANUP_HOLD")

    def test_unlock_failure_preserves_join_but_never_reports_clean_completion(self):
        self.unlock_failure = OSError("unlock uncertain")
        with self.assertRaises(OSError) as caught:
            self.run_owner()
        record = caught.exception.pi_native_action_evidence_observation
        self.assertTrue(record["readback"]["receipt_join_verified"])
        self.assertFalse(record["receipt_join_verified"])
        self.assertFalse(record["owned_handles_closed"])

    def test_readback_close_uncertainty_is_not_retried(self):
        self.close_failure = 93
        with self.assertRaises(RuntimeError) as caught:
            self.run_owner()
        self.assertEqual(self.closed_fds.count(93), 1)
        self.assertEqual(caught.exception.pi_native_action_evidence_observation["status"], "CLEANUP_HOLD")

    def test_root_store_control_close_uncertainty_keeps_retained_join(self):
        self.close_failure = 91
        with self.assertRaises(OSError) as caught:
            self.run_owner()
        record = caught.exception.pi_native_action_evidence_observation
        self.assertTrue(record["receipt_join_verified"])
        self.assertEqual(record["status"], "CLEANUP_HOLD")
        self.assertEqual(self.closed_fds.count(91), 1)

    def test_original_cancellation_survives_secondary_store_close_failure(self):
        original = KeyboardInterrupt("cancel")
        self.store_close_failure = OSError("secondary close")
        with self.assertRaises(KeyboardInterrupt) as caught:
            with subject.hold_native_action_evidence(self.custody) as owner:
                owner.retain("REQUEST_FRAME", {"header_base64": "AAAAAQ=="})
                raise original
        self.assertIs(caught.exception, original)
        self.assertEqual(original.pi_native_action_evidence_observation["status"], "CLEANUP_HOLD")
        self.assertEqual(len(original.pi_native_action_evidence_observation["retained_evidence"]["references"]), 1)

    def test_ordinary_failed_handoff_without_completion_is_refused_not_clean_success(self):
        with subject.hold_native_action_evidence(self.custody) as owner:
            owner.retain("FAILURE", {"phase": "OFFER", "offered": False})
        self.assertEqual(owner.observation["status"], "REFUSED")
        self.assertTrue(owner.observation["owned_handles_closed"])
        self.assertFalse(owner.observation["receipt_join_verified"])

    def test_returned_observation_and_custody_property_are_detached_and_fixed(self):
        with subject.hold_native_action_evidence(self.custody) as owner:
            self.assertIs(owner.custody, self.custody)
            self.complete(owner)
        value = owner.observation
        value["retained_evidence"]["references"].clear()
        self.assertTrue(owner.observation["retained_evidence"]["references"])
        with self.assertRaises(AttributeError):
            owner.custody = None
        with self.assertRaisesRegex(RuntimeError, "SCOPE_INACTIVE"):
            owner.retain("CHECK", {})


def load_tests(loader, _tests, _pattern):
    return loader.loadTestsFromTestCase(NativeActionEvidenceTests)
