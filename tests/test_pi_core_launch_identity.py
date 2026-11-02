"""New Pi launch/peer checks with inert files and mocked native boundaries.

These checks never create a socket, spawn a worker, query Linux proc, or perform
an effect. Kernel observations below are authored fixtures, not live custody or
Phase 3 qualification evidence.
"""

from __future__ import annotations

import base64
import copy
import os
import hashlib
from io import BytesIO
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

from aragorn import pi_core_worker_identity as identity
from aragorn import pi_core_bundle_launch as launch
from aragorn import runtime_active_skill_lineage as lineage_base
from aragorn import runtime_active_skill_lineage_v2 as lineage_v2
from aragorn.acquire import ingest_local
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from aragorn.runtime_action_worker import (
    RuntimeActionWorkerBinding,
    RuntimeActionWorkerConfig,
    _worker_result,
)
from aragorn.runtime_process_profile import runtime_process_profile


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _activation() -> dict:
    return {
        "schema": "aragorn/pi-core-activation/v1",
        "authority": "PROTECTED_LAUNCHER_BINDING_ONLY_NOT_EFFECT_AUTHORITY",
        "activation_id": "a" * 32,
        "session_id": "a" * 32,
        "run_id": "a" * 32,
        "pid": 1234,
        "uid": 1201,
        "gid": 1202,
        "start_time_ticks": 1700,
        "mount_namespace": {"device": 4, "inode": 5},
        "cgroup": "/aragorn/pi-test",
        "profile_digest": _digest("1"),
        "runtime_digest": _digest("2"),
        "executable_digest": _digest("3"),
        "active_skill_digest": _digest("4"),
        "install_context_digest": _digest("5"),
        "source_manifest_digest": _digest("6"),
        "tree_digest": _digest("7"),
        "active_record_digest": _digest("8"),
        "deployment_digest": _digest("9"),
        "policy_digest": _digest("c"),
        "expires_at_monotonic_ns": 2_000_000_000,
        "boot_id": "11111111-2222-3333-4444-555555555555",
    }


def _request(activation: dict) -> dict:
    return {
        "schema": "aragorn/runtime-action-worker-request/v1",
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "target_name": "output.txt",
        "payload_base64": base64.b64encode(b"fixture output").decode("ascii"),
        "session_id": activation["session_id"],
        "run_id": activation["run_id"],
        "tool_call_digest": _digest("b"),
    }


class PiActivationParserTests(unittest.TestCase):
    def test_exact_activation_accepts_and_is_detached(self) -> None:
        value = _activation()
        parsed = identity.validate_activation(value)
        self.assertEqual(parsed, value)
        value["mount_namespace"]["inode"] = 99
        self.assertEqual(parsed["mount_namespace"]["inode"], 5)

    def test_unknown_missing_and_nonobject_fields_refuse(self) -> None:
        for value in (None, [], "binding", {**_activation(), "extra": True}):
            with self.subTest(value=type(value).__name__), self.assertRaises(RuntimeError):
                identity.validate_activation(value)
        for name in _activation():
            value = _activation()
            del value[name]
            with self.subTest(missing=name), self.assertRaises(RuntimeError):
                identity.validate_activation(value)

    def test_schema_and_authority_cannot_grant_effect_authority(self) -> None:
        for name in ("schema", "authority"):
            value = _activation()
            value[name] = "ALLOW"
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                identity.validate_activation(value)

    def test_boolean_negative_and_fractional_kernel_ids_refuse(self) -> None:
        for name in ("pid", "uid", "gid", "start_time_ticks", "expires_at_monotonic_ns"):
            for invalid in (True, False, -1, 0, 1.5, "1"):
                value = _activation()
                value[name] = invalid
                with self.subTest(name=name, invalid=invalid), self.assertRaises(RuntimeError):
                    identity.validate_activation(value)

    def test_every_digest_requires_exact_lowercase_sha256(self) -> None:
        for name in (name for name in _activation() if name.endswith("digest")):
            for invalid in (_digest("a") + "\n", _digest("A"), "sha256:" + "a" * 63):
                value = _activation()
                value[name] = invalid
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    identity.validate_activation(value)

    def test_session_and_run_are_exact_fresh_activation_ids(self) -> None:
        for name in ("session_id", "run_id"):
            value = _activation()
            value[name] = "b" * 32
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                identity.validate_activation(value)
        for invalid in ("a" * 31, "a" * 32 + "\n", "A" * 32, "g" * 32):
            value = _activation()
            value.update(activation_id=invalid, session_id=invalid, run_id=invalid)
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                identity.validate_activation(value)

    def test_mount_namespace_requires_exact_integer_identity(self) -> None:
        for invalid in (
            None, 5, {"device": 4}, {"device": True, "inode": 5},
            {"device": -1, "inode": 5}, {"device": 4, "inode": 0},
            {"device": 4, "inode": 5, "extra": 1},
        ):
            value = _activation()
            value["mount_namespace"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                identity.validate_activation(value)

    def test_noncanonical_cgroup_and_boot_identity_refuse(self) -> None:
        for name, values in {
            "cgroup": ["/", "relative", "/aragorn/../x", "/aragorn//x", "/aragorn/x\n"],
            "boot_id": ["", "11111111-2222-3333-4444-555555555555\n", "not-a-uuid"],
        }.items():
            for invalid in values:
                value = _activation()
                value[name] = invalid
                with self.subTest(name=name, invalid=invalid), self.assertRaises(RuntimeError):
                    identity.validate_activation(value)


class PiActivationReadTests(unittest.TestCase):
    """Real files with test-only root-to-current-owner mapping at I/O edges."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home().resolve(), prefix="aragorn-pi-record-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / (_activation()["activation_id"] + ".json")
        self.path.write_bytes(canonical_json(_activation()))
        self.path.chmod(0o444)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        actual_uid = os.geteuid()
        original_open = identity.broker._open_protected_directory
        original_read = identity.broker._read_owned_bytes_at

        def open_directory(path, expected_uid, label):
            self.assertEqual(expected_uid, 0, "production reader must require root")
            return original_open(path, actual_uid, label)

        def read_file(*args, **kwargs):
            self.assertEqual(kwargs["expected_uid"], 0)
            self.assertEqual(kwargs["exact_mode"], 0o444)
            self.assertEqual(kwargs["max_bytes"], 8192)
            kwargs["expected_uid"] = actual_uid
            return original_read(*args, **kwargs)

        self.stack.enter_context(mock.patch.object(identity.broker, "_open_protected_directory", side_effect=open_directory))
        self.read = self.stack.enter_context(mock.patch.object(identity.broker, "_read_owned_bytes_at", side_effect=read_file))

    def test_canonical_root_required_record_is_read(self) -> None:
        self.assertEqual(identity.read_activation(self.path), _activation())
        self.read.assert_called_once()

    def test_noncanonical_record_refuses(self) -> None:
        self.path.chmod(0o644)
        self.path.write_bytes(canonical_json(_activation()) + b"\n")
        self.path.chmod(0o444)
        with self.assertRaises(identity.PiWorkerIdentityError):
            identity.read_activation(self.path)

    def test_writable_activation_refuses(self) -> None:
        self.path.chmod(0o644)
        with self.assertRaises(identity.PiWorkerIdentityError):
            identity.read_activation(self.path)

    def test_symlink_and_hardlink_activation_refuse(self) -> None:
        source = self.root / "source"
        self.path.rename(source)
        self.path.symlink_to(source)
        with self.assertRaises(identity.PiWorkerIdentityError):
            identity.read_activation(self.path)
        self.path.unlink()
        os.link(source, self.path)
        with self.assertRaises(identity.PiWorkerIdentityError):
            identity.read_activation(self.path)

    def test_filename_must_equal_fresh_activation_id(self) -> None:
        other = self.root / ("b" * 32 + ".json")
        self.path.rename(other)
        with self.assertRaises(identity.PiWorkerIdentityError):
            identity.read_activation(other)

    def test_named_record_replacement_during_read_refuses(self) -> None:
        original_reader = self.read.side_effect

        def replacing_read(*args, **kwargs):
            raw = original_reader(*args, **kwargs)
            replacement = self.root / "replacement"
            replacement.write_bytes(raw)
            replacement.chmod(0o444)
            replacement.replace(self.path)
            return raw

        self.read.side_effect = replacing_read
        with self.assertRaises(identity.PiWorkerIdentityError):
            identity.read_activation(self.path)


class PiWorkerIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.activation = _activation()
        self.profile = runtime_process_profile({
            "schema": "aragorn/runtime-single-skill-process-profile/v1",
            "authority": "ROOT_PROFILE_PIN_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
            "runtime_digest": self.activation["runtime_digest"],
            "executable_digest": self.activation["executable_digest"],
            "cgroup": self.activation["cgroup"],
            "skill_path": "/var/lib/aragorn-protected/skills/pi/SKILL.md",
        })
        self.activation["profile_digest"] = self.profile.digest
        self.config = RuntimeActionWorkerConfig(
            socket_path=Path("/run/aragorn-runtime-action-worker/worker.sock"),
            runtime_directory=Path("/run/aragorn-runtime-action-worker"),
            sensor_socket_path=Path("/run/aragorn-runtime-observation/sensor.sock"),
            protected_root=Path("/var/lib/aragorn-runtime-action"),
            expected_worker_uid=1301, expected_worker_gid=1302,
            expected_gateway_uid=self.activation["uid"],
            expected_gateway_gid=self.activation["gid"],
            expected_sensor_uid=1401, expected_sensor_gid=1402,
            expected_broker_uid=1501,
            binding=RuntimeActionWorkerBinding(
                runtime_digest=self.activation["runtime_digest"],
                active_skill_digest=self.activation["active_skill_digest"],
                policy_digest=_digest("c"), policy_version=1,
            ),
        )
        self.request = _request(self.activation)
        self.result = _worker_result(canonical_digest(self.request), "COMPLETED", {
            "verdict": "ALLOW", "effect_status": "CREATED",
        })
        self.attribution = {
            "schema": "aragorn/runtime-process-profile-attribution/v1",
            "authority": "KERNEL_PROCESS_PROFILE_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
            **{name: copy.deepcopy(self.activation[name]) for name in (
                "profile_digest", "runtime_digest", "executable_digest",
                "active_skill_digest", "cgroup", "pid", "uid", "gid",
                "start_time_ticks", "mount_namespace",
            )},
            "skill_path": str(self.profile.skill_path),
        }
        self.lineage = {
            "version_path": "pi",
            "context_digest": self.activation["install_context_digest"],
            "manifest_digest": self.activation["source_manifest_digest"],
            "tree_digest": self.activation["tree_digest"],
            "active_record_digest": self.activation["active_record_digest"],
            "active_skill_digest": self.activation["active_skill_digest"],
        }
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.events = []
        self.held = False

        @contextmanager
        def hold(*args, **kwargs):
            self.held = True
            self.events.append("hold")
            try:
                yield self.lineage
            finally:
                self.events.append("release")
                self.held = False

        def relay(*args, **kwargs):
            self.assertTrue(self.held, "lineage lock must span dispatch")
            self.assertNotIn("close", self.events)
            self.events.append("relay")
            return self.result

        def close(descriptor):
            self.assertEqual(descriptor, 951)
            self.events.append("close")

        def send(*args, **kwargs):
            self.assertFalse(self.held)
            self.assertIn("close", self.events)
            self.events.append("send")

        def patch(target, **kwargs):
            return self.stack.enter_context(mock.patch(target, **kwargs))

        self.validate_config = patch("aragorn.pi_core_worker_identity.worker._validate_config")
        self.read_activation = patch("aragorn.pi_core_worker_identity.read_activation", side_effect=lambda *a: copy.deepcopy(self.activation))
        self.peer = patch("aragorn.pi_core_worker_identity.broker._peer_credentials", return_value=(1234, 1201, 1202))
        self.pidfd = patch("aragorn.pi_core_worker_identity.process.open_peer_pidfd", return_value=951)
        self.measure = patch("aragorn.pi_core_worker_identity.process.measure_runtime_process_profile", side_effect=lambda *a, **k: copy.deepcopy(self.attribution))
        self.hold = patch("aragorn.pi_core_worker_identity.lineage.hold_runtime_active_skill_lineage", side_effect=hold)
        self.read = patch("aragorn.pi_core_worker_identity.broker._read_frame", side_effect=lambda *a: copy.deepcopy(self.request))
        self.relay = patch("aragorn.pi_core_worker_identity.worker._relay_request", side_effect=relay)
        self.send = patch("aragorn.pi_core_worker_identity.broker._send_frame", side_effect=send)
        self.close = patch("aragorn.pi_core_worker_identity.os.close", side_effect=close)
        self.boot = patch("aragorn.pi_core_worker_identity._boot_id", return_value=self.activation["boot_id"])
        patch("aragorn.pi_core_worker_identity.time.monotonic", return_value=1.0)
        self.monotonic_ns = patch("aragorn.pi_core_worker_identity.time.monotonic_ns", return_value=1_000_000_000)
        # Hard traps: a missing native mock must never turn into a live check.
        patch("socket.socket", side_effect=AssertionError("no live sockets"))
        patch("subprocess.Popen", side_effect=AssertionError("no worker spawning"))

    def handle(self):
        return identity.handle_pi_worker_connection(
            object(), self.config,
            activation_path=Path("/etc/aragorn") / (self.activation["activation_id"] + ".json"),
            profile=self.profile,
            protected_install_root=Path("/var/lib/aragorn-protected/skills"),
        )

    def assert_refused_before_relay(self) -> None:
        with self.assertRaises(identity.PiWorkerIdentityError):
            self.handle()
        self.relay.assert_not_called()
        self.send.assert_not_called()

    def test_valid_peer_dispatches_once_under_pidfd_and_lineage(self) -> None:
        result = self.handle()
        self.assertEqual(result, self.result)
        self.relay.assert_called_once()
        self.assertEqual(self.events, ["hold", "relay", "release", "close", "send"])
        self.assertEqual(self.send.call_args.args[1], canonical_json(self.result))
        self.assertGreaterEqual(self.measure.call_count, 3)

    def test_wrong_peer_pid_uid_or_gid_cannot_dispatch(self) -> None:
        for peer in ((999, 1201, 1202), (1234, 999, 1202), (1234, 1201, 999)):
            with self.subTest(peer=peer):
                self.peer.return_value = peer
                self.assert_refused_before_relay()

    def test_root_peer_cannot_use_unprivileged_activation(self) -> None:
        self.peer.return_value = (1234, 0, 0)
        self.assert_refused_before_relay()

    def test_absent_activation_cannot_open_pidfd_or_dispatch(self) -> None:
        self.read_activation.side_effect = identity.PiWorkerIdentityError("missing activation")
        self.assert_refused_before_relay()
        self.pidfd.assert_not_called()

    def test_exited_or_reused_pidfd_refuses_before_frame(self) -> None:
        self.pidfd.side_effect = RuntimeActionObservationPublisherError("exited")
        self.assert_refused_before_relay()
        self.read.assert_not_called()
        self.close.assert_not_called()

    def test_measured_process_identity_mismatch_refuses(self) -> None:
        for name in ("pid", "uid", "gid", "start_time_ticks", "cgroup", "mount_namespace", "executable_digest", "active_skill_digest"):
            before = copy.deepcopy(self.attribution[name])
            self.attribution[name] = {"device": 4, "inode": 99} if name == "mount_namespace" else "mismatch"
            with self.subTest(name=name):
                self.assert_refused_before_relay()
            self.attribution[name] = before

    def test_changed_profile_binding_refuses(self) -> None:
        self.activation["profile_digest"] = _digest("f")
        self.assert_refused_before_relay()

    def test_changed_policy_binding_refuses(self) -> None:
        self.activation["policy_digest"] = _digest("f")
        self.assert_refused_before_relay()

    def test_old_boot_activation_refuses(self) -> None:
        self.boot.return_value = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        self.assert_refused_before_relay()

    def test_expired_activation_refuses(self) -> None:
        self.monotonic_ns.return_value = self.activation["expires_at_monotonic_ns"]
        self.assert_refused_before_relay()

    def test_changed_active_tree_record_context_or_manifest_refuses(self) -> None:
        for name in ("context_digest", "manifest_digest", "tree_digest", "active_record_digest", "active_skill_digest"):
            before = self.lineage[name]
            self.lineage[name] = _digest("f")
            with self.subTest(name=name):
                self.assert_refused_before_relay()
            self.lineage[name] = before

    def test_quarantined_active_skill_refuses(self) -> None:
        self.hold.side_effect = RuntimeActionObservationPublisherError("quarantined")
        self.assert_refused_before_relay()
        self.read.assert_not_called()

    def test_worker_cannot_choose_another_session_or_run(self) -> None:
        for name in ("session_id", "run_id"):
            before = self.request[name]
            self.request[name] = "other-session"
            with self.subTest(name=name):
                self.assert_refused_before_relay()
            self.request[name] = before

    def test_malformed_request_refuses_before_relay(self) -> None:
        self.request["unexpected"] = "authority"
        self.assert_refused_before_relay()

    def test_identity_loss_before_dispatch_does_not_retry(self) -> None:
        self.measure.side_effect = [self.attribution, RuntimeActionObservationPublisherError("lost")]
        self.assert_refused_before_relay()
        self.close.assert_called_once_with(951)

    def test_activation_replacement_before_dispatch_refuses(self) -> None:
        replacement = {**self.activation, "deployment_digest": _digest("e")}
        self.read_activation.side_effect = [self.activation, replacement]
        self.assert_refused_before_relay()

    def test_identity_loss_after_dispatch_is_indeterminate(self) -> None:
        self.measure.side_effect = [self.attribution, self.attribution, RuntimeActionObservationPublisherError("lost after submit")]
        result = self.handle()
        self.assertEqual(result["status"], "INDETERMINATE")
        self.assertIsNone(result["broker_result"])
        self.assertEqual(result["request_digest"], canonical_digest(self.request))
        self.relay.assert_called_once()
        self.close.assert_called_once_with(951)

    def test_activation_expiry_after_dispatch_is_indeterminate(self) -> None:
        def relay(*args, **kwargs):
            self.monotonic_ns.return_value = self.activation["expires_at_monotonic_ns"]
            return self.result
        self.relay.side_effect = relay
        result = self.handle()
        self.assertEqual(result["status"], "INDETERMINATE")
        self.relay.assert_called_once()

    def test_relay_error_after_possible_submission_is_indeterminate(self) -> None:
        self.relay.side_effect = OSError("uncertain submission")
        result = self.handle()
        self.assertEqual(result["status"], "INDETERMINATE")
        self.assertIsNone(result["broker_result"])
        self.relay.assert_called_once()

    def test_pidfd_cleanup_failure_cannot_report_completed(self) -> None:
        self.close.side_effect = OSError("close failed")
        self.send.side_effect = None
        result = self.handle()
        self.assertEqual(result["status"], "INDETERMINATE")
        self.relay.assert_called_once()
        self.close.assert_called_once_with(951)


class PiBundlePreparationTests(unittest.TestCase):
    """Real temporary CAS/tree; owner mapping and kernel observations are inert.

The current-user owner adaptation is test-only. Production APIs expose no owner
override. The retained admission verifier is exercised with only its existing
decision-receipt dependency mocked; no old TestCase is imported or rerun.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home().resolve(), prefix="aragorn-pi-launch-test-")
        self.addCleanup(self.temporary.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.temporary.name).resolve()
        self.cas = CAS(self.root / "cas")
        self.source = self.root / "source"
        self.source.mkdir()
        self.skill_raw = b"# Admitted Pi capability\nUse only the provided request tool.\n"
        (self.source / "SKILL.md").write_bytes(self.skill_raw)
        (self.source / "references").mkdir()
        (self.source / "references" / "guide.txt").write_bytes(b"Known supporting bytes.\n")
        self.manifest = ingest_local(self.source, self.cas)
        manifest_raw = canonical_json(self.manifest)
        self.manifest_digest = self.cas.put(BytesIO(manifest_raw), max_bytes=len(manifest_raw))
        self.protected = self.root / "protected"
        self.protected.mkdir(mode=0o700)
        state = self.protected.stat()
        self.context = {
            "schema": "aragorn/protected-install-context/v2",
            "authority": "BROKER_CONTEXT_ONLY_NOT_INSTALLER_AUTHORITY",
            "context_id": _digest("1"), "status": "active",
            "expires_at_unix": 120, "operation": "install", "expected_active": None,
            "decision_digest": _digest("2"), "manifest_digest": self.manifest_digest,
            "artifact_graph_digest": _digest("3"), "policy_digest": _digest("c"),
            "analyzer_run_receipt_digests": [_digest("4")],
            "analyzer_verifier_digest": _digest("5"),
            "artifact_graph_verifier_digest": _digest("6"),
            "target_runtime_digest": _digest("7"),
            "runtime_conformance_digest": _digest("8"),
            "destination": {"root_device": state.st_dev, "root_inode": state.st_ino, "target_name": "pi"},
        }
        self.version_path = ".aragorn-versions/pi/" + self.context["context_id"][7:] + "-" + self.manifest_digest[7:]
        self.version = self.protected / self.version_path
        self.version.mkdir(parents=True)
        (self.protected / ".aragorn-versions").chmod(0o755)
        self.version.parent.chmod(0o755)
        (self.version / "references").mkdir()
        for entry in self.manifest["files"]:
            member = self.version / entry["path"]
            member.write_bytes((self.source / entry["path"]).read_bytes())
            member.chmod(0o444)
        (self.version / "references").chmod(0o555)
        self.version.chmod(0o555)
        self.context_digest = canonical_digest(self.context)
        self.transaction = {
            "schema": "aragorn/protected-install-transaction/v1",
            "authority": "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
            "context_digest": self.context_digest, "context_id": self.context["context_id"],
            "operation": "install", "expected_active": None,
            "manifest_digest": self.manifest_digest, "tree_digest": self.manifest["tree_digest"],
            "destination": self.context["destination"], "version_path": self.version_path,
        }
        self.active_record = {
            "schema": lineage_base.ACTIVE_RUNTIME_SCHEMA,
            "authority": lineage_base.ACTIVE_RUNTIME_AUTHORITY,
            "transaction": self.transaction,
        }
        active_path = self.protected / lineage_base.ACTIVE_RUNTIME_RECORD
        active_path.write_bytes(canonical_json(self.active_record))
        active_path.chmod(0o444)
        (self.protected / "pi").symlink_to(self.version_path)
        self.profile = runtime_process_profile({
            "schema": "aragorn/runtime-single-skill-process-profile/v1",
            "authority": "ROOT_PROFILE_PIN_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
            "runtime_digest": self.context["target_runtime_digest"],
            "executable_digest": _digest("9"), "cgroup": "/aragorn/pi-fixture",
            "skill_path": str(self.version / "SKILL.md"),
        })
        self.grant = {
            "active_skill_digest": "sha256:" + hashlib.sha256(self.skill_raw).hexdigest(),
            "install_context_digest": self.context_digest,
            "source_manifest_digest": self.manifest_digest,
        }
        self.deployment = {name: _digest("d") for name in (
            "runtime_commit_or_image", "adapter", "configuration", "worker",
            "os_profile", "policy", "aragorn_version",
        )}
        self.deployment["runtime_commit_or_image"] = self.profile.runtime_digest
        self.deployment["policy"] = self.context["policy_digest"]
        self.activation_directory = self.root / "activations"
        self.activation_directory.mkdir(mode=0o700)
        self.now = 100
        self.revoked = ()

        def patch(target, **kwargs):
            return self.stack.enter_context(mock.patch(target, **kwargs))

        original_open = lineage_base._open_protected_root
        original_directory = lineage_base._open_directory_at
        original_read = launch._read_owned_bytes_at
        original_hold = lineage_v2.hold_runtime_active_skill_lineage
        self.original_hold = original_hold
        actual_uid = os.geteuid()
        patch("aragorn.pi_core_bundle_launch._root")
        patch("aragorn.runtime_active_skill_lineage._open_protected_root",
              side_effect=lambda path, uid: original_open(path, actual_uid))
        patch("aragorn.runtime_active_skill_lineage._open_directory_at",
              side_effect=lambda fd, name, uid, mode, label: original_directory(fd, name, actual_uid, mode, label))

        def read_member(*args, **kwargs):
            kwargs["expected_uid"] = actual_uid
            return original_read(*args, **kwargs)

        def hold(*args, **kwargs):
            kwargs["expected_install_uid"] = actual_uid
            return original_hold(*args, **kwargs)

        patch("aragorn.pi_core_bundle_launch._read_owned_bytes_at", side_effect=read_member)
        patch("aragorn.pi_core_bundle_launch.hold_runtime_active_skill_lineage", side_effect=hold)
        self.decision = patch("aragorn.protected_install_context.verify_decision_v3",
                              return_value={"verdict": "ALLOW", "manifest_digest": self.manifest_digest})
        patch("aragorn.pi_core_bundle_launch.time.time", return_value=100.0)
        patch("aragorn.pi_core_bundle_launch.time.monotonic", return_value=1.0)
        self.monotonic_ns = patch("aragorn.pi_core_bundle_launch.time.monotonic_ns", return_value=1_000_000_000)
        patch("socket.socket", side_effect=AssertionError("no live sockets"))
        patch("subprocess.Popen", side_effect=AssertionError("no worker spawning"))
        patch("os.execve", side_effect=AssertionError("no native execution"))

    def prepare(self):
        return launch.hold_prepared_pi_bundle(
            self.cas, self.context, profile=self.profile, grant=self.grant,
            protected_root=self.protected, runtime_conformance_digest=_digest("8"),
            deployment=self.deployment, revoked_context_ids=self.revoked,
            now_unix=self.now, deadline=5.0,
        )

    def test_exact_retained_bundle_is_copied_without_execution(self) -> None:
        with self.prepare() as prepared:
            self.assertEqual(prepared.system_prompt.encode(), self.skill_raw)
            self.assertEqual(dict(prepared.members), {
                "SKILL.md": self.skill_raw,
                "references/guide.txt": b"Known supporting bytes.\n",
            })
            self.assertEqual(prepared.context_digest, self.context_digest)
            self.assertEqual(prepared.manifest_digest, self.manifest_digest)
            self.assertEqual(prepared.tree_digest, self.manifest["tree_digest"])
            self.assertEqual(prepared.active_record_digest, canonical_digest(self.active_record))
            self.assertEqual(prepared.deployment_digest, canonical_digest(self.deployment))
            self.assertEqual(len(prepared.activation_id), 32)
            self.assertTrue(prepared._lease.active)
            self.assertLessEqual(prepared.expires_at_monotonic_ns, 5_000_000_000)
        self.assertFalse(prepared._lease.active)

    def test_supporting_bytes_substitution_refuses(self) -> None:
        member = self.version / "references" / "guide.txt"
        member.chmod(0o644)
        member.write_bytes(b"Substituted bytes")
        member.chmod(0o444)
        with self.assertRaises((ValueError, RuntimeError)), self.prepare():
            self.fail("changed support bytes must not prepare")

    def test_undeclared_member_refuses(self) -> None:
        self.version.chmod(0o755)
        extra = self.version / "extra.txt"
        extra.write_bytes(b"undeclared")
        extra.chmod(0o444)
        self.version.chmod(0o555)
        with self.assertRaises((ValueError, RuntimeError)), self.prepare():
            self.fail("extra member must not prepare")

    def test_current_context_revocation_and_expiry_refuse(self) -> None:
        self.revoked = (self.context["context_id"],)
        with self.assertRaisesRegex(ValueError, "revoked"), self.prepare():
            self.fail("revoked context must not prepare")
        self.revoked = ()
        self.now = self.context["expires_at_unix"]
        with self.assertRaisesRegex(ValueError, "expired"), self.prepare():
            self.fail("expired context must not prepare")

    def test_untrusted_admission_context_cannot_prepare(self) -> None:
        self.context["decision_digest"] = _digest("e")
        with self.assertRaisesRegex(ValueError, "digest is untrusted"), self.prepare():
            self.fail("altered context must not prepare")

    def test_nonallow_retained_decision_cannot_prepare(self) -> None:
        self.decision.return_value = {"verdict": "BLOCK", "manifest_digest": self.manifest_digest}
        with self.assertRaisesRegex(ValueError, "not ALLOW"), self.prepare():
            self.fail("BLOCK decision must not prepare")

    def test_deployment_policy_and_runtime_must_match(self) -> None:
        for name in ("policy", "runtime_commit_or_image"):
            previous = self.deployment[name]
            self.deployment[name] = _digest("f")
            with self.subTest(name=name), self.assertRaises(ValueError), self.prepare():
                self.fail("unbound deployment must not prepare")
            self.deployment[name] = previous

    def test_incomplete_deployment_dimensions_refuse(self) -> None:
        del self.deployment["adapter"]
        with self.assertRaisesRegex(ValueError, "incomplete"), self.prepare():
            self.fail("missing deployment dimension must not prepare")

    def test_executable_closure_is_explicitly_unsupported(self) -> None:
        executable = copy.deepcopy(self.manifest)
        executable["files"][0]["executable"] = True
        with mock.patch.object(launch, "load_verified_retained_manifest", return_value=executable):
            with self.assertRaisesRegex(ValueError, "script execution"), self.prepare():
                self.fail("script must not enter this slice")

    def test_each_preparation_gets_fresh_context(self) -> None:
        with self.prepare() as first:
            first_id = first.activation_id
        with self.prepare() as second:
            self.assertNotEqual(second.activation_id, first_id)

    def test_binding_refuses_after_preparation_scope(self) -> None:
        with self.prepare() as prepared:
            pass
        with self.assertRaisesRegex(ValueError, "inactive"), mock.patch.object(launch, "_peer_credentials") as peer:
            launch.bind_pi_worker_activation(
                prepared, object(), expected_pid=1234, expected_uid=1201,
                expected_gid=1202, profile=self.profile,
                activation_path=self.activation_directory / (prepared.activation_id + ".json"),
            )
        peer.assert_not_called()

    def test_wrong_child_consumes_one_bind_attempt_before_measurement(self) -> None:
        with self.prepare() as prepared, mock.patch.object(launch, "_peer_credentials", return_value=(999, 1201, 1202)), mock.patch.object(launch, "open_peer_pidfd") as open_pidfd:
            kwargs = dict(expected_pid=1234, expected_uid=1201, expected_gid=1202,
                          profile=self.profile,
                          activation_path=self.activation_directory / (prepared.activation_id + ".json"))
            with self.assertRaisesRegex(ValueError, "supervisor's child"):
                launch.bind_pi_worker_activation(prepared, object(), **kwargs)
            with self.assertRaisesRegex(ValueError, "already consumed"):
                launch.bind_pi_worker_activation(prepared, object(), **kwargs)
            open_pidfd.assert_not_called()

    def test_mocked_kernel_binding_connects_preparation_record_and_guard(self) -> None:
        # A temporary ordinary descriptor stands in for the mocked PIDFD. No
        # kernel-process observation is performed or claimed by this fixture.
        with self.prepare() as prepared:
            pidfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            observed = {
                "pid": 1234, "uid": 1201, "gid": 1202,
                "start_time_ticks": 1700, "mount_namespace": {"device": 4, "inode": 5},
                "cgroup": self.profile.cgroup, "profile_digest": self.profile.digest,
                "runtime_digest": self.profile.runtime_digest,
                "executable_digest": self.profile.executable_digest,
                "active_skill_digest": self.grant["active_skill_digest"],
                "skill_path": str(self.profile.skill_path),
            }
            activation_path = self.activation_directory / (prepared.activation_id + ".json")
            with mock.patch.object(launch, "_peer_credentials", return_value=(1234, 1201, 1202)), \
                    mock.patch.object(launch, "open_peer_pidfd", return_value=pidfd), \
                    mock.patch.object(launch, "measure_runtime_process_profile", return_value=observed), \
                    mock.patch.object(launch, "require_live_pidfd"), \
                    mock.patch.object(identity, "_boot_id", return_value="11111111-2222-3333-4444-555555555555"):
                result = launch.bind_pi_worker_activation(prepared, object(),
                    expected_pid=1234, expected_uid=1201, expected_gid=1202,
                    profile=self.profile, activation_path=activation_path)
            self.assertEqual(activation_path.read_bytes(), canonical_json(result))
            self.assertEqual(activation_path.stat().st_mode & 0o777, 0o444)
            self.assertEqual(result["session_id"], prepared.activation_id)
            self.assertEqual(result["run_id"], prepared.activation_id)
            self.assertEqual(result["source_manifest_digest"], self.manifest_digest)
            self.assertEqual(result["deployment_digest"], canonical_digest(self.deployment))
            with self.assertRaises(OSError):
                os.fstat(pidfd)

            # Continue through the real published bytes and installed-tree
            # verifier. Only host ownership and native process/transport edges
            # are replaced, exactly as in the preparation fixture above.
            original_directory = identity.broker._open_protected_directory
            original_read = identity.broker._read_owned_bytes_at
            actual_uid = os.geteuid()

            def directory(path, expected_uid, label):
                self.assertEqual(expected_uid, 0)
                return original_directory(path, actual_uid, label)

            def read(*args, **kwargs):
                self.assertEqual(kwargs["expected_uid"], 0)
                kwargs["expected_uid"] = actual_uid
                return original_read(*args, **kwargs)

            def hold(*args, **kwargs):
                kwargs["expected_install_uid"] = actual_uid
                return self.original_hold(*args, **kwargs)

            config = RuntimeActionWorkerConfig(
                socket_path=Path("/run/pi/worker.sock"), runtime_directory=Path("/run/pi"),
                sensor_socket_path=Path("/run/sensor/sensor.sock"), protected_root=self.protected,
                expected_worker_uid=1301, expected_worker_gid=1302,
                expected_gateway_uid=1201, expected_gateway_gid=1202,
                expected_sensor_uid=1401, expected_sensor_gid=1402, expected_broker_uid=1501,
                binding=RuntimeActionWorkerBinding(self.profile.runtime_digest,
                    prepared.skill_digest, prepared.policy_digest, 1),
            )
            request = _request(result)
            reply = _worker_result(canonical_digest(request), "COMPLETED", {
                "verdict": "ALLOW", "effect_status": "CREATED",
            })
            guard_pidfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            with ExitStack() as checks:
                for target, replacement in (
                    ("aragorn.pi_core_worker_identity.broker._open_protected_directory", directory),
                    ("aragorn.pi_core_worker_identity.broker._read_owned_bytes_at", read),
                    ("aragorn.pi_core_worker_identity.lineage.hold_runtime_active_skill_lineage", hold),
                ):
                    checks.enter_context(mock.patch(target, side_effect=replacement))
                checks.enter_context(mock.patch.object(identity.worker, "_validate_config"))
                checks.enter_context(mock.patch.object(identity.broker, "_peer_credentials", return_value=(1234, 1201, 1202)))
                checks.enter_context(mock.patch.object(identity.process, "open_peer_pidfd", return_value=guard_pidfd))
                checks.enter_context(mock.patch.object(identity.process, "measure_runtime_process_profile", return_value=observed))
                checks.enter_context(mock.patch.object(identity, "_boot_id", return_value=result["boot_id"]))
                checks.enter_context(mock.patch.object(identity.broker, "_read_frame", return_value=request))
                relay = checks.enter_context(mock.patch.object(identity.worker, "_relay_request", return_value=reply))
                sent = checks.enter_context(mock.patch.object(identity.broker, "_send_frame"))
                self.assertEqual(identity.read_activation(activation_path), result)
                guarded = identity.handle_pi_worker_connection(object(), config,
                    activation_path=activation_path, profile=self.profile,
                    protected_install_root=self.protected)
                self.assertEqual(guarded, reply)
                relay.assert_called_once()
                self.assertEqual(sent.call_args.args[1], canonical_json(reply))
                with self.assertRaises(OSError):
                    os.fstat(guard_pidfd)

    def test_existing_activation_file_is_preserved_and_not_retried(self) -> None:
        with self.prepare() as prepared:
            activation_path = self.activation_directory / (prepared.activation_id + ".json")
            original = b"preexisting evidence"
            activation_path.write_bytes(original)
            activation_path.chmod(0o444)
            pidfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            observed = {
                "pid": 1234, "uid": 1201, "gid": 1202,
                "start_time_ticks": 1700, "mount_namespace": {"device": 4, "inode": 5},
                "cgroup": self.profile.cgroup, "profile_digest": self.profile.digest,
                "runtime_digest": self.profile.runtime_digest,
                "executable_digest": self.profile.executable_digest,
                "active_skill_digest": self.grant["active_skill_digest"],
                "skill_path": str(self.profile.skill_path),
            }
            kwargs = dict(expected_pid=1234, expected_uid=1201, expected_gid=1202,
                          profile=self.profile, activation_path=activation_path)
            with mock.patch.object(launch, "_peer_credentials", return_value=(1234, 1201, 1202)), \
                    mock.patch.object(launch, "open_peer_pidfd", return_value=pidfd), \
                    mock.patch.object(launch, "measure_runtime_process_profile", return_value=observed), \
                    mock.patch.object(launch, "require_live_pidfd"), \
                    mock.patch.object(identity, "_boot_id", return_value="11111111-2222-3333-4444-555555555555"):
                with self.assertRaises(FileExistsError):
                    launch.bind_pi_worker_activation(prepared, object(), **kwargs)
                with self.assertRaisesRegex(ValueError, "already consumed"):
                    launch.bind_pi_worker_activation(prepared, object(), **kwargs)
            self.assertEqual(activation_path.read_bytes(), original)
            with self.assertRaises(OSError):
                os.fstat(pidfd)

    def test_preparation_expiry_prevents_binding_before_pidfd(self) -> None:
        with self.prepare() as prepared, mock.patch.object(launch, "_peer_credentials", return_value=(1234, 1201, 1202)), mock.patch.object(launch, "open_peer_pidfd") as pidfd:
            self.monotonic_ns.return_value = prepared.expires_at_monotonic_ns
            with self.assertRaisesRegex(ValueError, "expired"):
                launch.bind_pi_worker_activation(prepared, object(), expected_pid=1234,
                    expected_uid=1201, expected_gid=1202, profile=self.profile,
                    activation_path=self.activation_directory / (prepared.activation_id + ".json"))
            pidfd.assert_not_called()

    def test_context_id_and_installed_version_join_is_mandatory(self) -> None:
        # Preserve exact bytes, manifest and copied context digest, but move the
        # installed transaction to another context ID/version. The independent
        # admission-context-to-version join must detect this inconsistent state.
        replacement_id = _digest("f")
        replacement_path = ".aragorn-versions/pi/" + replacement_id[7:] + "-" + self.manifest_digest[7:]
        replacement_version = self.protected / replacement_path
        self.version.rename(replacement_version)
        self.transaction["context_id"] = replacement_id
        self.transaction["version_path"] = replacement_path
        active_path = self.protected / lineage_base.ACTIVE_RUNTIME_RECORD
        active_path.chmod(0o644)
        active_path.write_bytes(canonical_json(self.active_record))
        active_path.chmod(0o444)
        (self.protected / "pi").unlink()
        (self.protected / "pi").symlink_to(replacement_path)
        self.profile = runtime_process_profile({
            "schema": "aragorn/runtime-single-skill-process-profile/v1",
            "authority": "ROOT_PROFILE_PIN_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
            "runtime_digest": self.profile.runtime_digest,
            "executable_digest": self.profile.executable_digest,
            "cgroup": self.profile.cgroup,
            "skill_path": str(replacement_version / "SKILL.md"),
        })
        with self.assertRaisesRegex(ValueError, "installed version differ"), self.prepare():
            self.fail("context ID must match exact immutable version")



