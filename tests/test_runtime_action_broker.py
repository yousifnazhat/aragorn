from __future__ import annotations

import base64
import fcntl
import json
import os
import socket
import stat
import struct
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import (
    RuntimeActionBrokerConfig,
    RuntimeActionBrokerError,
    RuntimeActionEffectIndeterminate,
    _acquire_lock,
    _action_digests,
    _atomic_create,
    _handle_connection,
    _open_lock_file,
    _prepare_socket_path,
    mediate_runtime_create,
    mediate_observed_runtime_create,
    publish_runtime_control_document,
)

_RUNTIME = "sha256:" + "1" * 64
_SKILL = "sha256:" + "2" * 64
_SENSOR = "sha256:" + "6" * 64
_REVOCATION_SOURCE = "sha256:" + "7" * 64
_FRAME_HEADER = struct.Struct(">I")


def _write_control(path: Path, document: object) -> None:
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(canonical_json(document))
    path.chmod(0o400)


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.control = root / "control"
        self.protected = root / "protected"
        self.staging = root / "staging"
        for directory in (self.control, self.protected, self.staging):
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        self.payload = b"Aragorn mediated exactly one action.\n"
        self.target_name = "action.txt"
        target_fd = os.open(self.protected, os.O_RDONLY | os.O_DIRECTORY)
        try:
            action = _action_digests(target_fd, self.target_name, self.payload)
        finally:
            os.close(target_fd)
        rule = {
            "runtime_digest": _RUNTIME,
            "active_skill_digest": _SKILL,
            **action,
        }
        self.policy = {
            "schema": "aragorn/runtime-action-policy/v1",
            "id": "p3-file-write-fixture",
            "version": 1,
            "default": "BLOCK",
            "sensor_digest": _SENSOR,
            "revocation_source_digest": _REVOCATION_SOURCE,
            "allow": [rule],
        }
        self.request = {
            "schema": "aragorn/runtime-action-request/v1",
            "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "runtime_digest": _RUNTIME,
            "session_id": "session-1",
            "run_id": "run-1",
            "tool_call_id": "call-1",
            "active_skill_digest": _SKILL,
            **action,
            "policy_digest": canonical_digest(self.policy),
            "policy_version": 1,
            "issued_at_unix": 98,
            "expires_at_unix": 103,
        }
        attribution = {
            key: self.request[key]
            for key in (
                "runtime_digest",
                "session_id",
                "run_id",
                "tool_call_id",
                "active_skill_digest",
            )
        }
        self.observation = {
            "schema": "aragorn/runtime-action-observation/v1",
            "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
            "sequence": 1,
            "sensor_digest": _SENSOR,
            "observed_at_unix": 98,
            "expires_at_unix": 103,
            "active": {
                "schema": "aragorn/runtime-active-context/v1",
                **attribution,
            },
            "measured_action": {
                "schema": "aragorn/measured-runtime-action/v1",
                **attribution,
                **action,
            },
        }
        self.revocations = {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": _REVOCATION_SOURCE,
            "generation": 3,
            "observed_at_unix": 95,
            "expires_at_unix": 105,
            "skill_digests": [],
        }
        self.health = {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": _RUNTIME,
            "sensor_digest": _SENSOR,
            "epoch": 4,
            "status": "healthy",
            "observed_at_unix": 95,
            "expires_at_unix": 105,
        }
        self.state = {
            "schema": "aragorn/runtime-action-broker-state/v2",
            "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "minimum_revocation_generation": 1,
            "minimum_mediator_health_epoch": 1,
            "consumed": [],
            "effect_journal": None,
        }
        self.paths = {
            name: self.control / f"{name}.json"
            for name in ("policy", "revocations", "health", "observation", "state")
        }
        for name in self.paths:
            _write_control(self.paths[name], getattr(self, name))
        self.lock_path = self.control / "broker.lock"
        self.lock_path.touch(mode=0o600)
        self.lock_path.chmod(0o600)
        self.instance_lock_path = self.control / "broker.instance.lock"
        self.instance_lock_path.touch(mode=0o600)
        self.instance_lock_path.chmod(0o600)
        self.config = RuntimeActionBrokerConfig(
            socket_path=self.control / "broker.sock",
            instance_lock_path=self.instance_lock_path,
            lock_path=self.lock_path,
            control_root=self.control,
            protected_root=self.protected,
            staging_root=self.staging,
            policy_path=self.paths["policy"],
            revocations_path=self.paths["revocations"],
            health_path=self.paths["health"],
            observation_path=self.paths["observation"],
            state_path=self.paths["state"],
            expected_broker_uid=os.geteuid(),
            expected_peer_uid=os.geteuid() + 1,
            expected_peer_gid=os.getegid(),
            expected_runtime_digest=_RUNTIME,
        )
        self.envelope = {
            "schema": "aragorn/runtime-action-broker-request/v1",
            "request": self.request,
            "effect": {
                "schema": "aragorn/runtime-create-file/v1",
                "operation": "create",
                "target_name": self.target_name,
                "payload_base64": base64.b64encode(self.payload).decode("ascii"),
            },
        }

    @property
    def target(self) -> Path:
        return self.protected / self.target_name

    def load_state(self) -> dict[str, object]:
        return json.loads(self.paths["state"].read_bytes())


def _observed_submission(
    fixture: _Fixture,
    config: RuntimeActionBrokerConfig,
) -> dict[str, object]:
    measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **{
            field: fixture.request[field]
            for field in (
                "runtime_digest",
                "session_id",
                "run_id",
                "tool_call_id",
                "active_skill_digest",
                "operation_digest",
                "path_digest",
                "payload_digest",
            )
        },
    }
    return {
        "schema": "aragorn/runtime-observed-create-submission/v1",
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "sensor_digest": _SENSOR,
        "envelope_digest": canonical_digest(fixture.envelope),
        "request_digest": canonical_digest(fixture.request),
        "runtime_peer": {
            "pid": 123,
            "uid": config.expected_runtime_uid,
            "gid": config.expected_runtime_gid,
        },
        "measured_action": measured,
        "envelope": fixture.envelope,
    }


_CRASH_EXIT = 73
_CRASH_CHECKPOINTS = {
    "after_replay_claim",
    "before_pending",
    "after_pending",
    "after_link",
    "before_applied",
    "after_applied",
    "after_stage_unlink",
    "after_journal_clear",
}


def _crash_during_mediation(fixture: _Fixture, checkpoint: str) -> int:
    if checkpoint not in _CRASH_CHECKPOINTS:
        raise AssertionError(f"unknown crash checkpoint: {checkpoint}")
    child = os.fork()
    if child == 0:
        from aragorn import runtime_action_broker as broker

        real_atomic_create = broker._atomic_create
        real_commit_state = broker._commit_state
        real_link = broker.os.link
        real_unlink = broker.os.unlink
        supports_dir_fd = set(broker.os.supports_dir_fd)
        supports_follow_symlinks = set(broker.os.supports_follow_symlinks)
        saw_applied = False

        def crash_atomic_create(*args: object, **kwargs: object) -> bool:
            if checkpoint == "after_replay_claim":
                os._exit(_CRASH_EXIT)
            return real_atomic_create(*args, **kwargs)

        def crash_commit_state(
            control_fd: int,
            config: RuntimeActionBrokerConfig,
            state: dict[str, object],
        ) -> None:
            nonlocal saw_applied
            journal = state.get("effect_journal")
            status = journal.get("status") if isinstance(journal, dict) else None
            if checkpoint == "before_pending" and status == "PENDING":
                os._exit(_CRASH_EXIT)
            if checkpoint == "before_applied" and status == "APPLIED":
                os._exit(_CRASH_EXIT)
            real_commit_state(control_fd, config, state)
            if checkpoint == "after_pending" and status == "PENDING":
                os._exit(_CRASH_EXIT)
            if status == "APPLIED":
                saw_applied = True
                if checkpoint == "after_applied":
                    os._exit(_CRASH_EXIT)
            elif (
                checkpoint == "after_journal_clear"
                and saw_applied
                and journal is None
            ):
                os._exit(_CRASH_EXIT)

        def crash_link(*args: object, **kwargs: object) -> None:
            real_link(*args, **kwargs)
            if checkpoint == "after_link":
                os._exit(_CRASH_EXIT)

        def crash_unlink(path: object, *args: object, **kwargs: object) -> None:
            real_unlink(path, *args, **kwargs)
            if (
                checkpoint == "after_stage_unlink"
                and isinstance(path, str)
                and path.startswith(".aragorn-runtime-")
            ):
                os._exit(_CRASH_EXIT)

        try:
            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(
                        broker,
                        "_atomic_create",
                        new=crash_atomic_create,
                    )
                )
                stack.enter_context(
                    patch.object(
                        broker,
                        "_commit_state",
                        new=crash_commit_state,
                    )
                )
                stack.enter_context(
                    patch.object(broker.os, "link", new=crash_link)
                )
                stack.enter_context(
                    patch.object(broker.os, "unlink", new=crash_unlink)
                )
                stack.enter_context(
                    patch.object(
                        broker.os,
                        "supports_dir_fd",
                        supports_dir_fd | {crash_link, crash_unlink},
                    )
                )
                stack.enter_context(
                    patch.object(
                        broker.os,
                        "supports_follow_symlinks",
                        supports_follow_symlinks | {crash_link},
                    )
                )
                broker.mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )
        except BaseException:
            os._exit(97)
        os._exit(98)
    _pid, status = os.waitpid(child, 0)
    return os.waitstatus_to_exitcode(status)


class RuntimeActionBrokerTests(unittest.TestCase):
    def test_allow_creates_once_and_persists_floors_before_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())

            result = mediate_runtime_create(
                fixture.envelope, fixture.config, clock=lambda: 100
            )

            self.assertEqual(result["verdict"], "ALLOW")
            self.assertEqual(result["effect_status"], "CREATED")
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            self.assertEqual(stat_mode(fixture.target), 0o400)
            state = fixture.load_state()
            self.assertEqual(state["minimum_revocation_generation"], 3)
            self.assertEqual(state["minimum_mediator_health_epoch"], 4)
            self.assertEqual(len(state["consumed"]), 1)

            replay = mediate_runtime_create(
                fixture.envelope,
                fixture.config,
                clock=lambda: 100,
            )
            self.assertEqual(replay["verdict"], "BLOCK")
            self.assertEqual(replay["reason_codes"], ["BROKER_REPLAY_BLOCKED"])
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)

    def test_observation_gateway_publication_and_effect_share_one_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            config = replace(
                fixture.config,
                expected_peer_uid=os.geteuid() + 1,
                expected_peer_gid=os.getegid() + 1,
                expected_runtime_uid=os.geteuid() + 2,
                expected_runtime_gid=os.getegid(),
            )
            submission = _observed_submission(fixture, config)

            result = mediate_observed_runtime_create(
                submission,
                config,
                clock=lambda: 100,
            )

            self.assertEqual(result["verdict"], "ALLOW")
            self.assertEqual(result["effect_status"], "CREATED")
            observation = json.loads(fixture.paths["observation"].read_bytes())
            health = json.loads(fixture.paths["health"].read_bytes())
            self.assertEqual(observation["sequence"], 2)
            self.assertEqual(observation["measured_action"], submission["measured_action"])
            self.assertEqual(health["epoch"], 5)
            self.assertEqual(health["status"], "healthy")
            self.assertEqual(result["observation_digest"], canonical_digest(observation))

    def test_observation_gateway_rejects_mutation_and_direct_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            config = replace(
                fixture.config,
                expected_peer_uid=os.geteuid() + 1,
                expected_peer_gid=os.getegid() + 1,
                expected_runtime_uid=os.geteuid() + 2,
                expected_runtime_gid=os.getegid(),
            )
            submission = _observed_submission(fixture, config)
            submission["measured_action"] = {
                **submission["measured_action"],
                "payload_digest": "sha256:" + "f" * 64,
            }
            with self.assertRaisesRegex(
                RuntimeActionBrokerError,
                "measurement changed",
            ):
                mediate_observed_runtime_create(
                    submission,
                    config,
                    clock=lambda: 100,
                )
            self.assertFalse(fixture.target.exists())
            self.assertEqual(
                json.loads(fixture.paths["observation"].read_bytes())["sequence"],
                1,
            )

            client, server = socket.socketpair()
            try:
                raw = canonical_json(fixture.envelope)
                client.sendall(_FRAME_HEADER.pack(len(raw)) + raw)
                client.shutdown(socket.SHUT_WR)
                with (
                    patch(
                        "aragorn.runtime_action_broker._peer_credentials",
                        return_value=(321, config.expected_peer_uid, config.expected_peer_gid),
                    ),
                    self.assertRaisesRegex(
                        RuntimeActionBrokerError,
                        "observed runtime submission fields",
                    ),
                ):
                    _handle_connection(server, config, timeout_seconds=0.5)
            finally:
                client.close()
                server.close()
            self.assertFalse(fixture.target.exists())

    def test_observation_gateway_publishes_before_replay_and_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            config = replace(
                fixture.config,
                expected_peer_uid=os.geteuid() + 1,
                expected_peer_gid=os.getegid() + 1,
                expected_runtime_uid=os.geteuid() + 2,
                expected_runtime_gid=os.getegid(),
            )
            submission = _observed_submission(fixture, config)
            from aragorn import runtime_action_broker as broker

            events: list[str] = []
            real_publish = broker._publish_control_locked
            real_commit = broker._commit_state
            real_link = broker.os.link
            supports_dir_fd = set(broker.os.supports_dir_fd)
            supports_follow_symlinks = set(broker.os.supports_follow_symlinks)

            def publish(*args: object, **kwargs: object) -> None:
                real_publish(*args, **kwargs)
                path = args[1]
                if path == config.health_path:
                    events.append("health")
                elif path == config.observation_path:
                    events.append("observation")

            def commit(
                control_fd: int,
                current_config: RuntimeActionBrokerConfig,
                state: dict[str, object],
            ) -> None:
                real_commit(control_fd, current_config, state)
                journal = state.get("effect_journal")
                if isinstance(journal, dict) and journal.get("status") == "PENDING":
                    events.append("pending")
                elif state.get("consumed") and journal is None and "replay" not in events:
                    events.append("replay")

            def link(*args: object, **kwargs: object) -> None:
                real_link(*args, **kwargs)
                events.append("link")

            with (
                patch.object(broker, "_publish_control_locked", new=publish),
                patch.object(broker, "_commit_state", new=commit),
                patch.object(broker.os, "link", new=link),
                patch.object(
                    broker.os,
                    "supports_dir_fd",
                    supports_dir_fd | {link},
                ),
                patch.object(
                    broker.os,
                    "supports_follow_symlinks",
                    supports_follow_symlinks | {link},
                ),
            ):
                result = mediate_observed_runtime_create(
                    submission,
                    config,
                    clock=lambda: 100,
                )

            self.assertEqual(result["effect_status"], "CREATED")
            self.assertLess(events.index("health"), events.index("observation"))
            self.assertLess(events.index("observation"), events.index("replay"))
            self.assertLess(events.index("replay"), events.index("pending"))
            self.assertLess(events.index("pending"), events.index("link"))

    def test_observation_gateway_cannot_promote_unhealthy_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            config = replace(
                fixture.config,
                expected_peer_uid=os.geteuid() + 1,
                expected_peer_gid=os.getegid() + 1,
                expected_runtime_uid=os.geteuid() + 2,
                expected_runtime_gid=os.getegid(),
            )
            _write_control(
                fixture.paths["health"],
                {**fixture.health, "epoch": 6, "status": "unhealthy"},
            )

            result = mediate_observed_runtime_create(
                _observed_submission(fixture, config),
                config,
                clock=lambda: 100,
            )

            self.assertEqual(result["verdict"], "BLOCK")
            self.assertIn("MEDIATOR_UNHEALTHY", result["reason_codes"])
            self.assertFalse(fixture.target.exists())
            retained = json.loads(fixture.paths["health"].read_bytes())
            self.assertEqual(retained["epoch"], 7)
            self.assertEqual(retained["status"], "unhealthy")

    def test_revocation_and_unhealthy_state_block_and_advance_floors(self) -> None:
        cases = (
            ("revoked", "revocations", "generation", 5, "ACTIVE_SKILL_REVOKED"),
            ("unhealthy", "health", "epoch", 6, "MEDIATOR_UNHEALTHY"),
        )
        for label, control, floor_name, floor, reason in cases:
            with self.subTest(label), tempfile.TemporaryDirectory() as temporary:
                fixture = _Fixture(Path(temporary).resolve())
                document = getattr(fixture, control)
                document[floor_name] = floor
                if control == "revocations":
                    document["skill_digests"] = [_SKILL]
                else:
                    document["status"] = "unhealthy"
                publish_runtime_control_document(
                    fixture.paths[control],
                    document,
                    fixture.config,
                    clock=lambda: 100,
                )

                result = mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )

                self.assertEqual(result["verdict"], "BLOCK")
                self.assertIn(reason, result["reason_codes"])
                self.assertFalse(fixture.target.exists())
                state = fixture.load_state()
                self.assertEqual(len(state["consumed"]), 1)
                persisted = (
                    state["minimum_revocation_generation"]
                    if control == "revocations"
                    else state["minimum_mediator_health_epoch"]
                )
                self.assertEqual(persisted, floor)

    def test_measurement_mismatch_or_existing_target_never_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            fixture.envelope["effect"]["payload_base64"] = base64.b64encode(
                b"changed"
            ).decode("ascii")
            result = mediate_runtime_create(
                fixture.envelope, fixture.config, clock=lambda: 100
            )
            self.assertEqual(result["verdict"], "BLOCK")
            self.assertEqual(
                result["reason_codes"],
                [
                    "BROKER_EFFECT_BINDING_MISMATCH",
                    "BROKER_EFFECT_MEASUREMENT_MISMATCH",
                ],
            )
            self.assertFalse(fixture.target.exists())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            fixture.target.symlink_to("elsewhere")
            with self.assertRaises(RuntimeActionBrokerError):
                mediate_runtime_create(
                    fixture.envelope, fixture.config, clock=lambda: 100
                )
            self.assertTrue(fixture.target.is_symlink())
            self.assertEqual(os.readlink(fixture.target), "elsewhere")

    def test_failure_after_consumption_remains_consumed_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            with (
                patch(
                    "aragorn.runtime_action_broker._atomic_create",
                    side_effect=OSError("injected pre-effect failure"),
                ),
                self.assertRaises(RuntimeActionBrokerError),
            ):
                mediate_runtime_create(
                    fixture.envelope, fixture.config, clock=lambda: 100
                )
            self.assertFalse(fixture.target.exists())
            self.assertEqual(len(fixture.load_state()["consumed"]), 1)

            replay = mediate_runtime_create(
                fixture.envelope,
                fixture.config,
                clock=lambda: 100,
            )
            self.assertEqual(replay["reason_codes"], ["BROKER_REPLAY_BLOCKED"])
            self.assertFalse(fixture.target.exists())

    def test_invalid_expiry_is_bounded_and_pruned(self) -> None:
        for deadline in (float("nan"), float("inf")):
            with self.subTest(deadline), tempfile.TemporaryDirectory() as temporary:
                fixture = _Fixture(Path(temporary).resolve())
                with self.assertRaises(RuntimeActionBrokerError):
                    mediate_runtime_create(
                        fixture.envelope,
                        fixture.config,
                        clock=lambda: 100,
                        deadline_monotonic=deadline,
                    )
                self.assertFalse(fixture.target.exists())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            fixture.request["expires_at_unix"] = 10**30

            blocked = mediate_runtime_create(
                fixture.envelope,
                fixture.config,
                clock=lambda: 100,
            )
            self.assertEqual(blocked["verdict"], "BLOCK")
            self.assertEqual(
                fixture.load_state()["consumed"][0]["expires_at_unix"], 105
            )

            fixture.request["issued_at_unix"] = 106
            fixture.request["expires_at_unix"] = 110
            fixture.observation["observed_at_unix"] = 105
            fixture.observation["expires_at_unix"] = 110
            fixture.revocations["observed_at_unix"] = 105
            fixture.revocations["expires_at_unix"] = 110
            fixture.health["observed_at_unix"] = 105
            fixture.health["expires_at_unix"] = 110
            for name in ("observation", "revocations", "health"):
                _write_control(fixture.paths[name], getattr(fixture, name))

            allowed = mediate_runtime_create(
                fixture.envelope,
                fixture.config,
                clock=lambda: 106,
            )
            self.assertEqual(allowed["verdict"], "ALLOW")
            self.assertEqual(len(fixture.load_state()["consumed"]), 1)

    def test_lock_delay_resamples_time_and_cannot_create_expired_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            held = os.open(fixture.lock_path, os.O_RDWR)
            fcntl.flock(held, fcntl.LOCK_EX)
            now = [100]
            outcome: list[BaseException | dict[str, object]] = []

            def mediate() -> None:
                try:
                    outcome.append(
                        mediate_runtime_create(
                            fixture.envelope,
                            fixture.config,
                            clock=lambda: now[0],
                            deadline_monotonic=time.monotonic() + 0.5,
                        )
                    )
                except RuntimeActionBrokerError as exc:
                    outcome.append(exc)

            worker = threading.Thread(target=mediate)
            worker.start()
            time.sleep(0.03)
            now[0] = 104
            fcntl.flock(held, fcntl.LOCK_UN)
            os.close(held)
            worker.join(timeout=1)

            self.assertFalse(worker.is_alive())
            self.assertIsInstance(outcome[0], RuntimeActionBrokerError)
            self.assertFalse(fixture.target.exists())

    def test_staging_delay_revalidates_immediately_before_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            from aragorn import runtime_action_broker as broker

            now = [100]
            write_all = broker.write_all

            def advance_after_payload(descriptor: int, content: bytes) -> None:
                write_all(descriptor, content)
                if content == fixture.payload:
                    now[0] = 104

            with (
                patch(
                    "aragorn.runtime_action_broker.write_all",
                    side_effect=advance_after_payload,
                ),
                self.assertRaises(RuntimeActionBrokerError),
            ):
                mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: now[0],
                )
            self.assertFalse(fixture.target.exists())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            samples = iter((100, 100, 104, 100))
            result = mediate_runtime_create(
                fixture.envelope,
                fixture.config,
                clock=lambda: next(samples),
            )
            self.assertEqual(result["verdict"], "BLOCK")
            self.assertEqual(result["reason_codes"], ["BROKER_CLOCK_ROLLBACK"])
            self.assertFalse(fixture.target.exists())

    def test_floors_advance_on_mismatch_replay_and_independent_stream_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            fixture.revocations["generation"] = 5
            fixture.health["epoch"] = 6
            _write_control(fixture.paths["revocations"], fixture.revocations)
            _write_control(fixture.paths["health"], fixture.health)
            fixture.envelope["effect"]["payload_base64"] = base64.b64encode(
                b"wrong"
            ).decode("ascii")
            mediate_runtime_create(
                fixture.envelope,
                fixture.config,
                clock=lambda: 100,
            )
            state = fixture.load_state()
            self.assertEqual(state["minimum_revocation_generation"], 5)
            self.assertEqual(state["minimum_mediator_health_epoch"], 6)

            fixture.revocations["generation"] = 4
            fixture.health["epoch"] = 5
            _write_control(fixture.paths["revocations"], fixture.revocations)
            _write_control(fixture.paths["health"], fixture.health)
            replay = mediate_runtime_create(
                fixture.envelope,
                fixture.config,
                clock=lambda: 100,
            )
            self.assertEqual(replay["reason_codes"], ["BROKER_REPLAY_BLOCKED"])
            state = fixture.load_state()
            self.assertEqual(state["minimum_revocation_generation"], 5)
            self.assertEqual(state["minimum_mediator_health_epoch"], 6)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            fixture.revocations["generation"] = 7
            _write_control(fixture.paths["revocations"], fixture.revocations)
            fixture.paths["health"].chmod(0o600)
            fixture.paths["health"].write_bytes(b"{")
            fixture.paths["health"].chmod(0o400)
            with self.assertRaises(RuntimeActionBrokerError):
                mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )
            self.assertEqual(
                fixture.load_state()["minimum_revocation_generation"],
                7,
            )

    def test_publisher_rejects_counter_rollback_and_equivocation(self) -> None:
        cases = (
            (
                "revocations",
                "generation",
                5,
                "skill_digests",
                [_SKILL],
                [],
                "minimum_revocation_generation",
                "ACTIVE_SKILL_REVOKED",
            ),
            (
                "health",
                "epoch",
                6,
                "status",
                "unhealthy",
                "healthy",
                "minimum_mediator_health_epoch",
                "MEDIATOR_UNHEALTHY",
            ),
        )
        for (
            control,
            counter,
            high,
            security_field,
            denied_value,
            allowed_value,
            state_field,
            reason,
        ) in cases:
            with self.subTest(control), tempfile.TemporaryDirectory() as temporary:
                fixture = _Fixture(Path(temporary).resolve())
                document = dict(getattr(fixture, control))
                document[counter] = high
                document[security_field] = denied_value
                publish_runtime_control_document(
                    fixture.paths[control],
                    document,
                    fixture.config,
                    clock=lambda: 100,
                )
                retained = fixture.paths[control].read_bytes()
                self.assertEqual(fixture.load_state()[state_field], high)

                for candidate_counter in (high - 1, high):
                    candidate = {
                        **document,
                        counter: candidate_counter,
                        security_field: allowed_value,
                    }
                    with self.assertRaises(RuntimeActionBrokerError):
                        publish_runtime_control_document(
                            fixture.paths[control],
                            candidate,
                            fixture.config,
                            clock=lambda: 100,
                        )
                    self.assertEqual(fixture.paths[control].read_bytes(), retained)

                result = mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertIn(reason, result["reason_codes"])
                self.assertFalse(fixture.target.exists())

    def test_publisher_crash_order_policy_and_observation_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            from aragorn import runtime_action_broker as broker

            document = {
                **fixture.revocations,
                "generation": 5,
                "skill_digests": [_SKILL],
            }
            with (
                patch.object(
                    broker,
                    "_commit_state",
                    side_effect=RuntimeActionBrokerError("injected state failure"),
                ),
                self.assertRaises(RuntimeActionBrokerError),
            ):
                publish_runtime_control_document(
                    fixture.paths["revocations"],
                    document,
                    fixture.config,
                    clock=lambda: 100,
                )
            self.assertEqual(
                json.loads(fixture.paths["revocations"].read_bytes())["generation"],
                5,
            )
            self.assertEqual(
                fixture.load_state()["minimum_revocation_generation"],
                1,
            )
            result = mediate_runtime_create(
                fixture.envelope,
                fixture.config,
                clock=lambda: 100,
            )
            self.assertEqual(result["verdict"], "BLOCK")
            self.assertIn("ACTIVE_SKILL_REVOKED", result["reason_codes"])
            self.assertEqual(
                fixture.load_state()["minimum_revocation_generation"],
                5,
            )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            document = {**fixture.revocations, "generation": 5}
            real_flock = fcntl.flock
            failed = False

            def fail_first_unlock(descriptor: int, operation: int) -> None:
                nonlocal failed
                if operation == fcntl.LOCK_UN and not failed:
                    failed = True
                    raise OSError("injected unlock failure")
                real_flock(descriptor, operation)

            with (
                patch(
                    "aragorn.runtime_action_broker.fcntl.flock",
                    side_effect=fail_first_unlock,
                ),
                self.assertRaises(RuntimeActionBrokerError),
            ):
                publish_runtime_control_document(
                    fixture.paths["revocations"],
                    document,
                    fixture.config,
                    clock=lambda: 100,
                )
            publish_runtime_control_document(
                fixture.paths["revocations"],
                document,
                fixture.config,
                clock=lambda: 100,
            )
            self.assertEqual(
                fixture.load_state()["minimum_revocation_generation"],
                5,
            )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            with self.assertRaises(RuntimeActionBrokerError):
                publish_runtime_control_document(
                    fixture.paths["policy"],
                    fixture.policy,
                    fixture.config,
                    clock=lambda: 100,
                )
            newer = {**fixture.observation, "sequence": 3}
            publish_runtime_control_document(
                fixture.paths["observation"],
                newer,
                fixture.config,
                clock=lambda: 100,
            )
            for candidate in (
                {**fixture.observation, "sequence": 2},
                {**newer, "active": None},
            ):
                with self.assertRaises(RuntimeActionBrokerError):
                    publish_runtime_control_document(
                        fixture.paths["observation"],
                        candidate,
                        fixture.config,
                        clock=lambda: 100,
                    )
            self.assertEqual(
                json.loads(fixture.paths["observation"].read_bytes())["sequence"],
                3,
            )

    def test_instance_lock_and_stale_socket_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            control_fd = os.open(fixture.control, os.O_RDONLY | os.O_DIRECTORY)
            first = _open_lock_file(
                control_fd,
                fixture.config,
                path=fixture.instance_lock_path,
            )
            second = _open_lock_file(
                control_fd,
                fixture.config,
                path=fixture.instance_lock_path,
            )
            stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                _acquire_lock(first, time.monotonic())
                with self.assertRaises(RuntimeActionBrokerError):
                    _acquire_lock(second, time.monotonic())
                stale.bind(os.fspath(fixture.config.socket_path))
                stale.close()
                os.close(first)
                first = -1
                _acquire_lock(second, time.monotonic())
                _prepare_socket_path(control_fd, fixture.config)
                self.assertFalse(fixture.config.socket_path.exists())

                fixture.config.socket_path.write_text("do not delete")
                with self.assertRaises(RuntimeActionBrokerError):
                    _prepare_socket_path(control_fd, fixture.config)
                self.assertEqual(
                    fixture.config.socket_path.read_text(),
                    "do not delete",
                )
            finally:
                stale.close()
                for descriptor in (first, second, control_fd):
                    if descriptor >= 0:
                        os.close(descriptor)

    def test_final_state_change_blocks_and_concurrent_replay_creates_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            from aragorn import runtime_action_broker as broker

            commit = broker._commit_state
            mutated = False

            def mutate_after_claim(*args: object) -> None:
                nonlocal mutated
                commit(*args)
                state = args[-1]
                if not mutated and isinstance(state, dict) and state["consumed"]:
                    mutated = True
                    fixture.revocations["generation"] = 5
                    fixture.revocations["skill_digests"] = [_SKILL]
                    _write_control(
                        fixture.paths["revocations"],
                        fixture.revocations,
                    )

            with patch(
                "aragorn.runtime_action_broker._commit_state",
                side_effect=mutate_after_claim,
            ):
                result = mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )
            self.assertEqual(result["verdict"], "BLOCK")
            self.assertIn("ACTIVE_SKILL_REVOKED", result["reason_codes"])
            self.assertFalse(fixture.target.exists())

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())

            def mediate_once() -> dict[str, object]:
                return mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _index: mediate_once(), range(2)))
            self.assertEqual(
                sorted(result["effect_status"] for result in results),
                ["CREATED", "NOT_PERFORMED"],
            )
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)

    def test_post_link_failure_is_reported_as_indeterminate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            staging_fd = os.open(fixture.staging, os.O_RDONLY | os.O_DIRECTORY)
            protected_fd = os.open(fixture.protected, os.O_RDONLY | os.O_DIRECTORY)
            real_fsync = os.fsync

            def fail_target_fsync(descriptor: int) -> None:
                if descriptor == protected_fd:
                    raise OSError("injected target fsync failure")
                real_fsync(descriptor)

            try:
                with (
                    patch(
                        "aragorn.runtime_action_broker.os.fsync",
                        side_effect=fail_target_fsync,
                    ),
                    self.assertRaises(RuntimeActionEffectIndeterminate),
                ):
                    _atomic_create(
                        staging_fd,
                        protected_fd,
                        fixture.target_name,
                        fixture.payload,
                    )
            finally:
                os.close(protected_fd)
                os.close(staging_fd)
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            staging_fd = os.open(fixture.staging, os.O_RDONLY | os.O_DIRECTORY)
            protected_fd = os.open(fixture.protected, os.O_RDONLY | os.O_DIRECTORY)
            real_fsync = os.fsync

            def interrupt_target_fsync(descriptor: int) -> None:
                if descriptor == protected_fd:
                    raise KeyboardInterrupt
                real_fsync(descriptor)

            try:
                with (
                    patch(
                        "aragorn.runtime_action_broker.os.fsync",
                        side_effect=interrupt_target_fsync,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    _atomic_create(
                        staging_fd,
                        protected_fd,
                        fixture.target_name,
                        fixture.payload,
                    )
            finally:
                os.close(protected_fd)
                os.close(staging_fd)
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            self.assertEqual(list(fixture.staging.iterdir()), [])

    def test_post_effect_recovery_failure_is_indeterminate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            from aragorn import runtime_action_broker as broker

            unlink_effect = broker._unlink_effect_file_at

            def fail_staged_cleanup(*args: object) -> None:
                if args[-1] == "runtime staged effect":
                    raise OSError("injected recovery cleanup failure")
                unlink_effect(*args)

            with (
                patch.object(
                    broker,
                    "_unlink_effect_file_at",
                    side_effect=fail_staged_cleanup,
                ),
                self.assertRaises(RuntimeActionEffectIndeterminate),
            ):
                mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )

            self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            self.assertEqual(fixture.target.stat().st_nlink, 2)
            self.assertEqual(len(list(fixture.staging.iterdir())), 1)
            self.assertEqual(
                fixture.load_state()["effect_journal"]["status"],
                "APPLIED",
            )

    def test_success_orders_journal_around_link_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            from aragorn import runtime_action_broker as broker

            events: list[str] = []
            real_commit = broker._commit_state
            real_effect_file = broker._effect_file_at
            real_link = broker.os.link
            real_fsync = broker.os.fsync
            real_unlink_effect = broker._unlink_effect_file_at
            supports_dir_fd = set(broker.os.supports_dir_fd)
            supports_follow_symlinks = set(broker.os.supports_follow_symlinks)
            protected_identity = (
                fixture.protected.stat().st_dev,
                fixture.protected.stat().st_ino,
            )
            staging_identity = (
                fixture.staging.stat().st_dev,
                fixture.staging.stat().st_ino,
            )
            saw_applied = False

            def record_commit(
                control_fd: int,
                config: RuntimeActionBrokerConfig,
                state: dict[str, object],
            ) -> None:
                nonlocal saw_applied
                real_commit(control_fd, config, state)
                journal = state.get("effect_journal")
                status = journal.get("status") if isinstance(journal, dict) else None
                if status == "PENDING":
                    events.append("pending")
                elif status == "APPLIED":
                    saw_applied = True
                    events.append("applied")
                elif saw_applied and journal is None:
                    events.append("clear")

            def record_link(*args: object, **kwargs: object) -> None:
                real_link(*args, **kwargs)
                events.append("link")

            def record_fsync(descriptor: int) -> None:
                metadata = os.fstat(descriptor)
                real_fsync(descriptor)
                identity = metadata.st_dev, metadata.st_ino
                if stat.S_ISDIR(metadata.st_mode) and identity == protected_identity:
                    events.append("protected-fsync")
                elif stat.S_ISDIR(metadata.st_mode) and identity == staging_identity:
                    events.append("staging-fsync")

            def record_unlink_effect(*args: object) -> None:
                real_unlink_effect(*args)
                if args[-1] == "runtime staged effect":
                    events.append("stage-unlink")

            def record_effect_file(*args: object, **kwargs: object) -> object:
                recovered = real_effect_file(*args, **kwargs)
                if (
                    kwargs.get("label") == "runtime protected effect"
                    and recovered is not None
                    and recovered.st_nlink == 1
                ):
                    events.append("target-verified")
                return recovered

            with (
                patch.object(broker, "_commit_state", new=record_commit),
                patch.object(broker, "_effect_file_at", new=record_effect_file),
                patch.object(
                    broker,
                    "_unlink_effect_file_at",
                    new=record_unlink_effect,
                ),
                patch.object(broker.os, "fsync", new=record_fsync),
                patch.object(broker.os, "link", new=record_link),
                patch.object(
                    broker.os,
                    "supports_dir_fd",
                    supports_dir_fd | {record_link},
                ),
                patch.object(
                    broker.os,
                    "supports_follow_symlinks",
                    supports_follow_symlinks | {record_link},
                ),
            ):
                result = mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )

            self.assertEqual(result["effect_status"], "CREATED")
            self.assertEqual(
                events,
                [
                    "staging-fsync",
                    "pending",
                    "link",
                    "protected-fsync",
                    "applied",
                    "stage-unlink",
                    "staging-fsync",
                    "target-verified",
                    "clear",
                ],
            )

    @unittest.skipUnless(hasattr(os, "fork"), "requires process crash injection")
    def test_process_crash_recovery_is_at_most_once(self) -> None:
        target_exists = {
            "after_replay_claim": False,
            "before_pending": False,
            "after_pending": False,
            "after_link": True,
            "before_applied": True,
            "after_applied": True,
            "after_stage_unlink": True,
            "after_journal_clear": True,
        }
        for checkpoint, expected_target in target_exists.items():
            with self.subTest(checkpoint), tempfile.TemporaryDirectory() as temporary:
                fixture = _Fixture(Path(temporary).resolve())
                from aragorn import runtime_action_broker as broker

                self.assertEqual(
                    _crash_during_mediation(fixture, checkpoint),
                    _CRASH_EXIT,
                )
                target_identity = None
                if expected_target:
                    target = fixture.target.stat()
                    target_identity = target.st_dev, target.st_ino
                broker._recover_before_listen(fixture.config, 0.5)

                replay = mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )

                self.assertEqual(replay["reason_codes"], ["BROKER_REPLAY_BLOCKED"])
                self.assertEqual(fixture.target.exists(), expected_target)
                if expected_target:
                    self.assertEqual(fixture.target.read_bytes(), fixture.payload)
                    self.assertEqual(stat_mode(fixture.target), 0o400)
                    target = fixture.target.stat()
                    self.assertEqual((target.st_dev, target.st_ino), target_identity)
                    self.assertEqual(target.st_nlink, 1)
                state = fixture.load_state()
                self.assertIsNone(state["effect_journal"])
                self.assertEqual(len(state["consumed"]), 1)
                self.assertEqual(state["minimum_revocation_generation"], 3)
                self.assertEqual(state["minimum_mediator_health_epoch"], 4)
                self.assertEqual(list(fixture.staging.iterdir()), [])

    @unittest.skipUnless(hasattr(os, "fork"), "requires process crash injection")
    def test_recovery_rejects_contradictory_effects_and_suspicious_orphans(
        self,
    ) -> None:
        for scenario, checkpoint in (
            ("foreign-target", "after_pending"),
            ("pending-target-only", "after_link"),
        ):
            with self.subTest(scenario), tempfile.TemporaryDirectory() as temporary:
                fixture = _Fixture(Path(temporary).resolve())
                self.assertEqual(
                    _crash_during_mediation(fixture, checkpoint),
                    _CRASH_EXIT,
                )
                if scenario == "foreign-target":
                    fixture.target.write_bytes(fixture.payload)
                    fixture.target.chmod(0o400)
                else:
                    next(fixture.staging.iterdir()).unlink()

                with self.assertRaises(RuntimeActionBrokerError):
                    mediate_runtime_create(
                        fixture.envelope,
                        fixture.config,
                        clock=lambda: 100,
                    )

                self.assertEqual(fixture.target.read_bytes(), fixture.payload)
                self.assertEqual(
                    fixture.load_state()["effect_journal"]["status"],
                    "PENDING",
                )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            self.assertEqual(
                _crash_during_mediation(fixture, "after_applied"),
                _CRASH_EXIT,
            )
            state = fixture.load_state()
            recorded_inode = state["effect_journal"]["staging_inode"]
            staged = next(fixture.staging.iterdir())
            fixture.target.unlink()
            fixture.target.write_bytes(fixture.payload)
            fixture.target.chmod(0o400)
            foreign = fixture.target.stat()

            with self.assertRaises(RuntimeActionBrokerError):
                mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )

            self.assertEqual(
                fixture.load_state()["effect_journal"]["status"],
                "APPLIED",
            )
            self.assertEqual(staged.stat().st_ino, recorded_inode)
            current = fixture.target.stat()
            self.assertEqual(
                (current.st_dev, current.st_ino),
                (foreign.st_dev, foreign.st_ino),
            )
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            orphan = fixture.staging / (".aragorn-runtime-" + "a" * 24)
            orphan.write_bytes(fixture.payload)
            orphan.chmod(0o400)
            alias = fixture.protected / "unrelated"
            os.link(orphan, alias)

            with self.assertRaises(RuntimeActionBrokerError):
                mediate_runtime_create(
                    fixture.envelope,
                    fixture.config,
                    clock=lambda: 100,
                )

            self.assertEqual(orphan.stat().st_nlink, 2)
            self.assertEqual(alias.read_bytes(), fixture.payload)
            self.assertEqual(fixture.load_state()["consumed"], [])

    @unittest.skipUnless(hasattr(os, "fork"), "requires process crash injection")
    def test_pending_recovery_preserves_publisher_floor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            self.assertEqual(
                _crash_during_mediation(fixture, "after_pending"),
                _CRASH_EXIT,
            )
            publication = {**fixture.revocations, "generation": 5}
            publish_runtime_control_document(
                fixture.paths["revocations"],
                publication,
                fixture.config,
                clock=lambda: 100,
            )

            replay = mediate_runtime_create(
                fixture.envelope,
                fixture.config,
                clock=lambda: 100,
            )

            self.assertEqual(replay["reason_codes"], ["BROKER_REPLAY_BLOCKED"])
            state = fixture.load_state()
            self.assertEqual(state["minimum_revocation_generation"], 5)
            self.assertEqual(state["minimum_mediator_health_epoch"], 4)
            self.assertIsNone(state["effect_journal"])
            self.assertEqual(len(state["consumed"]), 1)
            self.assertFalse(fixture.target.exists())
            self.assertEqual(list(fixture.staging.iterdir()), [])

    def test_startup_recovery_precedes_socket_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            from aragorn import runtime_action_broker as broker

            fixture.state["effect_journal"] = {}
            _write_control(fixture.paths["state"], fixture.state)
            with (
                patch.object(broker.socket, "SO_PEERCRED", 17, create=True),
                patch.object(broker.socket, "socket") as create_socket,
                self.assertRaises(RuntimeActionBrokerError),
            ):
                broker.serve_runtime_action_broker(fixture.config)
            create_socket.assert_not_called()

    def test_startup_migrates_private_v1_state_without_losing_floors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            from aragorn import runtime_action_broker as broker

            consumed = {
                "request_digest": canonical_digest(fixture.request),
                "observation_digest": canonical_digest(fixture.observation),
                "expires_at_unix": 105,
            }
            legacy = {
                key: value
                for key, value in fixture.state.items()
                if key != "effect_journal"
            }
            legacy["schema"] = "aragorn/runtime-action-broker-state/v1"
            legacy["minimum_revocation_generation"] = 3
            legacy["minimum_mediator_health_epoch"] = 4
            legacy["consumed"] = [consumed]
            _write_control(fixture.paths["state"], legacy)

            broker._recover_before_listen(fixture.config, 0.5)

            migrated = fixture.load_state()
            self.assertEqual(
                migrated["schema"],
                "aragorn/runtime-action-broker-state/v2",
            )
            self.assertEqual(migrated["minimum_revocation_generation"], 3)
            self.assertEqual(migrated["minimum_mediator_health_epoch"], 4)
            self.assertEqual(migrated["consumed"], [consumed])
            self.assertIsNone(migrated["effect_journal"])

    def test_stream_frame_and_peer_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            raw = canonical_json(fixture.envelope)
            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.sendall(_FRAME_HEADER.pack(len(raw)) + raw)
                client.shutdown(socket.SHUT_WR)
                with (
                    patch(
                        "aragorn.runtime_action_broker._peer_credentials",
                        return_value=(123, os.geteuid() + 1, os.getegid()),
                    ),
                    patch("aragorn.runtime_action_broker.time.time", return_value=100),
                ):
                    _handle_connection(server, fixture.config, timeout_seconds=0.5)
                response_size = _FRAME_HEADER.unpack(_recv_exact(client, 4))[0]
                response = json.loads(_recv_exact(client, response_size))
                self.assertEqual(response["effect_status"], "CREATED")
                self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            finally:
                client.close()
                server.close()

        noncanonical = b'{"effect":{}, "request":{},"schema":"x"}'
        overflow = b'{"a":1e400}'
        bad_frames = (
            _FRAME_HEADER.pack(len(noncanonical)) + noncanonical,
            _FRAME_HEADER.pack(1) + b"{}trailing",
            _FRAME_HEADER.pack(len(overflow)) + overflow,
            _FRAME_HEADER.pack(64 * 1024 + 1),
            _FRAME_HEADER.pack(10) + b"{}",
        )
        for index, frame in enumerate(bad_frames):
            with self.subTest(index), tempfile.TemporaryDirectory() as temporary:
                fixture = _Fixture(Path(temporary).resolve())
                client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    client.sendall(frame)
                    client.shutdown(socket.SHUT_WR)
                    with (
                        patch(
                            "aragorn.runtime_action_broker._peer_credentials",
                            return_value=(123, os.geteuid() + 1, os.getegid()),
                        ),
                        self.assertRaises(RuntimeActionBrokerError),
                    ):
                        _handle_connection(server, fixture.config, timeout_seconds=0.5)
                    self.assertFalse(fixture.target.exists())
                finally:
                    client.close()
                    server.close()

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                with (
                    patch(
                        "aragorn.runtime_action_broker._peer_credentials",
                        return_value=(123, os.geteuid() + 2, os.getegid()),
                    ),
                    self.assertRaises(RuntimeActionBrokerError),
                ):
                    _handle_connection(server, fixture.config, timeout_seconds=0.5)
                self.assertFalse(fixture.target.exists())
            finally:
                client.close()
                server.close()


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = connection.recv(size - len(received))
        if not chunk:
            raise AssertionError("test response ended early")
        received.extend(chunk)
    return bytes(received)


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
