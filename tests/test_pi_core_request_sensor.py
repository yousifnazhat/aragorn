"""New sensor adapter checks: mocked transport/kernel, real owned-file hashing.

No listener, socketpair, subprocess, worker or native sensor is run. Process
attribution and custody are mocked boundaries, not deployment qualification.
"""

import copy
import json
import os
import socket
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_request_sensor as sensor
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests.test_runtime_action_observation_publisher_v2 import _Fixture
from tests.test_runtime_action_observation_publisher_v3 import _grant


class PiRequestSensorTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.fixture = _Fixture(self.root)
        self.stack.callback(self.fixture.close)
        profile = sensor.process.runtime_process_profile({
            "schema": sensor.process.PROFILE_SCHEMA,
            "authority": sensor.process.PROFILE_AUTHORITY,
            "runtime_digest": self.fixture.profile.runtime_digest,
            "executable_digest": self.fixture.profile.executable_digest,
            "cgroup": "/system.slice/aragorn-pi-sensor-fixture.service",
            "skill_path": "/var/lib/aragorn/admitted/versions/fixture/SKILL.md",
        })
        self.fixture.profile = profile
        self.fixture.config = replace(self.fixture.config, runtime_profile=profile)
        self.fixture.attribution.update(profile_digest=profile.digest,
            cgroup=profile.cgroup, skill_path=str(profile.skill_path))
        self.attribution = copy.deepcopy(self.fixture.attribution)
        grant = json.loads(_grant(self.fixture))
        grant["expires_at_unix"] = 200
        self.config = sensor.configured.RuntimeActionObservationPublisherV4Config(
            self.fixture.config, canonical_json(grant), self.root / "admitted")
        self.request = {
            "schema": "aragorn/runtime-action-worker-request/v1",
            "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "session_id": "a" * 32, "run_id": "a" * 32,
            "tool_call_digest": "sha256:" + "b" * 64,
            "target_name": self.fixture.target_name,
            "payload_base64": self.fixture.envelope["effect"]["payload_base64"],
        }
        self.events = []
        self.custody = mock.Mock(spec=socket.socket)
        self.backend = mock.Mock(spec=socket.socket)
        self.source = mock.Mock(spec=socket.socket)
        for connection, fd in ((self.custody, 51), (self.backend, 52), (self.source, 53)):
            connection.fileno.return_value = fd
            connection.getsockopt.side_effect = lambda _level, option: {
                sensor.transport._DOMAIN: socket.AF_UNIX,
                socket.SO_TYPE: socket.SOCK_STREAM}[option]
        self.source.close.side_effect = lambda: self.events.append("source_closed")
        self.backend.shutdown.side_effect = lambda *_: self.events.append("backend_eof")
        self.candidate = SimpleNamespace(worker_connection=self.source,
            request=copy.deepcopy(self.request), request_digest=canonical_digest(self.request),
            deadline=1000.5, guard=mock.Mock(),
            ready=mock.Mock(side_effect=lambda: self.events.append("READY")),
            finish=mock.Mock(side_effect=self.finish))

        @contextmanager
        def held(connection, **options):
            self.assertIs(connection, self.custody)
            self.assertEqual(options, {"expected_supervisor_pid": 200, "deadline": 1001.0})
            self.events.append("candidate_enter")
            try:
                yield self.candidate
            finally:
                self.events.append("candidate_exit")

        @contextmanager
        def held_lineage(pid, measured, grant, **options):
            self.assertEqual(pid, self.fixture.peer[0])
            self.assertEqual(measured, self.attribution)
            self.assertEqual(options, {"protected_root": self.config.protected_install_root,
                "expected_install_uid": 0, "deadline": 1000.5})
            self.events.append("lineage_enter")
            try:
                yield {"active_record_digest": "sha256:" + "f" * 64}
            finally:
                self.events.append("lineage_exit")

        self.hold = self.stack.enter_context(mock.patch.object(sensor.custody,
            "hold_sensor_candidate", side_effect=held))
        self.lineage = self.stack.enter_context(mock.patch.object(sensor.lineage,
            "hold_runtime_active_skill_lineage", side_effect=held_lineage))
        self.stack.enter_context(mock.patch.object(sensor.time, "monotonic", return_value=1000.0))
        self.stack.enter_context(mock.patch.object(sensor.sys, "platform", "linux"))
        self.wall = self.stack.enter_context(mock.patch.object(sensor.time, "time", return_value=100.0))
        selected = self.config.publisher
        self.groups = self.stack.enter_context(mock.patch.object(sensor.os, "getgroups",
            return_value=[selected.expected_broker_gid]))
        self.security = self.stack.enter_context(mock.patch.object(sensor.profiled,
            "_process_security_status", return_value={
                "fsuid": selected.expected_runtime_uid, "fsgid": selected.expected_runtime_gid,
                "cap_eff": 0, "cap_prm": 0, "cap_inh": 0, "cap_amb": 0, "cap_bnd": 0}))
        self.broker_peer = (202, selected.expected_broker_uid, selected.expected_broker_gid)
        self.peer = self.stack.enter_context(mock.patch.object(sensor.broker, "_peer_credentials",
            side_effect=lambda connection: self.broker_peer if connection is self.backend else self.fixture.peer))
        self.pidfd = self.stack.enter_context(mock.patch.object(sensor.process, "open_peer_pidfd",
            side_effect=lambda connection, _pid: 701 if connection is self.backend else 702))
        self.pidfd_live = self.stack.enter_context(mock.patch.object(sensor.process, "require_live_pidfd"))
        self.backend_live = self.stack.enter_context(mock.patch.object(sensor.transport, "require_peer_live"))
        self.measure = self.stack.enter_context(mock.patch.object(sensor.process,
            "measure_runtime_process_profile", side_effect=lambda *_args, **_kwargs: copy.deepcopy(self.attribution)))
        self.open_root = self.stack.enter_context(mock.patch.object(sensor.publisher, "_open_protected_root",
            side_effect=lambda *_: os.dup(self.fixture.protected_fd)))
        real_close = os.close

        def close(fd):
            self.events.append(("close", fd))
            if fd not in (701, 702):
                real_close(fd)

        self.close = self.stack.enter_context(mock.patch.object(sensor.os, "close", side_effect=close))
        self.send = self.stack.enter_context(mock.patch.object(sensor.broker, "_send_frame", side_effect=self.send_frame))
        self.read = self.stack.enter_context(mock.patch.object(sensor.broker, "_read_frame", side_effect=self.read_result))
        self.adopt = self.stack.enter_context(mock.patch.object(sensor.profiled, "_adopt_runtime_fs_identity",
            side_effect=lambda *_: self.events.append("adopt")))
        self.restore = self.stack.enter_context(mock.patch.object(sensor.profiled, "_restore_observer_fs_identity",
            side_effect=lambda *_: self.events.append("restore")))
        self.stack.enter_context(mock.patch.object(sensor.capability.secrets, "token_hex", return_value="c" * 64))
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("live operation forbidden")))

    def send_frame(self, connection, raw, deadline):
        self.assertIs(connection, self.backend)
        self.assertEqual(deadline, 1000.5)
        self.sent = json.loads(raw)
        self.events.append("submit")

    def read_result(self, connection, deadline):
        self.assertIs(connection, self.backend)
        self.assertEqual(deadline, 1000.5)
        self.events.append("response")
        envelope = self.sent["issuance"]["profiled_submission"]["envelope"]
        return {"schema": "aragorn/runtime-action-broker-result/v1",
            "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "request_digest": canonical_digest(envelope["request"]),
            "observation_digest": "sha256:" + "d" * 64,
            "target_name": envelope["effect"]["target_name"], "verdict": "BLOCK",
            "reason_codes": ["BROKER_REPLAY_BLOCKED"], "effect_status": "NOT_PERFORMED", "decision": None}

    def finish(self, result):
        self.assertIn("lineage_exit", self.events)
        self.assertIn(("close", 701), self.events)
        self.assertIn(("close", 702), self.events)
        self.assertEqual(result["effect_status"], "NOT_PERFORMED")
        self.source.close()
        self.events.append("DONE")

    def run_request(self, *, dedicated=False, **options):
        function = sensor.run_pi_sensor_request if dedicated else sensor.handle_pi_sensor_request
        return function(self.custody, self.backend, options.pop("config", self.config),
            **{"expected_supervisor_pid": 200, "deadline": 1001.0, **options})

    def assert_no_shared_stream_operations(self):
        for name in ("recv", "recvmsg", "send", "sendall", "sendmsg", "shutdown", "settimeout"):
            getattr(self.source, name).assert_not_called()
        self.custody.close.assert_not_called()
        self.backend.close.assert_not_called()

    def test_independently_measured_profile_and_real_action_hashing_reach_broker_once(self):
        result = self.run_request()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertFalse(result["phase3_exit_eligible"])
        self.assertFalse(result["observer_fs_identity_restored"])
        self.assertEqual(result["request_digest"], canonical_digest(self.request))
        self.assertEqual(self.measure.call_count, 3)
        for call in self.measure.call_args_list:
            self.assertEqual(call.args, (self.fixture.peer[0], 702, self.fixture.profile))
            self.assertEqual(call.kwargs, {"expected_uid": self.fixture.peer[1], "expected_gid": self.fixture.peer[2]})
        submission = self.sent["issuance"]["profiled_submission"]
        self.assertEqual(submission["runtime_attribution"], self.attribution)
        self.assertEqual(submission["runtime_peer"], dict(zip(("pid", "uid", "gid"), self.fixture.peer)))
        self.assertEqual(submission["measured_action"]["path_digest"], self.fixture.request["path_digest"])
        self.assertEqual(self.sent["authority"], sensor.issuer.LINEAGE_ISSUANCE_AUTHORITY)
        self.assertLess(self.events.index("READY"), self.events.index("submit"))
        self.assertLess(self.events.index("response"), self.events.index("lineage_exit"))
        self.assertLess(self.events.index("lineage_exit"), self.events.index("DONE"))
        self.send.assert_called_once()
        self.backend.shutdown.assert_called_once_with(socket.SHUT_WR)
        self.adopt.assert_not_called()
        self.restore.assert_not_called()
        self.assert_no_shared_stream_operations()

    def test_dedicated_process_adopts_once_and_restores_before_done(self):
        result = self.run_request(dedicated=True)
        self.assertTrue(result["observer_fs_identity_restored"])
        self.adopt.assert_called_once_with(self.fixture.runtime_uid, self.fixture.runtime_gid,
            self.fixture.config.expected_observer_uid, self.fixture.config.expected_observer_gid)
        self.restore.assert_called_once()
        self.assertLess(self.events.index("adopt"), self.events.index("candidate_enter"))
        self.assertLess(self.events.index("lineage_exit"), self.events.index("restore"))
        self.assertLess(self.events.index("restore"), self.events.index("DONE"))

    def test_invalid_supervisor_pid_fails_before_custody(self):
        for pid in (True, 0, -1, 2**31):
            with self.subTest(pid=pid), self.assertRaises(sensor.PiRequestSensorError):
                self.run_request(expected_supervisor_pid=pid)
        self.hold.assert_not_called()
        self.send.assert_not_called()

    def test_expired_deadline_cannot_be_extended(self):
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request(deadline=999.0)
        self.pidfd.assert_not_called()

    def test_custody_cannot_extend_original_deadline(self):
        self.candidate.deadline = 1002.0
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.measure.assert_not_called()
        self.close.assert_called_once_with(701)

    def test_unprepared_fs_identity_is_refused_without_adoption(self):
        self.security.return_value = {**self.security.return_value, "fsuid": 0}
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.hold.assert_not_called()
        self.adopt.assert_not_called()

    def test_any_remaining_sensor_capability_is_refused(self):
        clean = dict(self.security.return_value)
        for field in ("cap_eff", "cap_prm", "cap_inh", "cap_amb", "cap_bnd"):
            self.security.return_value = {**clean, field: 1}
            with self.subTest(field=field), self.assertRaises(sensor.PiRequestSensorError):
                self.run_request()
        self.hold.assert_not_called()

    def test_wrong_effective_sensor_identity_is_refused(self):
        selected = replace(self.config.publisher,
            expected_observer_uid=self.config.publisher.expected_observer_uid + 10)
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request(config=replace(self.config, publisher=selected))
        self.hold.assert_not_called()

    def test_root_sensor_is_refused_even_if_legacy_config_validator_accepts(self):
        with mock.patch.object(sensor.configured, "_validate_config"), self.assertRaises(sensor.PiRequestSensorError):
            self.run_request(config=replace(self.config, publisher=replace(
                self.config.publisher, expected_observer_uid=0)))
        self.pidfd.assert_not_called()

    def test_control_channels_must_be_distinct(self):
        self.custody.fileno.return_value = self.backend.fileno.return_value
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.pidfd.assert_not_called()

    def test_broker_must_be_local_stream_with_exact_configured_peer(self):
        self.backend.getsockopt.side_effect = None
        self.backend.getsockopt.return_value = socket.AF_INET
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.pidfd.assert_not_called()

    def test_wrong_broker_peer_refuses_before_custody(self):
        self.broker_peer = (202, 9999, self.broker_peer[2])
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.hold.assert_not_called()

    def test_custody_authentication_failure_closes_broker_pidfd(self):
        self.hold.side_effect = RuntimeError("wrong root peer")
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.close.assert_called_once_with(701)
        self.measure.assert_not_called()

    def test_worker_descriptor_cannot_alias_backend(self):
        self.candidate.worker_connection = self.backend
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.measure.assert_not_called()

    def test_transferred_worker_descriptor_must_be_local_stream(self):
        self.source.getsockopt.side_effect = None
        self.source.getsockopt.return_value = socket.SOCK_SEQPACKET
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.measure.assert_not_called()

    def test_worker_peer_is_measured_not_copied_from_candidate(self):
        self.peer.side_effect = lambda connection: self.broker_peer if connection is self.backend else (101, 9999, 9998)
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.measure.assert_not_called()

    def test_missing_worker_peer_pidfd_refuses_without_submission(self):
        self.pidfd.side_effect = (701, OSError("SO_PEERPIDFD unavailable"))
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.close.assert_called_once_with(701)
        self.send.assert_not_called()

    def test_dead_worker_pidfd_cannot_issue(self):
        self.pidfd_live.side_effect = RuntimeError("worker exited")
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.send.assert_not_called()
        self.assertIn(("close", 702), self.events)

    def test_root_withdrawal_cannot_issue(self):
        self.candidate.guard.side_effect = RuntimeError("root unavailable")
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.send.assert_not_called()

    def test_candidate_request_digest_mismatch_is_refused(self):
        self.candidate.request_digest = "sha256:" + "0" * 64
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.open_root.assert_not_called()

    def test_candidate_request_cannot_carry_attribution_or_effect_authority(self):
        self.candidate.request["runtime_attribution"] = self.attribution
        self.candidate.request_digest = canonical_digest(self.candidate.request)
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.open_root.assert_not_called()

    def test_independent_measurement_error_is_not_replaced_by_root_metadata(self):
        self.measure.side_effect = RuntimeError("proc measurement denied")
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.lineage.assert_not_called()
        self.send.assert_not_called()

    def test_changed_after_measurement_refuses_before_ready(self):
        self.measure.side_effect = (self.attribution, {**self.attribution, "start_time_ticks": 742})
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.candidate.ready.assert_not_called()
        self.send.assert_not_called()

    def test_changed_final_measurement_refuses_before_ready(self):
        self.measure.side_effect = (self.attribution, self.attribution,
            {**self.attribution, "mount_namespace": {"device": 7, "inode": 9}})
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.candidate.ready.assert_not_called()
        self.send.assert_not_called()

    def test_quarantine_or_lineage_refusal_never_submits(self):
        self.lineage.side_effect = RuntimeError("active skill quarantined")
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.open_root.assert_not_called()

    def test_grant_profile_pin_mismatch_fails_real_issuer(self):
        grant = json.loads(self.config.capability_grant)
        grant["runtime_profile_digest"] = "sha256:" + "e" * 64
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request(config=replace(self.config, capability_grant=canonical_json(grant)))
        self.send.assert_not_called()

    def test_expired_grant_is_not_refreshed(self):
        self.wall.return_value = 201.0
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.lineage.assert_not_called()

    def test_ready_failure_does_not_submit_or_retry(self):
        self.candidate.ready.side_effect = OSError("READY uncertain")
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.candidate.ready.assert_called_once()
        self.send.assert_not_called()

    def test_possible_backend_send_is_indeterminate_without_retry(self):
        self.send.side_effect = OSError("short write")
        with self.assertRaises(sensor.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.send.assert_called_once()
        self.read.assert_not_called()
        self.candidate.finish.assert_not_called()

    def test_response_failure_after_send_is_indeterminate(self):
        self.read.side_effect = OSError("response lost")
        with self.assertRaises(sensor.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.send.assert_called_once()
        self.candidate.finish.assert_not_called()

    def test_unbound_broker_result_never_gets_done(self):
        self.read.side_effect = lambda *_: {"status": "COMPLETED"}
        with self.assertRaises(sensor.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.candidate.finish.assert_not_called()

    def test_owned_pidfd_close_failure_prevents_done_and_closes_other_handles(self):
        original = self.close.side_effect
        self.close.side_effect = lambda fd: (_ for _ in ()).throw(OSError("close uncertain")) if fd == 701 else original(fd)
        with self.assertRaises(sensor.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.assertIn(("close", 702), self.events)
        self.assertEqual(sum(call.args == (701,) for call in self.close.call_args_list), 1)
        self.candidate.finish.assert_not_called()

    def test_custody_done_failure_is_indeterminate(self):
        self.candidate.finish.side_effect = RuntimeError("DONE uncertain")
        with self.assertRaises(sensor.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.candidate.finish.assert_called_once()
        self.send.assert_called_once()

    def test_dedicated_restore_failure_is_not_retried_and_prevents_done(self):
        self.restore.side_effect = RuntimeError("FS restoration uncertain")
        with self.assertRaises(sensor.broker.RuntimeActionEffectIndeterminate):
            self.run_request(dedicated=True)
        self.restore.assert_called_once()
        self.candidate.finish.assert_not_called()

    def test_dedicated_pre_submission_failure_still_restores_once(self):
        self.measure.side_effect = RuntimeError("measurement failed")
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request(dedicated=True)
        self.restore.assert_called_once()
        self.send.assert_not_called()

    def test_failed_adoption_is_not_retried_or_restored_again(self):
        self.adopt.side_effect = RuntimeError("existing adoption helper already restored")
        with self.assertRaises(RuntimeError):
            self.run_request(dedicated=True)
        self.adopt.assert_called_once()
        self.restore.assert_not_called()
        self.hold.assert_not_called()

    def test_non_linux_dedicated_setup_refuses_before_privilege_transition(self):
        with mock.patch.object(sensor.sys, "platform", "darwin"), self.assertRaises(sensor.PiRequestSensorError):
            self.run_request(dedicated=True)
        self.adopt.assert_not_called()
        self.hold.assert_not_called()

    def test_fs_identity_change_during_measurement_refuses_before_submission(self):
        def change(*_args, **_kwargs):
            self.security.return_value = {**self.security.return_value, "cap_eff": 1}
            return self.attribution

        self.measure.side_effect = change
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.send.assert_not_called()

    def test_dead_broker_after_submission_is_indeterminate(self):
        def live(*_args):
            if "submit" in self.events:
                raise RuntimeError("broker exited")

        self.backend_live.side_effect = live
        with self.assertRaises(sensor.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.candidate.finish.assert_not_called()

    def test_original_deadline_expiring_at_ready_prevents_submission(self):
        self.candidate.ready.side_effect = lambda: self.stack.enter_context(
            mock.patch.object(sensor.time, "monotonic", return_value=1001.0))
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.send.assert_not_called()

    def test_lineage_cleanup_cannot_downgrade_possible_submission(self):
        @contextmanager
        def uncertain(*_args, **_kwargs):
            try:
                yield {"active_record_digest": "sha256:" + "f" * 64}
            finally:
                raise RuntimeError("lineage cleanup uncertain")

        self.lineage.side_effect = uncertain
        self.send.side_effect = OSError("send uncertain")
        with self.assertRaises(sensor.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.candidate.finish.assert_not_called()

    def test_missing_sensor_broker_traversal_group_is_refused(self):
        self.groups.return_value = [self.config.publisher.expected_observer_gid]
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.pidfd.assert_not_called()

    def test_unrelated_supplementary_group_is_refused(self):
        self.groups.return_value += [0]
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request()
        self.pidfd.assert_not_called()

    def test_optional_sensor_primary_supplementary_group_is_allowed(self):
        self.groups.return_value += [self.config.publisher.expected_observer_gid]
        self.assertEqual(self.run_request()["status"], "COMPLETED")

    def test_worker_cannot_share_the_broker_primary_group(self):
        selected = replace(self.config.publisher,
            expected_runtime_gid=self.config.publisher.expected_broker_gid)
        with self.assertRaises(sensor.PiRequestSensorError):
            self.run_request(config=replace(self.config, publisher=selected))
        self.pidfd.assert_not_called()
