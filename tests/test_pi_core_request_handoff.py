"""Focused inert request-reader/authority checks; no sockets, services or effects."""

import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import unittest
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path
from unittest import mock

from aragorn import pi_core_request_handoff as handoff
from aragorn import pi_core_identity_handoff as transport
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


def activation():
    return {**{key: "sha256:" + "a" * 64 for key in handoff.identity._PINS},
        "schema": handoff.identity.ACTIVATION_SCHEMA, "authority": handoff.identity.ACTIVATION_AUTHORITY,
        "activation_id": "a" * 32, "session_id": "a" * 32, "run_id": "a" * 32,
        "pid": 300, "uid": 1201, "gid": 1202, "start_time_ticks": 50,
        "mount_namespace": {"device": 1, "inode": 2}, "cgroup": "/system.slice/pi.service",
        "expires_at_monotonic_ns": 120_000_000_000,
        "boot_id": "11111111-2222-3333-4444-555555555555"}


def request():
    return {"schema": "aragorn/runtime-action-worker-request/v1",
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY", "target_name": "result.txt",
        "payload_base64": "eA==", "session_id": "a" * 32, "run_id": "a" * 32,
        "tool_call_digest": "sha256:" + "b" * 64}


def binding():
    return handoff.worker.RuntimeActionWorkerBinding(*["sha256:" + "a" * 64] * 3, 1)


def envelope():
    return {"schema": "aragorn/runtime-action-broker-request/v1", "request": {
        "schema": "aragorn/runtime-action-request/v1", "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "runtime_digest": "sha256:" + "a" * 64, "active_skill_digest": "sha256:" + "a" * 64,
        "policy_digest": "sha256:" + "a" * 64, "policy_version": 1,
        "session_id": "a" * 32, "run_id": "a" * 32, "tool_call_id": "sha256:" + "b" * 64,
        "operation_digest": canonical_digest({"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}),
        "path_digest": "sha256:" + "c" * 64, "payload_digest": "sha256:" + hashlib.sha256(b"x").hexdigest(),
        "issued_at_unix": 100, "expires_at_unix": 105}, "effect": {
        "schema": "aragorn/runtime-create-file/v1", "operation": "create", "target_name": "result.txt", "payload_base64": "eA=="}}


def result():
    return handoff.worker._worker_result(canonical_digest(request()), "COMPLETED", {
        "schema": "aragorn/runtime-action-broker-result/v1",
        "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "request_digest": canonical_digest(envelope()["request"]), "observation_digest": "sha256:" + "d" * 64,
        "target_name": "result.txt", "verdict": "BLOCK", "reason_codes": ["POLICY_BLOCKED"],
        "effect_status": "NOT_PERFORMED", "decision": None})


def fields():
    return {"nonce": "b" * 32, "activation_digest": canonical_digest(activation()),
        "request_digest": canonical_digest(request()), "deadline_ns": 120_000_000_000}


def offer():
    return handoff._packet("OFFER", **fields(), activation=activation(), worker_request=request())


class InertTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system"), (os, "open")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        for name in ("pidfd_open", "fork", "posix_spawn", "posix_spawnp"):
            self.stack.enter_context(mock.patch.object(os, name, create=True, side_effect=AssertionError("process operation forbidden")))
        self.stack.enter_context(mock.patch.object(handoff.time, "monotonic", return_value=100.0))
        self.stack.enter_context(mock.patch.object(handoff.time, "monotonic_ns", return_value=100_000_000_000))
        self.stack.enter_context(mock.patch.object(handoff.secrets, "token_hex", return_value="b" * 32))
        self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(os, "getegid", return_value=0))
        self.close = self.stack.enter_context(mock.patch.object(os, "close"))
        for name in ("open_peer_pidfd", "require_live_pidfd", "_read_virtual_file", "measure_runtime_process_profile"):
            self.stack.enter_context(mock.patch.object(handoff.process, name, side_effect=AssertionError("kernel read forbidden")))
        self.stack.enter_context(mock.patch.object(handoff.identity, "_boot_id", side_effect=AssertionError("boot read forbidden")))


class ProjectionTests(InertTests):
    def test_exact_create_projection_and_bound_block_result(self):
        self.assertEqual(handoff.validate_projection(envelope(), request(), activation(), binding()), envelope())
        self.assertEqual(handoff._result(envelope(), result(), request(), activation(), binding()), result())

    def test_changed_target_payload_session_tool_or_pins_refuse(self):
        changes = [("effect", "target_name", "other.txt"), ("effect", "payload_base64", "eQ=="),
            ("request", "session_id", "z"), ("request", "run_id", "z"),
            ("request", "tool_call_id", "sha256:" + "f" * 64),
            ("request", "runtime_digest", "sha256:" + "f" * 64),
            ("request", "active_skill_digest", "sha256:" + "f" * 64),
            ("request", "policy_digest", "sha256:" + "f" * 64),
            ("request", "payload_digest", "sha256:" + "f" * 64),
            ("request", "operation_digest", "sha256:" + "f" * 64)]
        for section, name, value in changes:
            changed = envelope()
            changed[section][name] = value
            with self.subTest(name=name), self.assertRaises((RuntimeError, ValueError)):
                handoff.validate_projection(changed, request(), activation(), binding())

    def test_fixed_policy_version_and_worker_session_cannot_change(self):
        with self.assertRaises(RuntimeError):
            handoff.validate_projection(envelope(), request(), activation(), replace(binding(), policy_version=2))
        with self.assertRaises(RuntimeError):
            handoff.validate_projection(envelope(), {**request(), "run_id": "z"}, activation(), binding())

    def test_fabricated_success_result_and_mismatched_digests_refuse(self):
        for changes in ({"request_digest": "sha256:" + "f" * 64}, {"authority": "EFFECT_AUTHORITY"},
                        {"status": "COMPLETED", "broker_result": None}, {"extra": True}):
            with self.subTest(changes=changes), self.assertRaises((RuntimeError, ValueError)):
                handoff._result(envelope(), {**result(), **changes}, request(), activation(), binding())

    def test_offer_requires_exact_digests_expiry_and_session(self):
        for changes in ({"request_digest": "sha256:" + "f" * 64}, {"deadline_ns": 120_000_000_001},
                        {"activation_digest": "sha256:" + "f" * 64}, {"worker_request": {**request(), "session_id": "wrong"}}):
            with self.subTest(changes=changes), self.assertRaises((RuntimeError, ValueError)):
                handoff._validate_packet({**offer(), **changes})

    def test_packet_kind_and_sequence_bounds_are_closed(self):
        for value in ({**offer(), "kind": "COMMIT"}, {**offer(), "kind": []},
                      handoff._packet("CHECK", **fields(), sequence=0),
                      handoff._packet("CHECK", **fields(), sequence=17),
                      handoff._packet("CURRENT", **fields(), sequence=True)):
            with self.subTest(kind=value["kind"]), self.assertRaises(RuntimeError):
                handoff._validate_packet(value)

    def test_maximum_existing_payload_fits_bounded_offer(self):
        changed = {**request(), "payload_base64": base64.b64encode(b"x" * 32768).decode("ascii")}
        value = {**offer(), "worker_request": changed, "request_digest": canonical_digest(changed)}
        handoff._validate_packet(value)
        self.assertLess(len(canonical_json(value)), handoff.MAX_PACKET_BYTES)


class AuthorityTests(InertTests):
    def setUp(self):
        super().setUp()
        self.connection = mock.Mock()
        self.events = []
        self.latest = None
        self.offered = offer()
        self.receive_count = 0
        self.override = None
        self.stack.enter_context(mock.patch.object(transport, "guard_channel", return_value=80))
        self.live = self.stack.enter_context(mock.patch.object(transport, "require_peer_live"))
        self.pidfd = self.stack.enter_context(mock.patch.object(transport, "validate_worker_pidfd"))

        def send(connection, document, deadline, **kwargs):
            self.latest = document
            self.events.append(document["kind"])

        def receive(connection, peer, deadline, **kwargs):
            self.receive_count += 1
            if self.receive_count == 1:
                return self.offered, (81,)
            if self.override is not None:
                return self.override, ()
            return {**self.latest, "kind": "CURRENT"}, ()

        self.send = self.stack.enter_context(mock.patch.object(handoff, "_send", side_effect=send))
        self.receive = self.stack.enter_context(mock.patch.object(handoff, "_receive", side_effect=receive))
        self.close.side_effect = lambda fd: self.events.append(("close", fd))

    def held(self, **changes):
        return handoff.hold_broker_request_authority(self.connection,
            **{"expected_supervisor_peer": (200, 0, 0), "deadline": 120.0, **changes})

    def test_constructor_cannot_mint_without_protected_factory(self):
        for values in ({}, {"seal": object()}, {"seal": {"authorized": True}}):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                handoff.PiRequestAuthority(**values)

    def test_scoped_authority_consumes_once_and_closes_before_done(self):
        with self.held() as authority:
            self.assertIs(type(authority), handoff.PiRequestAuthority)
            authority.begin()
            authority.finish(envelope(), result())
            with self.assertRaises(RuntimeError):
                authority.begin()
        self.assertEqual(self.events, ["CHALLENGE", "CHECK", "CHECK", ("close", 81), ("close", 80), "DONE"])
        self.connection.close.assert_not_called()

    def test_properties_detach_nested_documents_and_cannot_be_replaced(self):
        with self.held() as authority:
            document = authority.activation
            document["mount_namespace"]["inode"] = 999
            authority.worker_request["target_name"] = "wrong.txt"
            self.assertEqual(authority.activation["mount_namespace"]["inode"], 2)
            self.assertEqual(authority.worker_request, request())
            with self.assertRaises(AttributeError):
                authority.deadline = 999

    def test_context_exit_revokes_without_fabricated_done(self):
        with self.held() as authority:
            authority.begin()
        with self.assertRaises(RuntimeError):
            authority.guard()
        self.assertNotIn("DONE", self.events)
        self.assertEqual(self.close.call_args_list, [mock.call(81), mock.call(80)])

    def test_failed_current_invalidates_and_never_retries(self):
        with self.held() as authority:
            self.override = handoff._packet("CURRENT", **fields(), sequence=2)
            with self.assertRaises(RuntimeError):
                authority.begin()
            with self.assertRaises(RuntimeError):
                authority.guard()
        self.assertEqual(self.events.count("CHECK"), 1)

    def test_failed_begin_remains_consumed(self):
        with self.held() as authority:
            self.live.side_effect = RuntimeError("publisher exited")
            with self.assertRaises(RuntimeError):
                authority.begin()
            self.live.side_effect = None
            with self.assertRaisesRegex(RuntimeError, "consumed"):
                authority.begin()

    def test_check_budget_exhaustion_cannot_extend_authority(self):
        with self.held() as authority:
            authority.begin()
            for _ in range(15):
                authority.guard()
            # Mocked _send bypasses schema validation; restore only its actual
            # validator so sequence 17 refuses before any transport operation.
            self.send.side_effect = lambda connection, document, deadline: handoff._validate_packet(document)
            with self.assertRaises(RuntimeError):
                authority.guard()
        self.assertEqual(self.receive_count, 17)

    def test_expired_authority_cannot_issue_fresh_check(self):
        with self.held() as authority:
            with mock.patch.object(handoff.time, "monotonic_ns", return_value=120_000_000_000):
                with self.assertRaises(RuntimeError):
                    authority.begin()
        self.assertNotIn("CHECK", self.events)

    def test_wrong_nonce_deadline_or_root_peer_refuses_and_closes(self):
        self.offered["nonce"] = "f" * 32
        with self.assertRaises(RuntimeError), self.held():
            pass
        self.assertEqual(self.close.call_args_list, [mock.call(81), mock.call(80)])
        with self.assertRaises(RuntimeError), self.held(expected_supervisor_peer=(200, 1, 0)):
            pass

    def test_finish_requires_begin_and_matching_result(self):
        with self.held() as authority:
            with self.assertRaises(RuntimeError):
                authority.finish(envelope(), result())
            authority.begin()
            with self.assertRaises(RuntimeError):
                authority.finish(envelope(), {**result(), "request_digest": "sha256:" + "f" * 64})
        self.assertNotIn("DONE", self.events)

    def test_owned_close_failure_attempts_both_handles_and_prevents_done(self):
        with self.held() as authority:
            authority.begin()
            self.close.side_effect = [OSError("close failed"), None]
            with self.assertRaises(RuntimeError):
                authority.finish(envelope(), result())
        self.assertEqual(self.close.call_args_list, [mock.call(81), mock.call(80)])
        self.assertNotIn("DONE", self.events)

    def test_done_send_failure_has_no_retry_or_second_close(self):
        with self.held() as authority:
            authority.begin()
            original = self.send.side_effect
            def fail_done(connection, document, deadline, **kwargs):
                original(connection, document, deadline, **kwargs)
                if document["kind"] == "DONE":
                    raise OSError("send uncertain")
            self.send.side_effect = fail_done
            with self.assertRaises(OSError):
                authority.finish(envelope(), result())
            with self.assertRaises(RuntimeError):
                authority.finish(envelope(), result())
        self.assertEqual(self.events.count("DONE"), 1)
        self.assertEqual(self.close.call_count, 2)


class RootReaderTests(InertTests):
    def setUp(self):
        super().setUp()
        self.worker = mock.Mock()
        self.broker = mock.Mock()
        self.worker.fileno.return_value, self.broker.fileno.return_value = 1, 2
        self.worker.getsockopt.side_effect = lambda level, option: socket.AF_UNIX if option == transport._DOMAIN else socket.SOCK_STREAM
        self.profile = handoff.process.RuntimeProcessProfile("sha256:" + "a" * 64, "sha256:" + "a" * 64,
            "/system.slice/pi.service", Path("/var/lib/aragorn/admitted/version/SKILL.md"), "sha256:" + "a" * 64)
        self.events = []
        self.packet_list = [(handoff._packet("CHALLENGE", nonce="b" * 32), ()),
            (handoff._packet("CHECK", **fields(), sequence=1), ()),
            (handoff._packet("DONE", **fields(), envelope=envelope(), result=result()), ())]
        self.stack.enter_context(mock.patch.object(handoff.broker, "_peer_credentials", return_value=(300, 1201, 1202)))
        self.read_activation = self.stack.enter_context(mock.patch.object(handoff.identity, "read_activation", return_value=activation()))
        self.measured = self.stack.enter_context(mock.patch.object(handoff.identity, "_measured", return_value={"fixture": "measured"}))
        self.stack.enter_context(mock.patch.object(handoff.identity, "_remaining"))
        self.stack.enter_context(mock.patch.object(handoff.identity, "_lineage_matches"))
        self.stack.enter_context(mock.patch.object(handoff.process, "open_peer_pidfd", return_value=71))
        self.stack.enter_context(mock.patch.object(transport, "guard_channel", return_value=81))
        self.stack.enter_context(mock.patch.object(transport, "require_peer_live"))

        @contextmanager
        def held(*args, **kwargs):
            self.events.append("lineage_enter")
            yield {"fixture": "lineage"}
            self.events.append("lineage_exit")

        self.lineage = self.stack.enter_context(mock.patch.object(handoff.identity.lineage, "hold_runtime_active_skill_lineage", side_effect=held))
        self.read = self.stack.enter_context(mock.patch.object(handoff.broker, "_read_frame", return_value=request()))
        self.receive = self.stack.enter_context(mock.patch.object(handoff, "_receive", side_effect=lambda *a, **kw: self.packet_list.pop(0)))
        self.send = self.stack.enter_context(mock.patch.object(handoff, "_send", side_effect=lambda c, doc, d, **kw: self.events.append(doc["kind"])))
        self.deliver = self.stack.enter_context(mock.patch.object(handoff.broker, "_send_frame", side_effect=lambda *a: self.events.append("worker_response")))
        self.close.side_effect = lambda fd: self.events.append(("close", fd))

    def handle(self, **changes):
        options = dict(activation_path=Path("/var/lib/aragorn/pi-activations") / ("a" * 32 + ".json"),
            profile=self.profile, protected_install_root=Path("/var/lib/aragorn/admitted"), grant={},
            binding=binding(), expected_broker_peer=(400, 0, 0), deadline=120.0)
        options.update(changes)
        return handoff.handle_pi_request_connection(self.worker, self.broker, **options)

    def test_actual_frame_bound_to_offer_and_cleanup_precedes_success(self):
        actual = self.handle()
        self.assertEqual(actual, result())
        self.read.assert_called_once_with(self.worker, 120.0)
        offered = self.send.call_args_list[0]
        self.assertEqual(offered.args[1], offer())
        self.assertEqual(offered.kwargs, {"rights": (71,)})
        self.assertEqual(self.events, ["lineage_enter", "OFFER", "CURRENT", "lineage_exit",
            ("close", 71), ("close", 81), "worker_response"])
        self.assertGreaterEqual(self.measured.call_count, 5)
        self.worker.close.assert_not_called()
        self.broker.close.assert_not_called()

    def test_request_session_mismatch_is_not_submitted(self):
        self.read.return_value = {**request(), "session_id": "wrong"}
        self.assertEqual(self.handle()["status"], "NOT_SUBMITTED")
        self.send.assert_not_called()

    def test_activation_change_before_offer_is_not_submitted(self):
        self.read_activation.side_effect = [activation(), {**activation(), "pid": 301}]
        self.assertEqual(self.handle()["status"], "NOT_SUBMITTED")
        self.send.assert_not_called()

    def test_worker_measurement_change_after_offer_is_indeterminate(self):
        self.measured.side_effect = [{"fixture": "measured"}] * 3 + [{"fixture": "changed"}]
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.assertEqual([call.args[1]["kind"] for call in self.send.call_args_list], ["OFFER"])

    def test_short_uncertain_offer_never_retries(self):
        self.send.side_effect = OSError("send uncertain")
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.send.assert_called_once()

    def test_missing_or_replayed_check_sequence_is_indeterminate(self):
        self.packet_list[1] = (handoff._packet("CHECK", **fields(), sequence=2), ())
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.assertEqual(self.send.call_count, 1)

    def test_done_without_current_check_is_not_success(self):
        self.packet_list.pop(1)
        self.assertEqual(self.handle()["status"], "INDETERMINATE")

    def test_done_cannot_substitute_target_payload_or_result(self):
        self.packet_list[2][0]["envelope"]["effect"]["target_name"] = "other.txt"
        self.assertEqual(self.handle()["status"], "INDETERMINATE")

    def test_lineage_cleanup_failure_overrides_completed_result(self):
        @contextmanager
        def fails(*args, **kwargs):
            yield {"fixture": "lineage"}
            raise RuntimeError("lineage cleanup failed")
        self.lineage.side_effect = fails
        self.assertEqual(self.handle()["status"], "INDETERMINATE")

    def test_descriptor_cleanup_failure_attempts_all_and_overrides_success(self):
        self.close.side_effect = [OSError("close failed"), None]
        self.assertEqual(self.handle()["status"], "INDETERMINATE")
        self.assertEqual(self.close.call_args_list, [mock.call(71), mock.call(81)])

    def test_unreadable_request_never_offers_or_fabricates_digest(self):
        self.read.side_effect = RuntimeError("invalid frame")
        with self.assertRaises(handoff.PiRequestHandoffError):
            self.handle()
        self.send.assert_not_called()
        self.deliver.assert_not_called()

    def test_nonroot_bad_channel_or_unpinned_configuration_refuses(self):
        with mock.patch.object(os, "geteuid", return_value=1):
            with self.assertRaises(RuntimeError):
                self.handle()
        self.worker.fileno.return_value = 2
        with self.assertRaises(RuntimeError):
            self.handle()
        self.worker.fileno.return_value = 1
        self.worker.getsockopt.return_value = socket.SOCK_SEQPACKET
        self.worker.getsockopt.side_effect = lambda level, option: socket.AF_UNIX if option == transport._DOMAIN else socket.SOCK_SEQPACKET
        with self.assertRaises(RuntimeError):
            self.handle()
        self.read.assert_not_called()

    def test_worker_response_delivery_failure_is_uncertain_without_retry(self):
        self.deliver.side_effect = OSError("closed client")
        with self.assertRaisesRegex(handoff.PiRequestHandoffError, "uncertain"):
            self.handle()
        self.deliver.assert_called_once()


class FactoredTransportCompatibilityTests(InertTests):
    def setUp(self):
        super().setUp()
        self.connection = mock.Mock()
        self.peer = (200, 0, 0)
        self.credentials = (socket.SOL_SOCKET, transport._CREDENTIALS, transport._CRED.pack(*self.peer))
        self.stack.enter_context(mock.patch.object(os, "get_inheritable", return_value=False))

    def packet(self, value, descriptors=(81,), flags=0):
        controls = [self.credentials]
        if descriptors:
            controls.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("=" + "i" * len(descriptors), *descriptors)))
        self.connection.recvmsg.return_value = canonical_json(value), controls, flags, None

    def test_raw_request_packet_uses_same_authenticated_descriptor_custody(self):
        self.packet(offer())
        document, rights = handoff._receive(self.connection, self.peer, 120, rights=1)
        self.assertEqual(document, offer())
        self.assertEqual(rights, (81,))
        self.assertEqual(self.connection.recvmsg.call_args.args[2], transport._CLOEXEC)
        self.close.assert_not_called()

    def test_strict_identity_wrapper_rejects_request_offer_and_closes_right(self):
        self.packet(offer())
        with self.assertRaises(RuntimeError):
            transport.receive_packet(self.connection, self.peer, 120, expected_rights=1)
        self.close.assert_called_once_with(81)

    def test_strict_identity_sender_still_rejects_request_fields(self):
        with self.assertRaises(RuntimeError):
            transport.send_packet(self.connection, offer(), 120, rights=(71,))
        self.connection.sendmsg.assert_not_called()

    def test_strict_identity_unchanged_challenge_remains_compatible(self):
        original = {"schema": transport.SCHEMA, "authority": transport.AUTHORITY, "kind": "CHALLENGE", "nonce": "b" * 32}
        self.packet(original, ())
        self.assertEqual(transport.receive_packet(self.connection, self.peer, 120), (original, ()))
        self.connection.sendmsg.return_value = len(canonical_json(original))
        transport.send_packet(self.connection, original, 120)
        self.connection.sendmsg.assert_called_once()

    def test_bad_request_schema_after_adoption_closes_owned_right(self):
        self.packet({**offer(), "authority": "PORTABLE_EFFECT_PERMISSION"})
        with self.assertRaises(RuntimeError):
            handoff._receive(self.connection, self.peer, 120, rights=1)
        self.close.assert_called_once_with(81)

    def test_raw_transport_rejects_bad_credentials_and_truncation(self):
        for failure in ("credentials", "truncation"):
            self.close.reset_mock()
            self.packet(offer(), flags=getattr(socket, "MSG_CTRUNC", 8) if failure == "truncation" else 0)
            if failure == "credentials":
                self.connection.recvmsg.return_value[1][0] = (socket.SOL_SOCKET,
                    transport._CREDENTIALS, transport._CRED.pack(201, 0, 0))
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                handoff._receive(self.connection, self.peer, 120, rights=1)
            self.close.assert_called_once_with(81)

    def test_raw_send_remains_atomic_no_retry(self):
        self.connection.sendmsg.return_value = 1
        with self.assertRaises(RuntimeError):
            handoff._send(self.connection, offer(), 120, rights=(71,))
        self.connection.sendmsg.assert_called_once()
        self.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
