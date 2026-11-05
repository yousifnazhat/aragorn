"""New service protocol/lifecycle checks with every native edge intercepted."""

import copy
import os
import socket
import subprocess
import unittest
from contextlib import ExitStack
from unittest import mock

from aragorn import pi_core_openai_transport as transport
from aragorn import pi_core_provider_service as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_openai_responses as fixtures


def request_packet():
    request, route, profile = fixtures.request(), fixtures.route(), fixtures.profile()
    wire = subject.codec.wire_descriptor(request, route, profile)
    return {"schema": subject.SCHEMA, "authority": subject.AUTHORITY, "kind": "REQUEST",
        "nonce": "a" * 32, "deadline_ns": 110_000_000_000,
        "request_digest": canonical_digest(request), "wire_digest": canonical_digest(wire),
        "request": request, "route": route, "profile": profile, "wire": wire}


def completion():
    return subject.codec.parse_response(canonical_json(fixtures.response()), fixtures.request())


def result_packet(status="COMPLETED", *, connect=True, send=True):
    value = request_packet()
    result = completion()
    if status != "COMPLETED":
        result.update(status=status, completion=None)
    return {**{key: value[key] for key in subject._BASE}, "kind": "RESULT", "result": result,
        "cleanup": "OWNED_TRANSPORT_CLOSED", "connect_attempted": connect, "send_attempted": send}


class InertTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for owner, names in ((socket, ("socket", "socketpair", "create_connection", "getaddrinfo")),
                             (subprocess, ("run", "Popen")), (os, ("open", "system"))):
            for name in names:
                self.stack.enter_context(mock.patch.object(owner, name,
                    side_effect=AssertionError("live/native operation forbidden")))
        for name in ("fork", "posix_spawn", "posix_spawnp", "pidfd_open"):
            self.stack.enter_context(mock.patch.object(os, name, create=True,
                side_effect=AssertionError("native process operation forbidden")))
        for name in ("open_peer_pidfd", "require_live_pidfd", "_read_virtual_file"):
            self.stack.enter_context(mock.patch.object(subject.channel.process, name,
                side_effect=AssertionError("unmocked kernel operation forbidden")))
        self.stack.enter_context(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.clock = self.stack.enter_context(mock.patch.object(subject.time, "monotonic_ns", return_value=100_000_000_000))
        self.closed = self.stack.enter_context(mock.patch.object(os, "close"))


class ServicePacketTests(InertTests):
    def test_request_packet_binds_detached_request_profile_and_rendered_body(self):
        packet = request_packet()
        observed = subject.validate_packet(packet)
        self.assertEqual(observed, packet)
        self.assertIsNot(observed["request"], packet["request"])
        self.assertEqual(observed["wire"]["profile_digest"], canonical_digest(packet["profile"]))

    def test_kind_authority_schema_unknown_fields_and_base_types_refuse(self):
        changes = [lambda p: p.update(kind=[]), lambda p: p.update(kind="CHALLENGE"),
            lambda p: p.update(schema="aragorn/pi-core-provider-service/v1"),
            lambda p: p.update(authority="caller asserted"), lambda p: p.update(extra=True),
            lambda p: p.update(nonce="A" * 32), lambda p: p.update(request_digest="bad"),
            lambda p: p.update(wire_digest=[]), lambda p: p.update(deadline_ns=True),
            lambda p: p.update(deadline_ns=2**63)]
        for mutate in changes:
            value = request_packet(); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(subject.PiProviderServiceError):
                subject.validate_packet(value)

    def test_request_route_profile_and_wire_substitutions_refuse(self):
        changes = [lambda p: p["request"]["payload"]["messages"][1].update(content="substituted"),
            lambda p: p["route"].update(model="another"),
            lambda p: p["profile"].update(address="1.1.1.1"),
            lambda p: p["wire"].update(path="/v1/other"),
            lambda p: p.update(request_digest="sha256:" + "b" * 64)]
        for mutate in changes:
            value = request_packet(); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(subject.PiProviderServiceError):
                subject.validate_packet(value)

    def test_check_and_current_require_exact_ordered_phase_and_integer_expiry(self):
        fields = {key: request_packet()[key] for key in subject._BASE}
        check = {**fields, "kind": "CHECK", "phase": "CONNECT", "sequence": 1}
        self.assertEqual(subject.validate_packet(check), check)
        current = {**check, "kind": "CURRENT", "permit_expires_monotonic_ns": 100_050_000_000}
        self.assertEqual(subject.validate_packet(current), current)
        for change in ({"phase": "SEND"}, {"sequence": True}, {"sequence": 3},
                       {"permit_expires_monotonic_ns": True}, {"permit_expires_monotonic_ns": 110_000_000_001}):
            with self.subTest(change=change), self.assertRaises(subject.PiProviderServiceError):
                subject.validate_packet({**current, **change})

    def test_result_completion_and_attempt_flags_have_consistent_types(self):
        for change in ({"connect_attempted": False}, {"send_attempted": False},
                       {"send_attempted": 1}, {"cleanup": "CLEANUP_HOLD"}):
            with self.subTest(change=change), self.assertRaises(subject.PiProviderServiceError):
                subject.validate_packet({**result_packet(), **change})
        with self.assertRaises(subject.PiProviderServiceError):
            subject.validate_packet(result_packet("NOT_SUBMITTED", connect=True, send=False))
        for status, connect in (("NOT_SUBMITTED", False), ("INDETERMINATE", True)):
            value = result_packet(status, connect=connect, send=False)
            self.assertEqual(subject.validate_packet(value), value)

    def test_wrapper_packet_bound_includes_binding_overhead(self):
        value = result_packet()
        value["result"]["completion"]["content"] = [{"type": "text", "text": ""}, {"type": "text", "text": ""}]
        count = subject.MAX_PACKET_BYTES - len(canonical_json(value["result"]))
        value["result"]["completion"]["content"][0]["text"] = "a" * min(count, 32768)
        value["result"]["completion"]["content"][1]["text"] = "a" * (count - min(count, 32768))
        self.assertEqual(len(canonical_json(value["result"])), subject.MAX_PACKET_BYTES)
        with self.assertRaises(subject.PiProviderServiceError):
            subject.validate_packet(value)

    def test_send_uses_existing_authenticated_transport_once_without_rights(self):
        connection = mock.Mock()
        with mock.patch.object(subject.channel, "send_authenticated_packet") as send:
            subject.send_packet(connection, request_packet(), 110.0)
        send.assert_called_once_with(connection, request_packet(), 110.0, max_bytes=subject.MAX_PACKET_BYTES)

    def test_receive_uses_per_message_credentials_and_closes_unexpected_owned_rights(self):
        connection = mock.Mock()
        with mock.patch.object(subject.channel, "receive_authenticated_packet", return_value=(request_packet(), (77,))) as receive:
            with self.assertRaises(subject.PiProviderServiceError):
                subject.receive_packet(connection, (1000, 0, 0), 110.0)
        receive.assert_called_once_with(connection, (1000, 0, 0), 110.0,
            expected_rights=0, max_bytes=subject.MAX_PACKET_BYTES)
        self.closed.assert_called_once_with(77)

    def test_packet_validation_never_confers_factory_authority(self):
        with self.assertRaises(subject.PiProviderServiceError):
            subject.PiProviderServiceAuthority(object(), request_packet(), mock.Mock(), (1000, 0, 0), 71, 110)
        with self.assertRaises(subject.PiProviderServiceError):
            subject.PiProviderPermit(object(), object(), "CONNECT", 1, "sha256:" + "a" * 64, 101)
        with self.assertRaises(subject.PiProviderServiceError):
            subject.validate_permit(subject.validate_packet(request_packet()), "CONNECT", request_packet()["wire"])


class ServiceLifecycleTests(InertTests):
    def setUp(self):
        super().setUp()
        self.connection = mock.Mock()
        self.packet = request_packet()
        self.events, self.sent, self.authorities = [], [], []
        self.first_read = True
        self.current_mutation = None
        self.read_profile = self.stack.enter_context(mock.patch.object(transport, "read_profile", side_effect=self.profile))
        self.identity = self.stack.enter_context(mock.patch.object(transport, "_identity", side_effect=lambda p: self.events.append("service_identity")))
        self.guard = self.stack.enter_context(mock.patch.object(subject.channel, "guard_channel", side_effect=lambda *a: self.events.append("root_guard") or 71))
        self.live = self.stack.enter_context(mock.patch.object(subject.channel, "require_peer_live", side_effect=lambda *a: self.events.append("root_live")))
        self.receive = self.stack.enter_context(mock.patch.object(subject.channel, "receive_authenticated_packet", side_effect=self.receive_raw))
        self.send = self.stack.enter_context(mock.patch.object(subject.channel, "send_authenticated_packet", side_effect=self.send_raw))
        self.closed.side_effect = lambda fd: self.events.append(("close", fd))
        self.execute = self.stack.enter_context(mock.patch.object(transport, "execute_openai_request", side_effect=self.complete))

    def profile(self):
        self.events.append("profile")
        return fixtures.profile()

    def receive_raw(self, *args, **kwargs):
        if self.first_read:
            self.first_read = False
            return copy.deepcopy(self.packet), ()
        current = {**self.sent[-1], "kind": "CURRENT", "permit_expires_monotonic_ns": 100_050_000_000}
        if self.current_mutation is not None:
            self.current_mutation(current)
        return current, ()

    def send_raw(self, connection, packet, deadline, **kwargs):
        self.events.append(("send", packet["kind"]))
        self.sent.append(copy.deepcopy(packet))

    def phase(self, authority, phase):
        permit = authority.check(phase, authority.wire)
        subject.validate_permit(permit, phase, authority.wire)
        return permit

    def complete(self, authority, *, profile):
        self.authorities.append(authority)
        authority.begin()
        self.phase(authority, "CONNECT")
        self.phase(authority, "SEND")
        self.events.append("transport_closed")
        return {"result": completion(), "cleanup": "OWNED_TRANSPORT_CLOSED",
                "connect_attempted": True, "send_attempted": True}

    def run_service(self):
        return subject.handle_pi_provider_service(self.connection, expected_supervisor_pid=1000, deadline=110.0)

    def assert_no_terminal(self):
        self.assertFalse(any(packet["kind"] == "RESULT" for packet in self.sent))

    def test_connected_exchange_consumes_two_permits_and_closes_before_terminal(self):
        result = self.run_service()
        self.assertEqual([p["kind"] for p in self.sent], ["CHECK", "CHECK", "RESULT"])
        self.assertEqual([(p["phase"], p["sequence"]) for p in self.sent[:2]], [("CONNECT", 1), ("SEND", 2)])
        self.assertEqual(self.events[:3], ["profile", "service_identity", "root_guard"])
        self.assertLess(self.events.index("transport_closed"), self.events.index(("close", 71)))
        self.assertLess(self.events.index(("close", 71)), self.events.index(("send", "RESULT")))
        self.closed.assert_called_once_with(71)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertFalse(result["phase3_eligible"])
        self.connection.close.assert_not_called()
        self.connection.shutdown.assert_not_called()

    def test_observation_is_metadata_only_and_authority_is_withdrawn(self):
        result = self.run_service()
        self.assertNotIn("request", result)
        self.assertNotIn("completion", result)
        self.assertNotIn("Owned fixture result", canonical_json(result).decode())
        authority = self.authorities[0]
        self.assertFalse(authority._active)
        with self.assertRaises(subject.PiProviderServiceError):
            authority.check("SEND", authority.wire)

    def test_authority_properties_are_detached_from_root_packet(self):
        def changed(authority, *, profile):
            view = authority.request
            view["payload"]["messages"][1]["content"] = "changed"
            authority.profile["address"] = "1.1.1.1"
            authority.route["endpoint"]["path"] = "/other"
            authority.wire["body_digest"] = "sha256:" + "f" * 64
            self.assertEqual(authority.request, self.packet["request"])
            self.assertEqual(authority.profile, self.packet["profile"])
            self.assertEqual(authority.route, self.packet["route"])
            self.assertEqual(authority.wire, self.packet["wire"])
            return self.complete(authority, profile=profile)
        self.execute.side_effect = changed
        self.run_service()

    def test_invalid_supervisor_and_original_deadlines_refuse_before_profile(self):
        for pid, deadline in ((True, 110), (0, 110), (2**31, 110), (1000, 100),
                              (1000, float("nan")), (1000, 131)):
            with self.subTest(pid=pid, deadline=deadline), self.assertRaises(subject.PiProviderServiceError):
                subject.handle_pi_provider_service(self.connection, expected_supervisor_pid=pid, deadline=deadline)
        self.read_profile.assert_not_called()
        self.execute.assert_not_called()
        self.closed.assert_not_called()

    def test_profile_identity_failure_prevents_channel_and_transport(self):
        self.identity.side_effect = RuntimeError("private details never surfaced")
        with self.assertRaisesRegex(subject.PiProviderServiceError, "^PROVIDER_SERVICE_REFUSED_OR_CLEANUP_HOLD$"):
            self.run_service()
        self.guard.assert_not_called()
        self.execute.assert_not_called()

    def test_root_channel_rejection_prevents_request_read(self):
        self.guard.side_effect = RuntimeError("wrong peer")
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.receive.assert_not_called()
        self.execute.assert_not_called()
        self.closed.assert_not_called()

    def test_only_request_kind_can_mint_service_authority(self):
        self.packet = result_packet()
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.execute.assert_not_called()
        self.closed.assert_called_once_with(71)
        self.assert_no_terminal()

    def test_locally_installed_profile_mismatch_refuses_before_transport(self):
        different = fixtures.profile(); different["address"] = "1.1.1.1"
        self.read_profile.side_effect = None; self.read_profile.return_value = different
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.execute.assert_not_called()
        self.closed.assert_called_once_with(71)

    def test_request_cannot_extend_or_expire_original_budget(self):
        for deadline_ns in (110_000_000_001, 100_000_000_000):
            self.packet["deadline_ns"] = deadline_ns
            self.first_read = True
            with self.subTest(deadline_ns=deadline_ns), self.assertRaises(subject.PiProviderServiceError):
                self.run_service()
        self.execute.assert_not_called()

    def test_begin_is_one_use_even_when_peer_check_fails(self):
        def attempt(authority, *, profile):
            with mock.patch.object(subject.channel, "require_peer_live", side_effect=RuntimeError("peer exited")):
                with self.assertRaises(RuntimeError):
                    authority.begin()
            with self.assertRaises(subject.PiProviderServiceError):
                authority.begin()
            raise RuntimeError("stop")
        self.execute.side_effect = attempt
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.assertEqual(self.sent, [])

    def test_check_requires_begin_and_connect_consumption_before_send(self):
        def attempt(authority, *, profile):
            with self.assertRaises(subject.PiProviderServiceError):
                authority.check("CONNECT", authority.wire)
            authority.begin()
            with self.assertRaises(subject.PiProviderServiceError):
                authority.check("SEND", authority.wire)
            permit = authority.check("CONNECT", authority.wire)
            with self.assertRaises(subject.PiProviderServiceError):
                authority.check("SEND", authority.wire)
            subject.validate_permit(permit, "CONNECT", authority.wire)
            self.phase(authority, "SEND")
            return {"result": completion(), "cleanup": "OWNED_TRANSPORT_CLOSED", "connect_attempted": True, "send_attempted": True}
        self.execute.side_effect = attempt
        self.run_service()

    def test_changed_wire_refuses_before_check_send_and_cannot_retry(self):
        def attempt(authority, *, profile):
            authority.begin()
            wire = authority.wire; wire["path"] = "/other"
            with self.assertRaises(subject.PiProviderServiceError):
                authority.check("CONNECT", wire)
            with self.assertRaises(subject.PiProviderServiceError):
                authority.check("CONNECT", authority.wire)
            raise RuntimeError("stop")
        self.execute.side_effect = attempt
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.assertEqual(self.sent, [])

    def test_current_binding_nonce_deadline_digest_and_sequence_must_match(self):
        changes = [lambda p: p.update(nonce="b" * 32), lambda p: p.update(deadline_ns=109_000_000_000),
            lambda p: p.update(request_digest="sha256:" + "b" * 64),
            lambda p: p.update(wire_digest="sha256:" + "b" * 64),
            lambda p: p.update(sequence=2, phase="SEND")]
        for mutate in changes:
            self.first_read = True; self.current_mutation = mutate; self.sent.clear()
            with self.subTest(mutate=mutate), self.assertRaises(subject.PiProviderServiceError):
                self.run_service()
            self.assertEqual([p["kind"] for p in self.sent], ["CHECK"])

    def test_current_requires_unexpired_short_permit_without_renewal(self):
        for expires in (100_000_000_000, 100_100_000_001):
            self.first_read = True; self.sent.clear()
            self.current_mutation = lambda p: p.update(permit_expires_monotonic_ns=expires)
            with self.subTest(expires=expires), self.assertRaises(subject.PiProviderServiceError):
                self.run_service()
            self.assertEqual([p["kind"] for p in self.sent], ["CHECK"])

    def test_current_peer_liveness_is_checked_again_before_permit(self):
        def liveness(*args):
            if self.sent and self.sent[-1]["kind"] == "CHECK":
                raise RuntimeError("root exit during roundtrip")
        self.live.side_effect = liveness
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.assert_no_terminal()

    def test_permit_validation_has_no_native_io_and_is_one_use(self):
        def attempt(authority, *, profile):
            authority.begin()
            for phase in ("CONNECT", "SEND"):
                permit = authority.check(phase, authority.wire)
                with mock.patch.object(subject.channel, "require_peer_live", side_effect=AssertionError("no I/O")), \
                     mock.patch.object(subject, "send_packet", side_effect=AssertionError("no I/O")), \
                     mock.patch.object(subject, "receive_packet", side_effect=AssertionError("no I/O")):
                    subject.validate_permit(permit, phase, authority.wire)
                    with self.assertRaises(subject.PiProviderServiceError):
                        subject.validate_permit(permit, phase, authority.wire)
            return {"result": completion(), "cleanup": "OWNED_TRANSPORT_CLOSED", "connect_attempted": True, "send_attempted": True}
        self.execute.side_effect = attempt
        self.run_service()

    def test_wrong_phase_or_descriptor_cannot_consume_permit(self):
        def attempt(authority, *, profile):
            authority.begin()
            permit = authority.check("CONNECT", authority.wire)
            wire = authority.wire; wire["address"] = "1.1.1.1"
            for phase, descriptor in (("SEND", authority.wire), ("CONNECT", wire)):
                with self.assertRaises(subject.PiProviderServiceError):
                    subject.validate_permit(permit, phase, descriptor)
            subject.validate_permit(permit, "CONNECT", authority.wire)
            self.phase(authority, "SEND")
            return {"result": completion(), "cleanup": "OWNED_TRANSPORT_CLOSED", "connect_attempted": True, "send_attempted": True}
        self.execute.side_effect = attempt
        self.run_service()

    def test_permit_never_blocks_behind_a_concurrent_authority_roundtrip(self):
        def attempt(authority, *, profile):
            authority.begin()
            permit = authority.check("CONNECT", authority.wire)
            with authority._lock:
                with self.assertRaisesRegex(subject.PiProviderServiceError, "PROVIDER_PERMIT_BUSY"):
                    subject.validate_permit(permit, "CONNECT", authority.wire)
            subject.validate_permit(permit, "CONNECT", authority.wire)
            self.phase(authority, "SEND")
            return {"result": completion(), "cleanup": "OWNED_TRANSPORT_CLOSED", "connect_attempted": True, "send_attempted": True}
        self.execute.side_effect = attempt
        self.run_service()

    def test_float_budget_rounding_is_conservative_and_final_cleanup_cannot_extend_it(self):
        def attempt(authority, *, profile):
            self.assertLess(authority.deadline, self.packet["deadline_ns"] / 1_000_000_000)
            return self.complete(authority, profile=profile)
        self.execute.side_effect = attempt
        self.closed.side_effect = lambda fd: setattr(self.clock, "return_value", self.packet["deadline_ns"])
        with self.assertRaisesRegex(subject.PiProviderServiceError, "PROVIDER_SERVICE_RESULT_UNCERTAIN"):
            self.run_service()
        self.closed.assert_called_once_with(71)
        self.assert_no_terminal()

    def test_expired_permit_cannot_be_used_or_refreshed(self):
        def attempt(authority, *, profile):
            authority.begin()
            permit = authority.check("CONNECT", authority.wire)
            self.clock.return_value = 100_050_000_000
            with self.assertRaises(subject.PiProviderServiceError):
                subject.validate_permit(permit, "CONNECT", authority.wire)
            with self.assertRaises(subject.PiProviderServiceError):
                authority.check("CONNECT", authority.wire)
            raise RuntimeError("stop")
        self.execute.side_effect = attempt
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.assertEqual(len(self.sent), 1)

    def test_opaque_permit_cannot_outlive_its_scoped_authority(self):
        permits = []
        def attempt(authority, *, profile):
            authority.begin()
            permits.append(authority.check("CONNECT", authority.wire))
            raise transport.PiOpenAITransportError("PROVIDER_CONNECT_FAILED")
        self.execute.side_effect = attempt
        self.run_service()
        with self.assertRaises(subject.PiProviderServiceError):
            subject.validate_permit(permits[0], "CONNECT", self.packet["wire"])

    def test_completion_without_consumed_permits_cannot_be_fabricated(self):
        self.execute.side_effect = lambda authority, profile: {"result": completion(),
            "cleanup": "OWNED_TRANSPORT_CLOSED", "connect_attempted": True, "send_attempted": True}
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.assert_no_terminal()

    def test_closed_preconnect_failure_reports_not_submitted_without_secret_details(self):
        self.execute.side_effect = transport.PiOpenAITransportError("PROVIDER_CREDENTIAL_REFUSED")
        result = self.run_service()
        self.assertEqual(result["status"], "NOT_SUBMITTED")
        self.assertEqual([p["kind"] for p in self.sent], ["RESULT"])
        self.assertIsNone(self.sent[0]["result"]["completion"])
        self.assertLess(self.events.index(("close", 71)), self.events.index(("send", "RESULT")))

    def test_closed_possible_connect_failure_is_indeterminate_and_not_retried(self):
        def attempt(authority, *, profile):
            authority.begin(); self.phase(authority, "CONNECT")
            raise transport.PiOpenAITransportError("PROVIDER_CONNECT_FAILED", status="INDETERMINATE", connect_attempted=True)
        self.execute.side_effect = attempt
        result = self.run_service()
        self.assertEqual(result["status"], "INDETERMINATE")
        self.execute.assert_called_once()
        self.assertEqual([p["kind"] for p in self.sent], ["CHECK", "RESULT"])

    def test_cleanup_hold_never_emits_normal_result(self):
        self.execute.side_effect = transport.PiOpenAITransportError("PROVIDER_CLEANUP_HOLD", cleanup="CLEANUP_HOLD")
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.closed.assert_called_once_with(71)
        self.assert_no_terminal()

    def test_unexpected_transport_error_is_redacted_without_fabricated_status(self):
        self.execute.side_effect = RuntimeError("secret-api-key and untrusted provider response")
        with self.assertRaisesRegex(subject.PiProviderServiceError, "^PROVIDER_SERVICE_REFUSED_OR_CLEANUP_HOLD$"):
            self.run_service()
        self.assert_no_terminal()
        self.closed.assert_called_once_with(71)

    def test_root_pidfd_close_failure_prevents_terminal_and_is_not_retried(self):
        self.closed.side_effect = OSError("close uncertainty")
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.closed.assert_called_once_with(71)
        self.assert_no_terminal()
        self.assertFalse(self.authorities[0]._active)

    def test_terminal_send_failure_is_uncertain_after_owned_cleanup_once(self):
        def send(connection, packet, deadline, **kwargs):
            self.send_raw(connection, packet, deadline, **kwargs)
            if packet["kind"] == "RESULT":
                raise OSError("partial terminal send")
        self.send.side_effect = send
        with self.assertRaisesRegex(subject.PiProviderServiceError, "^PROVIDER_SERVICE_RESULT_UNCERTAIN$"):
            self.run_service()
        self.closed.assert_called_once_with(71)
        self.assertEqual([p["kind"] for p in self.sent], ["CHECK", "CHECK", "RESULT"])

    def test_late_transport_result_never_becomes_completed_terminal(self):
        def late(authority, *, profile):
            result = self.complete(authority, profile=profile)
            self.clock.return_value = 110_000_000_000
            return result
        self.execute.side_effect = late
        with self.assertRaises(subject.PiProviderServiceError):
            self.run_service()
        self.closed.assert_called_once_with(71)
        self.assert_no_terminal()
