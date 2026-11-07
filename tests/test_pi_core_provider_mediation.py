"""Only new provider data-gate checks; native edges and service I/O are mocked."""

import copy
import json
import os
import socket
import stat
import subprocess
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_provider_mediation as subject
from aragorn import pi_core_source_observer as source
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_confined_launch as launch_fixtures
from tests import test_pi_core_request_handoff as identity_fixtures
from tests import test_runtime_action_decision as policy_fixtures


def route():
    return {"schema": "aragorn/pi-core-provider-route/v1", "provider": "fixture", "api": "openai-responses",
        "model": "fixture", "endpoint": {"scheme": "https", "host": "provider.example", "port": 443, "path": "/v1"}}


def request():
    model = copy.deepcopy(launch_fixtures.configuration().model)
    model["baseUrl"] = "https://provider.example/v1"
    return {"schema": subject.REQUEST_SCHEMA, "authority": subject.REQUEST_AUTHORITY,
        "activation_id": "a" * 32, "route_digest": canonical_digest(route()), "sequence": 1,
        "payload": {"schema": "aragorn/pi-core-provider-payload/v1", "model": model,
            "messages": [{"role": "system", "content": "approved public instructions", "timestamp": 0,
                          "toolsAdded": [copy.deepcopy(subject._TOOL)]},
                         {"role": "user", "content": "approved fabricated task", "timestamp": 0}]}}


def result(value=None):
    return {"schema": subject.RESULT_SCHEMA, "authority": subject.RESULT_AUTHORITY,
        "request_digest": canonical_digest(request() if value is None else value), "status": "COMPLETED",
        "completion": {"stop_reason": "stop", "content": [{"type": "text", "text": "untrusted completion"}],
                       "usage": {"input_tokens": 1, "output_tokens": 2}}}


def metadata(*, directory=True, inode=10, size=0):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=(stat.S_IFDIR | 0o700) if directory else stat.S_IFREG | 0o400,
        st_uid=0, st_gid=0, st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=2)


class InertTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        for name in ("open", "close", "lstat", "stat", "fstat", "fsync", "read", "write", "mkdir", "unlink", "rename"):
            self.stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError("unmocked filesystem operation")))
        for name in ("fork", "posix_spawn", "posix_spawnp", "pidfd_open"):
            self.stack.enter_context(mock.patch.object(os, name, create=True, side_effect=AssertionError("native process operation")))
        for name in ("open_peer_pidfd", "require_live_pidfd", "_read_virtual_file", "measure_runtime_process_profile"):
            self.stack.enter_context(mock.patch.object(subject.process, name, side_effect=AssertionError("kernel read forbidden")))
        self.stack.enter_context(mock.patch.object(subject.identity, "_boot_id", side_effect=AssertionError("boot read forbidden")))
        self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(os, "getegid", return_value=0))
        self.stack.enter_context(mock.patch.object(os, "getpid", return_value=1000))
        self.stack.enter_context(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.stack.enter_context(mock.patch.object(subject.time, "monotonic_ns", return_value=100_000_000_000))
        self.wall = self.stack.enter_context(mock.patch.object(subject.time, "time", return_value=100))
        self.stack.enter_context(mock.patch.object(subject.secrets, "token_hex", return_value="b" * 32))


class ProviderContractTests(InertTests):
    def test_request_is_detached_and_digest_covers_exact_tool_and_transcript(self):
        value = request()
        observed = subject.validate_provider_request(value)
        self.assertEqual(observed, value)
        self.assertIsNot(observed["payload"], value["payload"])
        changed = request()
        changed["payload"]["messages"][1]["content"] += " extra"
        self.assertNotEqual(canonical_digest(value), canonical_digest(changed))

    def test_unknown_fields_continuations_and_unapproved_tool_schema_refuse(self):
        changes = [lambda value: value.update(secret="not allowed"),
            lambda value: value["payload"].update(tools=[]),
            lambda value: value["payload"]["messages"].append({"role": "assistant", "content": "extra"}),
            lambda value: value["payload"]["messages"][1].update(role="toolResult"),
            lambda value: value["payload"]["messages"][0]["toolsAdded"][0].update(name="shell"),
            lambda value: value["payload"]["messages"][0].update(timestamp=1)]
        for mutate in changes:
            value = request()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises((RuntimeError, ValueError)):
                subject.validate_provider_request(value)

    def test_payload_size_utf8_and_shared_integer_bounds_refuse(self):
        changes = [lambda value: value["payload"]["messages"][1].update(content="\ud800"),
            lambda value: value["payload"]["messages"][1].update(content="a" * 32769),
            lambda value: value["payload"]["messages"][1].update(content=[{"type": "text", "text": "a" * 32768}] * 2),
            lambda value: value.update(sequence=True),
            lambda value: value["payload"]["model"]["cost"].update(input=0.5),
            lambda value: value["payload"]["model"]["cost"].update(input=2**53)]
        for mutate in changes:
            value = request()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises((RuntimeError, ValueError)):
                subject.validate_provider_request(value)

    def test_text_blocks_and_empty_text_match_normalized_wire(self):
        value = request()
        value["payload"]["messages"][0]["content"] = [{"type": "text", "text": ""}]
        value["payload"]["messages"][1]["content"] = ""
        self.assertEqual(subject.validate_provider_request(value), value)

    def test_route_rejects_credential_query_redirect_and_local_overrides(self):
        for key, invalid in (("scheme", "http"), ("port", 8443), ("host", "localhost"),
                             ("host", "127.0.0.1"), ("host", "server.local"),
                             ("host", "user:secret@provider.example"), ("path", "/v1?redirect=http://local"),
                             ("path", "/../secret")):
            value = route()
            value["endpoint"][key] = invalid
            with self.subTest(key=key, invalid=invalid), self.assertRaises(RuntimeError):
                subject.validate_route(value)

    def test_response_stop_and_exact_single_create_tool_are_distinct(self):
        value = result()
        self.assertEqual(subject.validate_provider_result(value, canonical_digest(request())), value)
        value["completion"]["stop_reason"] = "toolUse"
        value["completion"]["content"] = [{"type": "toolCall", "id": "call-1", "name": "aragorn_runtime_create",
            "arguments": {"target_name": "result.txt", "content": ""}}]
        self.assertEqual(subject.validate_provider_result(value, canonical_digest(request())), value)
        value["completion"]["content"] *= 2
        with self.assertRaises(RuntimeError):
            subject.validate_provider_result(value, canonical_digest(request()))

    def test_result_digest_status_shape_and_shared_usage_limits_are_strict(self):
        changes = [lambda value: value.update(request_digest="sha256:" + "f" * 64),
            lambda value: value.update(status="NOT_SUBMITTED"),
            lambda value: value["completion"].update(secret="secret"),
            lambda value: value["completion"]["usage"].update(input_tokens=True),
            lambda value: value["completion"]["usage"].update(input_tokens=2**53 - 1),
            lambda value: value["completion"].update(stop_reason="toolUse")]
        for mutate in changes:
            value = result()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises((RuntimeError, ValueError)):
                subject.validate_provider_result(value, canonical_digest(request()))

    def test_empty_text_completion_and_explicit_service_refusal_are_supported(self):
        value = result()
        value["completion"]["content"][0]["text"] = ""
        self.assertEqual(subject.validate_provider_result(value, canonical_digest(request())), value)
        for status in ("NOT_SUBMITTED", "INDETERMINATE"):
            value.update(status=status, completion=None)
            self.assertEqual(subject.validate_provider_result(value, canonical_digest(request())), value)


class ProviderMediationTests(InertTests):
    def setUp(self):
        super().setUp()
        # Explicit inert dependency: no factory, source reads or health proof.
        self.source_observer = object.__new__(source.PiSourceObserver)
        self.source_health = self.stack.enter_context(mock.patch.object(
            source.PiSourceObserver, "guard_source_health", autospec=True))
        self.events = []
        self.request = request()
        self.values = policy_fixtures._fixture()
        digests = {"operation_digest": canonical_digest(subject._OPERATION), "path_digest": canonical_digest(route()),
                   "payload_digest": canonical_digest(self.request["payload"])}
        self.values["policy"]["allow"][0].update(digests)
        action = self.values["request"]
        action.update(digests, session_id="a" * 32, run_id="a" * 32, tool_call_id=canonical_digest(self.request),
                      policy_digest=canonical_digest(self.values["policy"]))
        for key in ("active", "measured_action"):
            for field in self.values[key]:
                if field != "schema":
                    self.values[key][field] = action[field]
        self.activation = identity_fixtures.activation()
        self.profile = subject.process.RuntimeProcessProfile(action["runtime_digest"], self.activation["executable_digest"],
            self.activation["cgroup"], Path("/var/lib/aragorn/admitted/version/SKILL.md"), action["active_skill_digest"])
        self.activation.update(runtime_digest=action["runtime_digest"], active_skill_digest=action["active_skill_digest"],
            policy_digest=action["policy_digest"], profile_digest=self.profile.digest)
        self.approval = {"schema": subject.APPROVAL_SCHEMA, "authority": subject.APPROVAL_AUTHORITY,
            "activation_digest": canonical_digest(self.activation), "route": route(), "data_class": "PUBLIC",
            "payload_digest": digests["payload_digest"], "max_requests": 1, "request": action}
        root = Path("/var/lib/aragorn/provider-control")
        self.config = subject.broker.RuntimeActionBrokerConfig(root / "broker.sock", root / "instance.lock", root / "broker.lock",
            root, Path("/var/lib/aragorn/output"), Path("/var/lib/aragorn/staging"),
            *(root / (name + ".json") for name in ("policy", "revocations", "health", "observation", "state")),
            0, 1301, 1302, action["runtime_digest"], 1201, 1202)
        observation = {"schema": "aragorn/runtime-action-observation/v1", "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
            "sequence": 1, "sensor_digest": self.values["policy"]["sensor_digest"], "observed_at_unix": 98,
            "expires_at_unix": 103, "active": self.values["active"], "measured_action": self.values["measured_action"]}
        self.storage = {"policy.json": self.values["policy"], "revocations.json": self.values["revocations"],
            "health.json": self.values["mediator_health"], "observation.json": observation,
            "state.json": {"schema": "aragorn/runtime-action-broker-state/v2", "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
                "minimum_revocation_generation": 3, "minimum_mediator_health_epoch": 1, "consumed": [], "effect_journal": None},
            subject.APPROVAL_NAME: self.approval}
        self.worker, self.provider = mock.Mock(), mock.Mock()
        self.worker.fileno.return_value, self.provider.fileno.return_value = 3, 4
        self.worker.getsockopt.side_effect = lambda level, key: socket.AF_UNIX if key == subject.channel._DOMAIN else socket.SOCK_STREAM
        self.peer = (400, 2201, 2202)
        self.claims = set()
        self.packet = None
        self.expected_deadline = 103.0
        self.service_result = result(self.request)
        self.stack.enter_context(mock.patch.object(subject.broker, "_validate_config"))  # OS portability guard only.
        self.read_activation = self.stack.enter_context(mock.patch.object(subject.identity, "read_activation", side_effect=lambda path: copy.deepcopy(self.activation)))
        self.stack.enter_context(mock.patch.object(subject.broker, "_peer_credentials", return_value=(300, 1201, 1202)))
        self.stack.enter_context(mock.patch.object(subject.process, "open_peer_pidfd", return_value=71))
        self.measured = self.stack.enter_context(mock.patch.object(subject.identity, "_measured", return_value={"measured": True}))
        self.stack.enter_context(mock.patch.object(subject.identity, "_remaining", side_effect=lambda end, _: subject.channel.validate_deadline(end)))
        self.stack.enter_context(mock.patch.object(subject.identity, "_lineage_matches"))

        @contextmanager
        def lineage(*args, **kwargs):
            self.events.append("lineage_enter")
            try:
                yield mock.sentinel.lineage
            finally:
                self.events.append("lineage_close")

        self.lineage = self.stack.enter_context(mock.patch.object(subject.identity.lineage, "hold_runtime_active_skill_lineage", side_effect=lineage))
        self.read = self.stack.enter_context(mock.patch.object(subject.broker, "_read_frame", side_effect=lambda *_: copy.deepcopy(self.request)))
        self.stack.enter_context(mock.patch.object(subject.broker, "_open_protected_directory", return_value=50))
        self.stack.enter_context(mock.patch.object(subject.broker, "_open_lock_file", return_value=51))
        self.stack.enter_context(mock.patch.object(subject.broker, "_acquire_lock", side_effect=lambda *_: self.events.append("locked")))
        self.stack.enter_context(mock.patch.object(os, "fstat", return_value=metadata()))
        self.stack.enter_context(mock.patch.object(os, "lstat", return_value=metadata()))

        def stat_claim(name, **kwargs):
            if name in self.claims:
                return metadata(directory=False)
            raise FileNotFoundError(name)

        self.stack.enter_context(mock.patch.object(os, "stat", side_effect=stat_claim))
        self.load = self.stack.enter_context(mock.patch.object(subject.broker, "_load_control",
            side_effect=lambda fd, path, *args: copy.deepcopy(self.storage[path.name])))

        def commit(fd, config, state):
            self.storage["state.json"] = copy.deepcopy(state)
            self.events.append("state_committed")

        self.commit = self.stack.enter_context(mock.patch.object(subject.broker, "_commit_state", side_effect=commit))

        def claim(fd, activation, request_digest, approval_digest):
            name = subject._claim_name(activation)
            if name in self.claims:
                raise FileExistsError(name)
            self.claims.add(name)
            self.events.append("claim_durable")

        self.claim = self.stack.enter_context(mock.patch.object(subject, "_claim_once", side_effect=claim))
        self.guard_channel = self.stack.enter_context(mock.patch.object(subject.channel, "guard_channel", return_value=81))
        self.peer_live = self.stack.enter_context(mock.patch.object(subject.channel, "require_peer_live"))

        def send(connection, packet, deadline, **kwargs):
            self.assertTrue(self.claims)
            self.assertEqual(len(self.storage["state.json"]["consumed"]), 1)
            self.assertEqual(deadline, self.expected_deadline)
            self.packet = copy.deepcopy(packet)
            self.events.append("service_send")

        def receive(*args, **kwargs):
            fields = {key: self.packet[key] for key in ("schema", "authority", "nonce", "deadline_ns", "request_digest")}
            self.events.append("service_reply")
            return {**fields, "kind": "RESULT", "result": copy.deepcopy(self.service_result)}, ()

        self.send = self.stack.enter_context(mock.patch.object(subject.channel, "send_authenticated_packet", side_effect=send))
        self.receive = self.stack.enter_context(mock.patch.object(subject.channel, "receive_authenticated_packet", side_effect=receive))
        self.release = self.stack.enter_context(mock.patch.object(subject.broker, "_release_lock_and_close",
            side_effect=lambda *_: self.events.append("control_close")))
        self.close = self.stack.enter_context(mock.patch.object(os, "close", side_effect=lambda fd: self.events.append(("fd_close", fd))))
        self.worker_send = self.stack.enter_context(mock.patch.object(subject.broker, "_send_frame",
            side_effect=lambda *_: self.events.append("worker_result")))
        self.worker.shutdown.side_effect = lambda *_: self.events.append("worker_eof")

    def run_request(self, **options):
        arguments = dict(activation_path=Path("/var/lib/aragorn/pi-activations") / ("a" * 32 + ".json"),
            profile=self.profile, protected_install_root=Path("/var/lib/aragorn/admitted"), grant={},
            expected_provider_peer=self.peer, deadline=120.0, source_observer=self.source_observer)
        arguments.update(options)
        return subject.handle_pi_provider_connection(self.worker, self.provider, self.config, **arguments)

    def test_real_policy_allow_consumes_before_handoff_and_closes_before_worker_completion(self):
        observed = self.run_request()
        self.assertEqual(observed["status"], "COMPLETED")
        self.assertEqual(self.events, ["lineage_enter", "locked", "claim_durable", "state_committed", "service_send",
            "service_reply", "control_close", "lineage_close", ("fd_close", 71), ("fd_close", 81), "worker_result", "worker_eof"])
        self.assertEqual(json.loads(self.worker_send.call_args.args[1]), self.service_result)
        self.assertFalse(observed["provider_transport_implemented"])
        self.assertFalse(observed["phase3_eligible"])
        self.worker.close.assert_not_called()
        self.provider.close.assert_not_called()

    def test_returned_observation_contains_no_prompt_response_route_secret_or_exception(self):
        observed = self.run_request()
        raw = canonical_json(observed)
        for text in (b"approved public instructions", b"untrusted completion", b"provider.example", b"Bearer"):
            self.assertNotIn(text, raw)
        self.assertEqual(observed["request_digest"], canonical_digest(self.request))
        self.assertEqual(observed["approval_digest"], canonical_digest(self.approval))

    def test_changed_transcript_or_tool_bytes_never_use_endpoint_permission_as_data_approval(self):
        self.request["payload"]["messages"][1]["content"] = "unapproved private bytes"
        observed = self.run_request()
        self.assertEqual(observed["status"], "NOT_SUBMITTED")
        self.send.assert_not_called()
        self.claim.assert_not_called()

    def test_private_data_class_or_unbound_activation_refuses(self):
        for key, value in (("data_class", "PRIVATE"), ("activation_digest", "sha256:" + "f" * 64)):
            with self.subTest(key=key):
                prior = self.approval[key]
                self.approval[key] = value
                self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
                self.approval[key] = prior
        self.send.assert_not_called()

    def test_base_url_is_exact_route_not_worker_selected_prefix(self):
        self.request["payload"]["model"]["baseUrl"] += "/other"
        self.approval["payload_digest"] = canonical_digest(self.request["payload"])
        self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.send.assert_not_called()

    def test_missing_independent_observation_refuses_without_synthesizing_state(self):
        del self.storage["observation.json"]
        self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.claim.assert_not_called()
        self.send.assert_not_called()
        self.assertNotIn("observation.json", self.storage)

    def test_unhealthy_revoked_and_unmeasured_real_policy_each_refuse(self):
        for kind in ("health", "revocation", "measurement"):
            saved = copy.deepcopy(self.storage)
            if kind == "health":
                self.storage["health.json"]["status"] = "unknown"
            elif kind == "revocation":
                self.storage["revocations.json"]["skill_digests"] = [self.activation["active_skill_digest"]]
            else:
                self.storage["observation.json"]["measured_action"]["payload_digest"] = "sha256:" + "f" * 64
            with self.subTest(kind=kind):
                self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
            self.storage = saved
        self.send.assert_not_called()

    def test_active_file_effect_journal_is_not_recovered_or_skipped(self):
        with mock.patch.object(subject.broker, "_evaluate_snapshot", return_value=(
                {**self.storage["state.json"], "effect_journal": {"status": "PENDING"}},
                "sha256:" + "f" * 64, {"verdict": "ALLOW"}, [])):
            self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.claim.assert_not_called()
        self.send.assert_not_called()

    def test_permanent_activation_claim_blocks_even_replaced_policy_or_empty_replay_state(self):
        self.assertEqual(self.run_request()["status"], "COMPLETED")
        self.storage["state.json"]["consumed"] = []
        self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.send.assert_called_once()
        self.claim.assert_called_once()

    def test_existing_replay_record_blocks_before_new_claim(self):
        self.storage["state.json"]["consumed"] = [{"request_digest": canonical_digest(self.approval["request"]),
            "observation_digest": "sha256:" + "f" * 64, "expires_at_unix": 103}]
        self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.claim.assert_not_called()
        self.send.assert_not_called()

    def test_claim_or_state_publication_failure_is_spent_and_never_sent(self):
        def uncertain(fd, config, state):
            raise OSError("secret detail must not escape")
        self.commit.side_effect = uncertain
        observed = self.run_request()
        self.assertEqual(observed["status"], "NOT_SUBMITTED")
        self.assertEqual(observed["activation_claim"], "RETAINED_OR_UNCERTAIN")
        self.assertTrue(self.claims)
        self.send.assert_not_called()
        self.assertNotIn("secret detail", str(observed))

    def test_policy_changes_before_final_send_refuse_after_spending_claim(self):
        old_commit = self.commit.side_effect
        def changed(*args):
            old_commit(*args)
            self.storage["health.json"]["status"] = "unknown"
        self.commit.side_effect = changed
        self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.assertTrue(self.claims)
        self.send.assert_not_called()

    def test_service_send_failure_is_indeterminate_and_never_retried(self):
        self.send.side_effect = OSError("secret detail")
        observed = self.run_request()
        self.assertEqual(observed["status"], "INDETERMINATE")
        self.send.assert_called_once()
        self.receive.assert_not_called()
        self.assertTrue(self.claims)
        self.assertNotIn("secret detail", str(observed))

    def test_reply_nonce_or_result_binding_substitution_is_indeterminate(self):
        old_receive = self.receive.side_effect
        def changed(*args, **kwargs):
            value, rights = old_receive(*args, **kwargs)
            value["nonce"] = "f" * 32
            return value, rights
        self.receive.side_effect = changed
        self.assertEqual(self.run_request()["status"], "INDETERMINATE")
        self.send.assert_called_once()

    def test_explicit_service_not_submitted_is_not_relabelled_completed(self):
        self.service_result.update(status="NOT_SUBMITTED", completion=None)
        self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.assertTrue(self.claims)

    def test_worker_identity_change_after_handoff_blocks_completion(self):
        old_receive = self.receive.side_effect
        def changed(*args, **kwargs):
            response = old_receive(*args, **kwargs)
            self.measured.return_value = {"changed": True}
            return response
        self.receive.side_effect = changed
        self.assertEqual(self.run_request()["status"], "INDETERMINATE")
        self.assertEqual(json.loads(self.worker_send.call_args.args[1])["status"], "INDETERMINATE")

    def test_cleanup_failure_still_attempts_all_owned_handles_and_prevents_completed(self):
        self.release.side_effect = OSError("control close uncertain")
        observed = self.run_request()
        self.assertEqual(observed["status"], "INDETERMINATE")
        self.assertEqual(observed["cleanup"], "CLEANUP_HOLD")
        self.assertIn("lineage_close", self.events)
        self.assertEqual(self.close.call_args_list, [mock.call(71), mock.call(81)])
        self.assertEqual(json.loads(self.worker_send.call_args.args[1])["status"], "INDETERMINATE")

    def test_process_handle_close_failure_precedes_any_success_response(self):
        self.close.side_effect = lambda fd: (_ for _ in ()).throw(OSError("close failed")) if fd == 71 else None
        self.assertEqual(self.run_request()["status"], "INDETERMINATE")
        self.assertEqual(self.close.call_args_list, [mock.call(71), mock.call(81)])
        self.assertEqual(json.loads(self.worker_send.call_args.args[1])["completion"], None)

    def test_deadline_clock_rollback_and_expiry_prevent_send(self):
        for final in (99, 103):
            self.wall.side_effect = [100, final]
            with self.subTest(final=final):
                self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
            self.claims.clear()  # Independent authored scenario, not production record erasure.
            self.storage["state.json"]["consumed"] = []
        self.send.assert_not_called()

    def test_fractional_wall_clock_shortens_original_action_budget_without_rounding_up(self):
        self.wall.return_value = 100.75
        self.expected_deadline = 102.25
        self.assertEqual(self.run_request()["status"], "COMPLETED")
        self.assertEqual(self.packet["deadline_ns"], 102_250_000_000)

    def test_expiry_after_final_policy_but_before_service_send_stays_not_submitted(self):
        self.wall.side_effect = [100, 100, 103]
        self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.assertTrue(self.claims)
        self.send.assert_not_called()

    def test_root_role_channel_alias_and_peer_overlap_fail_before_request(self):
        with mock.patch.object(os, "geteuid", return_value=1201), self.assertRaises(RuntimeError):
            self.run_request()
        with self.assertRaises(RuntimeError):
            self.run_request(expected_provider_peer=(400, 1201, 1202))
        with self.assertRaises(RuntimeError):
            self.run_request(expected_provider_peer=(400, 1301, 1302))
        self.provider.fileno.return_value = 3
        with self.assertRaises(RuntimeError):
            self.run_request()
        self.read.assert_not_called()


class PermanentClaimTests(InertTests):
    def setUp(self):
        super().setUp()
        self.activation = identity_fixtures.activation()
        self.written = None
        self.open = self.stack.enter_context(mock.patch.object(os, "open", return_value=70))
        self.close = self.stack.enter_context(mock.patch.object(os, "close"))
        self.fsync = self.stack.enter_context(mock.patch.object(os, "fsync"))
        self.stat = self.stack.enter_context(mock.patch.object(os, "stat",
            side_effect=lambda *_, **__: metadata(directory=False, size=len(self.written))))
        self.fstat = self.stack.enter_context(mock.patch.object(os, "fstat",
            side_effect=lambda *_: metadata(directory=False, size=0 if self.written is None else len(self.written))))
        def write(fd, raw):
            self.written = raw
        self.write = self.stack.enter_context(mock.patch.object(subject.broker, "write_all", side_effect=write))
        self.read = self.stack.enter_context(mock.patch.object(subject.broker, "_read_owned_bytes_at", side_effect=lambda *_, **__: self.written))

    def claim(self):
        subject._claim_once(50, self.activation, "sha256:" + "b" * 64, "sha256:" + "c" * 64)

    def test_exact_absent_only_claim_is_durable_metadata_only_and_never_renamed(self):
        self.claim()
        call = self.open.call_args
        self.assertEqual(call.args[0], "provider-activation-" + "a" * 32 + ".json")
        self.assertTrue(call.args[1] & os.O_EXCL)
        self.assertTrue(call.args[1] & os.O_NOFOLLOW)
        self.assertEqual(call.args[2], 0o400)
        self.assertEqual(self.fsync.call_args_list, [mock.call(70), mock.call(50)])
        self.assertEqual(set(json.loads(self.written)), {"schema", "authority", "activation_digest", "request_digest", "approval_digest", "status"})
        self.close.assert_called_once_with(70)

    def test_existing_claim_never_overwrites_or_retries(self):
        self.open.side_effect = FileExistsError("already spent")
        with self.assertRaises(FileExistsError):
            self.claim()
        self.open.assert_called_once()
        self.write.assert_not_called()
        self.close.assert_not_called()

    def test_fsync_or_readback_failure_keeps_claim_and_closes_once(self):
        self.fsync.side_effect = OSError("durability uncertain")
        with self.assertRaises(OSError):
            self.claim()
        self.assertIsNotNone(self.written)
        self.close.assert_called_once_with(70)

    def test_substituted_claim_name_is_refused_after_write_without_deletion(self):
        self.stat.side_effect = lambda *_, **__: metadata(directory=False, inode=11, size=len(self.written))
        with self.assertRaises(RuntimeError):
            self.claim()
        self.close.assert_called_once_with(70)
