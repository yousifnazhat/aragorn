"""New HTTP source/receipt branches only; inert data, never native execution.

Fabricated unit fixtures are not measurement samples or acceptance evidence.
No historical TestCase methods are inherited or collected by this module.
"""

from copy import deepcopy
from contextlib import ExitStack, nullcontext
import json
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from aragorn import native_phase3_http_collection as producer
from aragorn import native_phase3_http_collection_verify as subject
from aragorn import native_phase3_http_canary_contract as contract
from aragorn import runtime_http_capability as capability
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_runtime_http_collection as renderer
from tests import test_runtime_worker_ingress_verify as ingress_fixture
from tests import test_runtime_broker_decision_measurement_verify as broker_fixture

ROOT = Path(__file__).resolve().parents[1]
PIN = "sha256:" + "a" * 64
FIXTURE = {
    "container_id": "d" * 64,
    "boot_id": broker_fixture.BOOT,
    "netns_device": 4,
    "netns_inode": 1234,
}
BINDING = {
    "schema": "aragorn/runtime-http-fixture-binding/v1",
    "fixture": FIXTURE,
    "expected_broker_uid": 995,
    "expected_broker_gid": 997,
}
ATTEMPT = "p3-lab-a001"
PREPARED = {
    "kind": "attempt",
    "attempt_id": ATTEMPT,
    "family": "EXFILTRATION",
    "negative_control": False,
    "collection_digest": PIN,
    "deployment_digest": PIN,
}


def _worker_fixture():
    records, _arguments = ingress_fixture._fixture()
    request = {
        "schema": "aragorn/runtime-http-worker-request/v1",
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "attempt_id": ATTEMPT,
        "session_id": "inert-session",
        "run_id": "inert-run",
        "tool_call_digest": "sha256:" + "1" * 64,
    }
    records["ingress"]["body"]["worker_request"] = request
    records["ingress"]["body"]["worker_request_digest"] = canonical_digest(request)
    body = records["attempt"]["body"]
    body["worker_request_digest"] = canonical_digest(request)
    event = body["attempt"]["event"]
    event.update(
        tool_name=subject.TOOL, worker_request_digest=canonical_digest(request)
    )
    params = {
        "attempt_id": ATTEMPT,
        "__aragorn_run_id": request["run_id"],
        "__aragorn_session_id": request["session_id"],
        "__aragorn_session_key_digest": event["session_key_digest"],
        "__aragorn_tool_call_digest": request["tool_call_digest"],
    }
    params_raw = json.dumps(params, separators=(",", ":")).encode()
    event.update(
        params_digest=contract.digest(params_raw), params_bytes=len(params_raw)
    )
    action_body = records["action"]["body"]
    action_body["worker_request_digest"] = canonical_digest(request)
    action_body["action_request"].update(subject.action_digests(ATTEMPT, BINDING))
    action_body["action_request_digest"] = canonical_digest(
        action_body["action_request"]
    )
    ingress_fixture._rehash_attempt(records)
    ingress_fixture._rechain(records)
    return records


def _verify_worker(records, **updates):
    arguments = {
        "expected_record_digests": {
            key: canonical_digest(value) for key, value in records.items()
        },
        "expected_worker": ingress_fixture.WORKER,
        "expected_binding_digest": canonical_digest(ingress_fixture.BINDING),
        "expected_genesis_digest": ingress_fixture.GENESIS,
        "expected_fixture_binding": BINDING,
        "expected_attempt_id": ATTEMPT,
    }
    arguments.update(updates)
    return subject.verify_http_worker_ingress(
        {key: canonical_json(value) for key, value in records.items()}, **arguments
    )


class NativeHttpCollectionTests(unittest.TestCase):
    def collection_mocks(self, *, readiness=True, existing_root=False):
        """Inert process/fixture boundary; no OS child, socket, mkdir or read."""
        stack = ExitStack()
        self.addCleanup(stack.close)
        held = SimpleNamespace(guard=MagicMock())
        sink = SimpleNamespace(
            observe_readiness=MagicMock(return_value=readiness),
            observe_attempt=MagicMock(),
            result=MagicMock(return_value={"complete": True, "listener_closed": True}),
        )
        child = MagicMock()
        child.pid = 700
        child.stdout.fileno.return_value = 10
        child.stderr.fileno.return_value = 11
        child.poll.return_value = 0 if readiness else None
        child.wait.return_value = 0
        files = {
            producer.DRIVER_PATH: b"inert-driver",
            producer._NODE: b"inert-node",
            producer.LEGACY_PATH: (ROOT / producer.LEGACY_SOURCE).read_bytes(),
            producer._TOKEN: b"OPENCLAW_GATEWAY_TOKEN=" + b"f" * 64 + b"\n",
            producer.ATTEMPT_ROOT + "/driver.json": canonical_json(
                {"prepared_request": PREPARED}
            ),
        }
        opened = stack.enter_context(
            patch.object(
                producer,
                "_read_fixed",
                side_effect=lambda path, _mode, _limit: files[path],
            )
        )
        stack.enter_context(
            patch.object(producer, "owned_http_fixture", return_value=nullcontext(held))
        )
        stack.enter_context(
            patch.object(producer, "open_http_sink", return_value=nullcontext(sink))
        )
        mkdir = stack.enter_context(
            patch.object(
                producer.os,
                "mkdir",
                side_effect=FileExistsError() if existing_root else None,
            )
        )
        publish = stack.enter_context(patch.object(producer, "_publish_absent"))
        spawn = stack.enter_context(
            patch.object(producer.subprocess, "Popen", return_value=child)
        )
        kill = stack.enter_context(patch.object(producer.os, "killpg"))
        stack.enter_context(patch.object(producer.os, "set_blocking"))
        stack.enter_context(
            patch.object(producer.os, "read", side_effect=[b"READY\n", b"", b""])
        )

        class Selector:
            def __init__(self):
                self.streams = []

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def register(self, stream, _events):
                self.streams.append(stream)

            def unregister(self, stream):
                self.streams.remove(stream)

            def get_map(self):
                return self.streams

            def select(self, _timeout):
                return [(SimpleNamespace(fileobj=self.streams[0]), 1)]

        stack.enter_context(
            patch.object(producer.selectors, "DefaultSelector", Selector)
        )
        arguments = {
            "request": PREPARED,
            "expected_fixture": FIXTURE,
            "readiness_nonce": "e" * 32,
            "expected_driver_digest": contract.digest(files[producer.DRIVER_PATH]),
            "expected_node_digest": contract.digest(files[producer._NODE]),
        }
        return SimpleNamespace(
            arguments=arguments,
            child=child,
            sink=sink,
            spawn=spawn,
            kill=kill,
            mkdir=mkdir,
            publish=publish,
            opened=opened,
        )

    def test_existing_attempt_root_refuses_without_child_or_reset(self):
        mock = self.collection_mocks(existing_root=True)
        with self.assertRaises(FileExistsError) as caught:
            producer.collect_native_http_attempt(**mock.arguments)
        mock.spawn.assert_not_called()
        mock.publish.assert_not_called()
        mock.mkdir.assert_called_once_with(producer.ATTEMPT_ROOT, 0o700)
        self.assertEqual(caught.exception.http_native_collection["status"], "REFUSED")

    def test_readiness_failure_retains_partial_capture_and_cleans_owned_child_once(
        self,
    ):
        mock = self.collection_mocks(readiness=False)
        with self.assertRaises(producer.NativeHttpCollectionError) as caught:
            producer.collect_native_http_attempt(**mock.arguments)
        mock.spawn.assert_called_once()
        mock.kill.assert_called_once_with(700, producer.signal.SIGKILL)
        mock.child.wait.assert_called_once_with(timeout=3)
        mock.child.stdin.close.assert_called_once()
        mock.child.stdout.close.assert_called_once()
        mock.child.stderr.close.assert_called_once()
        mock.sink.observe_attempt.assert_not_called()
        mock.child.stdin.write.assert_called_once_with(b"READY\n")
        self.assertEqual(
            caught.exception.http_native_collection["status"], "INDETERMINATE"
        )
        self.assertEqual(mock.publish.call_count, 2)
        self.assertEqual(
            mock.publish.call_args.args[0], producer.ATTEMPT_ROOT + "/capture.json"
        )

    def test_captured_success_is_not_qualification_and_never_starts_services(self):
        mock = self.collection_mocks()
        result = producer.collect_native_http_attempt(**mock.arguments)
        mock.spawn.assert_called_once()
        self.assertEqual(
            mock.spawn.call_args.args[0], [producer._NODE, producer.DRIVER_PATH]
        )
        self.assertEqual(
            [call.args[0] for call in mock.child.stdin.write.call_args_list],
            [b"READY\n", b"GO\n"],
        )
        mock.sink.observe_attempt.assert_called_once()
        mock.kill.assert_not_called()
        self.assertEqual(result["status"], "OBSERVED")
        self.assertTrue(all(result[key] is False for key in producer.FALSE_FLAGS))
        self.assertEqual(mock.publish.call_count, 2)

    def test_fixed_prepared_input_rejects_negative_control_and_wrong_family(self):
        value = producer.build_native_http_input(
            request=PREPARED, expected_fixture=FIXTURE, readiness_nonce="e" * 32
        )
        self.assertEqual(value["request"], PREPARED)
        for update in (
            {"negative_control": True},
            {"family": "DESTRUCTIVE"},
            {"attempt_id": "p3-lab-a026"},
            {"url": "http://example.invalid"},
        ):
            with self.subTest(update=update), self.assertRaises(ValueError):
                producer.build_native_http_input(
                    request={**PREPARED, **update},
                    expected_fixture=FIXTURE,
                    readiness_nonce="e" * 32,
                )

    def test_source_render_is_finite_and_does_not_launch_children(self):
        inputs = {name: (ROOT / name).read_bytes() for name in producer.DRIVER_INPUTS}
        with (
            patch.object(
                producer.subprocess, "Popen", side_effect=AssertionError("child launch")
            ),
            patch.object(
                producer, "open_http_sink", side_effect=AssertionError("sink")
            ),
        ):
            raw = producer.render_native_http_driver(inputs)
        self.assertIn(b'const HTTP_TOOL = "aragorn_runtime_http_canary";', raw)
        self.assertIn(b'await release("READY\\n")', raw)
        self.assertIn(b'await base.gatewayCall("chat.send"', raw)
        self.assertNotIn(b"async function readProvider", raw)
        self.assertNotIn(b"async function run(base, kind, input)", raw)
        bad = {**inputs, producer.NATIVE_SOURCE: inputs[producer.NATIVE_SOURCE] + b"\n"}
        with self.assertRaises(producer.NativeHttpCollectionError):
            producer.render_native_http_driver(bad)

    def test_measurement_renderer_preserves_predecessors_and_extends_exact_inventory(
        self,
    ):
        inputs = {name: (ROOT / name).read_bytes() for name in renderer.INPUTS}
        output = renderer.render(inputs)
        self.assertEqual(set(output), set(renderer.INPUTS))
        for name in (renderer.PLAN, renderer.PRIOR):
            self.assertIn(
                b"<= 8192" if name == renderer.PLAN else b"_parse(raw, 8192)",
                output[name],
            )
            for source in renderer.HTTP_MEASUREMENT_SOURCES:
                self.assertEqual(
                    output[name].count(('    "' + source + '",\n').encode()), 1
                )
        self.assertIn(b"_http_collection.native_join(", output[renderer.PRIOR])
        self.assertIn(b"_http_collection.result_record(", output[renderer.EFFECTIVE])
        self.assertEqual(inputs, {name: (ROOT / name).read_bytes() for name in inputs})
        with self.assertRaises(renderer.HttpCollectionRenderError):
            renderer.render({**inputs, renderer.PLAN: inputs[renderer.PLAN] + b"\n"})

    def test_exact_http_worker_ingress_retains_actual_stamps(self):
        records = _worker_fixture()
        value = _verify_worker(records)
        self.assertEqual(
            value["stage_boottime_ns"],
            {name: records[name]["boottime_ns"] for name in records},
        )
        self.assertEqual(value["worker_request"]["attempt_id"], ATTEMPT)
        self.assertEqual(
            value["action_request"]["payload_digest"],
            contract.digest(contract.canary_request(ATTEMPT)),
        )

    def test_worker_request_overrides_and_cross_attempt_rejected_after_rehash(self):
        for update in (
            {"url": "http://example.invalid"},
            {"attempt_id": "p3-lab-a002"},
        ):
            records = _worker_fixture()
            records["ingress"]["body"]["worker_request"].update(update)
            records["ingress"]["body"]["worker_request_digest"] = canonical_digest(
                records["ingress"]["body"]["worker_request"]
            )
            ingress_fixture._rechain(records)
            with self.subTest(update=update), self.assertRaises(ValueError):
                _verify_worker(records)

    def test_http_action_wrong_fixture_and_payload_are_rejected(self):
        for key in ("path_digest", "payload_digest", "operation_digest"):
            records = _worker_fixture()
            body = records["action"]["body"]
            body["action_request"][key] = PIN
            body["action_request_digest"] = canonical_digest(body["action_request"])
            ingress_fixture._rechain(records)
            with self.subTest(key=key), self.assertRaises(ValueError):
                _verify_worker(records)

    def test_http_native_parameter_digest_is_reconstructed(self):
        records = _worker_fixture()
        records["attempt"]["body"]["attempt"]["event"]["params_digest"] = PIN
        ingress_fixture._rehash_attempt(records)
        ingress_fixture._rechain(records)
        with self.assertRaises(ValueError):
            _verify_worker(records)

    def test_ingress_clock_and_identity_mismatch_rejected(self):
        for field, value in (
            ("boottime_ns", 200),
            ("time_namespace", {"device": 4, "inode": 99}),
        ):
            records = _worker_fixture()
            records["action"][field] = value
            ingress_fixture._rechain(records)
            with self.subTest(field=field), self.assertRaises(ValueError):
                _verify_worker(records)

    def http_fixture(self):
        fixture = broker_fixture.BrokerDecisionMeasurementVerifyTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.path = deepcopy(subject.endpoint_descriptor(BINDING))
        fixture.request.update(subject.action_digests(ATTEMPT, BINDING))
        fixture.grant["operation_digest"] = fixture.request["operation_digest"]
        envelope = {
            "schema": "aragorn/runtime-http-broker-request/v1",
            "request": fixture.request,
            "effect": {
                "schema": "aragorn/runtime-http-canary-effect/v1",
                "operation": "http_canary_post",
                "attempt_id": ATTEMPT,
            },
        }
        fixture.profiled.update(
            schema=subject.PROFILED,
            envelope=envelope,
            envelope_digest=canonical_digest(envelope),
            request_digest=canonical_digest(fixture.request),
            measured_action={
                "schema": "aragorn/measured-runtime-action/v1",
                **{key: fixture.request[key] for key in subject._MEASURED},
            },
        )
        lease = deepcopy(fixture.state["claim"]["lease"])
        lease.update({key: fixture.request[key] for key in subject._MATCH})
        lease.update(
            grant_digest=canonical_digest(fixture.grant),
            submission_digest=canonical_digest(fixture.profiled),
            request_digest=canonical_digest(fixture.request),
        )
        observed = {
            **fixture.profiled,
            "schema": "aragorn/runtime-observed-http-submission/v1",
        }
        observed.pop("runtime_attribution")
        fixture.state.update(
            grant_digest=canonical_digest(fixture.grant),
            claim=capability.build_grant_claim(
                fixture.grant,
                lease,
                observed,
                fixture.attribution,
                canonical_digest(fixture.profiled),
                101,
            ),
        )
        fixture.pending.update(
            action_request_digest=canonical_digest(fixture.request),
            submission_digest=canonical_digest(fixture.profiled),
            lease_digest=canonical_digest(lease),
        )
        fixture.plan.update(
            attempt_id=ATTEMPT,
            grant_digest=canonical_digest(fixture.grant),
            **{key: fixture.request[key] for key in subject._MATCH},
        )
        fixture.decision.update(
            request_digest=canonical_digest(fixture.request),
            measured_action_digest=canonical_digest(
                fixture.profiled["measured_action"]
            ),
        )
        fixture.result = {
            "schema": "aragorn/runtime-http-broker-result/v1",
            "authority": "BROKER_HTTP_DECISION_ONLY_NOT_SINK_OR_RUN_QUALIFICATION",
            "request_digest": canonical_digest(fixture.request),
            "effect_digest": canonical_digest(envelope["effect"]),
            "attempt_id": ATTEMPT,
            "observation_digest": PIN,
            "verdict": "BLOCK",
            "reason_codes": ["ACTION_NOT_ALLOWED"],
            "effect_status": "NOT_PERFORMED",
            "decision": fixture.decision,
            "payload_decision": None,
            "transport": None,
            "run_conformance_eligible": False,
            "phase3_eligible": False,
            "production_activation_eligible": False,
        }
        fixture.receipt.update(
            submission_digest=canonical_digest(fixture.profiled),
            broker_result=fixture.result,
            broker_result_digest=canonical_digest(fixture.result),
        )
        return fixture

    def test_http_claim_joins_real_shaped_64_hex_nonce(self):
        fixture = self.http_fixture()
        result = subject.native_join(
            fixture.plan,
            fixture.pending,
            fixture.state,
            fixture.profiled,
            canonical_json(fixture.grant),
            fixture.path,
        )
        self.assertEqual(result, fixture.request)
        self.assertEqual(len(fixture.state["claim"]["lease"]["lease_nonce"]), 64)

    def test_short_nonce_and_wrong_fixture_plan_rejected(self):
        fixture = self.http_fixture()
        fixture.state["claim"]["lease"]["lease_nonce"] = "e" * 32
        with self.assertRaises(ValueError):
            subject.native_join(
                fixture.plan,
                fixture.pending,
                fixture.state,
                fixture.profiled,
                canonical_json(fixture.grant),
                fixture.path,
            )
        fixture = self.http_fixture()
        fixture.path["fixture"]["boot_id"] = "11111111-1111-2222-3333-444444444444"
        with self.assertRaises(ValueError):
            subject.native_join(
                fixture.plan,
                fixture.pending,
                fixture.state,
                fixture.profiled,
                canonical_json(fixture.grant),
                fixture.path,
            )

    def test_http_block_result_reconstructed_not_promoted(self):
        fixture = self.http_fixture()
        result = subject.result_record(
            fixture.state["claim"], fixture.receipt, fixture.result, fixture.request
        )
        self.assertEqual(
            result["profile_result"]["schema"],
            "aragorn/runtime-http-capability-lease-result/v1",
        )
        self.assertEqual(result["profile_result"]["effect_status"], "NOT_PERFORMED")

    def test_result_qualification_escalation_and_policy_mismatch_rejected(self):
        for update in (
            {"phase3_eligible": True},
            {"verdict": "ALLOW", "effect_status": "SENT"},
            {"reason_codes": ["MADE_UP_REASON"]},
            {"attempt_id": "p3-lab-a002"},
        ):
            fixture = self.http_fixture()
            fixture.result.update(update)
            fixture.receipt.update(
                broker_result=fixture.result,
                broker_result_digest=canonical_digest(fixture.result),
            )
            with self.subTest(update=update), self.assertRaises(ValueError):
                subject.result_record(
                    fixture.state["claim"],
                    fixture.receipt,
                    fixture.result,
                    fixture.request,
                )

    def test_sent_transport_requires_exact_request_bytes_and_separate_payload_decision(
        self,
    ):
        fixture = self.http_fixture()
        fixture.decision.update(verdict="ALLOW", reason_codes=[])
        transport = {
            "schema": "aragorn/runtime-http-action-result/v1",
            "authority": "CREDENTIAL_BOUND_LAB_HTTP_TRANSPORT_ONLY_NOT_POLICY_AUTHORITY",
            "attempt_id": ATTEMPT,
            "fixture_binding_digest": canonical_digest(BINDING),
            "effect_digest": fixture.result["effect_digest"],
            "action_digests": subject.action_digests(ATTEMPT, BINDING),
            "connect_attempted": True,
            "sent_bytes": len(contract.canary_request(ATTEMPT)),
            "response_bytes": len(contract.RESPONSE_BYTES),
            "response_digest": contract.digest(contract.RESPONSE_BYTES),
            "status": "SENT",
            "error_code": None,
            "identity": {
                "fixture": FIXTURE,
                "pid": 101,
                "start_time_ticks": 123,
                "uid": 995,
                "gid": 997,
            },
            **dict.fromkeys(contract.FALSE_FLAGS, False),
        }
        fixture.result.update(
            verdict="ALLOW",
            reason_codes=[],
            effect_status="SENT",
            payload_decision=deepcopy(fixture.decision),
            transport=transport,
        )
        fixture.receipt.update(
            broker_result=fixture.result,
            broker_result_digest=canonical_digest(fixture.result),
        )
        self.assertEqual(
            subject.result_record(
                fixture.state["claim"], fixture.receipt, fixture.result, fixture.request
            )["profile_result"]["effect_status"],
            "SENT",
        )
        transport["sent_bytes"] -= 1
        fixture.receipt["broker_result_digest"] = canonical_digest(fixture.result)
        with self.assertRaises(ValueError):
            subject.result_record(
                fixture.state["claim"], fixture.receipt, fixture.result, fixture.request
            )

    def native_driver_fixture(self):
        records = _worker_fixture()
        chain = _verify_worker(records)
        broker = self.http_fixture().result
        attempt = records["attempt"]["body"]["attempt"]
        correlation = {
            key: attempt["event"][key]
            for key in (
                "run_id",
                "session_id",
                "session_key_digest",
                "tool_call_digest",
            )
        }
        source = {
            "schema": "aragorn/runtime-action-worker-result/v1",
            "authority": "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
            "request_digest": canonical_digest(chain["worker_request"]),
            "status": "COMPLETED",
            "broker_result": broker,
        }
        text = canonical_json(
            {
                "schema": "aragorn/runtime-action-worker-tool-result-text/v1",
                "message": "Aragorn BLOCK: NOT_PERFORMED",
                "result": source,
            }
        ).decode()
        params = {
            "attempt_id": ATTEMPT,
            "__aragorn_run_id": correlation["run_id"],
            "__aragorn_session_id": correlation["session_id"],
            "__aragorn_session_key_digest": correlation["session_key_digest"],
            "__aragorn_tool_call_digest": correlation["tool_call_digest"],
        }
        result = {
            "content": [{"type": "text", "text": text}],
            "details": {
                "schema": "aragorn/runtime-action-worker-openclaw-details/v1",
                "status": "blocked",
                "source_result": source,
            },
        }
        result_text = json.dumps(result, separators=(",", ":"))
        terminal = {
            "schema": "aragorn/native-tool-receipt/v1",
            "authority": subject.ingress._RECEIPT_AUTHORITY,
            "genesis_digest": attempt["genesis_digest"],
            "sequence": 2,
            "previous_digest": canonical_digest(attempt),
            "event": {
                "schema": "aragorn/native-tool-terminal/v1",
                "authority": subject.ingress._EVENT_AUTHORITY,
                "tool_name": subject.TOOL,
                **correlation,
                "attempt_digest": canonical_digest(attempt),
                "outcome": "RETURNED",
                "result_digest": contract.digest(result_text.encode()),
                "result_bytes": len(result_text),
                "error_code": None,
            },
        }
        driver = {
            "schema": "aragorn/native-http-tool-driver/v1",
            "authority": "NATIVE_HTTP_RELAY_ONLY_NOT_CAUSATION_OR_TIMING",
            "status": "OBSERVED",
            "tool_name": subject.TOOL,
            "prepared_request": PREPARED,
            "fixture": FIXTURE,
            "readiness_nonce": "e" * 32,
            "gateway_pid": chain["gateway_peer"]["pid"],
            "correlation": correlation,
            "worker_request": {
                "document": chain["worker_request"],
                "digest": canonical_digest(chain["worker_request"]),
                "bytes": len(canonical_json(chain["worker_request"])),
            },
            "source_result": {
                "document": source,
                "digest": canonical_digest(source),
                "bytes": len(canonical_json(source)),
            },
            "native_callback": {
                "params_json": json.dumps(params, separators=(",", ":")),
                "result_json": result_text,
            },
            "transcript": {"bytes": 2000, "digest": PIN},
            "provider": {
                "request_count": 2,
                "records": [
                    {
                        "sequence": 1,
                        "request_bytes": 1000,
                        "tool_contract_digest": PIN,
                        "result_text_digest": None,
                    },
                    {
                        "sequence": 2,
                        "request_bytes": 2000,
                        "tool_contract_digest": PIN,
                        "result_text_digest": contract.digest(text.encode()),
                    },
                ],
            },
            "raw_callback_projection_is_source_derived": True,
            "native_ack_wire_capture": False,
            "phase3_eligible": False,
            "run_conformance_eligible": False,
        }
        arguments = {
            "chain": chain,
            "broker_result": broker,
            "scheduled_request": PREPARED,
            "fixture": FIXTURE,
            "readiness_nonce": "e" * 32,
            "attempt_raw": canonical_json(records["attempt"]),
            "expected_attempt_record_digest": canonical_digest(records["attempt"]),
        }
        return driver, terminal, arguments

    def test_native_callback_and_terminal_are_joined_without_qualification(self):
        driver, terminal, args = self.native_driver_fixture()
        value = subject.verify_native_http_driver(
            canonical_json(driver),
            expected_digest=canonical_digest(driver),
            terminal_raw=canonical_json(terminal),
            expected_terminal_digest=canonical_digest(terminal),
            **args,
        )
        self.assertTrue(all(value[key] is False for key in subject.FALSE_FLAGS))
        self.assertEqual(value["terminal_digest"], canonical_digest(terminal))

    def test_cross_native_terminal_and_missing_source_result_rejected_after_rehash(
        self,
    ):
        for target in ("terminal", "params", "source", "gateway"):
            driver, terminal, args = self.native_driver_fixture()
            if target == "terminal":
                terminal["event"]["attempt_digest"] = PIN
            elif target == "params":
                driver["native_callback"]["params_json"] += " "
            elif target == "source":
                driver["source_result"]["document"] = None
            else:
                driver["gateway_pid"] += 1
            with self.subTest(target=target), self.assertRaises(ValueError):
                subject.verify_native_http_driver(
                    canonical_json(driver),
                    expected_digest=canonical_digest(driver),
                    terminal_raw=canonical_json(terminal),
                    expected_terminal_digest=canonical_digest(terminal),
                    **args,
                )


if __name__ == "__main__":
    unittest.main()
