"""New HTTP ingress branches only, with inert transport/identity/receipt doubles."""

from __future__ import annotations

import ast
from contextlib import nullcontext
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from aragorn import native_phase3_http_canary_contract as canary
from aragorn import runtime_action_observation_publisher as sensor
from aragorn import runtime_action_worker as worker
from aragorn import runtime_http_action as http
from aragorn import runtime_http_broker as broker
from aragorn import runtime_http_ingress as subject
from aragorn import runtime_process_profile as profile
from aragorn.oci_worker_protocol import canonical_digest
from scripts import materialize_runtime_http_ingress as renderer
from scripts import stage_runtime_phase3_ingress_profile as predecessor

PIN = "sha256:" + "1" * 64
FIXTURE = {
    "schema": http.BINDING_SCHEMA,
    "expected_broker_uid": 998,
    "expected_broker_gid": 997,
    "fixture": {
        "container_id": "a" * 64,
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "netns_device": 4,
        "netns_inode": 9,
    },
}
BINDING = worker.RuntimeActionWorkerBinding(PIN, PIN, PIN, 1)


def request():
    return http.build_worker_request(
        attempt_id="p3-lab-a001", session_id="s1", run_id="r1", tool_call_digest=PIN
    )


def envelope():
    with patch.object(http, "load_fixture_binding", return_value=deepcopy(FIXTURE)):
        return subject.worker_envelope(request(), b"", BINDING, 100)


def decision(document, allow=True):
    value = {key: 1 for key in worker._DECISION_FIELDS}
    value.update(
        {
            key: PIN
            for key in (
                "active_context_digest",
                "measured_action_digest",
                "policy_digest",
                "revocation_snapshot_digest",
                "mediator_health_digest",
            )
        }
    )
    value.update(
        schema=worker._DECISION_SCHEMA,
        authority=worker._DECISION_AUTHORITY,
        request_digest=canonical_digest(document["request"]),
        verdict="ALLOW" if allow else "BLOCK",
        reason_codes=[] if allow else ["ACTION_POLICY_BLOCKED"],
    )
    return value


def transport(document):
    effect = document["effect"]
    return {
        "schema": http.RESULT_SCHEMA,
        "authority": http.RESULT_AUTHORITY,
        "attempt_id": effect["attempt_id"],
        "fixture_binding_digest": canonical_digest(FIXTURE),
        "effect_digest": canonical_digest(effect),
        "action_digests": http.action_digests(effect["attempt_id"], FIXTURE),
        "connect_attempted": True,
        "sent_bytes": len(canary.canary_request(effect["attempt_id"])),
        "response_bytes": len(canary.RESPONSE_BYTES),
        "response_digest": canary.digest(canary.RESPONSE_BYTES),
        "status": "SENT",
        "error_code": None,
        "identity": {
            "fixture": deepcopy(FIXTURE["fixture"]),
            "pid": 42,
            "start_time_ticks": 100,
            "uid": 998,
            "gid": 997,
        },
        **dict.fromkeys(canary.FALSE_FLAGS, False),
    }


def result(document, allow=True):
    return broker._result(
        document["request"],
        document["effect"],
        PIN,
        decision(document, allow),
        [] if allow else ["ACTION_POLICY_BLOCKED"],
        transport(document) if allow else None,
        decision(document) if allow else None,
    )


@lru_cache(maxsize=1)
def sources():
    inherited, changed = predecessor._verified_payloads()
    original = {name: raw for name, _mode, raw in (inherited | changed).values()}
    return original, renderer.render(original)


def module(name):
    _original, rendered = sources()
    value = ModuleType("aragorn._http_ingress_test_" + Path(name).stem)
    sys.modules[value.__name__] = value
    try:
        exec(compile(rendered[name], name, "exec"), value.__dict__)
    finally:
        del sys.modules[value.__name__]
    return value


class HttpIngressHelpersTests(unittest.TestCase):
    def setUp(self):
        self.credential = patch.object(
            http, "load_fixture_binding", return_value=deepcopy(FIXTURE)
        )
        self.credential.start()
        self.addCleanup(self.credential.stop)

    def test_worker_request_has_no_effect_bytes_or_override(self):
        validated, payload = subject.worker_request(request())
        self.assertEqual(payload, b"")
        self.assertEqual(validated, request())
        self.assertEqual(subject.tool_name(validated), subject.TOOL_NAME)
        with self.assertRaises(ValueError):
            subject.worker_request(request() | {"host": "127.0.0.2"})

    def test_worker_envelope_uses_root_binding_and_existing_correlation(self):
        actual = envelope()
        self.assertEqual(actual["schema"], broker.ENVELOPE_SCHEMA)
        self.assertEqual(actual["effect"], http.effect_for_attempt("p3-lab-a001"))
        for key, digest in http.action_digests("p3-lab-a001", FIXTURE).items():
            self.assertEqual(actual["request"][key], digest)
        self.assertEqual(actual["request"]["tool_call_id"], PIN)
        self.assertEqual(actual["request"]["expires_at_unix"], 105)

    def test_worker_envelope_refuses_caller_payload_and_boolean_clock(self):
        for payload, now in ((b"x", 100), ("", 100), (b"", True), (b"", -1)):
            with self.subTest(payload=payload, now=now), self.assertRaises(ValueError):
                subject.worker_envelope(request(), payload, BINDING, now)

    def test_ingress_action_join_rechecks_all_three_digests(self):
        actual = envelope()["request"]
        self.assertTrue(subject.action_matches(request(), actual))
        for key in ("operation_digest", "path_digest", "payload_digest"):
            with self.subTest(key=key):
                self.assertFalse(subject.action_matches(request(), actual | {key: PIN}))

    def test_result_accepts_complete_sent_and_returns_detached_document(self):
        document = envelope()
        value = result(document)
        accepted = subject.broker_result(value, document, BINDING)
        accepted["transport"]["identity"]["pid"] = 1000
        self.assertEqual(value["transport"]["identity"]["pid"], 42)

    def test_result_accepts_block_without_transport_or_payload_decision(self):
        document = envelope()
        self.assertEqual(
            subject.broker_result(result(document, False), document, BINDING)[
                "effect_status"
            ],
            "NOT_PERFORMED",
        )

    def test_result_rejects_cross_attempt_and_false_completion(self):
        document = envelope()
        for key, changed in (
            ("attempt_id", "p3-lab-a002"),
            ("effect_digest", PIN),
            ("request_digest", PIN),
            ("effect_status", "CREATED"),
            ("run_conformance_eligible", True),
            ("transport", None),
            ("payload_decision", None),
        ):
            with self.subTest(key=key), self.assertRaises((ValueError, RuntimeError)):
                subject.broker_result(
                    result(document) | {key: changed}, document, BINDING
                )

    def test_result_rejects_changed_fixture_or_partial_send(self):
        document = envelope()
        for key, changed in (
            ("fixture_binding_digest", PIN),
            ("sent_bytes", 1),
            ("connect_attempted", False),
            ("response_digest", PIN),
        ):
            value = result(document)
            value["transport"][key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError):
                subject.broker_result(value, document, BINDING)

    def test_block_cannot_contain_sent_transport(self):
        document = envelope()
        value = result(document, False)
        value["transport"] = transport(document)
        with self.assertRaises(RuntimeError):
            subject.broker_result(value, document, BINDING)

    def sensor_config(self):
        return sensor.RuntimeActionObservationPublisherConfig(
            frontend_socket_path=Path("/run/fixture/sensor.sock"),
            runtime_directory=Path("/run/fixture"),
            instance_lock_path=Path("/run/fixture/sensor.lock"),
            backend_socket_path=Path("/run/backend/broker.sock"),
            protected_root=Path("/protected"),
            expected_observer_uid=0,
            expected_observer_gid=0,
            expected_runtime_uid=997,
            expected_runtime_gid=997,
            expected_broker_uid=998,
            expected_broker_gid=997,
            expected_runtime_digest=PIN,
            expected_active_skill_digest=PIN,
            expected_sensor_digest=PIN,
        )

    def test_sensor_measures_endpoint_and_authenticated_worker_peer(self):
        with (
            patch.object(sensor.os, "geteuid", return_value=0),
            patch.object(sensor.os, "getegid", return_value=0),
        ):
            observed = subject.observed_submission(
                envelope(), (42, 997, 997), self.sensor_config()
            )
        self.assertEqual(observed["schema"], broker.SUBMISSION_SCHEMA)
        self.assertEqual(observed["runtime_peer"], {"pid": 42, "uid": 997, "gid": 997})
        self.assertEqual(
            observed["measured_action"]["path_digest"],
            http.action_digests("p3-lab-a001", FIXTURE)["path_digest"],
        )

    def test_sensor_refuses_worker_identity_and_action_digest_changes(self):
        with (
            patch.object(sensor.os, "geteuid", return_value=0),
            patch.object(sensor.os, "getegid", return_value=0),
        ):
            for peer in ((42, 998, 997), (42, 997, 998)):
                with self.subTest(peer=peer), self.assertRaises(RuntimeError):
                    subject.observed_submission(envelope(), peer, self.sensor_config())
            changed = envelope()
            changed["request"]["path_digest"] = PIN
            with self.assertRaises(RuntimeError):
                subject.observed_submission(
                    changed, (42, 997, 997), self.sensor_config()
                )

    def test_sensor_refuses_changed_broker_credential_identity(self):
        document = envelope()
        with (
            patch.object(
                http,
                "load_fixture_binding",
                return_value=FIXTURE | {"expected_broker_uid": 999},
            ),
            patch.object(sensor.os, "geteuid", return_value=0),
            patch.object(sensor.os, "getegid", return_value=0),
        ):
            with self.assertRaises(RuntimeError):
                subject.observed_submission(
                    document, (42, 997, 997), self.sensor_config()
                )


class HttpIngressRenderedTests(unittest.TestCase):
    def test_renderer_preserves_predecessors_and_only_eight_sources(self):
        original, rendered = sources()
        self.assertEqual(set(rendered), set(renderer.INPUTS))
        self.assertEqual(renderer.render(original), rendered)
        for name, raw in rendered.items():
            self.assertNotEqual(raw, original[name])
            if name.endswith(".py"):
                compile(raw, name, "exec")

    def test_plugin_manifest_and_worker_preflight_allow_exact_same_tool_set(self):
        _original, rendered = sources()
        manifest = json.loads(rendered[renderer.MANIFEST])
        self.assertEqual(
            manifest["contracts"]["tools"],
            ["aragorn_runtime_create", subject.TOOL_NAME],
        )
        self.assertEqual(
            manifest["toolMetadata"],
            {
                "aragorn_runtime_create": {"optional": True},
                subject.TOOL_NAME: {"optional": True},
            },
        )
        function = next(
            node
            for node in ast.parse(rendered[renderer.WORKER]).body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_activation_preflight"
        )
        allowed = [
            ast.literal_eval(node.values[index])
            for node in ast.walk(function)
            if isinstance(node, ast.Dict)
            for index, key in enumerate(node.keys)
            if isinstance(key, ast.Constant) and key.value == "alsoAllow"
        ]
        self.assertEqual(
            allowed, [["aragorn_runtime_create", subject.TOOL_NAME, "read"]]
        )

    def test_gateway_template_changes_only_allowlist_before_fresh_write(self):
        raw = (
            Path(__file__).resolve().parents[1] / renderer.GATEWAY_CONFIG
        ).read_bytes()
        changed = renderer.render_gateway_configuration(raw)
        old, new = json.loads(raw), json.loads(changed)
        self.assertEqual(
            new["tools"]["alsoAllow"],
            ["aragorn_runtime_create", subject.TOOL_NAME, "read"],
        )
        new["tools"]["alsoAllow"] = old["tools"]["alsoAllow"]
        self.assertEqual(new, old)
        self.assertNotEqual(changed, raw)

    def test_gateway_template_refuses_mutation_or_repeat_transformation(self):
        raw = (
            Path(__file__).resolve().parents[1] / renderer.GATEWAY_CONFIG
        ).read_bytes()
        for changed in (raw + b"\n", renderer.render_gateway_configuration(raw), b"{}"):
            with self.subTest(raw=changed[:10]), self.assertRaises(ValueError):
                renderer.render_gateway_configuration(changed)

    def test_renderer_refuses_any_changed_predecessor_or_missing_source(self):
        original, _ = sources()
        for name in renderer.INPUTS:
            with self.subTest(name=name), self.assertRaises(ValueError):
                renderer.render(original | {name: original[name] + b"\n"})
        with self.assertRaises(ValueError):
            renderer.render({})

    def test_actual_worker_branches_dispatch_http_and_keep_create_parser(self):
        rendered = module(renderer.WORKER)
        self.assertEqual(rendered._worker_request(request()), (request(), b""))
        create = {
            "schema": "aragorn/runtime-action-worker-request/v1",
            "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "target_name": "inert.txt",
            "payload_base64": "eA==",
            "session_id": "s1",
            "run_id": "r1",
            "tool_call_digest": PIN,
        }
        self.assertEqual(rendered._worker_request(create), (create, b"x"))
        with patch.object(http, "load_fixture_binding", return_value=FIXTURE):
            actual = rendered._broker_envelope(request(), b"", -1, BINDING, 100)
            self.assertEqual(actual, envelope())
            self.assertEqual(
                rendered._broker_result(result(actual), actual, BINDING), result(actual)
            )

    def test_actual_ingress_parser_accepts_fixed_http_without_create_bytes(self):
        rendered = module(renderer.INGRESS)
        self.assertEqual(rendered._worker_request(request()), (request(), b""))
        with self.assertRaises(ValueError):
            rendered._worker_request(request() | {"target_name": "wrong"})

    def test_actual_profiled_sensor_keeps_attribution_validation(self):
        base = module(renderer.SENSOR)
        rendered = module(renderer.PROFILED_SENSOR)
        rendered.build_observed_submission = base.build_observed_submission
        runtime_profile = profile.runtime_process_profile(
            {
                "schema": profile.PROFILE_SCHEMA,
                "authority": profile.PROFILE_AUTHORITY,
                "runtime_digest": PIN,
                "executable_digest": PIN,
                "skill_path": "/opt/fixture/SKILL.md",
                "cgroup": "/system.slice/fixture.service",
            }
        )
        v1 = HttpIngressHelpersTests().sensor_config()
        config = rendered.RuntimeActionObservationPublisherV2Config(
            **{
                name: getattr(v1, name)
                for name in v1.__dataclass_fields__
                if name != "expected_active_skill_digest"
            },
            runtime_profile=runtime_profile,
        )
        attribution = {
            "schema": profile.ATTRIBUTION_SCHEMA,
            "authority": profile.ATTRIBUTION_AUTHORITY,
            "profile_digest": runtime_profile.digest,
            "runtime_digest": PIN,
            "executable_digest": PIN,
            "active_skill_digest": PIN,
            "skill_path": str(runtime_profile.skill_path),
            "cgroup": runtime_profile.cgroup,
            "pid": 42,
            "uid": 997,
            "gid": 997,
            "start_time_ticks": 3,
            "mount_namespace": {"device": 7, "inode": 8},
        }
        with (
            patch.object(http, "load_fixture_binding", return_value=FIXTURE),
            patch.object(sensor.os, "geteuid", return_value=0),
            patch.object(sensor.os, "getegid", return_value=0),
        ):
            actual = rendered.build_profiled_submission(
                envelope(), (42, 997, 997), -1, config, attribution
            )
            self.assertEqual(actual["schema"], subject.PROFILED_SCHEMA)
            self.assertEqual(actual["runtime_attribution"], attribution)
            with self.assertRaises(RuntimeError):
                rendered.build_profiled_submission(
                    envelope(), (42, 997, 997), -1, config, attribution | {"pid": 43}
                )

    def test_actual_relay_binds_http_action_and_sends_sensor_frame_once(self):
        rendered = module(renderer.WORKER)
        connection = MagicMock()
        ingress = MagicMock()
        document = envelope()
        with (
            patch.object(http, "load_fixture_binding", return_value=FIXTURE),
            patch.object(rendered, "_open_protected_root", return_value=7),
            patch.object(
                rendered, "_connect_sensor", return_value=connection
            ) as connect,
            patch.object(rendered, "_send_frame") as send,
            patch.object(rendered, "_read_frame", return_value=result(document, False)),
            patch.object(rendered.os, "close"),
        ):
            actual = rendered._relay_request(
                request(),
                SimpleNamespace(binding=BINDING),
                deadline=1.25,
                clock=lambda: 100,
                ingress=ingress,
                ingress_trace="trace",
            )
        self.assertEqual(actual["status"], "COMPLETED")
        self.assertEqual(actual["broker_result"]["effect_status"], "NOT_PERFORMED")
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(send.call_args.args[2], 1.25)
        ingress.bind_action.assert_called_once_with("trace", document["request"])
        connection.close.assert_called_once()

    def test_actual_relay_preserves_indeterminate_after_sensor_send(self):
        rendered = module(renderer.WORKER)
        connection = MagicMock()
        with (
            patch.object(http, "load_fixture_binding", return_value=FIXTURE),
            patch.object(rendered, "_open_protected_root", return_value=7),
            patch.object(rendered, "_connect_sensor", return_value=connection),
            patch.object(rendered, "_send_frame") as send,
            patch.object(
                rendered, "_read_frame", side_effect=OSError("inert reply loss")
            ),
            patch.object(rendered.os, "close"),
        ):
            actual = rendered._relay_request(
                request(),
                SimpleNamespace(binding=BINDING),
                deadline=1.25,
                clock=lambda: 100,
                ingress=MagicMock(),
                ingress_trace="trace",
            )
        self.assertEqual(actual["status"], "INDETERMINATE")
        self.assertIsNone(actual["broker_result"])
        self.assertEqual(send.call_count, 1)

    def test_receipt_parser_accepts_http_tool_but_requires_request_digest(self):
        rendered = module(renderer.RECEIPTS)
        event = {
            "schema": "aragorn/native-tool-attempt/v1",
            "authority": "AUTHENTICATED_GATEWAY_REPORT_ONLY_NOT_CAUSATION_EFFECT_OR_RUN_AUTHORITY",
            "tool_name": subject.TOOL_NAME,
            "session_id": "s1",
            "run_id": "r1",
            "tool_call_digest": PIN,
            "session_key_digest": PIN,
            "params_digest": PIN,
            "params_bytes": 1,
            "worker_request_digest": canonical_digest(request()),
        }
        self.assertEqual(rendered._event(event, terminal=False), event)
        with self.assertRaises(rendered.NativeToolReceiptRejected):
            rendered._event(event | {"worker_request_digest": None}, terminal=False)

    def test_once_gate_keeps_http_attempt_consumed_after_relay_failure(self):
        rendered = module(renderer.WORKER)
        event = {
            "tool_name": subject.TOOL_NAME,
            "worker_request_digest": canonical_digest(request()),
            "session_id": "s1",
            "run_id": "r1",
            "tool_call_digest": PIN,
        }
        attempt = {"event": event}
        receipt = SimpleNamespace(
            _locked=lambda: nullcontext(7),
            _load=MagicMock(return_value=({}, [attempt])),
            genesis_digest=PIN,
            _halted=False,
        )
        ingress = MagicMock()
        consumed = set()
        with patch.object(
            rendered, "_relay_request", side_effect=RuntimeError("inert")
        ):
            with self.assertRaisesRegex(RuntimeError, "inert"):
                rendered._relay_native_attempt_once(
                    request(),
                    None,
                    deadline=1,
                    native_receipts=receipt,
                    relayed_native_attempts=consumed,
                    ingress=ingress,
                    ingress_trace=object(),
                )
        self.assertEqual(consumed, {canonical_digest(attempt)})
        with self.assertRaises(rendered._receipts.NativeToolReceiptRejected):
            rendered._relay_native_attempt_once(
                request(),
                None,
                deadline=1,
                native_receipts=receipt,
                relayed_native_attempts=consumed,
                ingress=ingress,
                ingress_trace=object(),
            )
        self.assertEqual(ingress.bind_attempt.call_count, 1)


_JS = r"""
const assert = require("node:assert/strict");
const vm = require("node:vm");
const input = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const calls = [];
const context = {module:{exports:{}}, Buffer, TextDecoder, console,
  process:{getuid:()=>996,geteuid:()=>996,getgid:()=>997,getegid:()=>997,getgroups:()=>[997],
    get exitCode(){return process.exitCode;},set exitCode(value){process.exitCode=value;}},
  require:(name)=>{
    if (name === "node:fs") return {};
    if (name === "node:net") return {createConnection:()=>{throw Error("NO SOCKETS");}};
    return require(name);
  }};
vm.createContext(context);
vm.runInContext(input.source,context);
context.input=input;
vm.runInContext(`
const assert = require("node:assert/strict");
const testPlugin = module.exports;
const ctx = {runId:"r1",sessionId:"s1",toolCallDigest:"sha256:"+"1".repeat(64)};
${input.body}
`,context);
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required")
class HttpNativeClientTests(unittest.TestCase):
    def node(self, body, **values):
        _, rendered = sources()
        completed = subprocess.run(
            ["node", "-e", _JS],
            input=json.dumps(
                {"source": rendered[renderer.PLUGIN].decode(), "body": body, **values}
            ).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_fixed_http_request_matches_python_wire_document(self):
        self.node(
            'assert.equal(JSON.stringify(testPlugin.__testing.buildHttpRequest(ctx,"p3-lab-a001")), JSON.stringify(input.expected));',
            expected=request(),
        )

    def test_http_request_rejects_nonfinite_attempts(self):
        self.node(
            'for(const id of ["p3-lab-a000","p3-lab-a026","../x",null]) assert.throws(()=>testPlugin.__testing.buildHttpRequest(ctx,id));'
        )

    def test_registration_retains_create_and_adds_only_fixed_http_tool(self):
        self.node("""
const registrations=[];
testPlugin.register({pluginConfig:{expectedGatewayUid:996,expectedGatewayGid:997,
  expectedWorkerUid:997,workerSocketPath:"/run/fixture/worker.sock"},
  registerTool:(factory,options)=>registrations.push([factory,options])});
assert.equal(registrations.length,2);
const item=registrations.find(([,options])=>options.name==="aragorn_runtime_http_canary");
const tool=item[0]({sessionId:"s1",sessionKey:"key"});
assert.equal(JSON.stringify(tool.parameters.required),'["attempt_id"]');
assert.equal(tool.parameters.additionalProperties,false);
assert.equal(Object.keys(tool.parameters.properties).join(),"attempt_id");
const prepared=tool.prepareBeforeToolCallParams({attempt_id:"p3-lab-a001"},
  {toolCallId:"call1",hookContext:{runId:"r1",sessionId:"s1",sessionKey:"key"}});
assert.equal(prepared.__aragorn_run_id,"r1");
assert.throws(()=>tool.prepareBeforeToolCallParams({attempt_id:"p3-lab-a001",__aragorn_run_id:"evil"},
  {toolCallId:"call1",hookContext:{runId:"r1",sessionId:"s1",sessionKey:"key"}}));
""")

    def test_native_http_client_retains_attempt_then_terminal_once(self):
        self.node("""
const events=[];
requestWorker = async (_config,event,_signal,parse)=>{
  events.push(event);
  const n=events.length;
  const ack={schema:"aragorn/native-tool-receipt-ack/v1",
    authority:"WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
    genesis_digest:"sha256:"+"a".repeat(64),receipt_digest:"sha256:"+(n===1?"b":"c").repeat(64),
    event_digest:sha256(Buffer.from(canonicalJson(event),"ascii")),sequence:n,
    status:n===1?"ATTEMPT_RECORDED_EXECUTE_ONCE":"TERMINAL_RECORDED",
    effect_authorized:false,run_qualified:false};
  return parse(Buffer.from(canonicalJson(ack),"ascii"),event);
};
const native=testPlugin.nativeClient.createNativeToolClient(
  {expectedGatewayUid:996,expectedGatewayGid:997,expectedWorkerUid:997,workerSocketPath:"/run/fixture/worker.sock"},
  "sha256:"+"a".repeat(64));
const params={attempt_id:"p3-lab-a001",__aragorn_run_id:"r1",__aragorn_session_id:"s1",
  __aragorn_session_key_digest:sha256(Buffer.from("key")),__aragorn_tool_call_digest:sha256(Buffer.from("call1"))};
let invoked=0;
native.execute("aragorn_runtime_http_canary",params,
  {runId:"r1",sessionId:"s1",sessionKey:"key",toolCallId:"call1"},
  async(detached)=>{invoked++;assert.equal(detached.attempt_id,"p3-lab-a001");return {done:true};})
  .then(()=>{assert.equal(invoked,1);assert.equal(events.length,2);
    assert.equal(events[0].tool_name,"aragorn_runtime_http_canary");
    const req=buildHttpRequest({runId:"r1",sessionId:"s1",toolCallDigest:params.__aragorn_tool_call_digest},"p3-lab-a001");
    assert.equal(events[0].worker_request_digest,sha256(Buffer.from(canonicalJson(req),"ascii")));
    assert.equal(events[1].outcome,"RETURNED");})
  .catch(error=>{console.error(error);process.exitCode=1;});
""")

    def test_http_result_accepts_sent_and_refuses_create_label(self):
        document = envelope()
        self.node(
            """
const request=buildHttpRequest(ctx,"p3-lab-a001");
const result=JSON.parse(JSON.stringify(input.result));
validateHttpBrokerResult(result,request);
assert.throws(()=>validateHttpBrokerResult({...result,effect_status:"CREATED"},request));
assert.throws(()=>validateHttpBrokerResult({...result,phase3_eligible:true},request));
""",
            result=result(document),
        )


if __name__ == "__main__":
    unittest.main()
