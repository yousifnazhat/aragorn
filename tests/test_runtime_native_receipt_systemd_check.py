"""Inert receipt/projection checks; never activates services or contacts Docker."""

import copy
import io
import itertools
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import runtime_native_receipt_systemd_check as subject
from scripts import stage_runtime_native_receipt_profile as stage
from tests.test_runtime_native_tool_receipts import Fixture

ROOT = Path(__file__).resolve().parents[1]
DRIVER = (
    ROOT
    / "benchmark/admission/openclaw-v2026.7.1/native-receipt-read-create-driver-v1.mjs"
)


class NativeReceiptFixtureTests(unittest.TestCase):
    def test_exact_installed_pins_and_credential_sets(self):
        original, replacements = stage._verified_payloads()
        payloads = original | replacements
        for path, (size, digest, mode) in subject._EXTRA_CODE.items():
            _, installed_mode, raw = payloads[path.removeprefix("/")]
            self.assertEqual(
                (len(raw), subject.prior._digest(raw)), (size, "sha256:" + digest)
            )
            self.assertEqual(mode, installed_mode)
        self.assertEqual(
            (DRIVER.stat().st_size, subject.prior._digest(DRIVER.read_bytes())),
            subject._DRIVER_PIN,
        )
        common = (
            "native-tool-genesis",
            "/etc/aragorn/runtime-native-tool-genesis.json",
        )
        config = ("openclaw-config", "/etc/aragorn/agent-gateway/openclaw.json")
        for unit, values in (
            (
                subject.setup_prior._WORKER,
                (
                    ("worker-binding", "/etc/aragorn/runtime-action-worker.json"),
                    config,
                    common,
                ),
            ),
            (subject.setup_prior._GATEWAY, (config, common)),
        ):
            for order in itertools.permutations(values):
                fields = [
                    "a(ss)",
                    str(len(values)),
                    *itertools.chain.from_iterable(order),
                ]
                subject._credentials(" ".join(fields), unit)
            for raw in (
                "a(ss) 0",
                " ".join(fields[:-1]),
                " ".join(fields + ["extra"]),
                " ".join(fields).replace("native-tool-genesis", "other"),
            ):
                with self.subTest(unit=unit, raw=raw), self.assertRaises(RuntimeError):
                    subject._credentials(raw, unit)

    def test_actual_local_receipts_join_driver_projections_and_reject_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary).resolve() / "receipts")
            fixture.genesis["runtime_digest"] = subject._RUNTIME
            fixture.expected = canonical_digest(fixture.genesis)
            fixture.state["genesis_digest"] = fixture.expected
            fixture.write("genesis.json", canonical_json(fixture.genesis))
            fixture.write("state.json", canonical_json(fixture.state))
            store = fixture.open()
            drivers = []
            for index, tool in enumerate(("read", "aragorn_runtime_create"), 1):
                attempt = fixture.attempt(index, tool)
                ack = store.retain_attempt(attempt)
                terminal = fixture.terminal(attempt, ack)
                store.retain_terminal(terminal)
                drivers.append(
                    {
                        "tool_name": tool,
                        "status": "OBSERVED",
                        "phase3_eligible": False,
                        "run_conformance_eligible": False,
                        "turn": {
                            "identifiers": {
                                **{
                                    key: attempt[key]
                                    for key in subject.core._CORRELATION
                                },
                                "request_digest": attempt["worker_request_digest"],
                            }
                        },
                        "native_projection": {
                            "params": {
                                "bytes": attempt["params_bytes"],
                                "digest": attempt["params_digest"],
                            },
                            "result": {
                                "bytes": terminal["result_bytes"],
                                "digest": terminal["result_digest"],
                            },
                        },
                    }
                )
            state = json.loads((fixture.root / "state.json").read_bytes())
            cas = CAS(fixture.root / "cas", read_only=True)
            snapshot = {
                "genesis": fixture.genesis,
                "state": state,
                "receipts": [
                    json.loads(cas.read(digest)) for digest in state["receipts"]
                ],
            }
            acks = subject._receipt_proof(snapshot, drivers)
            self.assertEqual([ack["sequence"] for ack in acks], [1, 2, 3, 4])
            self.assertTrue(all(ack["effect_authorized"] is False for ack in acks))
            for kind in (
                "sequence",
                "previous",
                "terminal_event_digest",
                "params",
                "count",
                "runtime",
            ):
                bad, bad_drivers = copy.deepcopy(snapshot), copy.deepcopy(drivers)
                if kind == "sequence":
                    bad["receipts"][0]["sequence"] = True
                elif kind == "previous":
                    bad["receipts"][2]["previous_digest"] = fixture.expected
                elif kind == "terminal_event_digest":
                    bad["receipts"][1]["event"]["attempt_digest"] = canonical_digest(
                        bad["receipts"][0]["event"]
                    )
                elif kind == "params":
                    bad_drivers[0]["native_projection"]["params"]["bytes"] = 17.0
                elif kind == "count":
                    bad["state"]["receipts"].pop()
                else:
                    bad["genesis"]["runtime_digest"] = fixture.genesis["policy_digest"]
                with (
                    self.subTest(kind=kind),
                    self.assertRaises((RuntimeError, ValueError)),
                ):
                    subject._receipt_proof(bad, bad_drivers)

    def test_fixture_guard_precedes_effects_and_failure_always_stops_stack(self):
        with (
            patch.object(
                subject.setup_prior,
                "_require_fixture",
                side_effect=RuntimeError("guard"),
            ),
            patch.object(subject, "_prepare") as prepare,
        ):
            with self.assertRaisesRegex(RuntimeError, "guard"):
                subject._run("invalid")
            prepare.assert_not_called()
        with (
            patch.object(subject.setup_prior, "_require_fixture"),
            patch.object(subject, "_sources", return_value={}),
            patch.object(subject, "_prepare", side_effect=RuntimeError("setup")),
            patch.object(subject.prior, "_stop_fixture", return_value={}) as stop,
        ):
            with self.assertRaisesRegex(RuntimeError, "setup"):
                subject._run("c" * 64)
            stop.assert_called_once_with()
        with (
            patch.object(subject.response, "_read_regular", side_effect=OSError),
            patch.object(subject.setup_prior, "_stop_fixture", return_value={}) as stop,
        ):
            subject.prior._stop_fixture()
            stop.assert_called_once_with(reset_worker_failed=False)
        for failure, visible in (
            (
                subject._FixtureRefusal("native stream already exists"),
                "native stream already exists",
            ),
            (RuntimeError("SECRET_MUST_NOT_APPEAR"), "RuntimeError"),
        ):
            output = io.StringIO()
            with (
                patch.object(subject, "_run", side_effect=failure),
                redirect_stderr(output),
            ):
                self.assertEqual(subject.main(["c" * 64]), 126)
            self.assertIn(visible, output.getvalue())
            self.assertNotIn("SECRET_MUST_NOT_APPEAR", output.getvalue())

    def test_driver_input_keeps_legacy_newline_and_failure_diagnostics_redact(self):
        import runtime_action_worker_openclaw_systemd_probe as p37b

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(p37b, "_DRIVER_ROOT", Path(temporary)),
            patch.object(p37b.openclaw.profile_prior, "_write_file") as write,
            patch.object(subject.prior, "_stack_failure"),
            patch.object(
                p37b,
                "subprocess",
                SimpleNamespace(
                    run=lambda *_a, **_kw: SimpleNamespace(
                        returncode=1, stdout=b"", stderr=b"INERT_SECRET refused"
                    )
                ),
            ),
        ):
            with self.assertRaises(subject._FixtureRefusal) as failure:
                subject._driver(p37b, "read", "a" * 16, "INERT_SECRET")
            args = write.call_args.args
            document = json.loads(args[1])
            self.assertEqual(args[1], canonical_json(document) + b"\n")
            self.assertEqual(args[2:], (0, 0, 0o400))
            self.assertEqual(document["scenario"]["id"], "native-read-" + "a" * 16)
            notes = str(failure.exception.__notes__)
            self.assertNotIn("INERT_SECRET", notes)
            self.assertIn("[REDACTED]", notes)

    def test_driver_definitions_without_main_or_native_calls(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required for the inert driver regression")
        program = r"""
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const source = readFileSync(process.argv[1], "utf8");
const anchor = "\nmain().catch(";
assert.equal(source.split(anchor).length, 2);
const definitions = source.split(anchor)[0] + "\nexport { projection, run };\n";
const mod = await import("data:text/javascript;base64," + Buffer.from(definitions).toString("base64"));
const legacySource = readFileSync(process.argv[2], "utf8");
const legacy = await import("data:text/javascript;base64," + Buffer.from(legacySource.split("\nmain().catch((cause) => {")[0] + "\nexport { canonicalJson };\n").toString("base64"));
const canonicalJson = legacy.canonicalJson;
assert.equal(mod.projection({b:1,a:2}).bytes, 13);
assert.notEqual(mod.projection({b:1,a:2}).digest, mod.projection({a:2,b:1}).digest);
const scenario = {id:"inert-create",content:"Aragorn P3.7b distinct worker create\n",target_name:"runtime-worker-qualified.txt",
  expected_result:{schema:"aragorn/runtime-action-worker-result/v1",status:"COMPLETED",broker_result:{verdict:"ALLOW",effect_status:"CREATED"}}};
const retained = {result: scenario.expected_result};
const rpc = {role:"toolResult",toolName:"aragorn_runtime_create",toolCallId:"call1",isError:false,
  content:[{type:"text",text:canonicalJson(retained)}]};
const calls = [], provider = {records:[{},{}],errors:[],close:async()=>calls.push("close")};
const base = {canonicalJson, requiredSecret:()=>"INERT_TEST_ONLY", commandEnvironment:()=>({}),
  deterministicToolCallId:()=>"call1",startProvider:async()=>provider,
  waitForGateway:async()=>({command:{},response:{pid:42}}), parseCommand:(x)=>x,commandSummary:()=>({}),
  gatewayCall:async(method,_env,params)=>{ calls.push(method);
    if(method==="chat.send") {assert.equal(params.message,"Invoke aragorn_runtime_create exactly once for bounded scenario inert-create."); return {status:"started",runId:"run1"};}
    if(method==="agent.wait") return {status:"ok",runId:"run1",endedAt:1};
    assert.equal(method,"chat.history"); return {sessionKey:"agent:main:aragorn-worker-inert-create",sessionId:"session1",messages:[rpc]};},
  transcriptToolResult:()=>({message:rpc,checks:{same:true}}), workerRequest:()=>({request:"inert"}),
  relaySummary:()=>({observed:scenario.expected_result,details_checks:{same:true}}),expectedOutcome:()=>true};
const result = await mod.run(base,"create",{scenario});
assert.deepEqual(calls,["chat.send","agent.wait","chat.history","close"]);
assert.equal(result.phase3_eligible,false);
assert.equal(result.read_transcript,null);
const ids = result.turn.identifiers;
assert.deepEqual(result.native_projection.params,mod.projection({content:scenario.content,target_name:scenario.target_name,
  __aragorn_run_id:"run1",__aragorn_session_id:"session1",__aragorn_session_key_digest:ids.session_key_digest,__aragorn_tool_call_digest:ids.tool_call_digest}));
assert.deepEqual(result.native_projection.result,mod.projection({content:rpc.content,details:{schema:"aragorn/runtime-action-worker-openclaw-details/v1",status:"completed",source_result:JSON.parse(rpc.content[0].text).result}}));
provider.errors.push("PRIVATE_FIXTURE_TEST");
let diagnostic = "";
const originalWrite = process.stderr.write;
process.stderr.write = (text)=>{diagnostic += text; return true;};
try { await assert.rejects(mod.run({...base,gatewayCall:async()=>{throw new Error("PRIVATE_FIXTURE_TEST");}},"create",{scenario})); }
finally {process.stderr.write = originalWrite;}
assert.ok(!diagnostic.includes("PRIVATE_FIXTURE_TEST"));
assert.match(JSON.parse(diagnostic).provider_error_digests[0],/^sha256:[0-9a-f]{64}$/);
// Only the small transcript function is evaluated with inert I/O bindings.
const functionSource = source.split("function readTranscript(")[1].split("\nasync function run(")[0];
const text = JSON.stringify({type:"message",message:{role:"toolResult",toolName:"read",toolCallId:"read1",isError:false,content:[{type:"text",text:"inert"}]}})+"\n";
const raw = Buffer.from(text);
const fakeStat = ()=>({uid:1000,gid:1000,mode:0o100600});
const read = new Function("lstatSync","heldRead","expect","sha", "return function readTranscript("+functionSource)(fakeStat,()=>raw,(value)=>assert.ok(value),()=>"digest");
const readRpc = {toolCallId:"read1",content:[{type:"text",text:"inert"}]};
assert.equal(read({canonicalJson},"session1",readRpc).exact_transcript_rpc_join,true);
assert.throws(()=>read({canonicalJson},"session1",{...readRpc,toolCallId:"wrong"}));
console.log("INERT_DRIVER_CHECKS_PASSED");
"""
        completed = subprocess.run(
            [
                node,
                "--input-type=module",
                "-e",
                program,
                str(DRIVER),
                str(
                    ROOT
                    / "benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs"
                ),
            ],
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stdout, b"INERT_DRIVER_CHECKS_PASSED\n")


if __name__ == "__main__":
    unittest.main()
