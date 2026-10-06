"""Pinned rendering and inert JS definitions only; no guest, provider or tool run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import materialize_runtime_native_blocked_create_driver as subject

# The local pipeline deliberately supplies only os.defpath. Use this reviewed
# developer interpreter explicitly; it is not the fixture's Node v24 runtime.
# Keep its content pin in this fingerprinted test source, not an ambient PATH.
_NODE = Path("/opt/homebrew/Cellar/node/26.3.1/bin/node")
_NODE_DIGEST = "56694c81b093cc8da273fa017cf91765b3653e5f64f16727976ffaa87b2b6b31"


_JS = r"""
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
const input = JSON.parse(readFileSync(0, "utf8"));
const anchor = "\nmain().catch(";
assert.equal(input.native.split(anchor).length, 2);
assert.equal(input.legacy.split(anchor).length, 2);
let diagnostic = "";
// Evaluated definitions have no actual main/import/provider/gateway invocation.
// All I/O available to the functions under test is an explicit inert double.
const nativeBody = input.native.slice(input.native.indexOf("const LEGACY ="), input.native.indexOf(anchor));
const mod = new Function("createHash", "Buffer", "structuredClone", "process",
  nativeBody + "\nreturn {run, projection, retainedDocument};")(
  createHash, Buffer, structuredClone, {stderr:{write:(value)=>{diagnostic += value;}}});
let transcript;
const fakeStat = () => ({isFile:()=>true,isSymbolicLink:()=>false,nlink:1,dev:1,ino:2,mtimeMs:3,
  size:Buffer.byteLength(JSON.stringify({type:"message",message:transcript})+"\n")});
const legacyBody = input.legacy.slice(input.legacy.indexOf("const INPUT_SCHEMA"), input.legacy.indexOf(anchor));
const helpers = new Function("createHash", "Buffer", "resolve", "lstatSync", "readFileSync",
  legacyBody + "\nreturn {canonicalJson,workerRequest,relaySummary,expectedOutcome,transcriptToolResult,deterministicToolCallId};")(
  createHash, Buffer, resolve, fakeStat, ()=>Buffer.from(JSON.stringify({type:"message",message:transcript})+"\n"));
const {canonicalJson} = helpers;
const sha = value => "sha256:"+createHash("sha256").update(value).digest("hex");
const pin = letter => "sha256:"+letter.repeat(64);
const container = "c".repeat(64);

function fixture() {
  diagnostic = "";
  const scenario = {id:"inert-blocked-create",target_name:"runtime-worker-qualified.txt",
    content:"Aragorn P3.7b distinct worker create\n",expected_result:{
      schema:"aragorn/runtime-action-worker-result/v1",status:"COMPLETED",
      broker_result:{verdict:"BLOCK",effect_status:"NOT_PERFORMED"}}};
  const call = helpers.deterministicToolCallId(scenario.id);
  const request = helpers.workerRequest(scenario,"session1","run1",call);
  const decision = {schema:"aragorn/runtime-action-decision/v1",
    authority:"RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
    request_digest:pin("b"),policy_digest:pin("a"),policy_version:1,verdict:"ALLOW",reason_codes:[],
    active_context_digest:pin("a"),measured_action_digest:pin("a"),
    revocation_snapshot_digest:pin("a"),mediator_health_digest:pin("a"),evaluated_at_unix:1,
    revocation_generation:1,minimum_revocation_generation:1,mediator_health_epoch:1,minimum_mediator_health_epoch:1};
  const result = {schema:"aragorn/runtime-action-worker-result/v1",
    authority:"WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
    request_digest:sha(Buffer.from(canonicalJson(request),"ascii")),status:"COMPLETED",broker_result:{
      schema:"aragorn/runtime-action-broker-result/v1",
      authority:"RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
      request_digest:pin("b"),observation_digest:pin("a"),target_name:scenario.target_name,
      verdict:"BLOCK",effect_status:"NOT_PERFORMED",reason_codes:["BROKER_TARGET_EXISTS"],decision}};
  const rpc = {__openclaw:{},role:"toolResult",timestamp:1,toolName:"aragorn_runtime_create",
    toolCallId:call,isError:false,content:[]};
  const refresh = () => {
    rpc.content = [{type:"text",text:canonicalJson({schema:"aragorn/runtime-action-worker-tool-result-text/v1",
      message:`Aragorn ${result.broker_result?.verdict}: ${result.broker_result?.effect_status}`,result})}];
    transcript = {role:rpc.role,timestamp:rpc.timestamp,toolName:rpc.toolName,toolCallId:rpc.toolCallId,
      isError:rpc.isError,content:structuredClone(rpc.content),details:{
        schema:"aragorn/runtime-action-worker-openclaw-details/v1",status:"blocked",source_result:structuredClone(result)}};
  };
  refresh();
  const calls = [], records = [{sequence:1},{sequence:2}], errors = [];
  const provider = {records,errors,close:async()=>{calls.push("close");}};
  const base = {...helpers,requiredSecret:()=>"INERT_SECRET",commandEnvironment:()=>({}),
    startProvider:async()=>{calls.push("provider");return provider;},
    waitForGateway:async()=>{calls.push("ready");return {command:{},response:{pid:42}};},
    parseCommand:value=>value,commandSummary:()=>({}),
    gatewayCall:async(method,_environment,params)=>{
      calls.push(method);
      if(method==="chat.send") {
        assert.equal(params.deliver,false);
        assert.equal(params.message,`Invoke aragorn_runtime_create exactly once for bounded scenario ${scenario.id}.`);
        return {status:"started",runId:"run1"};
      }
      if(method==="agent.wait") return {status:"ok",runId:"run1",endedAt:1};
      assert.equal(method,"chat.history");
      return {sessionKey:`agent:main:aragorn-worker-${scenario.id}`,sessionId:"session1",messages:[rpc]};
    }};
  return {scenario,request,result,rpc,refresh,calls,provider,base};
}

if (input.mode === "positive") {
  const f = fixture();
  const out = await mod.run(f.base,"blocked-create",{scenario:f.scenario},container);
  assert.deepEqual(f.calls,["provider","ready","chat.send","agent.wait","chat.history","close"]);
  assert.equal(out.schema,"aragorn/native-blocked-create-tool-driver/v1");
  assert.equal(out.authority,"OWNED_FIXTURE_TOOL_RELAY_OBSERVATION_NOT_SINK_ATTRIBUTION_OR_TIMING");
  assert.equal(out.container_id,container);
  assert.equal(out.read_transcript,null);
  assert.equal(out.source_result.document.broker_result.decision.verdict,"ALLOW");
  assert.equal(out.relay.observed.broker_result.verdict,"BLOCK");
  for(const name of ["worker_request","source_result"]){
    const value=out[name],raw=Buffer.from(canonicalJson(value.document),"ascii");
    assert.equal(value.bytes,raw.length); assert.equal(value.digest,sha(raw));
  }
  assert.deepEqual(out.worker_request.document,f.request);
  assert.deepEqual(out.source_result.document,f.result);
  for(const name of ["params","result"]){
    const raw=Buffer.from(out.native_callback[name+"_json"],"utf8");
    assert.equal(out.native_projection[name].bytes,raw.length);
    assert.equal(out.native_projection[name].digest,sha(raw));
  }
  const projected=JSON.parse(out.native_callback.result_json);
  assert.equal(projected.details.status,"blocked");
  assert.deepEqual(projected.details,transcript.details);
  assert.deepEqual(JSON.parse(projected.content[0].text).result,f.result);
  assert.equal(out.native_projection.result.digest,mod.projection(projected).digest);
  const wrong=structuredClone(projected);wrong.details.status="completed";
  assert.notEqual(out.native_projection.result.digest,mod.projection(wrong).digest);
  assert.ok(Object.values(out.transcript_checks).every(value=>value===true));
  assert.ok(Object.values(out.relay.details_checks).every(value=>value===true));
  for(const name of ["native_ack_wire_capture","sink_observed","attribution_verified","elapsed_time_derived","phase3_eligible","run_conformance_eligible"])
    assert.equal(out[name],false);
} else if(input.mode === "refusals") {
  for(const kind of ["read","create","arbitrary"]){
    const f=fixture();await assert.rejects(mod.run(f.base,kind,{scenario:f.scenario},container));
    assert.deepEqual(f.calls,[]);
  }
  for(const key of ["target","payload","expected","container"]){
    const f=fixture();
    if(key==="target")f.scenario.target_name="other.txt";
    if(key==="payload")f.scenario.content="different";
    if(key==="expected")f.scenario.expected_result.broker_result={verdict:"ALLOW",effect_status:"CREATED"};
    await assert.rejects(mod.run(f.base,"blocked-create",{scenario:f.scenario},key==="container"?"bad":container));
    assert.deepEqual(f.calls,[]);
  }
  for(const key of ["allow","details","source","rpc_join","request","empty_reason","duplicate"]){
    const f=fixture();
    if(key==="allow")Object.assign(f.result.broker_result,{verdict:"ALLOW",effect_status:"CREATED",reason_codes:[]});
    if(key==="empty_reason")f.result.broker_result.reason_codes=[];
    if(key==="request")f.result.request_digest=pin("f");
    f.refresh();
    if(key==="details")transcript.details.status="completed";
    if(key==="source")transcript.details.source_result.request_digest=pin("e");
    if(key==="rpc_join")transcript.content=[{type:"text",text:"different"}];
    if(key==="duplicate"){
      const call=f.base.gatewayCall;f.base.gatewayCall=async(...args)=>{
        const value=await call(...args);if(args[0]==="chat.history")value.messages.push(f.rpc);return value;};
    }
    await assert.rejects(mod.run(f.base,"blocked-create",{scenario:f.scenario},container));
    assert.equal(f.calls.filter(value=>value==="chat.send").length,1);
    assert.equal(f.calls.filter(value=>value==="close").length,1);
  }
} else if(input.mode === "failure_once") {
  for(const phase of ["chat.send","agent.wait","chat.history","close"]){
    const f=fixture(),original=f.base.gatewayCall;
    f.provider.errors.push("PRIVATE_TEST_FAILURE");
    f.base.gatewayCall=async(...args)=>{
      if(args[0]===phase){f.calls.push(phase);throw new Error("PRIVATE_TEST_FAILURE");}
      return original(...args);
    };
    if(phase==="close")f.provider.close=async()=>{f.calls.push("close");throw new Error("PRIVATE_TEST_FAILURE");};
    await assert.rejects(mod.run(f.base,"blocked-create",{scenario:f.scenario},container));
    assert.equal(f.calls.filter(value=>value==="chat.send").length,1);
    assert.equal(f.calls.filter(value=>value==="close").length,1);
    assert.ok(!diagnostic.includes("PRIVATE_TEST_FAILURE")&&!diagnostic.includes("INERT_SECRET"));
    assert.match(JSON.parse(diagnostic).provider_error_digests[0],/^sha256:[0-9a-f]{64}$/);
  }
} else if(input.mode === "fixture_guard") {
  const start=input.native.indexOf("function ownedFixture("),end=input.native.indexOf("\nfunction retainedDocument(");
  assert.ok(start>0&&end>start);
  const fn=input.native.slice(start,end);
  for(const fault of [null,"wrong","extra","oversize","inode","mode","owner","open"]){
    let count=0,closes=0,opens=0;
    const raw=Buffer.from(fault==="wrong"?`0::/docker/${"d".repeat(64)}/init.scope\n`:
      fault==="extra"?`0::/docker/${container}/init.scope\n1:name=systemd:/\n`:
      fault==="oversize"?"x".repeat(1025):`0::/docker/${container}/init.scope\n`);
    const metadata=()=>({isFile:()=>true,uid:fault==="owner"?1:0,gid:0,nlink:1,size:0,
      mode:fault==="mode"?0o100644:0o100444,dev:1,ino:2});
    const constants={O_RDONLY:0,O_NOFOLLOW:1,O_NONBLOCK:2};
    const open=(path,flags)=>{opens++;assert.equal(path,"/proc/1/cgroup");assert.equal(flags,3);
      if(fault==="open")throw new Error("open refused");return 50;};
    const read=(fd,buffer,offset,length)=>{assert.equal(fd,50);const n=Math.min(length,raw.length-count);
      raw.copy(buffer,offset,count,count+n);count+=n;return n;};
    const guard=new Function("constants","openSync","fstatSync","lstatSync","readSync","closeSync","Buffer","expect",
      fn+"\nreturn ownedFixture;")(
      constants,open,metadata,()=>({...metadata(),ino:fault==="inode"?3:2}),read,
      fd=>{assert.equal(fd,50);closes++;},Buffer,(value,message)=>assert.ok(value,message));
    assert.throws(()=>guard("invalid"));assert.equal(opens,0);
    if(fault===null)guard(container);else assert.throws(()=>guard(container));
    assert.equal(opens,1);assert.equal(closes,fault==="open"?0:1);
  }
  const main=input.native.slice(input.native.indexOf("async function main() {"));
  assert.ok(main.indexOf("ownedFixture(process.argv[3])")<main.indexOf("await legacyHelpers()"));
  assert.ok(main.includes('process.argv.length === 6 && process.argv[2] === "blocked-create"'));
  assert.ok(main.includes("base.readInput(process.argv[4])"));
  assert.ok(main.includes("base.publish(process.argv[5], result)"));
} else { throw new Error("unknown inert test mode"); }
console.log("INERT_BLOCKED_CREATE_DRIVER_CHECKS_PASSED");
"""


class NativeBlockedCreateDriverTests(unittest.TestCase):
    def node(self, mode):
        self.assertEqual(hashlib.sha256(_NODE.read_bytes()).hexdigest(), _NODE_DIGEST)
        native = subject._verified_source()
        legacy = subject.overlay._read_pinned(
            subject._LEGACY, *subject._INPUTS[subject._LEGACY], root=subject._ROOT
        )
        completed = subprocess.run(
            [str(_NODE), "--input-type=module", "-e", _JS],
            input=json.dumps(
                {"native": native.decode(), "legacy": legacy.decode(), "mode": mode}
            ).encode(),
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(hashlib.sha256(_NODE.read_bytes()).hexdigest(), _NODE_DIGEST)
        self.assertEqual(
            completed.stdout, b"INERT_BLOCKED_CREATE_DRIVER_CHECKS_PASSED\n"
        )

    def test_exact_sources_reversible_transform_and_independent_output_pin(self):
        original, legacy = (
            (subject._ROOT / name).read_bytes()
            for name in (subject._SOURCE, subject._LEGACY)
        )
        rendered = subject._verified_source()
        self.assertEqual(
            (len(rendered), "sha256:" + hashlib.sha256(rendered).hexdigest()),
            subject._OUTPUT,
        )
        for before, after in reversed(subject._REPLACEMENTS):
            self.assertEqual(rendered.count(after), 1)
            rendered = rendered.replace(after, before)
        self.assertEqual(rendered, original)
        for native_raw, legacy_raw in (
            (original + b"\n", legacy),
            (original, legacy + b"\n"),
            (b"", legacy),
            (original, bytearray(legacy)),
        ):
            with (
                self.subTest(sizes=(len(native_raw), len(legacy_raw))),
                self.assertRaises(subject.NativeBlockedCreateDriverError),
            ):
                subject._transform(native_raw, legacy_raw)
        # Pinning alone must not replace counted structural anchors.
        before, _ = subject._REPLACEMENTS[0]
        changed = original.replace(before, before + b"\n" + before)
        with patch.dict(
            subject._INPUTS,
            {subject._SOURCE: (len(changed), subject.overlay._digest(changed))},
        ):
            with self.assertRaisesRegex(
                subject.NativeBlockedCreateDriverError, "anchor"
            ):
                subject._transform(changed, legacy)

    def test_absent_only_source_artifact_and_failure_preserves_partial_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "driver"
            report = subject.materialize_runtime_native_blocked_create_driver(output)
            path = output / subject._OUTPUT_NAME
            self.assertEqual(path.read_bytes(), subject._verified_source())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            self.assertEqual(report["driver_schema"], subject.DRIVER_SCHEMA)
            self.assertEqual(
                report["files"],
                [
                    {
                        "name": subject._OUTPUT_NAME,
                        "bytes": subject._OUTPUT[0],
                        "digest": subject._OUTPUT[1],
                        "mode": "0444",
                    }
                ],
            )
            for name in (
                "standalone_executable",
                "capture_performed",
                "production_activation_eligible",
                "sink_observed",
                "attribution_verified",
                "elapsed_time_derived",
                "run_eligible",
                "phase3_eligible",
            ):
                self.assertIs(report[name], False)
            with self.assertRaises(subject.NativeBlockedCreateDriverError):
                subject.materialize_runtime_native_blocked_create_driver(output)
            link = root / "link"
            link.symlink_to(output, target_is_directory=True)
            with self.assertRaises(subject.NativeBlockedCreateDriverError):
                subject.materialize_runtime_native_blocked_create_driver(link)
            with self.assertRaises(subject.NativeBlockedCreateDriverError):
                subject.materialize_runtime_native_blocked_create_driver(
                    Path("relative")
                )
            raw = path.read_bytes()
            partial = root / "partial"
            with patch.object(
                subject, "_verified_source", side_effect=[raw, ValueError("changed")]
            ) as verify:
                with self.assertRaises(subject.NativeBlockedCreateDriverError):
                    subject.materialize_runtime_native_blocked_create_driver(partial)
                self.assertEqual(verify.call_count, 2)
            self.assertEqual((partial / subject._OUTPUT_NAME).read_bytes(), raw)
            # Publication intentionally leaves immutable outputs; only test
            # temporary-directory cleanup needs caller-owned directory writes.
            output.chmod(0o755)
            partial.chmod(0o755)

    def test_real_legacy_semantics_bind_blocked_callback_and_source_documents(self):
        self.node("positive")

    def test_fixed_inputs_and_coherent_result_transcript_tampering_are_refused(self):
        self.node("refusals")

    def test_command_and_provider_close_failures_never_retry_action_or_close(self):
        self.node("failure_once")

    def test_owned_cgroup_guard_is_bounded_held_and_precedes_helpers(self):
        self.node("fixture_guard")


if __name__ == "__main__":
    unittest.main()
