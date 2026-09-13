"""Synthetic inert Node fixtures only; no native hooks, effects or activation."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aragorn import runtime_native_tool_receipts as core
from scripts import materialize_runtime_native_tool_client as subject
from tests import test_runtime_action_worker_plugin as legacy

_JS = r"""
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const os = require("node:os");
const plugin = require(process.argv[1]);
const { canonicalJson, sha256, buildRequest } = plugin.__testing;
const { nativeSnapshot, nativeReceiptAck } = plugin.__nativeTesting;
const { createNativeToolClient } = plugin.nativeClient;
const digest = (c) => "sha256:" + c.repeat(64);
const genesis = digest("a");
const context = () => ({runId:"run-1", sessionId:"session-1", sessionKey:"session:key", toolCallId:"call:1"});
const response = (event, sequence, status) => ({
  schema:"aragorn/native-tool-receipt-ack/v1",
  authority:"WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
  genesis_digest:genesis, receipt_digest:digest(sequence % 2 ? "b" : "c"),
  event_digest:sha256(Buffer.from(canonicalJson(event), "ascii")), sequence,
  status:status || (sequence % 2 ? "ATTEMPT_RECORDED_EXECUTE_ONCE" : "TERMINAL_RECORDED"),
  effect_authorized:false, run_qualified:false,
});
const encode = (value) => Buffer.from(canonicalJson(value), "ascii");
const later = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return {promise, resolve}; };

async function fixture(handler, body) {
  // The transport server is inert and same-user. Only client identity functions
  // are mocked; this does not claim Linux peer credentials or actual UID split.
  const actualUid = process.getuid();
  const actualGid = process.getgid();
  const original = [process.getuid, process.getgid, process.getgroups];
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "native-client-test-"));
  const socketPath = path.join(root,"worker.sock");
  fs.chmodSync(root,0o711);
  const events = [];
  let connections = 0;
  const faults = [];
  const server = net.createServer({allowHalfOpen:true}, (socket) => {
    connections += 1;
    const chunks = [];
    socket.on("error", () => {});
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("end", async () => {
      try {
        const frame = Buffer.concat(chunks);
        assert.equal(frame.readUInt32BE(0), frame.length - 4);
        const raw = frame.subarray(4);
        const event = JSON.parse(raw.toString("ascii"));
        assert.equal(raw.toString("ascii"), canonicalJson(event));
        events.push(event);
        const ack = await handler(event, events.length);
        const payload = Buffer.isBuffer(ack) ? ack : encode(ack);
        const output = Buffer.alloc(4 + payload.length);
        output.writeUInt32BE(payload.length,0);
        payload.copy(output,4);
        socket.end(output);
      } catch (error) { faults.push(error); socket.destroy(); }
    });
  });
  await new Promise((resolve,reject) => { server.once("error",reject); server.listen(socketPath,resolve); });
  fs.chmodSync(socketPath,0o660);
  process.getuid = () => actualUid + 1;
  process.getgid = () => actualGid;
  process.getgroups = () => [actualGid];
  const config = {expectedGatewayUid:actualUid+1, expectedGatewayGid:actualGid, expectedWorkerUid:actualUid, workerSocketPath:socketPath};
  try {
    await body(createNativeToolClient(config,genesis), events, () => connections, config);
    assert.deepEqual(faults,[]);
  } finally {
    [process.getuid, process.getgid, process.getgroups] = original;
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(root,{recursive:true,force:true});
  }
}
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required")
class RuntimeNativeToolClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="native-client-source-test-")
        cls.output = Path(cls.temporary.name) / "source"
        cls.manifest = subject.materialize_runtime_native_tool_client(cls.output)
        cls.plugin = cls.output / "index.js"

    @classmethod
    def tearDownClass(cls):
        cls.output.chmod(0o755)
        cls.temporary.cleanup()

    def node(self, body):
        completed = subprocess.run(
            [
                "node",
                "-e",
                _JS
                + "\n(async()=>{\n"
                + body
                + "\n})().catch(e=>{console.error(e);process.exitCode=1;});",
                str(self.plugin),
            ],
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        return json.loads(completed.stdout) if completed.stdout else None

    def test_exact_source_read_only_output_and_original_effect_transport(self):
        self.assertEqual(
            (
                self.plugin.stat().st_size,
                subject.overlay._digest(self.plugin.read_bytes()),
            ),
            subject._OUTPUT,
        )
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o555)
        self.assertEqual(self.plugin.stat().st_mode & 0o777, 0o444)
        for name in (
            "standalone_executable",
            "production_activation_eligible",
            "native_hook_reachability",
            "create_to_attempt_enforcement",
            "mandatory_capture",
            "run_eligible",
        ):
            self.assertIs(self.manifest[name], False)
        original = subject.overlay._read_pinned(
            subject._PLUGIN, *subject._INPUTS[subject._PLUGIN], root=subject._ROOT
        )
        client = subject.overlay._read_pinned(
            subject._CLIENT, *subject._INPUTS[subject._CLIENT], root=subject._ROOT
        )
        changed = original
        for before, after in subject._REPLACEMENTS:
            self.assertEqual(changed.count(before), 1)
            changed = changed.replace(before, after)
        self.assertEqual(self.plugin.read_bytes(), changed + b"\n" + client)
        with mock.patch.object(legacy, "_PLUGIN", self.output):
            case = legacy.RuntimeActionWorkerPluginTests()
            case.test_exact_protocol_and_relay_semantics()
            case.test_uid_owned_endpoint_uses_exact_framing_without_retry()

    def test_pin_anchor_dependency_output_and_partial_publication_fail_closed(self):
        for category in ("plugin", "client", "dependency", "output", "anchor"):
            inputs = copy.deepcopy(subject._INPUTS)
            dependencies = copy.deepcopy(subject._DEPENDENCIES)
            output = subject._OUTPUT
            replacements = subject._REPLACEMENTS
            if category in {"plugin", "client"}:
                name = subject._PLUGIN if category == "plugin" else subject._CLIENT
                inputs[name] = (inputs[name][0] + 1, inputs[name][1])
            elif category == "dependency":
                name = next(iter(dependencies))
                dependencies[name] = (dependencies[name][0], "sha256:" + "0" * 64)
            elif category == "output":
                output = (output[0], "sha256:" + "0" * 64)
            else:
                replacements = ((b"nonexistent anchor", b"replacement"),)
            with (
                self.subTest(category=category),
                mock.patch.object(subject, "_INPUTS", inputs),
                mock.patch.object(subject, "_DEPENDENCIES", dependencies),
                mock.patch.object(subject, "_OUTPUT", output),
                mock.patch.object(subject, "_REPLACEMENTS", replacements),
                self.assertRaises(ValueError),
            ):
                subject._verified_inputs()
        with self.assertRaises(ValueError):
            subject.materialize_runtime_native_tool_client(self.output)
        with self.assertRaises(ValueError):
            subject.materialize_runtime_native_tool_client(Path("relative"))
        with (
            mock.patch.object(
                subject.overlay,
                "_write_overlay",
                side_effect=OSError("synthetic partial publication"),
            ),
            self.assertRaises(ValueError),
        ):
            subject.materialize_runtime_native_tool_client(
                Path(self.temporary.name) / "partial"
            )
        with (
            mock.patch.object(
                subject.overlay,
                "_digest",
                side_effect=AssertionError("hashed invalid size"),
            ),
            self.assertRaises(ValueError),
        ):
            subject._transform(b"", b"")

    def test_opaque_json_float_unicode_snapshot_and_unsupported_graphs(self):
        self.node(r"""
const value = {fraction:0.25, negativeZero:-0, nested:[true,null,"雪😀\ud800\n\u0001"]};
const saved = nativeSnapshot(value);
assert.equal(saved.raw.toString("utf8"), JSON.stringify(value));
assert.equal(Object.is(saved.snapshot.negativeZero,-0),true);
assert.equal(saved.digest, sha256(Buffer.from(JSON.stringify(value),"utf8")));
assert.equal(Object.isFrozen(saved.snapshot.nested),true);
value.nested[0] = false;
assert.equal(saved.snapshot.nested[0],true);
assert.throws(()=>canonicalJson({fraction:0.25}),/canonical/);
let effects = 0;
const getter = Object.defineProperty({},"x",{enumerable:true,get(){effects++;return 1;}});
const cycle = {}; cycle.x = cycle;
const deep = {}; let cursor = deep; for(let i=0;i<66;i++){cursor.x={};cursor=cursor.x;}
const proxy = new Proxy({}, {ownKeys(){effects++;return [];}});
for(const bad of [getter,cycle,deep,proxy,{toJSON(){effects++;return {}; }},NaN,Infinity,undefined,1n,new Date(),[ ,1],{x:()=>1},{x:Symbol("x")},{x:"x".repeat(16*1024*1024)}]) {
  assert.throws(()=>nativeSnapshot(bad),/UNSUPPORTED/);
}
assert.equal(effects,0);
const special = JSON.parse('{"__proto__":{"safe":true}}');
assert.equal(nativeSnapshot(special).raw.toString(),JSON.stringify(special));
""")

    def test_detached_final_params_context_create_request_and_exact_terminal(self):
        events = self.node(r"""
const entered = later(), release = later();
const all = [];
await fixture(async(event,n)=>{ if(n===1){entered.resolve();await release.promise;} return response(event,n); },async(client,events)=>{
  const params = {path:"original",limit:0.5,nested:{text:"雪"}};
  const ctx = context(); const saved = JSON.stringify(params);
  let calls = 0;
  const result = {content:[{type:"text",text:"inert"}],details:{elapsed:0.125}};
  const pending = client.execute("read",params,ctx,async(actual)=>{
    calls++; assert.equal(JSON.stringify(actual),saved); assert.notEqual(actual,params);
    assert.equal(Object.isFrozen(actual.nested),true); return result;
  });
  await entered.promise;
  params.path = "changed"; params.nested.text="changed"; ctx.runId="changed";
  release.resolve();
  assert.equal(await pending,result); assert.equal(calls,1);
  assert.equal(events[0].run_id,"run-1");
  assert.equal(events[0].params_digest,sha256(Buffer.from(saved,"utf8")));
  assert.equal(events[0].worker_request_digest,null);
  assert.equal(events[1].attempt_digest,digest("b"));
  assert.equal(events[1].result_digest,sha256(Buffer.from(JSON.stringify(result),"utf8")));
  assert.equal(events[1].outcome,"RETURNED"); all.push(...events);
});
await fixture((event,n)=>response(event,n),async(client,events)=>{
  const ctx=context();
  const params={content:"payload雪",target_name:"inert.txt",__aragorn_run_id:ctx.runId,__aragorn_session_id:ctx.sessionId,__aragorn_session_key_digest:sha256(Buffer.from(ctx.sessionKey)),__aragorn_tool_call_digest:sha256(Buffer.from(ctx.toolCallId))};
  const expected=buildRequest({runId:ctx.runId,sessionId:ctx.sessionId,toolCallDigest:params.__aragorn_tool_call_digest},params.target_name,Buffer.from(params.content,"utf8"));
  await client.execute("aragorn_runtime_create",params,ctx,async(actual)=>{assert.deepEqual(actual,params);return {inert:true};});
  assert.equal(events[0].worker_request_digest,sha256(Buffer.from(canonicalJson(expected),"ascii")));
  all.push(...events);
});
console.log(JSON.stringify(all));
""")
        self.assertEqual(len(events), 4)
        for index, event in enumerate(events):
            core._event(event, terminal=bool(index % 2))

    def test_ack_bindings_duplicate_uncertainty_and_sticky_no_execution(self):
        self.node(r"""
const mutations = [
  ack=>({...ack,genesis_digest:digest("d")}), ack=>({...ack,event_digest:digest("d")}),
  ack=>({...ack,receipt_digest:"bad"}), ack=>({...ack,sequence:2}), ack=>({...ack,sequence:true}),
  ack=>({...ack,sequence:1025}), ack=>Buffer.from(JSON.stringify({...ack,sequence:1.5})), ack=>({...ack,effect_authorized:true}),
  ack=>({...ack,run_qualified:0}), ack=>({...ack,authority:"other"}), ack=>({...ack,extra:1}),
  ack=>({...ack,status:"TERMINAL_RECORDED"}), ack=>Buffer.from(JSON.stringify(ack)+"\n"),
  ack=>({...ack,status:"ALREADY_RECORDED_DO_NOT_EXECUTE"}), ack=>Buffer.alloc(4097,32),
];
for(const change of mutations) {
  await fixture((event,n)=>{const ack=response(event,n);return change(ack);},async(client,events,count)=>{
    let calls=0;
    await assert.rejects(client.execute("read",{path:"inert"},context(),async()=>{calls++;return {};}));
    await assert.rejects(client.execute("read",{},context(),async()=>{}),/UNCERTAIN/);
    assert.equal(calls,0); assert.equal(count(),1); assert.equal(events.length,1);
  });
}
for(const change of [ack=>({...ack,sequence:4}),ack=>({...ack,event_digest:digest("e")}),ack=>({...ack,status:"ATTEMPT_RECORDED_EXECUTE_ONCE"})]) {
  await fixture((event,n)=>n===2?change(response(event,n)):response(event,n),async(client,events)=>{
    let calls=0;
    await assert.rejects(client.execute("read",{},context(),async()=>{calls++;return {};}));
    await assert.rejects(client.execute("read",{},context(),async()=>{}),/UNCERTAIN/);
    assert.equal(calls,1); assert.equal(events.length,2); assert.equal(events[1].outcome,"RETURNED");
  });
}
await fixture((event,n)=>response(event,n===3?5:n),async(client,events)=>{
  await client.execute("read",{},context(),async()=>({}));
  let calls=0;
  await assert.rejects(client.execute("read",{}, {...context(),toolCallId:"call:2"},async()=>{calls++;return {};}));
  assert.equal(calls,0);assert.equal(events.length,3);
});
await fixture((event,n)=>response(event,n),async(client,events,_count,config)=>{
  assert.throws(()=>createNativeToolClient(config,null));
  const forged={...context(),runId:"bad id"};
  await assert.rejects(client.execute("read",{},forged,async()=>{}));
  await assert.rejects(client.execute("exec",{},context(),async()=>{}));
  const params={content:"inert",target_name:"inert.txt",__aragorn_run_id:"forged",__aragorn_session_id:"session-1",__aragorn_session_key_digest:digest("a"),__aragorn_tool_call_digest:digest("b")};
  await assert.rejects(client.execute("aragorn_runtime_create",params,context(),async()=>{}));
  assert.equal(events.length,0);
  await client.execute("read",{},context(),async()=>({}));
  const attempt=response(events[0],1);
  const terminal={...events[1],attempt_digest:digest("f")};
  assert.throws(()=>nativeReceiptAck(encode(response(terminal,2)),terminal,genesis,attempt,null),/invalid/);
});
""")

    def test_single_flight_native_throw_cancel_and_unsupported_return(self):
        self.node(r"""
const nativeEntered=later(), nativeRelease=later(), terminalEntered=later(), terminalRelease=later();
await fixture(async(event,n)=>{if(n===2){terminalEntered.resolve();await terminalRelease.promise;}return response(event,n);},async(client,events)=>{
  const failure=new Error("original native error");
  const pending=client.execute("read",{},context(),async()=>{nativeEntered.resolve();await nativeRelease.promise;throw failure;});
  const observed=assert.rejects(pending,error=>error===failure);
  await nativeEntered.promise;
  await assert.rejects(client.execute("read",{},context(),async()=>{}),/BUSY/);
  nativeRelease.resolve(); await terminalEntered.promise;
  await assert.rejects(client.execute("read",{},context(),async()=>{}),/BUSY/);
  terminalRelease.resolve();await observed;
  assert.equal(events[1].outcome,"RAISED");assert.equal(events[1].error_code,"NATIVE_ERROR");
  assert.equal(events[1].result_digest,null);
  await client.execute("read",{}, {...context(),toolCallId:"call:2"},async()=>({ok:true}));
  assert.equal(events.length,4);
});
for(const make of [()=>undefined,()=>({float:Infinity}),()=>{const v={};v.v=v;return v;},()=>Object.defineProperty({},"x",{enumerable:true,get(){throw new Error("getter ran");}})]) {
  await fixture((event,n)=>response(event,n),async(client,events)=>{
    let calls=0;
    await assert.rejects(client.execute("read",{},context(),async()=>{calls++;return make();}),/UNSUPPORTED/);
    await assert.rejects(client.execute("read",{},context(),async()=>{}),/UNCERTAIN/);
    assert.equal(calls,1); assert.equal(events.length,1);
  });
}
await fixture((event,n)=>response(event,n),async(client,events)=>{
  let reads=0,calls=0;
  const signal={get aborted(){return ++reads>=3;},addEventListener(){},removeEventListener(){}};
  await assert.rejects(client.execute("read",{},context(),async()=>{calls++;return {};},signal),error=>error.name==="AbortError");
  assert.equal(calls,0);assert.equal(events[1].outcome,"CANCELLED");
});
await fixture((event,n)=>response(event,n),async(client,events)=>{
  const abort=new AbortController();abort.abort();
  await assert.rejects(client.execute("read",{},context(),async()=>{},abort.signal),error=>error.status==="NOT_SUBMITTED");
  assert.equal(events.length,0);
  await client.execute("read",{},context(),async()=>({}));
});
const terminalSeen=later(), allowAck=later();
await fixture(async(event,n)=>{if(n===2){terminalSeen.resolve();await allowAck.promise;}return response(event,n);},async(client,events)=>{
  const result={value:1.5};
  const pending=client.execute("read",{},context(),async()=>result);
  const rejected=assert.rejects(pending,/RESULT_CHANGED/);
  await terminalSeen.promise;result.value=9.5;allowAck.resolve();await rejected;
  await assert.rejects(client.execute("read",{},context(),async()=>{}),/UNCERTAIN/);
  assert.equal(events.length,2);assert.equal(events[1].outcome,"RETURNED");
});
""")


if __name__ == "__main__":
    unittest.main()
