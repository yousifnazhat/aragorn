"""Exact source functions with inert callbacks/transport; no live tools or helper."""

from __future__ import annotations

import copy
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import materialize_runtime_native_tool_hooks as subject

_JS = r"""
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ts = require(process.argv[3]);
const sources = Object.fromEntries([
  "integration.cjs", "agent-tools.before-tool-call.ts", "agent-tool-definition-adapter.ts",
  "aragorn-native-tool-execution.ts",
].map((name) => [name, fs.readFileSync(path.join(process.argv[1], name), "utf8")]));
const pluginSource = fs.readFileSync(process.argv[2], "utf8");
const genesis = "sha256:" + "a".repeat(64);
const config = {expectedGatewayGid:1002,expectedGatewayUid:1001,expectedWorkerUid:1003,
  workerSocketPath:"/run/aragorn-runtime-action-worker/worker.sock"};
const directory = "/run/credentials/aragorn-agent-gateway.service";
const context = () => ({runId:"run-1",sessionId:"session-1",sessionKey:"session:key",toolCallId:"call:1"});
const bound = () => ({genesis_digest:genesis,worker_config:{...config}});
const encode = (value) => Buffer.from(JSON.stringify(value), "ascii");
const later = () => {let resolve;const promise=new Promise((done)=>{resolve=done;});return {promise,resolve};};
const success = () => ({status:0,signal:null,stdout:encode(bound()),stderr:Buffer.alloc(0)});

function fixture(options = {}) {
  const processMock = {platform:"linux",env:{CREDENTIALS_DIRECTORY:directory,OPENCLAW_CONFIG_PATH:directory+"/openclaw-config",SECRET:"never-pass-this"},
    getuid:()=>1001,geteuid:()=>1001,getgid:()=>1002,getegid:()=>1002,getgroups:()=>[1002]};
  Object.assign(processMock,options.process);
  const pluginModule={exports:{}};
  const evaluate=(source,require,module)=>vm.runInThisContext(
    "(function(require,module,exports,process){"+source+"\n})",
  )(require,module,module.exports,processMock);
  const allowed=new Set(["node:crypto","node:fs","node:net","node:path","node:util"]);
  const requirePlugin=(name)=>{assert.ok(allowed.has(name));return require(name);};
  // Keep actual pinned client logic; replace only its transport in this inert test.
  const control=vm.runInThisContext("(function(require,module,exports,process){"+pluginSource+
    ";return {transport(fn){requestWorker=fn;},error(){return new WorkerClientError('inert','INDETERMINATE');}};})"
  )(requirePlugin,pluginModule,pluginModule.exports,processMock);
  const plugin=pluginModule.exports;
  const events=[];
  const {canonicalJson,sha256}=plugin.__testing;
  const ack=(event,sequence,status)=>({
    schema:"aragorn/native-tool-receipt-ack/v1",authority:"WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
    genesis_digest:genesis,receipt_digest:"sha256:"+(sequence%2?"b":"c").repeat(64),
    event_digest:sha256(Buffer.from(canonicalJson(event),"ascii")),sequence,
    status:status||(sequence%2?"ATTEMPT_RECORDED_EXECUTE_ONCE":"TERMINAL_RECORDED"),effect_authorized:false,run_qualified:false,
  });
  control.transport(async (_config,event,signal,parse)=>{
    events.push(event);
    const candidate=options.transport ? await options.transport(event,events.length,ack,control,signal) : ack(event,events.length);
    return parse(Buffer.from(canonicalJson(candidate),"ascii"),event);
  });
  let factories=0;
  const actualFactory=plugin.nativeClient.createNativeToolClient;
  const pluginView={id:plugin.id,nativeClient:{createNativeToolClient(...args){factories++;return actualFactory(...args);}}};
  const spawns=[];
  const integrationModule={exports:{}};
  evaluate(sources["integration.cjs"],(name)=>{
    if(name==="node:child_process")return {spawnSync(...args){spawns.push(args);return options.spawn?options.spawn(...args):success();}};
    if(name==="node:util")return require(name);
    assert.equal(name,"/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/index.js");
    if(options.pluginError)throw options.pluginError;
    return pluginView;
  },integrationModule);
  return {bridge:integrationModule.exports,events,spawns,processMock,plugin,control,ack,factories:()=>factories};
}

function compiledFunction(file,name,scope) {
  const source=sources[file];
  const tree=ts.createSourceFile(file,source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
  const node=tree.statements.find((item)=>ts.isFunctionDeclaration(item)&&item.name?.text===name);
  assert.ok(node,name);
  const raw=node.getText(tree).replace(/^export /,"");
  const result=ts.transpileModule(raw,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS},reportDiagnostics:true});
  assert.equal((result.diagnostics||[]).filter((item)=>item.category===ts.DiagnosticCategory.Error).length,0);
  return new Function(...Object.keys(scope),result.outputText+"\nreturn "+name+";")(...Object.values(scope));
}

function callers(fixture,options={}) {
  const marker=Symbol("wrapped");
  const noop=()=>{};
  const identity=(x)=>x;
  const native=compiledFunction("aragorn-native-tool-execution.ts","executeAragornNativeTool",{bridge:fixture.bridge});
  const scope={
    executeAragornNativeTool:native,normalizeToolName:identity,
    resolveToolDiagnosticIdentity:()=>({}),resolveDiagnosticModelContentCapturePolicy:()=>null,
    normalizeCodeModeExecBeforeHookParams:({params})=>params,getCodeModeExecBeforeHookMetadata:()=>({}),
    runBeforeToolCallHook:options.hook|| (async({params})=>({blocked:false,params})),
    reconcileCodeModeExecBeforeHookParams:({adjustedParams})=>adjustedParams,
    recordAdjustedParamsForToolCall:noop,summarizeToolParams:()=>({}),
    emitTrustedDiagnosticEvent:noop,emitTrustedDiagnosticEventWithPrivateData:noop,
    recordLoopOutcome:options.recordLoopOutcome||(async()=>{}),rememberPendingTerminalPresentation:noop,
    resolveToolTerminalPresentation:()=>undefined,findSkillUsageMatch:()=>undefined,
    resolveToolResultTerminalDiagnostic:()=>({}),buildToolContentPrivateData:()=>({}),
    resolveToolErrorDiagnostic:()=>({}),recordPreExecutionBlockedToolCall:noop,
    tagBeforeToolCallFailure:identity,BeforeToolCallFailureError:Error,
    copyPluginToolMeta:noop,copyChannelAgentToolMeta:noop,copyToolTerminalPresentation:noop,
    BEFORE_TOOL_CALL_WRAPPED:marker,BEFORE_TOOL_CALL_DIAGNOSTIC_OPTIONS:Symbol(),
    BEFORE_TOOL_CALL_SOURCE_TOOL:Symbol(),BEFORE_TOOL_CALL_HOOK_CONTEXT:Symbol(),
    isToolWrappedWithBeforeToolCallHook:(tool)=>tool[marker]===true,
    recordStructuredReplayTrustForToolCall:noop,normalizeToolExecutionResult:options.normalize||(({result})=>result),
    isBeforeToolCallBlockedError:()=>false,logDebug:noop,logError:noop,
    describeToolExecutionError:(error)=>({message:String(error)}),describeToolFailureInputs:()=>"inert",
    buildToolExecutionErrorResult:({message})=>({error:message}),buildBlockedToolResult:()=>({blocked:true}),
    emitToolBlockedSecurityEvent:noop,
  };
  for(const name of ["isAbortSignal","isLegacyToolExecuteArgs","splitToolExecuteArgs","prepareToolParamsBeforeHook","finalizeToolParamsBeforeExecute"]){
    scope[name]=compiledFunction("agent-tool-definition-adapter.ts",name,scope);
  }
  return {
    wrap:compiledFunction("agent-tools.before-tool-call.ts","wrapToolWithBeforeToolCallHook",scope),
    adapt:compiledFunction("agent-tool-definition-adapter.ts","toToolDefinitions",scope),
    rewrap: null,
    native,
  };
}
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required")
class NativeToolHookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.typescript = subject._UPSTREAM / "node_modules/typescript/lib/typescript.js"
        if not cls.typescript.is_file():
            raise unittest.SkipTest("Existing offline TypeScript compiler is required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="native-hook-inert-")
        cls.addClassCleanup(cls.cleanup_rendered)
        cls.root = Path(cls.temporary.name)
        cls.output = cls.root / "hooks"
        cls.manifest = subject.materialize_runtime_native_tool_hooks(cls.output)
        cls.client_output = cls.root / "client"
        subject.client.materialize_runtime_native_tool_client(cls.client_output)

    @classmethod
    def cleanup_rendered(cls):
        # Class setup may fail after either read-only publication; cleanup is
        # registered first and restores only the two owned, non-symlink leaves.
        for name in ("hooks", "client"):
            path = Path(cls.temporary.name) / name
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(metadata.st_mode):
                path.chmod(0o755)
        cls.temporary.cleanup()

    def node(self, body):
        result = subprocess.run(
            [
                "node",
                "-e",
                _JS
                + "\n(async()=>{\n"
                + body
                + "\n})().catch(e=>{console.error(e);process.exitCode=1;});",
                str(self.output),
                str(self.client_output / "index.js"),
                str(self.typescript),
            ],
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")

    def test_exact_readonly_render_preserves_all_other_caller_source(self):
        self.assertEqual(self.manifest["upstream_commit"], subject._SOURCE)
        self.assertIsNone(self.manifest["runtime_build_identity"])
        for field in (
            "standalone_executable",
            "production_activation_eligible",
            "native_hook_reachability",
            "native_causation_verified",
            "mandatory_capture",
            "run_eligible",
        ):
            self.assertIs(self.manifest[field], False)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o555)
        for name, pin in subject._OUTPUTS.items():
            raw = (self.output / name).read_bytes()
            self.assertEqual((len(raw), subject.overlay._digest(raw)), pin)
            self.assertEqual((self.output / name).stat().st_mode & 0o777, 0o444)
        for name in subject._UPSTREAM_INPUTS:
            raw = (self.output / Path(name).name).read_bytes()
            for before, after in reversed(subject._REPLACEMENTS[name]):
                raw = subject.credentials._replace(raw, after, before)
            self.assertEqual(raw, subject._upstream_bytes(name))
        self.node(r"""
for(const [name,source] of Object.entries(sources)){
  if(!name.endsWith(".ts"))continue;
  const result=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext},reportDiagnostics:true});
  assert.equal((result.diagnostics||[]).filter((item)=>item.category===ts.DiagnosticCategory.Error).length,0);
}
assert.ok(sources["aragorn-native-tool-execution.ts"].includes('createRequire(import.meta.url)'));
assert.ok(sources["aragorn-native-tool-execution.ts"].includes('/usr/lib/aragorn/openclaw/aragorn-runtime-native-tool-client/integration.cjs'));
""")

    def test_fixed_bootstrap_and_shared_client_for_both_callers(self):
        self.node(r"""
const f=fixture();const a=callers(f);const b=callers(f);
const result={content:[{type:"text",text:"inert"}],details:undefined};
assert.equal(await a.native("read",{path:"inert"},context(),()=>result),result);
assert.equal(await b.native("read",{path:"inert"},{...context(),toolCallId:"call:2"},()=>result),result);
assert.equal(f.spawns.length,1);assert.equal(f.factories(),1);assert.equal(f.events.length,4);
const [command,argv,options]=f.spawns[0];
assert.equal(command,"/usr/bin/python3.12");
assert.deepEqual(argv,["-I","-S","-B","/usr/libexec/aragorn/aragorn-runtime-native-gateway-credentials.py"]);
assert.deepEqual(options,{cwd:"/",shell:false,encoding:"buffer",stdio:["ignore","pipe","pipe"],timeout:2000,killSignal:"SIGKILL",maxBuffer:1024,
  env:{CREDENTIALS_DIRECTORY:directory,HOME:"/nonexistent",LANG:"C",LC_ALL:"C",PATH:"/usr/bin:/bin",PYTHONDONTWRITEBYTECODE:"1",TZ:"UTC"}});
assert.ok(Object.isFrozen(f.bridge));
""")

    def test_bootstrap_errors_are_sticky_and_never_invoke_or_leak(self):
        self.node(r"""
const mutations=[
  (r)=>{r.status=1;},(r)=>{r.signal="SIGKILL";},(r)=>{r.error=new Error("secret");},
  (r)=>{r.stderr=Buffer.from("secret");},(r)=>{r.stderr="";},(r)=>{r.stdout=Buffer.alloc(0);},
  (r)=>{r.stdout=Buffer.alloc(1025);},(r)=>{r.stdout=Buffer.from([255]);},
  (r)=>{r.stdout=Buffer.from(r.stdout.toString()+"\n");},
  (r)=>{r.stdout=Buffer.from('{"genesis_digest":"duplicate",'+r.stdout.toString().slice(1));},
  (r)=>{const x=bound();x.extra=1;r.stdout=encode(x);},
  (r)=>{const x=bound();x.genesis_digest="sha256:"+"A".repeat(64);r.stdout=encode(x);},
  ...["expectedGatewayGid","expectedGatewayUid","expectedWorkerUid"].flatMap((key)=>
    [true,0,-1,0x100000000,1.5].map((value)=>(r)=>{const x=bound();x.worker_config[key]=value;r.stdout=encode(x);})),
  (r)=>{const x=bound();x.worker_config.expectedWorkerUid=1001;r.stdout=encode(x);},
  (r)=>{const x=bound();x.worker_config.workerSocketPath="/tmp/other";r.stdout=encode(x);},
  (r)=>{const x=bound();x.worker_config.extra=true;r.stdout=encode(x);},
];
for(const mutate of mutations){
  const f=fixture({spawn(){const r=success();mutate(r);return r;}});let calls=0;let error;
  for(let index=0;index<2;index++){
    try{await f.bridge.execute("read",{},context(),()=>{calls++;});assert.fail();}
    catch(e){assert.equal(e.message,"ARAGORN_NATIVE_BOOTSTRAP_REFUSED");if(error)assert.equal(e,error);error=e;}
  }
  assert.equal(calls,0);assert.equal(f.spawns.length,1);assert.equal(f.factories(),0);assert.equal(f.events.length,0);
}
for(const process of [{platform:"darwin"},{env:{}},{getuid:()=>0},{geteuid:()=>1004},{getgid:()=>0},{getegid:()=>0},{getgroups:()=>[1002,1004]}]){
  const f=fixture({process});await assert.rejects(async()=>f.bridge.execute("read",{},context(),()=>assert.fail()),/BOOTSTRAP_REFUSED/);
  await assert.rejects(async()=>f.bridge.execute("read",{},context(),()=>assert.fail()),/BOOTSTRAP_REFUSED/);
  assert.ok(f.spawns.length<=1);assert.equal(f.factories(),0);
}
const f=fixture({spawn(){throw new Error("secret");}});
await assert.rejects(async()=>f.bridge.execute("read",{},context(),()=>assert.fail()),/BOOTSTRAP_REFUSED/);
assert.equal(f.spawns.length,1);
const missing=fixture({pluginError:new Error("secret")});
await assert.rejects(async()=>missing.bridge.execute("read",{},context(),()=>assert.fail()),/BOOTSTRAP_REFUSED/);
await assert.rejects(async()=>missing.bridge.execute("read",{},context(),()=>assert.fail()),/BOOTSTRAP_REFUSED/);
assert.equal(missing.spawns.length,1);
""")

    def test_both_exact_execute_paths_detach_final_params_and_forward_arguments(self):
        self.node(r"""
for(const wrapped of [true,false]){
  const gate=later();const terminal=later();
  const f=fixture({transport:async(event,index,ack)=>{await (index===1?gate.promise:terminal.promise);return ack(event,index);}});
  const c=callers(f,{hook:async({params})=>({blocked:false,params:{...params,content:"hook-final"}})});
  const controller=new AbortController();const updates=[];const onUpdate=(value)=>updates.push(value);
  const original={path:"inert",nested:{value:1.25}};let finalParams;let called=0;
  const result={content:[{type:"text",text:"inert"}],details:undefined};
  const tool={name:"read",parameters:{},
    prepareBeforeToolCallParams:(params)=>({...params,prepared:true}),
    finalizeBeforeToolCallParams:(params)=>{finalParams={...params,finalized:true};return finalParams;},
    execute:(id,params,signal,update)=>{
      called++;assert.equal(id,"call:1");assert.equal(signal,controller.signal);assert.equal(update,onUpdate);
      assert.notEqual(params,finalParams);assert.ok(Object.isFrozen(params));assert.ok(Object.isFrozen(params.nested));
      assert.equal(params.content,"hook-final");assert.equal(params.finalized,true);assert.equal(params.nested.value,1.25);
      update("inert-progress");return result;
    }};
  const selected=wrapped?c.wrap(tool,context(),{emitDiagnostics:false}):tool;
  const [definition]=c.adapt([selected],context());
  let done=false;const pending=definition.execute("call:1",original,controller.signal,onUpdate).then((value)=>{done=true;return value;});
  while(!f.events.length)await new Promise(setImmediate);
  assert.equal(called,0);original.nested.value=9;finalParams.content="late-mutation";
  gate.resolve();while(f.events.length<2)await new Promise(setImmediate);
  assert.equal(called,1);assert.equal(done,false);assert.deepEqual(updates,["inert-progress"]);
  assert.equal(f.events.length,2);assert.equal(f.events[1].outcome,"RETURNED");
  terminal.resolve();assert.equal(await pending,result);assert.equal(f.spawns.length,1);assert.equal(f.factories(),1);
}
""")

    def test_native_throw_identity_and_post_return_failures_do_not_add_terminals(self):
        self.node(r"""
const nativeError={inert:"same thrown identity"};const terminal=later();
const f=fixture({transport:async(event,index,ack)=>{if(index===2)await terminal.promise;return ack(event,index);}});
const c=callers(f);let observed;
const pending=c.wrap({name:"read",execute(){throw nativeError;}},context(),{emitDiagnostics:false}).execute("call:1",{path:"inert"}).catch((e)=>{observed=e;});
while(f.events.length<2)await new Promise(setImmediate);
assert.equal(observed,undefined);assert.equal(f.events[1].outcome,"RAISED");terminal.resolve();await pending;assert.equal(observed,nativeError);
for(const kind of ["diagnostic","normalization"]){
  const f=fixture();const after=new Error("after native return");
  const c=callers(f,kind==="diagnostic"?{recordLoopOutcome:async()=>{throw after;}}:{normalize:()=>{throw after;}});
  const tool={name:"read",execute:()=>({content:[]})};
  if(kind==="diagnostic")await assert.rejects(c.wrap(tool,context(),{emitDiagnostics:false}).execute("call:1",{}),(e)=>e===after);
  else {const [definition]=c.adapt([tool],context());const result=await definition.execute("call:1",{});assert.ok(result.error);}
  assert.equal(f.events.length,2);assert.equal(f.events[1].outcome,"RETURNED");
}
""")

    def test_actual_client_create_digest_busy_duplicate_abort_and_uncertainty(self):
        self.node(r"""
const f=fixture();let creates=0;
const ctx=context();const {sha256,canonicalJson,buildRequest}=f.plugin.__testing;
const params={content:"inert",target_name:"inert.txt",__aragorn_run_id:ctx.runId,__aragorn_session_id:ctx.sessionId,
  __aragorn_session_key_digest:sha256(Buffer.from(ctx.sessionKey)),__aragorn_tool_call_digest:sha256(Buffer.from(ctx.toolCallId))};
await f.bridge.execute("aragorn_runtime_create",params,ctx,(detached)=>{creates++;const request=buildRequest({runId:ctx.runId,sessionId:ctx.sessionId,toolCallDigest:params.__aragorn_tool_call_digest},detached.target_name,Buffer.from(detached.content));assert.equal(f.events[0].worker_request_digest,sha256(Buffer.from(canonicalJson(request),"ascii")));return {content:[]};});
assert.equal(creates,1);assert.equal(f.events.length,2);
for(const name of ["write","exec","Read",""]){await assert.rejects(async()=>f.bridge.execute(name,{},ctx,()=>assert.fail()),/TOOL_UNSUPPORTED/);}
const aborted=new AbortController();const gate=later();
const cancellation=fixture({transport:async(event,index,ack)=>{if(index===1)await gate.promise;return ack(event,index);}});
const one=cancellation.bridge.execute("read",{},ctx,()=>assert.fail(),aborted.signal);
await assert.rejects(cancellation.bridge.execute("read",{},ctx,()=>assert.fail()),/NATIVE_CALL_BUSY/);
aborted.abort();gate.resolve();await assert.rejects(one,/aborted/);assert.equal(cancellation.events[1].outcome,"CANCELLED");
for(const mode of ["duplicate","attempt-uncertain","terminal-uncertain","unsupported-result"]){
  const f=fixture({transport:(event,index,ack,control)=>{
    if(mode==="attempt-uncertain"&&index===1||mode==="terminal-uncertain"&&index===2)throw control.error();
    return ack(event,index,mode==="duplicate"?"ALREADY_RECORDED_DO_NOT_EXECUTE":undefined);
  }});let invokes=0;
  await assert.rejects(async()=>f.bridge.execute("read",{},ctx,()=>{invokes++;return mode==="unsupported-result"?()=>{}:{content:[]};}));
  const count=f.events.length;
  await assert.rejects(async()=>f.bridge.execute("read",{},ctx,()=>assert.fail()),/NATIVE_RETENTION_UNCERTAIN/);
  assert.equal(f.events.length,count);assert.equal(invokes,mode==="duplicate"||mode==="attempt-uncertain"?0:1);assert.equal(f.spawns.length,1);
}
""")

    def test_source_pin_git_failure_companion_and_publication_refusals(self):
        for name in subject._UPSTREAM_INPUTS:
            raw = subject._upstream_bytes(name)
            for changed in (raw + b"\n", raw[:-1], bytearray(raw)):
                with self.assertRaises(ValueError):
                    subject._transform(name, changed)
        for result in (
            subprocess.CompletedProcess([], 1, b"", b"error"),
            subprocess.CompletedProcess([], 0, b"wrong", b""),
        ):
            with (
                mock.patch.object(subject.subprocess, "run", return_value=result),
                self.assertRaises(ValueError),
            ):
                subject._upstream_bytes(subject._WRAPPER)
        for name in (
            "_DEPENDENCIES",
            "_UPSTREAM_INPUTS",
            "_OUTPUTS",
            "_CREDENTIAL_PINS",
        ):
            changed = copy.deepcopy(getattr(subject, name))
            key = next(iter(changed))
            changed[key] = (changed[key][0], "sha256:" + "0" * 64)
            with (
                mock.patch.object(subject, name, changed),
                self.assertRaises(ValueError),
            ):
                subject._verified_inputs()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for output in ("string", Path("relative"), root):
                with (
                    mock.patch.object(subject, "_verified_inputs") as verified,
                    self.assertRaises(ValueError),
                ):
                    subject.materialize_runtime_native_tool_hooks(output)
                verified.assert_not_called()

            def partial(output, rendered, _parts):
                output.mkdir()
                (output / "incomplete").write_bytes(b"inert")
                raise OSError("partial")

            with (
                mock.patch.object(
                    subject.overlay, "_write_overlay", side_effect=partial
                ),
                self.assertRaises(ValueError),
            ):
                subject.materialize_runtime_native_tool_hooks(root / "partial")
            self.assertTrue((root / "partial").exists())


if __name__ == "__main__":
    unittest.main()
