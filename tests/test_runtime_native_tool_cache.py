"""Inert exact-source cache selection checks; no native calls or sockets."""

from __future__ import annotations

import base64
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import materialize_runtime_native_tool_cache as subject
from tests.test_runtime_native_tool_hooks import _JS

_CACHE_JS = r"""
sources["tools.ts"]=fs.readFileSync(process.argv[4],"utf8");
sources["original-tools.ts"]=Buffer.from(process.argv[5],"base64").toString("utf8");
const target="aragorn-runtime-action-worker";
function descriptor(pluginId,name){return {optional:true,descriptor:{name,title:name,description:"inert",
  inputSchema:{type:"object"},owner:{kind:"plugin",pluginId},executor:{kind:"plugin",pluginId,toolName:name}}};}
function resolveCache(file,options={}){
  const reads=[],created=[];
  const plugins=[{id:target,contracts:{tools:["aragorn_runtime_create"]}},
    {id:"other-plugin",contracts:{tools:["other_tool"]}}];
  const scope={
    denylistBlocksPlugin:({pluginId})=>options.denied===pluginId,
    isManifestPluginAvailableForControlPlane:({plugin})=>options.disabled!==plugin.id,
    listManifestToolNamesForAvailability:({toolNames})=>toolNames,
    denylistBlocksPluginTool:()=>false,filterManifestToolNamesForAvailability:({toolNames})=>toolNames,
    normalizeToolName:(name)=>name,
    buildPluginDescriptorCacheKey:({plugin})=>plugin.id,
    readCachedPluginToolDescriptors:(id)=>{reads.push(id);return options.missing===id?undefined:
      [descriptor(id,id===target?"aragorn_runtime_create":"other_tool")];},
    cachedDescriptorsCoverToolNames:({descriptors,toolNames})=>toolNames.every((name)=>
      descriptors.some((entry)=>entry.descriptor.name===name)),
    isOptionalToolAllowed:({toolName,allowlist})=>allowlist.has(toolName),
    createCachedDescriptorPluginTool:({descriptor:entry})=>{created.push(entry.descriptor.name);return {name:entry.descriptor.name};},
  };
  const params={snapshot:{plugins},config:{},availabilityConfig:{},env:{},
    allowlist:new Set(["aragorn_runtime_create","other_tool"]),denylist:[],
    onlyPluginIds:options.only||plugins.map((plugin)=>plugin.id),existing:new Set(),
    existingNormalized:new Set(options.conflict?[options.conflict]:[]),ctx:{},loadContext:{},configCacheKeyMemo:new WeakMap()};
  const result=compiledFunction(file,"resolveCachedPluginTools",scope)(params);
  return {names:result.tools.map((tool)=>tool.name),handled:[...result.handledPluginIds],reads,created};
}
"""


@unittest.skipUnless(shutil.which("node"), "Node.js is required")
class NativeToolCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.typescript = (
            subject.hooks._UPSTREAM / "node_modules/typescript/lib/typescript.js"
        )
        if not cls.typescript.is_file():
            raise unittest.SkipTest("Existing offline TypeScript compiler is required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="native-cache-inert-")
        cls.addClassCleanup(cls.cleanup_rendered)
        cls.root = Path(cls.temporary.name)
        cls.hooks = cls.root / "hooks"
        cls.client = cls.root / "client"
        cls.cache = cls.root / "cache"
        subject.hooks.materialize_runtime_native_tool_hooks(cls.hooks)
        subject.hooks.client.materialize_runtime_native_tool_client(cls.client)
        cls.manifest = subject.materialize_runtime_native_tool_cache(cls.cache)
        cls.original = subject._upstream_bytes()

    @classmethod
    def cleanup_rendered(cls):
        for name in ("hooks", "client", "cache"):
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
                + _CACHE_JS
                + "\n(async()=>{\n"
                + body
                + "\n})().catch(e=>{console.error(e);process.exitCode=1;});",
                str(self.hooks),
                str(self.client / "index.js"),
                str(self.typescript),
                str(self.cache / "tools.ts"),
                base64.b64encode(self.original).decode("ascii"),
            ],
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")

    def test_original_cached_constructor_loses_real_preparation_before_transport(self):
        self.node(r"""
const f=fixture();const c=callers(f);const ctx=context();let factory;let loads=0;
f.plugin.register({pluginConfig:config,registerTool(value){factory=value;}});
const actual=factory({sessionId:ctx.sessionId,sessionKey:ctx.sessionKey});
assert.equal(typeof actual.prepareBeforeToolCallParams,"function");
assert.equal(typeof actual.finalizeBeforeToolCallParams,"function");
const constructor=compiledFunction("original-tools.ts","createCachedDescriptorPluginTool",{
  setPluginToolMeta:()=>{},isManifestToolReplaySafe:()=>false,isTrustedManifestLocalMediaTool:()=>false,
  buildPluginRuntimeLoadOptions:()=>{loads++;throw new Error("unexpected lazy execution");},
});
const cached=constructor({descriptor:descriptor(target,actual.name),plugin:{id:target},ctx,loadContext:{}});
assert.equal(cached.prepareBeforeToolCallParams,undefined);
assert.equal(cached.finalizeBeforeToolCallParams,undefined);
await f.bridge.execute("read",{path:"inert"},ctx,()=>({content:[]}));
assert.equal(f.events.length,2);
const [definition]=c.adapt([c.wrap(cached,ctx,{emitDiagnostics:false})],ctx);
const result=await definition.execute(ctx.toolCallId,{content:"Aragorn P3.7b distinct worker create\n",
  target_name:"runtime-worker-qualified.txt"});
assert.match(result.error,/runtime create parameters are invalid/);
assert.equal(f.events.length,2);assert.equal(loads,0);
assert.equal(f.spawns.length,1);assert.equal(f.factories(),1);
""")

    def test_fixed_target_skips_descriptor_read_and_other_selection_is_unchanged(self):
        self.node(r"""
assert.deepEqual(resolveCache("original-tools.ts"),{
  names:["aragorn_runtime_create","other_tool"],handled:[target,"other-plugin"],
  reads:[target,"other-plugin"],created:["aragorn_runtime_create","other_tool"]});
assert.deepEqual(resolveCache("tools.ts"),{
  names:["other_tool"],handled:["other-plugin"],reads:["other-plugin"],created:["other_tool"]});
assert.deepEqual(resolveCache("tools.ts",{only:[target]}),{names:[],handled:[],reads:[],created:[]});
for(const options of [{},{disabled:"other-plugin"},{denied:"other-plugin"},
  {missing:"other-plugin"},{conflict:"other_tool"},{conflict:"other-plugin"}]){
  const input={...options,only:["other-plugin"]};
  assert.deepEqual(resolveCache("tools.ts",input),resolveCache("original-tools.ts",input));
}
// The existing caller selects the cold factory for every unhandled plugin.
const selected=resolveCache("tools.ts");
assert.deepEqual([target,"other-plugin"].filter((id)=>!selected.handled.includes(id)),[target]);
""")

    def test_exact_readonly_render_pins_and_false_ceilings(self):
        rendered = subject._verified_inputs()
        self.assertEqual(set(rendered), {"tools.ts"})
        raw = (self.cache / "tools.ts").read_bytes()
        self.assertEqual(raw, rendered["tools.ts"])
        self.assertEqual(
            (len(raw), subject.hooks.overlay._digest(raw)), subject._OUTPUT_PIN
        )
        self.assertEqual(raw.replace(subject._AFTER, subject._BEFORE), self.original)
        self.assertEqual(self.cache.stat().st_mode & 0o777, 0o555)
        self.assertEqual((self.cache / "tools.ts").stat().st_mode & 0o777, 0o444)
        self.assertIsNone(self.manifest["runtime_build_identity"])
        for name in (
            "production_activation_eligible",
            "run_eligible",
            "phase3_eligible",
        ):
            self.assertIs(self.manifest[name], False)
        for changed in (
            self.original + b"\n",
            self.original.replace(subject._BEFORE, b"", 1),
        ):
            with (
                mock.patch.object(subject, "_upstream_bytes", return_value=changed),
                self.assertRaises(ValueError),
            ):
                subject._verified_inputs()
        for output in ("string", Path("relative"), self.cache):
            with self.assertRaises(ValueError):
                subject.materialize_runtime_native_tool_cache(output)


if __name__ == "__main__":
    unittest.main()
