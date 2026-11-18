"use strict";
// Developer-side parser only: the candidate is input to Acorn, never to the VM.
const fs = require("node:fs"), crypto = require("node:crypto"), vm = require("node:vm");
const acornPath = "/opt/homebrew/lib/node_modules/vercel/node_modules/acorn/dist/acorn.js";
const acornPin = "b373ccd10e9deb63654289f73216eeefcaf0405d9ee24289aabf596b91b4c318";
const source = fs.readFileSync(acornPath);
if (crypto.createHash("sha256").update(source).digest("hex") !== acornPin) throw Error("parser pin mismatch");
const parser = {};
vm.runInNewContext(source.toString("utf8"), {module: {exports: parser}, exports: parser}, {
  filename: "pinned-acorn.js", timeout: 4000, contextCodeGeneration: {strings: false, wasm: false}
});
if (parser.version !== "8.17.0") throw Error("parser version mismatch");
const raw = fs.readFileSync(0);
if (!raw.length || raw.length > 8 * 1024 * 1024) throw Error("candidate byte bound");
const text = new TextDecoder("utf-8", {fatal: true}).decode(raw);
const restricted = process.argv.length === 2 && process.argv[1] === "restricted-gate-v2";
if (process.argv.length !== (restricted ? 2 : 1)) throw Error("unknown inspection profile");
const digest = data => crypto.createHash("sha256").update(data).digest("hex");
if (restricted && digest(raw) !== "0806d07ae9110eaa1d98d97b49d4ee305deaf95b82c0c0b61ca905f24bf73c44")
  throw Error("unreviewed restricted worker");
const ast = parser.parse(text, {
  ecmaVersion: "latest", sourceType: "module", locations: true, allowHashBang: false
});
const allowed = {
  "node:crypto": ["createHash", "randomBytes"], "node:fs": ["lstatSync", "realpathSync", "statSync"],
  "node:net": ["createConnection"], "node:path": ["dirname", "isAbsolute", "resolve"],
  "node:perf_hooks": ["performance"], "node:url": ["pathToFileURL"], "node:util": ["TextDecoder"]
};
const processMembers = new Set(["argv", "env", "exitCode", "getuid", "geteuid", "getgid", "getegid",
  "getgroups", "platform", "stderr", "version", "versions"]);
const forbidden = new Set(["require", "__require", "module", "__non_webpack_require__", "createRequire",
  "getBuiltinModule", "_load", "_linkedBinding", "binding", "dlopen", "mainModule", "importScripts",
  "registerHooks", "Worker", "SharedWorker"]);
const reflection = new Set(["eval", "Function", "AsyncFunction", "GeneratorFunction", "AsyncGeneratorFunction"]);
const builtin = new Set(), exported = new Set(), aliases = new Map(), failures = [], counts = Object.create(null);
for (const declaration of ast.body) {
  if (declaration.type === "ExportDefaultDeclaration") exported.add("default");
  if (declaration.type === "ExportNamedDeclaration") {
    for (const s of declaration.specifiers) exported.add(s.exported.name ?? s.exported.value);
    const d = declaration.declaration;
    if (d?.id?.name) exported.add(d.id.name);
    for (const v of d?.declarations || []) if (v.id.name) exported.add(v.id.name);
  }
  if (declaration.type !== "ImportDeclaration") continue;
  for (const spec of declaration.specifiers) {
    if (spec.type === "ImportDefaultSpecifier" && Object.hasOwn(allowed, declaration.source.value))
      aliases.set(spec.local.name, allowed[declaration.source.value]);
  }
}
let nodes = 0;
// These review records name concrete parsed subtrees within the byte-pinned product.
// A matching identifier outside its reviewed subtree remains an ordinary failure.
const regions = [], expected = new Map();
if (restricted) {
  const records = {
    // Local bundled partial-json thunk; not Node's require().
    __commonJS: ["9cb935e042e8adce4a9a199f5a87f3c2a33ce30dd4a780b8469d976b4523f69c", {"loader-identifier:__require":1}],
    // Third parameter is an approval DTO, not process.binding.
    buildProviderRequest: ["a289400d488cd262d1f7db02b3a9aed9d4bd7eedebeaaf9225b105e7d81d9bf8", {"loader-identifier:binding":8}],
    IsConstructor: ["ffa1f0b72405d4a94d2ce417d2ad485e44cb1a86be02ab91f9cc19c182a14763", {"in-memory-code-review:Function":1}],
    IsClassInstance: ["a0d9199cbb251743fd851e27717eccd1c02aa1498c73603d46f5089615565f4e", {"ambient-global-review:globalThis":2, "reflective-constructor-review:constructor":3}],
    FromTypedArray2: ["a3b9a4e5364dc3d87e219617c7d84c90c0b7f4ea768de3a5de283b43a6b292c5", {"ambient-global-review:globalThis":2, "reflective-constructor-review:constructor":2}],
    // Exact probe -> catch -> false -> interpreted CheckSchema fallback. This does
    // not attest that the pinned launch restriction is already enforced on a VM.
    TryEvaluate: ["12f06a35abd3b3ab3677df9470bbe90786c24fc9292376c52a7914b5bc99330e", {}],
    CanEvaluate: ["d0509aca5dc56be987dde2e37b43ba5c4859a892e6f97e6c84c6517c3a1f1e11", {}],
    Evaluate: ["1c2af741feeabd5720e5dbbadefaff9ac36c51e1c25d8d362bc8d8b9da11294b", {"ambient-global-review:globalThis":1}],
    CreateCheck: ["a183e764cfb9ef9a4c6c8c1a718b416263de34b2a898494142d0ffe16929fcb1", {}],
    CreateEvaluatedCheck: ["8f32a91a7b8cb37ebe8b2f9723a49486abaae893084d1b38545634c7e0595965", {}],
    CreateDynamicCheck: ["7f422cde04a760bee907b9cf7c244c0a9c9a572620495af6b19d095fb55fd2ad", {}],
  };
  for (const [name, pair] of Object.entries(records)) expected.set(name, pair);
  for (const kind of ["Int8Array","Uint8Array","Uint8ClampedArray","Int16Array","Uint16Array","Int32Array",
                      "Uint32Array","Float32Array","Float64Array","BigInt64Array","BigUint64Array","RegExp","Date","Set","Map"]) {
    const name = "Is" + kind;
    expected.set(name, [digest(`function ${name}(value) {\n  return value instanceof globalThis.${kind};\n}`),
                        {"ambient-global-review:globalThis":1}]);
  }
  expected.set("IsTypeArray", [digest("function IsTypeArray(value) {\n  return globalThis.ArrayBuffer.isView(value);\n}"),
                               {"ambient-global-review:globalThis":1}]);
  for (const [name, fields] of Object.entries({builtin_crypto:"createHash", builtin_fs:"lstatSync, realpathSync, statSync",
           builtin_net:"createConnection", builtin_path:"dirname, isAbsolute", builtin_util:"TextDecoder: TextDecoder2"})) {
    expected.set(name, [digest(`{ ${fields} } = ${name}`), {["unbound-builtin-object:"+name]:1}]);
  }
}
function register(node) {
  const name = node.type === "AssignmentExpression" && node.left.type === "ObjectPattern" ? node.right.name :
    node.type === "FunctionDeclaration" || node.type === "VariableDeclarator" && node.id.name === "__commonJS" ? node.id?.name : null;
  if (!expected.has(name)) return;
  const [pin, limits] = expected.get(name);
  if (regions.some(r=>r.name === name) || digest(text.slice(node.start,node.end)) !== pin)
    throw Error("substituted restricted review region: "+name);
  regions.push({name,start:node.start,end:node.end,remaining:{...limits}});
}
function issue(kind, node, detail) {
  if (restricted) {
    const key = kind+":"+detail;
    const r = regions.find(r=>r.start <= node.start && node.end <= r.end && r.remaining[key] > 0);
    if (r) { r.remaining[key]--; return; }
  }
  counts[kind] = (counts[kind] || 0) + 1;
  if (failures.length < 32) failures.push({kind, line: node.loc.start.line, column: node.loc.start.column + 1,
    detail: String(detail).slice(0, 100)});
}
function staticName(node, depth=0) {
  if (!node || depth > 12) return null;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral" && !node.expressions.length) return node.quasis[0].value.cooked;
  if (node.type === "BinaryExpression" && node.operator === "+") {
    const a = staticName(node.left, depth+1), b = staticName(node.right, depth+1);
    if (a !== null && b !== null && a.length+b.length <= 2048) return a+b;
  }
  return null;
}
function member(node) { return node.computed ? staticName(node.property) : node.property.name; }
function visit(node, parent) {
  if (!node || typeof node !== "object" || !node.type) return;
  if (++nodes > 1500000) throw Error("AST node bound");
  if (restricted) register(node);
  if (node.type === "ImportDeclaration" || node.type.startsWith("Export") && node.source) {
    const name = node.source.value;
    if (!Object.hasOwn(allowed, name)) issue("undeclared-static-import", node, name);
    else {
      builtin.add(name);
      for (const spec of node.specifiers || []) {
        if (spec.type !== "ImportDefaultSpecifier" &&
            (spec.type !== "ImportSpecifier" || !allowed[name].includes(spec.imported.name)))
          issue("unreviewed-builtin-binding", spec, name);
      }
      if (node.type !== "ImportDeclaration" || node.attributes?.length) issue("unreviewed-import-form", node, name);
    }
  }
  if (node.type === "ImportExpression") issue("external-dynamic-import", node, staticName(node.source) ?? "computed");
  if (node.type === "MetaProperty" && node.meta.name === "import" &&
      !(parent?.type === "MemberExpression" && parent.object === node && member(parent) === "url"))
    issue("unreviewed-import-meta", node, "import.meta");
  if (node.type === "MemberExpression") {
    const prop = member(node);
    if (forbidden.has(prop)) issue("loader-member", node, prop);
    if (prop === "constructor" && !(parent?.type === "BinaryExpression" && parent.operator === "instanceof"))
      issue("reflective-constructor-review", node, prop);
  }
  if (node.type === "Property" && parent?.type === "ObjectPattern") {
    const key = node.computed ? staticName(node.key) : node.key.name ?? node.key.value;
    if (forbidden.has(key)) issue("destructured-loader", node, key);
    if (reflection.has(key) || key === "constructor") issue("reflective-destructure-review", node, key);
  }
  if (node.type === "Identifier") {
    const passive = parent && !parent.computed &&
      ((parent.type === "MemberExpression" && parent.property === node) ||
       (["Property", "MethodDefinition", "PropertyDefinition"].includes(parent.type) &&
          parent.key === node && !parent.shorthand));
    if (!passive) {
      if (aliases.has(node.name) && !(parent?.type === "ImportDefaultSpecifier" ||
          parent?.type === "MemberExpression" && parent.object === node && aliases.get(node.name).includes(member(parent)) ||
          parent?.type === "VariableDeclarator" && parent.init === node && parent.id.type === "ObjectPattern" &&
          parent.id.properties.every(p => p.type === "Property" && !p.computed && aliases.get(node.name).includes(p.key.name)))) {
        issue("unbound-builtin-object", node, node.name);
      }
      if (forbidden.has(node.name)) issue("loader-identifier", node, node.name);
      if (reflection.has(node.name)) issue("in-memory-code-review", node, node.name);
      if (node.name === "process" && !(parent?.type === "MemberExpression" && parent.object === node &&
          processMembers.has(member(parent)))) issue("unreviewed-process-access", node, "process");
      if (["globalThis", "global", "self", "window"].includes(node.name) &&
          !(parent?.type === "UnaryExpression" && parent.operator === "typeof"))
        issue("ambient-global-review", node, node.name);
      if (node.name === "Reflect" && !(parent?.type === "MemberExpression" && parent.object === node &&
          member(parent) === "ownKeys")) issue("unreviewed-reflection", node, "Reflect");
    }
  }
  for (const [key, child] of Object.entries(node)) {
    if (["loc","start","end"].includes(key)) continue;
    if (Array.isArray(child)) for (const item of child) visit(item, node);
    else visit(child, node);
  }
}
visit(ast, null);
if (restricted && (regions.length !== expected.size ||
    regions.some(r=>Object.values(r.remaining).some(n=>n !== 0)))) throw Error("incomplete restricted review");
process.stdout.write(JSON.stringify({static_builtins: [...builtin].sort(), exports: [...exported].sort(), nodes, failures, counts,
  ...(restricted ? {restricted_review: regions.map(r=>r.name).sort()} : {})}));
