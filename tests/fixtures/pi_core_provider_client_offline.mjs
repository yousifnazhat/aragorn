// Real pinned Pi, canonical codecs and source adapter; all OS/transport peers are
// in-memory authored fixtures. No kernel, provider or authorization evidence.
import { createRequire, registerHooks, syncBuiltinESMExports } from "node:module";
import { EventEmitter } from "node:events";
import { performance } from "node:perf_hooks";
import fs from "node:fs";
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import childProcess from "node:child_process";

const selected = process.argv[2];
const require = createRequire(import.meta.url);
const providerPath = "/run/aragorn-pi-bootstrap/provider/provider.sock";
const actionPath = "/run/aragorn-pi-bootstrap/requests/request.sock";
const activation = "a".repeat(32), route = "sha256:" + "b".repeat(64);
const uid = 1101, gid = 1102;
const liveIO = [], connections = [], requests = [], replies = [], socketEvents = [], fsReads = [];
const forbid = (name) => () => { liveIO.push(name); throw new Error(`offline fixture forbids ${name}`); };
const errorRecord = (error) => ({ name: error?.name, message: String(error?.message ?? error), status: error?.status ?? null });
globalThis.fetch = forbid("fetch");
for (const [name, module, methods] of [
  ["net", net, ["connect", "createServer"]], ["tls", tls, ["connect", "createServer"]],
  ["http", http, ["get", "request", "createServer"]], ["https", https, ["get", "request", "createServer"]],
  ["child_process", childProcess, ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]],
]) for (const method of methods) module[method] = forbid(`${name}.${method}`);
net.Socket.prototype.connect = forbid("net.Socket.connect");
net.Server.prototype.listen = forbid("net.Server.listen");

let currentUid = uid, currentEuid = uid, currentGid = gid, currentEgid = gid;
let groups = [], platform = "linux", phase = "initial", controller;
let clockOffset = 0;
const realNow = performance.now.bind(performance);
Object.defineProperty(performance, "now", { configurable: true, value: () => realNow() + clockOffset });
Object.defineProperty(process, "platform", { configurable: true, get: () => platform });
process.getuid = () => currentUid; process.geteuid = () => currentEuid;
process.getgid = () => currentGid; process.getegid = () => currentEgid;
process.getgroups = () => [...groups];

const paths = new Set(["/", "/run", "/run/aragorn-pi-bootstrap",
  "/run/aragorn-pi-bootstrap/provider", providerPath,
  "/run/aragorn-pi-bootstrap/requests", actionPath]);
const realLstat = fs.lstatSync, realStat = fs.statSync, realRealpath = fs.realpathSync;
function metadata(path) {
  const socket = path === providerPath || path === actionPath;
  const endpoint = socket || path.endsWith("/provider") || path.endsWith("/requests");
  let owner = 0n, group = endpoint ? BigInt(gid) : 0n;
  let mode = socket ? 0o140660n : endpoint ? 0o40711n : 0o40755n;
  let inode = BigInt([...paths].indexOf(path) + 1), symlink = false;
  if (selected === "clientWrongOwner" && path === providerPath) owner = 999n;
  if (selected === "clientWrongGroup" && path === providerPath) group = 999n;
  if (selected === "clientWritableSocket" && path === providerPath) mode = 0o140666n;
  if (selected === "clientWritableAncestor" && path === "/run") mode = 0o40777n;
  if (selected === "clientLinkedAncestor" && path === "/run") symlink = true;
  if (selected === "clientReplaceBeforeSend" && path === providerPath && phase !== "initial") inode += 100n;
  if (selected === "clientReplaceAfterResponse" && path === providerPath && phase === "response") inode += 100n;
  return { uid: owner, gid: group, mode, dev: 1n, ino: inode, nlink: socket ? 1n : 2n,
    ctimeNs: 1n, isSocket: () => socket, isDirectory: () => !socket && !symlink,
    isSymbolicLink: () => symlink };
}
fs.lstatSync = (path, options) => {
  if (!paths.has(String(path))) return realLstat(path, options); // pinned source/dependency loading only
  fsReads.push(String(path)); return metadata(String(path));
};
fs.statSync = (path, options) => paths.has(String(path)) ? metadata(String(path)) : realStat(path, options);
fs.realpathSync = (path, ...options) => paths.has(String(path)) ? String(path) : realRealpath(path, ...options);

let codec;
function providerReply(request) {
  const reply = { schema: "aragorn/pi-core-provider-result/v1",
    authority: "PROVIDER_DATA_MEDIATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
    request_digest: codec.sha256(Buffer.from(codec.canonicalJson(request), "ascii")),
    status: "COMPLETED", completion: { stop_reason: "stop",
      content: [{ type: "text", text: "Owned public fixture reply." }],
      usage: { input_tokens: 5, output_tokens: 7 } } };
  if (selected === "composeTool") reply.completion = { stop_reason: "toolUse",
    content: [{ type: "toolCall", id: "provider-fixture-call", name: "aragorn_runtime_create",
      arguments: { content: "owned fixture bytes", target_name: "provider-fixture.txt" } }],
    usage: { input_tokens: 5, output_tokens: 7 } };
  if (selected === "clientWrongDigest") reply.request_digest = "sha256:" + "0".repeat(64);
  if (selected === "clientNotSubmitted") { reply.status = "NOT_SUBMITTED"; reply.completion = null; }
  if (selected === "clientIndeterminate") { reply.status = "INDETERMINATE"; reply.completion = null; }
  if (selected === "clientSecretError") reply.credential = "FIXTURE_SECRET_NOT_A_REAL_CREDENTIAL";
  if (selected === "clientUnknownTool") reply.completion = { stop_reason: "toolUse",
    content: [{ type: "toolCall", id: "wrong", name: "shell", arguments: {} }],
    usage: { input_tokens: 5, output_tokens: 7 } };
  if (selected === "clientInvalidUsage") reply.completion.usage.output_tokens = Number.MAX_SAFE_INTEGER + 1;
  if (selected === "clientOversizedContent") reply.completion.content[0].text = "x".repeat(70 * 1024);
  return reply;
}
function actionReply(request) {
  return { schema: "aragorn/runtime-action-worker-result/v1",
    authority: "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
    request_digest: codec.sha256(Buffer.from(codec.canonicalJson(request), "ascii")),
    status: "NOT_SUBMITTED", broker_result: null };
}
class InMemoryProtectedSocket extends EventEmitter {
  constructor(path) { super(); this.path = path; this.destroyed = false; }
  getPeerCredentials() { return { pid: 200, uid: selected === "clientWrongPeer" ? 999 : 0, gid: 0 }; }
  end(frame) {
    socketEvents.push("end-request");
    if (!Buffer.isBuffer(frame) || frame.length < 5 || frame.readUInt32BE(0) !== frame.length - 4) {
      throw new Error("fixture received malformed request frame");
    }
    const raw = frame.subarray(4).toString("ascii"), request = JSON.parse(raw);
    if (codec.canonicalJson(request) !== raw) throw new Error("fixture received noncanonical request");
    requests.push({ path: this.path, value: request, canonical: raw, frameBytes: frame.length,
      digest: codec.sha256(Buffer.from(raw, "ascii")) });
    if (selected === "clientAbortAfterSend") { controller.abort(); return; }
    if (selected === "clientDeadline" || selected === "clientMissingEOF") {
      if (selected === "clientDeadline") return;
    }
    queueMicrotask(() => {
      if (this.destroyed) return;
      phase = "response";
      if (selected === "clientLateReply") clockOffset = 2000;
      if (selected === "clientTransportError") {
        this.emit("error", new Error("FIXTURE_SECRET_NOT_A_REAL_CREDENTIAL")); return;
      }
      const reply = this.path === providerPath ? providerReply(request) : actionReply(request);
      replies.push({ path: this.path, value: reply });
      // Deliberately malformed numeric response bypasses the sender's strict
      // encoder so the production receiver, not our fixture, rejects it.
      const body = Buffer.from(selected === "clientInvalidUsage" ? JSON.stringify(reply) : codec.canonicalJson(reply), "ascii");
      const response = Buffer.alloc(body.length + 4);
      response.writeUInt32BE(body.length); body.copy(response, 4);
      if (selected === "clientTruncated") this.emit("data", response.subarray(0, 3));
      else if (selected === "clientTrailingBytes") this.emit("data", Buffer.concat([response, Buffer.from("x")]));
      else this.emit("data", response);
      if (selected !== "clientMissingEOF") this.emit("end");
    });
  }
  destroy() { this.destroyed = true; socketEvents.push("destroy"); }
}
net.createConnection = (options) => {
  const allowed = options.path === providerPath
    ? Object.keys(options).sort().join() === "allowHalfOpen,path" && options.allowHalfOpen === true
    : Object.keys(options).join() === "path" && options.path === actionPath;
  if (!allowed) {
    return forbid("unexpected-endpoint")();
  }
  connections.push({ ...options });
  const socket = new InMemoryProtectedSocket(options.path);
  queueMicrotask(() => { phase = "connected"; socket.emit("connect"); });
  return socket;
};
syncBuiltinESMExports();

const entrypointUrl = new URL("../../packaging/pi-core/entrypoint.ts", import.meta.url).href;
const providerUrl = new URL("../../packaging/pi-core/provider.ts", import.meta.url).href;
const remappedImports = [];
const hook = registerHooks({ resolve(specifier, context, nextResolve) {
  if ([entrypointUrl, providerUrl].includes(context.parentURL) && ["./worker.js", "./provider.js"].includes(specifier)) {
    remappedImports.push({ parent: context.parentURL.split("/").at(-1), specifier });
    return nextResolve(new URL(specifier.replace(/\.js$/, ".ts"), context.parentURL).href, context);
  }
  return nextResolve(specifier, context);
} });
const entrypoint = await import(entrypointUrl), provider = await import(providerUrl);
codec = require("../../packaging/openclaw/aragorn-runtime-action-worker/index.js").__testing;

const model = { id: "offline-provider", name: "Offline provider", api: "openai-completions",
  provider: "offline-provider", baseUrl: "https://fixture.invalid", reasoning: false,
  input: ["text"], contextWindow: 4096, maxTokens: 512,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } };
const declaration = { name: "aragorn_runtime_create",
  description: "Request a single policy-mediated file creation; this tool itself grants no authority.",
  parameters: { type: "object", properties: {
    content: { type: "string", maxLength: 32768 },
    target_name: { type: "string", pattern: "^[a-z0-9][a-z0-9._-]{0,127}(?![\\s\\S])", maxLength: 128 },
  }, required: ["content", "target_name"], additionalProperties: false } };
function context() {
  return { messages: [{ role: "system", content: "Owned public instructions.",
    toolsAdded: [structuredClone(declaration)], timestamp: 10001 },
  { role: "user", content: [{ type: "text", text: "Owned public question: café 🛡." }], timestamp: 10002 }] };
}
function start() {
  return { schema: "aragorn/pi-core-bootstrap-start/v2", activation_id: activation,
    system_prompt: "Owned public instructions.", task: "Owned public question: café 🛡.",
    model: structuredClone(model), limits: { maxTurns: 3, maxToolCalls: 1, maxRunMs: 1000 },
    native_request: { schema: "aragorn/pi-core-native-request-endpoint/v1", socket_path: actionPath,
      worker_uid: uid, worker_gid: gid, supervisor_uid: 0, max_requests: 1 }, provider_status: "UNAVAILABLE" };
}
const buildMutations = {
  build: () => {},
  buildContinuation: (_m, c) => c.messages.push({ role: "assistant", content: [], timestamp: 0 }),
  buildImage: (_m, c) => c.messages[1].content.push({ type: "image", data: "not-an-image", mimeType: "image/png" }),
  buildUnknownTool: (_m, c) => { c.messages[0].toolsAdded[0].name = "shell"; },
  buildChangedTool: (_m, c) => { c.messages[0].toolsAdded[0].description = "Changed authority claim"; },
  buildUnsafeTimestamp: (_m, c) => { c.messages[1].timestamp = Number.MAX_SAFE_INTEGER + 1; },
  buildCredentials: (m) => { m.apiKey = "FIXTURE_SECRET_NOT_A_REAL_CREDENTIAL"; },
  buildContextExtra: (_m, c) => { c.headers = { authorization: "fixture-only" }; },
  buildModelAccessor: (m) => { Object.defineProperty(m, "id", { get() { throw new Error("accessor invoked"); } }); },
  buildContextAccessor: (_m, c) => { Object.defineProperty(c.messages[1].content[0], "text", {
    get() { throw new Error("accessor invoked"); } }); },
  buildOversized: (_m, c) => { c.messages[0].content = "x".repeat(30 * 1024); c.messages[1].content = "y".repeat(30 * 1024); },
  buildLoneSurrogate: (_m, c) => { c.messages[1].content = "\ud800"; },
};
function build() {
  let value = null, error = null, changed = null;
  const m = structuredClone(model), c = context();
  try {
    if (selected === "buildSemanticMutation") {
      value = provider.buildProviderRequest(m, c, { activationId: activation, routeDigest: route });
      c.messages[1].content[0].text += " changed";
      changed = provider.buildProviderRequest(m, c, { activationId: activation, routeDigest: route });
    } else {
      buildMutations[selected](m, c);
      value = provider.buildProviderRequest(m, c, { activationId: activation, routeDigest: route });
      c.messages[0].content = "caller mutation after projection";
    }
  } catch (caught) { error = errorRecord(caught); }
  return { value, error, changed };
}
async function collect(stream) {
  const resolved = await stream, events = [];
  for await (const event of resolved) events.push(structuredClone(event));
  return { events, message: await resolved.result() };
}
async function client() {
  controller = new AbortController();
  const options = { activationId: activation, routeDigest: route, workerUid: uid, workerGid: gid,
    deadlineMs: performance.now() + (["clientDeadline", "clientMissingEOF"].includes(selected) ? 30 : 1000),
    signal: controller.signal };
  if (selected === "clientWrongUid") currentUid++;
  if (selected === "clientWrongEgid") currentEgid++;
  if (selected === "clientExtraGroups") groups = [gid, 999];
  if (selected === "clientNonLinux") platform = "darwin";
  if (selected === "clientExpired") options.deadlineMs = performance.now() - 1;
  if (selected === "clientPreAbort") controller.abort();
  if (selected === "clientEndpointInjection") options.socketPath = "/tmp/evil.sock";
  let value = null, error = null, second = null;
  try {
    const stream = provider.createProtectedProviderStream(options);
    if (selected === "clientIdentityChanged") currentEuid++;
    const streamOptions = { signal: controller.signal };
    if (selected === "clientOptionsSecret") {
      streamOptions.apiKey = "FIXTURE_SECRET_NOT_A_REAL_CREDENTIAL";
      streamOptions.headers = { authorization: "FIXTURE_SECRET_NOT_A_REAL_CREDENTIAL" };
      streamOptions.onPayload = forbid("Pi-options-callback");
    }
    if (selected === "clientRefusedThenRetry") {
      const invalid = context(); invalid.messages.push({ role: "assistant", content: [], timestamp: 0 });
      value = await collect(stream(model, invalid, streamOptions));
      second = await collect(stream(model, context(), streamOptions));
    } else if (selected === "clientConcurrent") value = await Promise.all([
      collect(stream(model, context(), streamOptions)), collect(stream(model, context(), streamOptions)),
    ]);
    else {
      value = await collect(stream(model, context(), streamOptions));
      if (selected === "clientOneUse") second = await collect(stream(model, context(), streamOptions));
    }
  } catch (caught) { error = errorRecord(caught); }
  return { value, error, second };
}
async function compose() {
  let report = null, error = null;
  const options = { routeDigest: route, deadlineMs: performance.now() + 1000 };
  if (selected === "composeInjectedStream") options.streamFn = forbid("injected-provider");
  if (selected === "composeInjectedRelay") options.relay = forbid("injected-relay");
  try { report = await entrypoint.runProtectedNativePiEntry(start(), options); }
  catch (caught) { error = errorRecord(caught); }
  return { report, error };
}
async function bootstrap() {
  const writes = []; let reads = 0;
  const report = await entrypoint.runBootstrapChannel({
    async read() { return entrypoint.encodeBootstrapFrame(++reads === 1 ? start()
      : { schema: "aragorn/pi-core-bootstrap-release/v1", activation_id: activation }); },
    async write(frame) { writes.push(entrypoint.decodeBootstrapFrame(frame)); },
  }, { workerNonce: "c".repeat(32), deadlineMs: performance.now() + 1000 });
  return { report, writes, reads };
}
let result;
const watchdog = setTimeout(() => { throw new Error("inert provider fixture exceeded bounded runtime"); }, 1500);
try {
  if (selected?.startsWith("build")) result = build();
  else if (selected?.startsWith("client")) result = await client();
  else if (selected?.startsWith("compose")) result = await compose();
  else if (selected === "nativeBootstrapUnavailable") result = await bootstrap();
  else throw new Error("unknown provider fixture scenario");
} finally { clearTimeout(watchdog); hook.deregister(); }
process.stdout.write(JSON.stringify({ fixture: "REAL_PI_MOCKED_PROVIDER_CHANNEL_NOT_DATA_OR_EFFECT_AUTHORITY",
  selected, nodeVersion: process.version, result, connections, requests, replies, liveIO,
  fsReads, socketEvents, remappedImports, syntheticClockAdvanceMs: clockOffset }));
