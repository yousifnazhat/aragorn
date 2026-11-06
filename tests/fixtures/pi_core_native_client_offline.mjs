// Real pinned Pi + frozen requestWorker codec, with in-memory OS boundaries.
// Replies/identity below are authored fixtures, never native or effect evidence.
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
const endpointPath = "/run/aragorn-pi-bootstrap/requests/request.sock";
const activation = "a".repeat(32);
const uid = 1101, gid = 1102;
const liveIO = [], connections = [], requests = [], fsReads = [], socketEvents = [];
const forbid = (name) => () => { liveIO.push(name); throw new Error(`offline fixture forbids ${name}`); };
const errorRecord = (error) => ({ name: error?.name, message: String(error?.message ?? error), status: error?.status ?? null });
const realNow = performance.now.bind(performance);
let clockOffset = 0;
Object.defineProperty(performance, "now", { configurable: true, value: () => realNow() + clockOffset });
globalThis.fetch = forbid("fetch");
for (const [name, module, methods] of [
  ["net", net, ["connect", "createServer"]],
  ["tls", tls, ["connect", "createServer"]],
  ["http", http, ["get", "request", "createServer"]],
  ["https", https, ["get", "request", "createServer"]],
  ["child_process", childProcess, ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]],
]) for (const method of methods) module[method] = forbid(`${name}.${method}`);
net.Socket.prototype.connect = forbid("net.Socket.connect");
net.Server.prototype.listen = forbid("net.Server.listen");

let currentUid = uid, currentEuid = uid, currentGid = gid, currentEgid = gid;
let groups = [], platform = "linux", phase = "initial", clientController;
Object.defineProperty(process, "platform", { configurable: true, get: () => platform });
process.getuid = () => currentUid;
process.geteuid = () => currentEuid;
process.getgid = () => currentGid;
process.getegid = () => currentEgid;
process.getgroups = () => [...groups];

const realLstat = fs.lstatSync, realStat = fs.statSync, realRealpath = fs.realpathSync;
const protectedPaths = new Set(["/", "/run", "/run/aragorn-pi-bootstrap", "/run/aragorn-pi-bootstrap/requests", endpointPath]);
function metadata(path) {
  const isSocket = path === endpointPath;
  const isEndpointDirectory = path === "/run/aragorn-pi-bootstrap/requests";
  let owner = 0n, group = isSocket || isEndpointDirectory ? BigInt(gid) : 0n;
  let mode = isSocket ? 0o140660n : isEndpointDirectory ? 0o40711n : 0o40755n;
  let inode = BigInt([...protectedPaths].indexOf(path) + 1), symlink = false;
  if (selected === "clientWrongSocketOwner" && isSocket) owner = 999n;
  if (selected === "clientWrongSocketGroup" && isSocket) group = 999n;
  if (selected === "clientUnsafeSocketMode" && isSocket) mode = 0o140666n;
  if (selected === "clientUnsafeAncestor" && path === "/run") mode = 0o40777n;
  if (selected === "clientLinkedAncestor" && path === "/run") symlink = true;
  if (selected === "clientReplaceBeforeSend" && isSocket && phase !== "initial") inode += 100n;
  if (selected === "clientReplaceAfterSend" && isSocket && phase === "response") inode += 100n;
  if (selected === "clientReplaceAncestorAfterSend" && path === "/run/aragorn-pi-bootstrap" && phase === "response") inode += 200n;
  return { uid: owner, gid: group, mode, dev: 1n, ino: inode, nlink: isSocket ? 1n : 2n,
    ctimeNs: 1n, isDirectory: () => !isSocket && !symlink,
    isSocket: () => isSocket, isSymbolicLink: () => symlink };
}
fs.lstatSync = (path, options) => {
  if (!protectedPaths.has(String(path))) return realLstat(path, options); // pinned module loading only
  fsReads.push(String(path));
  return metadata(String(path));
};
fs.statSync = (path, options) => {
  if (!protectedPaths.has(String(path))) return realStat(path, options);
  fsReads.push(String(path));
  // Model synchronous metadata consuming the original budget without a busy
  // wait. The frozen helper can still send; only INDETERMINATE is defensible.
  if (selected === "clientSlowMetadata") clockOffset = 2000;
  return metadata(String(path));
};
fs.realpathSync = (path, ...options) => protectedPaths.has(String(path)) ? String(path) : realRealpath(path, ...options);

let codec;
function reply(request) {
  const result = {
    schema: "aragorn/runtime-action-worker-result/v1",
    authority: "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
    request_digest: codec.sha256(Buffer.from(codec.canonicalJson(request), "ascii")),
    status: "NOT_SUBMITTED", broker_result: null,
  };
  if (selected === "clientWrongResponseDigest") result.request_digest = "sha256:" + "0".repeat(64);
  if (selected === "clientCompletedBlock") {
    result.status = "COMPLETED";
    result.broker_result = {
      schema: "aragorn/runtime-action-broker-result/v1",
      authority: "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
      request_digest: "sha256:" + "5".repeat(64), observation_digest: "sha256:" + "6".repeat(64),
      target_name: request.target_name, verdict: "BLOCK", reason_codes: ["BROKER_REPLAY_BLOCKED"],
      effect_status: "NOT_PERFORMED", decision: null,
    };
  }
  return result;
}
class InMemoryRootSocket extends EventEmitter {
  constructor() { super(); this.destroyed = false; }
  getPeerCredentials() { return { pid: 200, uid: selected === "clientWrongRootPeer" ? 999 : 0, gid: 0 }; }
  end(frame) {
    socketEvents.push("end-request");
    if (!Buffer.isBuffer(frame) || frame.readUInt32BE(0) !== frame.length - 4) throw new Error("fixture received wrong frame");
    const raw = frame.subarray(4).toString("ascii"), request = JSON.parse(raw);
    if (codec.canonicalJson(request) !== raw) throw new Error("fixture received noncanonical request");
    requests.push({ value: request, canonical: raw, frameBytes: frame.length,
      digest: codec.sha256(Buffer.from(raw, "ascii")) });
    if (selected === "clientAbortAfterSend") { clientController.abort(); return; }
    if (selected === "clientOriginalDeadline") return;
    queueMicrotask(() => {
      if (this.destroyed) return;
      phase = "response";
      const body = Buffer.from(codec.canonicalJson(reply(request)), "ascii");
      const response = Buffer.alloc(body.length + 4);
      response.writeUInt32BE(body.length); body.copy(response, 4);
      if (selected === "clientTruncatedResponse") this.emit("data", response.subarray(0, 3));
      else this.emit("data", response);
      this.emit("end");
    });
  }
  destroy() { this.destroyed = true; socketEvents.push("destroy"); }
}
net.createConnection = (options) => {
  if (Object.keys(options).join() !== "path" || options.path !== endpointPath) return forbid("unexpected-native-endpoint")();
  connections.push({ ...options });
  const socket = new InMemoryRootSocket();
  queueMicrotask(() => { phase = "connected"; socket.emit("connect"); });
  return socket;
};
syncBuiltinESMExports();

const entrypointUrl = new URL("../../packaging/pi-core/entrypoint.ts", import.meta.url).href;
let remappedWorkerImports = 0;
const sourceHook = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "./worker.js" && context.parentURL === entrypointUrl) {
      remappedWorkerImports += 1;
      return nextResolve(new URL("./worker.ts", entrypointUrl).href, context);
    }
    return nextResolve(specifier, context);
  },
});
let entrypoint, worker;
try {
  entrypoint = await import(entrypointUrl);
  worker = await import("../../packaging/pi-core/worker.ts");
} finally { sourceHook.deregister(); }
codec = require("../../packaging/openclaw/aragorn-runtime-action-worker/index.js").__testing;
const { createAssistantMessageEventStream } = await import(
  "../../packaging/pi-core/node_modules/@earendil-works/pi-ai/dist/index.js"
);
const endpoint = () => ({ schema: "aragorn/pi-core-native-request-endpoint/v1",
  socket_path: endpointPath, worker_uid: uid, worker_gid: gid, supervisor_uid: 0, max_requests: 1 });
const model = { id: "offline-native", name: "Offline native", api: "openai-completions",
  provider: "offline-native", baseUrl: "https://fixture.invalid", reasoning: false,
  input: ["text"], contextWindow: 4096, maxTokens: 512,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } };
function start() {
  return { schema: "aragorn/pi-core-bootstrap-start/v2", activation_id: activation,
    system_prompt: "Owned scripted Pi; only the broker request tool is supplied.",
    task: "Request the inert fixture file.", model: structuredClone(model),
    limits: { maxTurns: 2, maxToolCalls: 1, maxRunMs: 1000 }, native_request: endpoint(),
    provider_status: "UNAVAILABLE" };
}
const parserMutations = {
  parseNative: () => {},
  parseExtraRelay: (value) => { value.relay = {}; },
  parseMissingEndpoint: (value) => { delete value.native_request; },
  parseNonRootSupervisor: (value) => { value.native_request.supervisor_uid = 100; },
  parseRootWorker: (value) => { value.native_request.worker_uid = 0; },
  parseUnsafeWorkerId: (value) => { value.native_request.worker_uid = Number.MAX_SAFE_INTEGER + 1; },
  parseWrongSocket: (value) => { value.native_request.socket_path = "/run/legacy/worker.sock"; },
  parseMultipleRequests: (value) => { value.native_request.max_requests = 2; },
  parseMultipleTools: (value) => { value.limits.maxToolCalls = 2; },
  parseEndpointExtra: (value) => { value.native_request.token = "fixture-only"; },
  parseEndpointAccessor: (value) => { Object.defineProperty(value.native_request, "worker_uid", {
    get() { throw new Error("accessor invoked"); } }); },
};
function makeRequest() {
  return codec.buildRequest({ sessionId: activation, runId: activation,
    toolCallDigest: "sha256:" + "b".repeat(64) }, "native-fixture.txt", Buffer.from("inert native bytes"));
}
async function client() {
  let value = null, error = null, second = null;
  clientController = new AbortController();
  const request = makeRequest();
  const options = { activationId: activation,
    deadlineMs: performance.now() + (selected === "clientOriginalDeadline" ? 30 : 1000),
    signal: clientController.signal };
  if (selected === "clientWrongUid") currentUid += 1;
  if (selected === "clientWrongEuid") currentEuid += 1;
  if (selected === "clientWrongGid") currentGid += 1;
  if (selected === "clientExtraGroups") groups = [gid, 999];
  if (selected === "clientPrimaryGroup") groups = [gid];
  if (selected === "clientNonLinux") platform = "darwin";
  if (selected === "clientExpired") options.deadlineMs = performance.now() - 1;
  if (selected === "clientPreAbort") clientController.abort();
  if (selected === "clientWrongCorrelation") request.run_id = "c".repeat(32);
  const began = performance.now();
  try {
    const relay = worker.createNativeRelay(endpoint(), options);
    if (selected === "clientIdentityChanged") currentEuid += 1;
    if (selected === "clientConcurrent") {
      const outcomes = await Promise.allSettled([relay(request), relay(request)]);
      value = outcomes.map((outcome) => outcome.status === "fulfilled"
        ? { value: JSON.parse(Buffer.from(outcome.value).toString("ascii")), error: null }
        : { value: null, error: errorRecord(outcome.reason) });
    } else {
      value = JSON.parse(Buffer.from(await relay(request)).toString("ascii"));
      if (selected === "clientOneUse") {
        try { second = { value: JSON.parse(Buffer.from(await relay(request)).toString("ascii")), error: null }; }
        catch (caught) { second = { value: null, error: errorRecord(caught) }; }
      }
    }
  } catch (caught) { error = errorRecord(caught); }
  return { value, error, second, elapsedMs: performance.now() - began };
}
function scriptedStream() {
  const message = { role: "assistant", content: [{ type: "toolCall", id: "native-call",
    name: "aragorn_runtime_create", arguments: { content: "inert native bytes", target_name: "native-fixture.txt" } }],
    api: model.api, provider: model.provider, model: model.id, stopReason: "toolUse", timestamp: 0,
    usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } };
  const stream = createAssistantMessageEventStream();
  stream.push({ type: "start", partial: { ...message, content: [] } });
  stream.push({ type: "done", reason: "toolUse", message }); stream.end(); return stream;
}
async function compose() {
  let report = null, error = null, providerCalls = 0;
  const contexts = [], value = start();
  const dependencies = { streamFn: async (_model, context) => {
    providerCalls += 1; contexts.push(structuredClone(context)); return scriptedStream();
  }, deadlineMs: performance.now() + 1000 };
  if (selected === "composeInjectedRelay") dependencies.relay = forbid("injected-relay");
  if (selected === "composeMissingProvider") delete dependencies.streamFn;
  if (selected === "composeExpired") dependencies.deadlineMs = performance.now() - 1;
  try {
    if (selected === "composeLegacyEntry") report = await entrypoint.runPreparedPiEntry(value,
      { ...dependencies, relay: forbid("legacy-relay") });
    else report = await entrypoint.runPreparedNativePiEntry(value, dependencies);
  } catch (caught) { error = errorRecord(caught); }
  return { report, error, providerCalls, contexts };
}
async function bootstrap() {
  const writes = [], value = start();
  let reads = 0;
  const report = await entrypoint.runBootstrapChannel({
    async read() { reads += 1; return entrypoint.encodeBootstrapFrame(reads === 1 ? value
      : { schema: "aragorn/pi-core-bootstrap-release/v1", activation_id: activation }); },
    async write(frame) { writes.push(entrypoint.decodeBootstrapFrame(frame)); },
  }, { workerNonce: "b".repeat(32), deadlineMs: performance.now() + 1000 });
  return { report, writes, reads };
}

let result;
const watchdog = setTimeout(() => { throw new Error("inert native fixture exceeded its bounded runtime"); }, 1500);
try {
  if (selected?.startsWith("client")) result = await client();
  else if (selected?.startsWith("compose")) result = await compose();
  else if (selected === "nativeBootstrapUnavailable") result = await bootstrap();
  else {
    let value = null, error = null;
    try {
      if (selected === "pythonStart") {
        const chunks = []; for await (const chunk of process.stdin) chunks.push(chunk);
        const raw = Buffer.concat(chunks), frame = Buffer.alloc(raw.length + 4);
        frame.writeUInt32BE(raw.length); raw.copy(frame, 4);
        value = entrypoint.parseStart(entrypoint.decodeBootstrapFrame(frame));
      } else if (selected === "parseLegacy" || selected === "parseLegacyMixed") {
        const input = start();
        input.schema = "aragorn/pi-core-bootstrap-start/v1";
        input.limits.maxToolCalls = 2;
        input.relay = { expectedGatewayUid: uid, expectedGatewayGid: gid,
          expectedWorkerUid: 1103, workerSocketPath: "/run/legacy/worker.sock" };
        if (selected === "parseLegacy") delete input.native_request;
        value = entrypoint.parseStart(input);
      } else if (Object.hasOwn(parserMutations, selected)) {
        const input = start(); parserMutations[selected](input); value = entrypoint.parseStart(input);
        if (selected === "parseNative") input.native_request.worker_uid = 999; // copy must remain detached
      } else throw new Error("unknown native fixture scenario");
    } catch (caught) { error = errorRecord(caught); }
    result = { value, error };
  }
} finally { clearTimeout(watchdog); }
process.stdout.write(JSON.stringify({
  fixture: "REAL_PI_FROZEN_CLIENT_MOCKED_NATIVE_BOUNDARIES_NOT_ENFORCEMENT_EVIDENCE",
  selected, nodeVersion: process.version, result, connections, requests, fsReads,
  socketEvents, liveIO, remappedWorkerImports, syntheticClockAdvanceMs: clockOffset,
}));
