// Real pinned Pi and fixed clients, authored peers/OS metadata only. This is not
// native execution, provider delivery, authorization, source or cleanup evidence.
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
const liveIO = [], connections = [], requests = [], socketEvents = [], writes = [];
const forbid = (name) => () => { liveIO.push(name); throw new Error(`offline fixture forbids ${name}`); };
globalThis.fetch = forbid("fetch");
for (const [name, module, methods] of [
  ["net", net, ["connect", "createServer"]], ["tls", tls, ["connect", "createServer"]],
  ["http", http, ["get", "request", "createServer"]], ["https", https, ["get", "request", "createServer"]],
  ["child_process", childProcess, ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]],
]) for (const method of methods) module[method] = forbid(`${name}.${method}`);
net.Socket.prototype.connect = forbid("net.Socket.connect");
net.Server.prototype.listen = forbid("net.Server.listen");
Object.defineProperty(process, "platform", { configurable: true, value: "linux" });
process.getuid = process.geteuid = () => uid;
process.getgid = process.getegid = () => gid;
process.getgroups = () => [];
const paths = new Set(["/", "/run", "/run/aragorn-pi-bootstrap",
  "/run/aragorn-pi-bootstrap/provider", providerPath,
  "/run/aragorn-pi-bootstrap/requests", actionPath]);
const realLstat = fs.lstatSync, realStat = fs.statSync, realRealpath = fs.realpathSync;
function metadata(path) {
  const socket = path === providerPath || path === actionPath;
  const endpoint = socket || path.endsWith("/provider") || path.endsWith("/requests");
  return { uid: 0n, gid: endpoint ? BigInt(gid) : 0n,
    mode: socket ? 0o140660n : endpoint ? 0o40711n : 0o40755n,
    dev: 1n, ino: BigInt([...paths].indexOf(path) + 1), nlink: socket ? 1n : 2n, ctimeNs: 1n,
    isSocket: () => socket, isDirectory: () => !socket, isSymbolicLink: () => false };
}
fs.lstatSync = (path, options) => paths.has(String(path)) ? metadata(String(path)) : realLstat(path, options);
fs.statSync = (path, options) => paths.has(String(path)) ? metadata(String(path)) : realStat(path, options);
fs.realpathSync = (path, ...options) => paths.has(String(path)) ? String(path) : realRealpath(path, ...options);
let codec;
class InMemorySocket extends EventEmitter {
  constructor(path) { super(); this.path = path; this.destroyed = false; }
  getPeerCredentials() { return { pid: 200, uid: 0, gid: 0 }; }
  end(frame) {
    if (!Buffer.isBuffer(frame) || frame.length < 5 || frame.readUInt32BE(0) !== frame.length - 4) {
      throw new Error("fixture received invalid frame");
    }
    const raw = frame.subarray(4).toString("ascii"), request = JSON.parse(raw);
    if (codec.canonicalJson(request) !== raw) throw new Error("fixture received noncanonical request");
    const digest = codec.sha256(Buffer.from(raw, "ascii"));
    requests.push({ path: this.path, value: request, digest });
    if (selected === "missingProviderResponse") return;
    queueMicrotask(() => {
      if (this.destroyed) return;
      let response;
      if (this.path === providerPath) {
        response = { schema: "aragorn/pi-core-provider-result/v1",
          authority: "PROVIDER_DATA_MEDIATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
          request_digest: digest, status: "COMPLETED",
          completion: { stop_reason: "stop", content: [{ type: "text", text: "Fixture-only reply." }],
            usage: { input_tokens: 5, output_tokens: 7 } } };
        if (["toolRefused", "toolCompleted"].includes(selected)) response.completion = { stop_reason: "toolUse",
          content: [{ type: "toolCall", id: "fixture-create", name: "aragorn_runtime_create",
            arguments: { target_name: "result.json", content: "{\"total\":3}" } }],
          usage: { input_tokens: 5, output_tokens: 7 } };
        if (selected === "providerFailure") { response.status = "NOT_SUBMITTED"; response.completion = null; }
        if (selected === "providerIndeterminate") { response.status = "INDETERMINATE"; response.completion = null; }
      } else {
        response = { schema: "aragorn/runtime-action-worker-result/v1",
          authority: "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
          request_digest: digest, status: "NOT_SUBMITTED", broker_result: null };
        if (selected === "toolCompleted") {
          // Authored existing-contract peer reply, not an actual created file.
          const pin = (char) => "sha256:" + char.repeat(64);
          response.status = "COMPLETED";
          response.broker_result = { schema: "aragorn/runtime-action-broker-result/v1",
            authority: "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            request_digest: pin("5"), observation_digest: pin("6"), target_name: request.target_name,
            verdict: "ALLOW", reason_codes: [], effect_status: "CREATED",
            decision: { schema: "aragorn/runtime-action-decision/v1",
              authority: "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
              request_digest: pin("5"), active_context_digest: pin("a"), measured_action_digest: pin("b"),
              policy_digest: pin("c"), policy_version: 1, evaluated_at_unix: 100,
              revocation_snapshot_digest: pin("d"), revocation_generation: 1, minimum_revocation_generation: 1,
              mediator_health_digest: pin("e"), mediator_health_epoch: 1, minimum_mediator_health_epoch: 1,
              verdict: "ALLOW", reason_codes: [] } };
        }
      }
      const body = Buffer.from(codec.canonicalJson(response), "ascii"), reply = Buffer.alloc(body.length + 4);
      reply.writeUInt32BE(body.length); body.copy(reply, 4);
      this.emit("data", reply); this.emit("end");
    });
  }
  destroy() { this.destroyed = true; socketEvents.push({ path: this.path, event: "destroy" }); }
}
net.createConnection = (options) => {
  const allowed = options.path === providerPath
    ? Object.keys(options).sort().join() === "allowHalfOpen,path" && options.allowHalfOpen === true
    : Object.keys(options).join() === "path" && options.path === actionPath;
  if (!allowed) return forbid("unexpected-endpoint")();
  connections.push({ ...options });
  const socket = new InMemorySocket(options.path);
  queueMicrotask(() => socket.emit("connect"));
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
const entrypoint = await import(entrypointUrl);
codec = require("../../packaging/openclaw/aragorn-runtime-action-worker/index.js").__testing;
const duration = selected === "missingProviderResponse" ? 50 : 1000;
const start = { schema: "aragorn/pi-core-bootstrap-start/v3", activation_id: activation,
  system_prompt: "Calculate the sum of these fabricated numbers.", task: "Save the sum of 1 and 2.",
  model: { id: "offline-provider", name: "Offline provider", api: "openai-completions",
    provider: "offline-provider", baseUrl: "https://fixture.invalid", reasoning: false,
    input: ["text"], contextWindow: 4096, maxTokens: 512,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } },
  limits: { maxTurns: 1, maxToolCalls: 1, maxRunMs: duration },
  native_request: { schema: "aragorn/pi-core-native-request-endpoint/v1", socket_path: actionPath,
    worker_uid: uid, worker_gid: gid, supervisor_uid: 0, max_requests: 1 },
  provider_status: "PROTECTED", provider: { route_digest: route, max_requests: 1, request_timeout_ms: duration } };
const originalStart = structuredClone(start);
const mutations = {
  parse: () => {},
  badRoute: () => { start.provider.route_digest += "\n"; },
  unknownEndpoint: () => { start.provider.socket_path = "/tmp/foreign.sock"; },
  credentials: () => { start.provider.apiKey = "FIXTURE_NOT_REAL"; },
  callback: () => { start.provider.import_path = "./foreign.js"; },
  moreRequests: () => { start.provider.max_requests = 2; },
  booleanRequests: () => { start.provider.max_requests = true; },
  moreTurns: () => { start.limits.maxTurns = 2; },
  moreTools: () => { start.limits.maxToolCalls = 2; },
  widenedTimeout: () => { start.provider.request_timeout_ms++; },
  disabledV3: () => { start.provider_status = "UNAVAILABLE"; },
  enabledV2: () => { start.schema = "aragorn/pi-core-bootstrap-start/v2"; },
  enabledV1: () => { start.schema = "aragorn/pi-core-bootstrap-start/v1"; },
  missingProvider: () => { delete start.provider; },
  callerRelay: () => { start.relay = {}; },
};
let value = null, error = null;
try {
  if (Object.hasOwn(mutations, selected)) {
    mutations[selected]();
    value = entrypoint.parseStart(start);
    start.task = "caller mutation after parse";
  } else if (selected === "routeOverride") {
    value = await entrypoint.runProtectedNativePiEntry(start, {
      routeDigest: "sha256:" + "c".repeat(64), deadlineMs: performance.now() + 1000 });
  } else {
    if (selected === "unavailableV1" || selected === "unavailableV2") {
      delete start.provider; start.provider_status = "UNAVAILABLE";
      start.schema = "aragorn/pi-core-bootstrap-start/" + (selected === "unavailableV1" ? "v1" : "v2");
      if (selected === "unavailableV1") {
        delete start.native_request;
        start.relay = { expectedGatewayUid: uid, expectedGatewayGid: gid,
          expectedWorkerUid: 1200, workerSocketPath: "/run/aragorn-relay/worker.sock" };
      }
    }
    const incoming = [entrypoint.encodeBootstrapFrame(start), entrypoint.encodeBootstrapFrame({
      schema: "aragorn/pi-core-bootstrap-release/v1",
      activation_id: selected === "wrongRelease" ? "c".repeat(32) : activation })];
    value = await entrypoint.runBootstrapChannel({
      async read() { const frame = incoming.shift(); if (!frame) throw new Error("unexpected fixture read"); return frame; },
      async write(frame) { writes.push(entrypoint.decodeBootstrapFrame(frame)); },
    }, { workerNonce: "d".repeat(32), deadlineMs: performance.now() + (selected === "expired" ? -1 : 2000) });
  }
} catch (caught) { error = { name: caught?.name, message: String(caught?.message ?? caught) }; }
hook.deregister();
process.stdout.write(JSON.stringify({ fixture: "PROTECTED_START_REAL_PI_INERT_PEERS_NOT_QUALIFICATION",
  selected, nodeVersion: process.version, liveIO, remappedImports, connections, requests, socketEvents,
  originalStart, writes, result: { value, error } }));
