// Native entrypoint import and bootstrap state machine: in-memory channels only.
// Composition invokes the real pinned Pi Agent with a scripted provider and a
// fabricated NOT_SUBMITTED relay result, never enforcement/provider evidence.
import { createRequire, registerHooks, syncBuiltinESMExports } from "node:module";
import { performance } from "node:perf_hooks";
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import childProcess from "node:child_process";

const require = createRequire(import.meta.url);
const liveIO = [];
const forbid = (name) => () => { liveIO.push(name); throw new Error(`offline fixture forbids ${name}`); };
globalThis.fetch = forbid("fetch");
for (const [name, module, methods] of [
  ["net", net, ["connect", "createConnection", "createServer"]],
  ["tls", tls, ["connect", "createServer"]],
  ["http", http, ["get", "request", "createServer"]],
  ["https", https, ["get", "request", "createServer"]],
  ["child_process", childProcess, ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]],
]) for (const method of methods) module[method] = forbid(`${name}.${method}`);
net.Socket.prototype.connect = forbid("net.Socket.connect");
net.Server.prototype.listen = forbid("net.Server.listen");
syncBuiltinESMExports();

// Node's strip-types loader deliberately does not rewrite compiled .js import
// specifiers. Remap only this entrypoint's worker import for the source fixture;
// compiled deployment imports and all other resolution remain untouched.
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
let entrypoint;
try { entrypoint = await import(entrypointUrl); }
finally { sourceHook.deregister(); }
const { parseStart, encodeBootstrapFrame, decodeBootstrapFrame, runBootstrapChannel, runPreparedPiEntry } = entrypoint;
const { createAssistantMessageEventStream } = await import(
  "../../packaging/pi-core/node_modules/@earendil-works/pi-ai/dist/index.js"
);
const { canonicalJson, sha256 } = require("../../packaging/openclaw/aragorn-runtime-action-worker/index.js").__testing;
const model = {
  id: "offline-fixture", name: "Offline fixture", api: "openai-completions",
  provider: "offline-fixture", baseUrl: "https://fixture.invalid", reasoning: false,
  input: ["text"], contextWindow: 4096, maxTokens: 512,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
};
function start() {
  return {
    schema: "aragorn/pi-core-bootstrap-start/v1", activation_id: "a".repeat(32),
    system_prompt: "Owned offline fixture; only the supplied request tool exists.",
    task: "Issue one inert request.", model: structuredClone(model),
    limits: { maxTurns: 2, maxToolCalls: 2, maxRunMs: 2000 },
    relay: { expectedGatewayUid: 1101, expectedGatewayGid: 1101, expectedWorkerUid: 1102,
      workerSocketPath: "/run/aragorn-pi-action/worker.sock" },
    provider_status: "UNAVAILABLE",
  };
}
function rawFrame(body) {
  const raw = Buffer.from(body, "utf8"), frame = Buffer.alloc(raw.length + 4);
  frame.writeUInt32BE(raw.length); raw.copy(frame, 4); return frame;
}
const parserMutations = {
  parse: () => {},
  unicode: (value) => { value.task = "caf\u00e9 \ud83d\ude00\n"; },
  unknownProvider: (value) => { value.provider_status = "READY"; },
  extraField: (value) => { value.api_key = "not-a-secret-fixture"; },
  trailingId: (value) => { value.activation_id += "\n"; },
  unpairedText: (value) => { value.task = "bad\ud800"; },
  excessiveText: (value) => { value.task = "x".repeat(32769); },
  totalWireLimit: (value) => { value.task = value.system_prompt = "\u00e9".repeat(16000); },
  unsafeInteger: (value) => { value.limits.maxRunMs = Number.MAX_SAFE_INTEGER + 1; },
  excessiveDeadline: (value) => { value.limits.maxRunMs = 30001; },
  fractionalCost: (value) => { value.model.cost.input = 0.25; },
  relayTraversal: (value) => { value.relay.workerSocketPath = "/run/../worker.sock"; },
  relaySameUid: (value) => { value.relay.expectedWorkerUid = value.relay.expectedGatewayUid; },
  modelCredential: (value) => { value.model.apiKey = "not-a-secret-fixture"; },
  accessor: (value) => { Object.defineProperty(value, "task", { get() { throw new Error("accessor invoked"); } }); },
};

async function bootstrap(kind) {
  const writes = [], order = [];
  let reads = 0;
  const value = start();
  if (kind === "channelUnknownProvider") value.provider_status = "READY";
  const channel = {
    async write(frame) { const record = decodeBootstrapFrame(frame); writes.push(record); order.push(record.schema); },
    async read() {
      reads += 1;
      order.push(`read-${reads}`);
      if (reads === 1) return encodeBootstrapFrame(value);
      if (kind === "channelMissingRelease") return new Promise(() => {});
      return encodeBootstrapFrame({ schema: "aragorn/pi-core-bootstrap-release/v1",
        activation_id: kind === "channelWrongRelease" ? "c".repeat(32) : value.activation_id });
    },
  };
  let report = null, error = null;
  try {
    report = await runBootstrapChannel(channel, {
      workerNonce: "b".repeat(32), deadlineMs: performance.now() + (kind === "channelMissingRelease" ? 25 : 2000),
    });
  } catch (caught) { error = { name: caught.name, message: caught.message }; }
  return { report, error, writes, reads, order };
}

function stream() {
  const message = {
    role: "assistant", content: [{ type: "toolCall", id: "entry-call", name: "aragorn_runtime_create",
      arguments: { content: "fabricated inert bytes", target_name: "entry-fixture.txt" } }],
    api: model.api, provider: model.provider, model: model.id, stopReason: "toolUse", timestamp: 0,
    usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
  };
  const result = createAssistantMessageEventStream();
  result.push({ type: "start", partial: { ...message, content: [] } });
  result.push({ type: "done", reason: message.stopReason, message });
  result.end();
  return result;
}
async function composition(kind) {
  const requests = [], contexts = [];
  let providerCalls = 0, report = null, error = null;
  const value = start();
  const dependencies = {
    async streamFn(_model, context) {
      providerCalls += 1; contexts.push(structuredClone(context));
      if (kind === "composeDeadline") return new Promise(() => {});
      return stream();
    },
    async relay(request) {
      requests.push(structuredClone(request));
      return Buffer.from(canonicalJson({
        schema: "aragorn/runtime-action-worker-result/v1",
        authority: "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
        request_digest: sha256(Buffer.from(canonicalJson(request), "ascii")),
        status: "NOT_SUBMITTED", broker_result: null,
      }), "ascii");
    },
    deadlineMs: performance.now() + (kind === "composeDeadline" ? 25 : 2000),
  };
  if (kind === "composeMissingProvider") delete dependencies.streamFn;
  if (kind === "composeExpired") dependencies.deadlineMs = performance.now() - 1;
  try { report = await runPreparedPiEntry(value, dependencies); }
  catch (caught) { error = { name: caught.name, message: caught.message }; }
  return { report, error, providerCalls, requests, contexts };
}

const selected = process.argv[2];
let result;
if (selected?.startsWith("channel")) {
  if (!["channel", "channelUnknownProvider", "channelWrongRelease", "channelMissingRelease"].includes(selected)) throw new Error("unknown scenario");
  result = await bootstrap(selected);
} else if (selected?.startsWith("compose")) {
  if (!["compose", "composeDeadline", "composeMissingProvider", "composeExpired"].includes(selected)) throw new Error("unknown scenario");
  result = await composition(selected);
} else {
  let value = null, error = null;
  try {
    if (Object.hasOwn(parserMutations, selected)) {
      const input = start(); parserMutations[selected](input); value = parseStart(input);
      if (selected === "parse") input.limits.maxTurns = 8; // returned value is detached
    } else if (selected === "duplicateKey") {
      value = decodeBootstrapFrame(rawFrame('{"value":1,"value":2}'));
    } else if (selected === "noncanonical") {
      value = decodeBootstrapFrame(rawFrame('{ "value":1}'));
    } else if (selected === "rawUnsafeInteger") {
      value = decodeBootstrapFrame(rawFrame('{"value":9007199254740993}'));
    } else if (selected === "truncated") {
      value = decodeBootstrapFrame(encodeBootstrapFrame(start()).subarray(0, 12));
    } else if (selected === "oversizedFrame") {
      value = decodeBootstrapFrame(rawFrame('"' + "x".repeat(65536) + '"'));
    } else if (selected === "rawNonAscii") {
      value = decodeBootstrapFrame(rawFrame('{"value":"\u00e9"}'));
    } else throw new Error("unknown offline fixture scenario");
  } catch (caught) { error = { name: caught.name, message: caught.message }; }
  result = { value, error };
}
process.stdout.write(JSON.stringify({
  fixture: "PI_ENTRYPOINT_IN_MEMORY_BOOTSTRAP_AND_SCRIPTED_PI_NOT_DEPLOYMENT_EVIDENCE",
  nodeVersion: process.version, selected, result, liveIO, remappedWorkerImports,
}));
