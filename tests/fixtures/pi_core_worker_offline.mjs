// Real pinned Pi Agent loop; scripted model and in-memory relay only.
// Broker replies below are fabricated fixtures, never effect/health evidence.
import { createRequire, syncBuiltinESMExports } from "node:module";
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import childProcess from "node:child_process";

const require = createRequire(import.meta.url);
const liveIO = [];
const forbid = (name) => () => {
  liveIO.push(name);
  throw new Error(`offline fixture forbids ${name}`);
};
globalThis.fetch = forbid("fetch");
for (const [name, module, methods] of [
  ["net", net, ["connect", "createConnection", "createServer"]],
  ["tls", tls, ["connect", "createServer"]],
  ["http", http, ["get", "request", "createServer"]],
  ["https", https, ["get", "request", "createServer"]],
  ["child_process", childProcess, ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]],
]) {
  for (const method of methods) module[method] = forbid(`${name}.${method}`);
}
net.Socket.prototype.connect = forbid("net.Socket.connect");
net.Server.prototype.listen = forbid("net.Server.listen");
syncBuiltinESMExports();
const { runManagedPiWorker, createLegacyRelay } = await import("../../packaging/pi-core/worker.ts");
// Pi AI exposes only an ESM import condition, so CJS require.resolve cannot
// select its entrypoint. This exact published import target is in the pinned
// dependency tree checked by Python before this fixture is evaluated.
const { createAssistantMessageEventStream } = await import(
  "../../packaging/pi-core/node_modules/@earendil-works/pi-ai/dist/index.js"
);
const { canonicalJson, sha256 } = require(
  "../../packaging/openclaw/aragorn-runtime-action-worker/index.js",
).__testing;
const pin = (character) => `sha256:${character.repeat(64)}`;
const tool = (id = "call-1", args = {}) => ({
  type: "toolCall", id, name: "aragorn_runtime_create",
  arguments: { target_name: "output.txt", content: "fixture payload", ...args },
});
const done = [{ type: "text", text: "Scripted fixture finished." }];
const model = {
  id: "offline-fixture", name: "Offline fixture", api: "openai-completions",
  provider: "offline-fixture", baseUrl: "https://fixture.invalid",
  reasoning: false, input: ["text"], contextWindow: 4096, maxTokens: 512,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
};

function reply(request, status = "COMPLETED", blocked = false) {
  const reasons = blocked ? ["ACTION_POLICY_DENIED"] : [];
  const brokerDigest = pin("5");
  const broker = {
    schema: "aragorn/runtime-action-broker-result/v1",
    authority: "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
    request_digest: brokerDigest, observation_digest: pin("6"),
    target_name: request.target_name, verdict: blocked ? "BLOCK" : "ALLOW",
    reason_codes: reasons, effect_status: blocked ? "NOT_PERFORMED" : "CREATED",
    decision: {
      schema: "aragorn/runtime-action-decision/v1",
      authority: "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
      request_digest: brokerDigest, active_context_digest: pin("a"),
      measured_action_digest: pin("b"), policy_digest: pin("c"), policy_version: 1,
      evaluated_at_unix: 100, revocation_snapshot_digest: pin("d"),
      revocation_generation: 1, minimum_revocation_generation: 1,
      mediator_health_digest: pin("e"), mediator_health_epoch: 1,
      minimum_mediator_health_epoch: 1,
      verdict: blocked ? "BLOCK" : "ALLOW", reason_codes: reasons,
    },
  };
  return {
    schema: "aragorn/runtime-action-worker-result/v1",
    authority: "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
    request_digest: sha256(Buffer.from(canonicalJson(request), "ascii")),
    status, broker_result: status === "COMPLETED" ? broker : null,
  };
}

function scriptedStream(content, spec = {}) {
  const message = {
    role: "assistant", content, api: model.api, provider: model.provider,
    model: model.id, stopReason: content.some((part) => part.type === "toolCall") ? "toolUse" : "stop",
    usage: {
      input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    timestamp: 0,
  };
  const stream = createAssistantMessageEventStream();
  stream.push({ type: "start", partial: { ...message, content: [] } });
  if (spec.oversizedPartial) {
    const text = "x".repeat(64 * 1024);
    stream.push({
      type: "text_delta", contentIndex: 0, delta: text,
      partial: { ...message, content: [{ type: "text", text }] },
    });
  }
  stream.push({ type: "done", reason: message.stopReason, message });
  stream.end();
  return stream;
}

async function scenario(spec = {}) {
  const requests = [], providerContexts = [], order = [];
  let providerCalls = 0, activeRelays = 0, maxActiveRelays = 0;
  const controller = new AbortController();
  const streamFn = async (_model, context) => {
    providerCalls += 1;
    providerContexts.push(JSON.parse(JSON.stringify(context)));
    if (providerCalls > 10) throw new Error("fixture provider call ceiling exceeded");
    if (spec.hangProvider) return new Promise(() => {});
    if (spec.providerFailure) throw new Error("fixture provider unavailable");
    const content = spec.turns?.[providerCalls - 1] ?? done;
    return scriptedStream(content, spec);
  };
  const relay = async (request, signal) => {
    requests.push({
      value: JSON.parse(JSON.stringify(request)), canonical: canonicalJson(request),
      digest: sha256(Buffer.from(canonicalJson(request), "ascii")),
    });
    activeRelays += 1;
    maxActiveRelays = Math.max(maxActiveRelays, activeRelays);
    order.push(`start:${request.target_name}`);
    try {
      await Promise.resolve();
      if (spec.hangRelay) return await new Promise(() => {});
      if (spec.abortDuringRelay) {
        controller.abort();
        const error = new Error("fixture cancelled after relay entry");
        error.status = "INDETERMINATE";
        throw error;
      }
      if (spec.relayFailure) throw new Error("fixture reply unavailable after relay entry");
      if (spec.malformedRelay) return Buffer.from("not canonical JSON", "ascii");
      const result = reply(request, spec.status, spec.blocked);
      if (spec.wrongDigest) result.request_digest = pin("9");
      if (spec.unsafeInteger) {
        return Buffer.from(canonicalJson(result).replace(
          '"evaluated_at_unix":100', '"evaluated_at_unix":9007199254740992',
        ), "ascii");
      }
      if (spec.noncanonicalRelay) return Buffer.from(JSON.stringify(result, null, 2), "utf8");
      return Buffer.from(canonicalJson(result), "ascii");
    } finally {
      order.push(`end:${request.target_name}`);
      activeRelays -= 1;
    }
  };
  const options = {
    systemPrompt: "Offline fixture: only the supplied broker-request tool exists.",
    task: "Perform the scripted, inert test task.", model,
    correlation: { sessionId: "session-fixture", runId: "run-fixture" },
    limits: { maxTurns: 4, maxToolCalls: 4, maxRunMs: 2000, ...spec.limits },
    streamFn, relay, signal: controller.signal,
  };
  if (spec.preAborted) controller.abort();
  if (spec.changeOptions) spec.changeOptions(options);
  let report = null, error = null;
  try {
    report = await runManagedPiWorker(options);
  } catch (caught) {
    error = { name: caught?.name, message: String(caught?.message ?? caught) };
  }
  return { report, error, providerCalls, providerContexts, requests, maxActiveRelays, order };
}

async function nativeRefusal(kind) {
  let error = null;
  try {
    const config = kind === "invalid" ? {} : {
      expectedGatewayUid: process.getuid() + 1,
      expectedGatewayGid: process.getgid(),
      expectedWorkerUid: process.getuid() + 2,
      workerSocketPath: "/never-opened/aragorn-fixture.sock",
    };
    const relay = createLegacyRelay(config);
    await relay({});
  } catch (caught) {
    error = { name: caught?.name, message: String(caught?.message ?? caught), status: caught?.status };
  }
  return { error };
}

const specifications = {
  create: { turns: [[tool()], done] },
  unicode: { turns: [[tool("call-\u00e9-\ud83d\ude00", { content: "caf\u00e9 \ud83d\ude00\n\u0000" })], done] },
  blocked: { turns: [[tool()], done], blocked: true },
  notSubmitted: { turns: [[tool(), tool("call-2", { target_name: "second.txt" })], done], status: "NOT_SUBMITTED" },
  indeterminate: { turns: [[tool(), tool("call-2", { target_name: "second.txt" })], [tool("call-3", { target_name: "third.txt" })]], status: "INDETERMINATE" },
  malformedRelay: { turns: [[tool()]], malformedRelay: true },
  wrongDigest: { turns: [[tool()]], wrongDigest: true },
  noncanonicalRelay: { turns: [[tool()]], noncanonicalRelay: true },
  unsafeInteger: { turns: [[tool()]], unsafeInteger: true },
  relayFailure: { turns: [[tool()]], relayFailure: true },
  badTarget: { turns: [[tool("call-1", { target_name: "../escape" })], done] },
  extraArgument: { turns: [[tool("call-1", { authority: "ALLOW" })], done] },
  oversizedPayload: { turns: [[tool("call-1", { content: "\u00e9".repeat(16385) })], done] },
  unpairedContentHigh: { turns: [[tool("call-1", { content: "\ud800" })], done] },
  unpairedContentLow: { turns: [[tool("call-1", { content: "\udc00" })], done] },
  unpairedCallIdHigh: { turns: [[tool("call-\ud800")], done] },
  unpairedCallIdLow: { turns: [[tool("call-\udc00")], done] },
  unknownTool: { turns: [[{ ...tool(), name: "exec" }], done] },
  duplicateId: { turns: [[tool()], [tool()], done] },
  duplicateAction: { turns: [[tool()], [tool("different-call-id")], done] },
  callLimit: { turns: [[tool(), tool("call-2", { target_name: "second.txt" })], done], limits: { maxToolCalls: 1 } },
  turnLimit: { turns: [[tool()], [tool("call-2")]], limits: { maxTurns: 1 } },
  sequential: { turns: [[tool("call-1", { target_name: "first.txt" }), tool("call-2", { target_name: "second.txt" })], done] },
  preAborted: { preAborted: true, turns: [[tool()]] },
  abortDuringRelay: { abortDuringRelay: true, turns: [[tool(), tool("call-2", { target_name: "second.txt" })], [tool("call-3", { target_name: "third.txt" })]] },
  providerFailure: { providerFailure: true },
  providerDeadline: { hangProvider: true, limits: { maxRunMs: 25 } },
  relayDeadline: { hangRelay: true, turns: [[tool(), tool("call-2", { target_name: "second.txt" })]], limits: { maxRunMs: 25 } },
  oversizedCompletedOutput: { turns: [[{ type: "text", text: "x".repeat(64 * 1024) }]] },
  oversizedPartialOutput: { oversizedPartial: true, turns: [[tool()]] },
  missingProvider: { changeOptions(options) { delete options.streamFn; } },
  missingRelay: { changeOptions(options) { delete options.relay; } },
  extraConfig: { changeOptions(options) { options.messages = [{ role: "user", content: "inherited" }]; } },
  unsafeLimits: { limits: { maxToolCalls: Number.MAX_SAFE_INTEGER + 1 } },
  badCorrelation: { changeOptions(options) { options.correlation.runId = "../untrusted"; } },
  oversizedPrompt: { changeOptions(options) { options.systemPrompt = "\u00e9".repeat(16385); } },
  unpairedPrompt: { changeOptions(options) { options.systemPrompt = "bad\ud800"; } },
  unpairedTask: { changeOptions(options) { options.task = "bad\udc00"; } },
};
const selected = process.argv[2];
let result;
if (selected === "nativeInvalid" || selected === "nativeWrongUid") {
  result = await nativeRefusal(selected === "nativeInvalid" ? "invalid" : "uid");
} else {
  if (!Object.hasOwn(specifications, selected)) throw new Error("unknown offline fixture scenario");
  result = await scenario(specifications[selected]);
}

process.stdout.write(JSON.stringify({
  fixture: "ACTUAL_PI_LOOP_SCRIPTED_MODEL_IN_MEMORY_RELAY_NOT_ENFORCEMENT_EVIDENCE",
  nodeVersion: process.version,
  selected, result, liveIO,
}));
