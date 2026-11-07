// Real pinned Pi lifecycle; fabricated replies and in-memory callbacks only.
// This fixture proves neither protected endpoint identity nor effect authority.
import { createRequire, registerHooks, syncBuiltinESMExports } from "node:module";
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import childProcess from "node:child_process";

const selected = process.argv[2];
const liveIO = [];
const forbid = (name) => () => { liveIO.push(name); throw new Error(`Forbidden live I/O: ${name}`); };
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

const require = createRequire(import.meta.url);
const { canonicalJson, sha256 } = require("../../packaging/openclaw/aragorn-runtime-action-worker/index.js").__testing;
const { runManagedPiWorker } = await import("../../packaging/pi-core/worker.ts");
const { createAssistantMessageEventStream } = await import(
  "../../packaging/pi-core/node_modules/@earendil-works/pi-ai/dist/index.js");
const model = {
  id: "offline", name: "Offline", api: "openai-responses", provider: "offline",
  baseUrl: "https://fixture.invalid", reasoning: false, input: ["text"],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 4096, maxTokens: 512,
};
const pin = (character) => "sha256:" + character.repeat(64);
const call = (id, target = "result.json") => ({ type: "toolCall", id, name: "aragorn_runtime_create",
  arguments: { target_name: target, content: '{"sum":6}' } });
const controller = new AbortController();
let providerCalls = 0, relayCalls = 0, providerAborts = 0, toolAborts = 0;
const replies = [], requests = [];

function reply(request) {
  const blocked = selected === "blocked";
  const reasons = blocked ? ["ACTION_POLICY_DENIED"] : [];
  const status = selected === "indeterminate" ? "INDETERMINATE" :
    selected === "notSubmitted" ? "NOT_SUBMITTED" : "COMPLETED";
  return { schema: "aragorn/runtime-action-worker-result/v1",
    authority: "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
    request_digest: selected === "wrongDigest" ? pin("9") : sha256(Buffer.from(canonicalJson(request), "ascii")),
    status, broker_result: status !== "COMPLETED" ? null : {
      schema: "aragorn/runtime-action-broker-result/v1",
      authority: "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
      request_digest: pin("5"), observation_digest: pin("6"), target_name: request.target_name,
      verdict: blocked ? "BLOCK" : "ALLOW", reason_codes: reasons,
      effect_status: blocked ? "NOT_PERFORMED" : "CREATED",
      decision: { schema: "aragorn/runtime-action-decision/v1",
        authority: "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
        request_digest: pin("5"), active_context_digest: pin("a"), measured_action_digest: pin("b"),
        policy_digest: pin("c"), policy_version: 1, evaluated_at_unix: 100,
        revocation_snapshot_digest: pin("d"), revocation_generation: 1, minimum_revocation_generation: 1,
        mediator_health_digest: pin("e"), mediator_health_epoch: 1, minimum_mediator_health_epoch: 1,
        verdict: blocked ? "BLOCK" : "ALLOW", reason_codes: reasons },
    } };
}
const streamFn = async (_model, _context, options) => {
  providerCalls++;
  options.signal?.addEventListener("abort", () => { providerAborts++; }, { once: true });
  if (selected === "providerFailure") throw new Error("Offline provider failure");
  if (providerCalls !== 1) throw new Error("Unexpected provider continuation");
  const content = selected === "textOnly" ? [{ type: "text", text: "No tool requested." }] :
    selected === "twoCalls" ? [call("call-1"), call("call-2", "second.json")] : [call("call-1")];
  const message = { role: "assistant", content, api: model.api, provider: model.provider, model: model.id,
    stopReason: selected === "providerAborted" ? "aborted" : selected === "textOnly" ? "stop" : "toolUse",
    usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } }, timestamp: 0 };
  const stream = createAssistantMessageEventStream();
  stream.push({ type: "start", partial: { ...message, content: [] } });
  if (message.stopReason === "aborted") stream.push({ type: "error", reason: "aborted", error: message });
  else stream.push({ type: "done", reason: message.stopReason, message });
  stream.end();
  return stream;
};
const relay = async (request, signal) => {
  relayCalls++;
  requests.push(structuredClone(request));
  signal?.addEventListener("abort", () => { toolAborts++; }, { once: true });
  if (selected === "relayDeadline") return new Promise(() => {});
  if (selected === "callerAbort") { controller.abort(); return new Promise(() => {}); }
  if (selected === "relayFailure") throw new Error("Unknown post-submission failure");
  if (selected === "malformed") return Buffer.from("not JSON");
  const result = reply(request);
  replies.push(structuredClone(result));
  return Buffer.from(canonicalJson(result), "ascii");
};
const options = { systemPrompt: "Offline one-shot fixture.", task: "Calculate and save fabricated data.", model,
  correlation: { sessionId: "one-shot", runId: "one-shot" },
  limits: { maxTurns: selected === "invalidTurns" ? 2 : 1,
    maxToolCalls: selected === "invalidTools" ? 2 : 1, maxRunMs: selected === "relayDeadline" ? 25 : 2000 },
  streamFn, relay, signal: controller.signal, completeAfterSingleToolResult: true };
if (selected === "default") delete options.completeAfterSingleToolResult;
if (selected === "invalidOption") options.completeAfterSingleToolResult = false;
if (selected === "preAborted") controller.abort();
let report = null, error = null;
try {
  if (selected === "protectedEntry") {
    // Replace only transport factories. The protected entry and Agent lifecycle
    // are real source; this is not an endpoint/credential/deployment test.
    globalThis.__oneShotRelay = relay;
    globalThis.__oneShotStream = streamFn;
    const workerUrl = new URL("../../packaging/pi-core/worker.ts", import.meta.url).href;
    registerHooks({
      resolve(specifier, context, nextResolve) {
        if (context.parentURL?.endsWith("/entrypoint.ts") && specifier === "./worker.js") {
          return { url: "aragorn-one-shot:worker", shortCircuit: true };
        }
        if (context.parentURL?.endsWith("/entrypoint.ts") && specifier === "./provider.js") {
          return { url: "aragorn-one-shot:provider", shortCircuit: true };
        }
        return nextResolve(specifier, context);
      },
      load(url, context, nextLoad) {
        if (url === "aragorn-one-shot:worker") return { format: "module", shortCircuit: true,
          source: `export * from ${JSON.stringify(workerUrl)}; export const createNativeRelay = () => globalThis.__oneShotRelay;` };
        if (url === "aragorn-one-shot:provider") return { format: "module", shortCircuit: true,
          source: "export const createProtectedProviderStream = () => globalThis.__oneShotStream;" };
        return nextLoad(url, context);
      },
    });
    const { runProtectedNativePiEntry } = await import("../../packaging/pi-core/entrypoint.ts");
    report = await runProtectedNativePiEntry({ schema: "aragorn/pi-core-bootstrap-start/v2",
      activation_id: "a".repeat(32), system_prompt: options.systemPrompt, task: options.task, model,
      limits: { maxTurns: 4, maxToolCalls: 1, maxRunMs: 2000 }, provider_status: "UNAVAILABLE",
      native_request: { schema: "aragorn/pi-core-native-request-endpoint/v1",
        socket_path: "/run/aragorn-pi-bootstrap/requests/request.sock", worker_uid: 1101,
        worker_gid: 1102, supervisor_uid: 0, max_requests: 1 } }, { routeDigest: pin("b") });
  } else report = await runManagedPiWorker(options);
} catch (caught) { error = { name: caught?.name, message: String(caught?.message ?? caught) }; }
process.stdout.write(JSON.stringify({ fixture: "REAL_PI_ONE_SHOT_MOCKED_TRANSPORTS_NOT_EFFECT_AUTHORITY",
  nodeVersion: process.version, selected, liveIO, report, error,
  providerCalls, relayCalls, providerAborts, toolAborts, requests, replies }));
