/**
 * One fresh, request-only Pi loop. This is not a launcher or an authenticated
 * capability principal. Correlation IDs, Pi events and this report confer no
 * effect, admission, cleanup or RUN authority. The protected activation/peer
 * join and credential-isolated provider route are still deployment work.
 */
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { isAbsolute } from "node:path";
import { Agent } from "@earendil-works/pi-agent-core";
import type { AgentMessage, AgentTool, StreamFn } from "@earendil-works/pi-agent-core";
import type { Api, Model } from "@earendil-works/pi-ai";
import { Type } from "typebox";

export type TransportStatus = "COMPLETED" | "NOT_SUBMITTED" | "INDETERMINATE";
export interface WorkerRequest {
  schema: "aragorn/runtime-action-worker-request/v1";
  authority: "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY";
  target_name: string;
  payload_base64: string;
  session_id: string;
  run_id: string;
  tool_call_digest: string;
}
export interface WorkerResult {
  schema: "aragorn/runtime-action-worker-result/v1";
  authority: "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY";
  request_digest: string;
  status: TransportStatus;
  broker_result: null | {
    verdict: "ALLOW" | "BLOCK";
    effect_status: "CREATED" | "NOT_PERFORMED";
    [field: string]: unknown;
  };
}
export interface LegacyRelayConfig {
  expectedGatewayGid: number;
  expectedGatewayUid: number;
  expectedWorkerUid: number;
  workerSocketPath: string;
}
export type WorkerRelay = (
  request: Readonly<WorkerRequest>, signal?: AbortSignal,
) => Promise<Uint8Array>;
export interface WorkerOptions {
  systemPrompt: string;
  task: string;
  model: Model<Api>;
  correlation: { sessionId: string; runId: string };
  limits: { maxTurns: number; maxToolCalls: number; maxRunMs: number };
  streamFn: StreamFn;
  relay: WorkerRelay;
  signal?: AbortSignal;
}
export interface OperationRecord {
  toolCallId: string;
  toolCallDigest: string;
  requestDigest: string;
  transportStatus: TransportStatus;
  sourceResult: WorkerResult | null;
}
export interface WorkerReport {
  schema: "aragorn/pi-core-worker-report/v1";
  authority: "ADAPTER_CORRELATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY";
  status: "COMPLETED" | "STOPPED";
  stopReason: string | null;
  correlation: { sessionId: string; runId: string };
  providerCalls: number;
  toolCalls: number;
  agentSettled: boolean;
  transcriptComplete: boolean;
  results: OperationRecord[];
  messages: AgentMessage[];
}

// Preserve the predecessor unchanged. Its existing exports are reused narrowly;
// loading the module does not call register() or activate an OpenClaw plugin.
// Packaging must retain this exact relative dependency in the adapter closure.
const require = createRequire(import.meta.url);
const legacy = require("../openclaw/aragorn-runtime-action-worker/index.js").__testing as {
  buildRequest(context: { sessionId: string; runId: string; toolCallDigest: string },
    target: string, payload: Buffer): WorkerRequest;
  canonicalJson(value: unknown): string;
  parseWorkerResult(raw: Buffer, request: WorkerRequest): WorkerResult;
  requestWorker(config: LegacyRelayConfig, request: WorkerRequest, signal?: AbortSignal): Promise<WorkerResult>;
};
const TOOL_NAME = "aragorn_runtime_create";
// Unlike $, the final lookahead does not accept a trailing newline.
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}(?![\s\S])/;
const TARGET = /^[a-z0-9][a-z0-9._-]{0,127}(?![\s\S])/;
const MAX_TEXT_BYTES = 32 * 1024;
const MAX_FRAME_BYTES = 64 * 1024;
const MAX_REPORT_BYTES = 1024 * 1024;
const PARAMETERS = Type.Object({
  content: Type.String({ maxLength: MAX_TEXT_BYTES }),
  target_name: Type.String({ pattern: TARGET.source, maxLength: 128 }),
}, { additionalProperties: false });

function record(value: unknown, required: string[], optional: string[] = []): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError("Expected a plain record");
  }
  const keys = Reflect.ownKeys(value);
  if (required.some((key) => !Object.hasOwn(value, key)) || keys.some((key) =>
    typeof key !== "string" || !required.concat(optional).includes(key) ||
    !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key)!, "value"))) {
    throw new TypeError("Unexpected, missing or accessor fields");
  }
}
function text(value: unknown, max: number, label: string): asserts value is string {
  if (typeof value !== "string" || !value.isWellFormed() || value.length === 0 || Buffer.byteLength(value, "utf8") > max) {
    throw new TypeError(`${label} is invalid`);
  }
}
function uint(value: unknown, min: number, max: number): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) {
    throw new TypeError("Integer is outside the allowed range");
  }
}
function digest(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
function boundedSnapshot<T>(value: T, maxBytes: number): { value: T; bytes: number } {
  const raw = JSON.stringify(value, (_key, item: unknown) => {
    if ((typeof item === "string" && !item.isWellFormed()) ||
        (typeof item === "number" && !Number.isFinite(item)) ||
        ["bigint", "function", "symbol"].includes(typeof item)) {
      throw new TypeError("Unrepresentable transcript value");
    }
    return item;
  });
  if (raw === undefined || Buffer.byteLength(raw, "utf8") > maxBytes) throw new TypeError("Transcript byte limit");
  return { value: JSON.parse(raw) as T, bytes: Buffer.byteLength(raw, "utf8") };
}
function copiedModel(value: unknown): Model<Api> {
  // Deliberately no headers, credentials, compatibility callbacks, sampling
  // hooks or extra provider options in this first request-only surface.
  record(value, ["id", "name", "api", "provider", "baseUrl", "reasoning", "input", "cost", "contextWindow", "maxTokens"]);
  for (const field of ["id", "name", "api", "provider", "baseUrl"]) text(value[field], 2048, field);
  if (typeof value.reasoning !== "boolean" || !Array.isArray(value.input) ||
      value.input.length !== 1 || value.input[0] !== "text") throw new TypeError("Only an explicit text model is supported");
  uint(value.contextWindow, 1, 10_000_000);
  uint(value.maxTokens, 1, 1_000_000);
  record(value.cost, ["input", "output", "cacheRead", "cacheWrite"]);
  if (Object.values(value.cost).some((n) => typeof n !== "number" || !Number.isFinite(n) || n < 0)) {
    throw new TypeError("Model costs are invalid");
  }
  const model = structuredClone(value) as unknown as Model<Api>;
  Object.freeze(model.input);
  Object.freeze(model.cost);
  return Object.freeze(model);
}
function createArguments(value: unknown): { content: string; target_name: string } {
  record(value, ["content", "target_name"]);
  if (typeof value.content !== "string" || !value.content.isWellFormed() || Buffer.byteLength(value.content, "utf8") > MAX_TEXT_BYTES ||
      typeof value.target_name !== "string" || !TARGET.test(value.target_name)) {
    throw new TypeError("Create arguments are invalid");
  }
  return { content: value.content, target_name: value.target_name };
}
function actionDigest(args: { content: string; target_name: string }): string {
  return digest(Buffer.from(legacy.canonicalJson(args), "ascii"));
}
class NativeRelayFailure extends Error {
  status: "NOT_SUBMITTED" | "INDETERMINATE";
  constructor(status: "NOT_SUBMITTED" | "INDETERMINATE") {
    super(`Legacy relay ${status}`);
    this.status = status;
  }
}

/** Explicit opt-in transport; this factory itself opens no socket. */
export function createLegacyRelay(value: LegacyRelayConfig): WorkerRelay {
  record(value, ["expectedGatewayGid", "expectedGatewayUid", "expectedWorkerUid", "workerSocketPath"]);
  for (const name of ["expectedGatewayGid", "expectedGatewayUid", "expectedWorkerUid"]) uint(value[name], 0, 0xffffffff);
  if (value.expectedGatewayUid === value.expectedWorkerUid || typeof value.workerSocketPath !== "string" ||
      !value.workerSocketPath.isWellFormed() || !isAbsolute(value.workerSocketPath) ||
      value.workerSocketPath.includes("\0") || Buffer.byteLength(value.workerSocketPath, "utf8") > 4096) {
    throw new TypeError("Relay configuration is invalid");
  }
  const config = Object.freeze({ ...value }) as LegacyRelayConfig;
  return async (request, signal) => {
    // The frozen requestWorker helper does not perform the plugin wrapper's
    // caller checks. Preserve them here; UID/GID is still not a bundle/PID join.
    if (!process.getuid || !process.getgid || !process.getgroups ||
        process.getuid() !== config.expectedGatewayUid || process.getgid() !== config.expectedGatewayGid ||
        process.getgroups().some((gid) => gid !== config.expectedGatewayGid)) {
      throw new NativeRelayFailure("NOT_SUBMITTED");
    }
    try {
      return Buffer.from(legacy.canonicalJson(await legacy.requestWorker(config, request, signal)), "ascii");
    } catch (error) {
      // Only this local, frozen-helper boundary interprets its known status.
      const status = error && typeof error === "object" && "status" in error && error.status === "NOT_SUBMITTED"
        ? "NOT_SUBMITTED" : "INDETERMINATE";
      throw new NativeRelayFailure(status);
    }
  };
}

/** One call creates one Agent; there is no continuation, discovery or resume API. */
export async function runManagedPiWorker(options: WorkerOptions): Promise<WorkerReport> {
  record(options, ["systemPrompt", "task", "model", "correlation", "limits", "streamFn", "relay"], ["signal"]);
  text(options.systemPrompt, MAX_TEXT_BYTES, "systemPrompt");
  text(options.task, MAX_TEXT_BYTES, "task");
  if (typeof options.streamFn !== "function" || typeof options.relay !== "function") throw new TypeError("Explicit provider and relay functions are required");
  if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) throw new TypeError("Invalid abort signal");
  record(options.correlation, ["sessionId", "runId"]);
  for (const value of Object.values(options.correlation)) {
    if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new TypeError("Correlation ID is invalid");
  }
  record(options.limits, ["maxTurns", "maxToolCalls", "maxRunMs"]);
  uint(options.limits.maxTurns, 1, 8);
  uint(options.limits.maxToolCalls, 1, 8);
  uint(options.limits.maxRunMs, 1, 30_000);
  const model = copiedModel(options.model);
  const correlation = Object.freeze({ ...options.correlation });
  const limits = Object.freeze({ ...options.limits });
  const { systemPrompt, task, streamFn, relay, signal: callerSignal } = options;
  const results: OperationRecord[] = [];
  const usedIds = new Set<string>();
  const usedActions = new Set<string>();
  const controller = new AbortController();
  let providerCalls = 0, toolCalls = 0;
  let stopReason: string | null = null;
  let sealed = false, agentSettled = false;
  let agent: Agent;
  let releaseStop!: () => void;
  const stopped = new Promise<void>((resolve) => { releaseStop = resolve; });
  const stop = (reason: string) => {
    stopReason ??= reason;
    controller.abort();
    agent?.abort();
    releaseStop();
  };
  const tool: AgentTool<typeof PARAMETERS, OperationRecord | { reason: string }> = {
    name: TOOL_NAME,
    label: "Aragorn mediated create request",
    description: "Request a single policy-mediated file creation; this tool itself grants no authority.",
    parameters: PARAMETERS,
    executionMode: "sequential",
    replay: "never",
    execute: async (toolCallId, params, toolSignal) => {
      if (sealed || stopReason || controller.signal.aborted || toolSignal?.aborted) {
        stop("ABORTED");
        return { content: [{ type: "text", text: "Aragorn request not submitted" }], details: { reason: stopReason! }, isError: true, terminate: true };
      }
      text(toolCallId, 4096, "tool call ID");
      const args = createArguments(params);
      const action = actionDigest(args);
      if (usedIds.has(toolCallId) || usedActions.has(action) || toolCalls >= limits.maxToolCalls) {
        stop(usedIds.has(toolCallId) ? "DUPLICATE_TOOL_CALL" : usedActions.has(action) ? "DUPLICATE_ACTION" : "TOOL_CALL_LIMIT");
        return { content: [{ type: "text", text: "Aragorn request not submitted" }], details: { reason: stopReason! }, isError: true, terminate: true };
      }
      usedIds.add(toolCallId);
      usedActions.add(action);
      toolCalls++;
      const toolCallDigest = digest(Buffer.from(toolCallId, "utf8"));
      const request = Object.freeze(legacy.buildRequest({ ...correlation, toolCallDigest }, args.target_name, Buffer.from(args.content, "utf8")));
      const item: OperationRecord = {
        toolCallId, toolCallDigest,
        requestDigest: digest(Buffer.from(legacy.canonicalJson(request), "ascii")),
        transportStatus: "INDETERMINATE", sourceResult: null,
      };
      // Once the callback is entered, an unclassified failure cannot establish
      // that no effect was submitted. The in-flight record starts indeterminate.
      results.push(item);
      try {
        const raw = await relay(request, toolSignal);
        if (!sealed) {
          if (!(raw instanceof Uint8Array) || raw.byteLength === 0 || raw.byteLength > MAX_FRAME_BYTES) throw new TypeError("Invalid relay bytes");
          const sourceResult = legacy.parseWorkerResult(Buffer.from(raw), request);
          item.sourceResult = sourceResult;
          item.transportStatus = sourceResult.status;
          if (sourceResult.status !== "COMPLETED") stop(`RELAY_${sourceResult.status}`);
          else if (sourceResult.broker_result!.verdict !== "ALLOW") stop("BROKER_BLOCKED");
        }
      } catch (error) {
        if (!sealed) {
          item.transportStatus = error instanceof NativeRelayFailure ? error.status : "INDETERMINATE";
          stop(error instanceof NativeRelayFailure ? `RELAY_${error.status}` : "INVALID_OR_UNCERTAIN_RELAY_RESULT");
        }
      }
      const failed = item.transportStatus !== "COMPLETED" || item.sourceResult?.broker_result?.verdict !== "ALLOW";
      return {
        content: [{ type: "text", text: legacy.canonicalJson(item) }],
        details: structuredClone(item), isError: failed, terminate: failed,
      };
    },
  };
  const guardedStream: StreamFn = async (...args) => {
    if (sealed || stopReason || controller.signal.aborted) throw new Error("Managed run stopped");
    if (providerCalls >= limits.maxTurns) { stop("TURN_LIMIT"); throw new Error("Managed turn limit reached"); }
    providerCalls++;
    try { return await streamFn(...args); }
    catch { stop("PROVIDER_FAILED"); throw new Error("Explicit provider failed"); }
  };
  agent = new Agent({
    initialState: { systemPrompt, model, tools: [tool], messages: [], thinkingLevel: "off" },
    streamFn: guardedStream,
    toolExecution: "sequential",
    identity: { attribution: null },
    finishTurn: () => stopReason ? { action: "end" } : undefined,
  });
  agent.subscribe((event) => {
    if (sealed) { agent.abort(); return; }
    if ((event.type === "message_start" || event.type === "message_update" || event.type === "message_end") &&
        event.message.role === "assistant") {
      try { boundedSnapshot(event.message, MAX_FRAME_BYTES); }
      catch { stop("PROVIDER_OUTPUT_LIMIT"); return; }
    }
    if (event.type === "message_end" && event.message.role === "assistant") {
      const message = event.message;
      if (message.stopReason === "error" || message.stopReason === "aborted") {
        stop(message.stopReason === "aborted" ? "PROVIDER_ABORTED" : "PROVIDER_FAILED");
        return;
      }
      if (message.stopReason !== "stop" && message.stopReason !== "toolUse") {
        stop("UNSUPPORTED_PROVIDER_OUTCOME");
        return;
      }
      // Preflight the whole emitted batch before its first effect, including
      // unknown tools and invalid raw arguments that Pi might otherwise turn
      // into an error result followed by another model request.
      const calls = message.content.filter((part) => part.type === "toolCall");
      if (calls.length + toolCalls > limits.maxToolCalls) { stop("TOOL_CALL_LIMIT"); return; }
      const batchIds = new Set<string>();
      const batchActions = new Set<string>();
      for (const call of calls) {
        if (call.name !== TOOL_NAME) { stop("UNKNOWN_TOOL"); return; }
        let action: string;
        try { text(call.id, 4096, "tool call ID"); action = actionDigest(createArguments(call.arguments)); }
        catch { stop("INVALID_TOOL_ARGUMENTS"); return; }
        if (usedIds.has(call.id) || batchIds.has(call.id)) { stop("DUPLICATE_TOOL_CALL"); return; }
        if (usedActions.has(action) || batchActions.has(action)) { stop("DUPLICATE_ACTION"); return; }
        batchIds.add(call.id);
        batchActions.add(action);
      }
    }
    if (event.type === "tool_execution_end" && event.isError) stop("TOOL_FAILED");
  });
  const callerAbort = () => stop("ABORTED");
  callerSignal?.addEventListener("abort", callerAbort, { once: true });
  const timer = setTimeout(() => stop("DEADLINE_EXCEEDED"), limits.maxRunMs);
  try {
    if (callerSignal?.aborted) { stop("ABORTED"); agentSettled = true; }
    else {
      const running = agent.prompt(task).catch(() => { stop("RUN_FAILED"); }).then(() => { agentSettled = true; });
      await Promise.race([running, stopped]);
    }
  } finally {
    clearTimeout(timer);
    callerSignal?.removeEventListener("abort", callerAbort);
    sealed = true;
  }
  // An uncooperative provider/relay can outlive this bounded adapter return.
  // Latching forbids further dispatch, but only external process containment
  // can prove shutdown. In-flight entries remain INDETERMINATE; no retry occurs.
  const report: WorkerReport = {
    schema: "aragorn/pi-core-worker-report/v1",
    authority: "ADAPTER_CORRELATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
    status: stopReason ? "STOPPED" : "COMPLETED", stopReason,
    correlation: { ...correlation }, providerCalls, toolCalls, agentSettled,
    transcriptComplete: agentSettled && stopReason !== "PROVIDER_OUTPUT_LIMIT",
    results: structuredClone(results), messages: [],
  };
  // Preserve operation outcomes first. The remaining report budget bounds the
  // transcript; omitted data is explicit, never represented as full retention.
  // This serialization bound is not an OS memory/CPU containment guarantee.
  let remaining = MAX_REPORT_BYTES - boundedSnapshot(report, MAX_REPORT_BYTES).bytes - 256;
  for (const message of agent.state.messages) {
    try {
      const snapshot = boundedSnapshot(message, Math.min(MAX_FRAME_BYTES, remaining));
      remaining -= snapshot.bytes + 1;
      report.messages.push(snapshot.value);
    } catch {
      report.transcriptComplete = false;
      stop("REPORT_OUTPUT_LIMIT");
      report.status = "STOPPED";
      report.stopReason = stopReason;
      break;
    }
  }
  return report;
}
