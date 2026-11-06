/**
 * One bounded, credential-free provider request to a fixed protected endpoint.
 * The worker's payload/digest is a candidate, never data-egress authority. The
 * external mediator must authorize the exact payload before any provider send.
 * No native provider server or network route is installed by this module.
 */
import { createHash } from "node:crypto";
import { lstatSync } from "node:fs";
import { createRequire } from "node:module";
import { createConnection } from "node:net";
import type { Socket } from "node:net";
import { performance } from "node:perf_hooks";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import type { Api, AssistantMessage, Model, TextContent, ToolCall } from "@earendil-works/pi-ai";

const require = createRequire(import.meta.url);
const { canonicalJson } = require("../openclaw/aragorn-runtime-action-worker/index.js").__testing as {
  canonicalJson(value: unknown): string;
};
export const PROVIDER_SOCKET = "/run/aragorn-pi-bootstrap/provider/provider.sock";
export const MAX_PROVIDER_PAYLOAD_BYTES = 48 * 1024;
export const MAX_PROVIDER_FRAME_BYTES = 64 * 1024;
const MAX_TEXT = 32 * 1024;
const MAX_TOTAL_MS = 30_000;
const ID = /^[a-f0-9]{32}(?![\s\S])/;
const DIGEST = /^sha256:[a-f0-9]{64}(?![\s\S])/;
const TARGET = /^[a-z0-9][a-z0-9._-]{0,127}(?![\s\S])/;
const TOOL = {
  name: "aragorn_runtime_create",
  description: "Request a single policy-mediated file creation; this tool itself grants no authority.",
  parameters: {
    type: "object", properties: {
      content: { type: "string", maxLength: MAX_TEXT },
      target_name: { type: "string", pattern: TARGET.source, maxLength: 128 },
    }, required: ["content", "target_name"], additionalProperties: false,
  },
};

export interface ProtectedProviderOptions {
  activationId: string;
  routeDigest: string;
  workerUid: number;
  workerGid: number;
  deadlineMs: number;
  signal?: AbortSignal;
}
export interface ProviderRequest {
  schema: "aragorn/pi-core-provider-request/v1";
  authority: "PI_PROVIDER_REQUEST_ONLY_NOT_DATA_AUTHORITY";
  activation_id: string;
  route_digest: string;
  sequence: 1;
  payload: {
    schema: "aragorn/pi-core-provider-payload/v1";
    model: Model<Api>;
    messages: Record<string, unknown>[];
  };
}
type Completion = {
  stop_reason: "stop" | "toolUse";
  content: (TextContent | ToolCall)[];
  usage: { input_tokens: number; output_tokens: number };
};
type FailureStatus = "NOT_SUBMITTED" | "INDETERMINATE";
class ProviderFailure extends Error {
  readonly status: FailureStatus;
  readonly aborted: boolean;
  constructor(status: FailureStatus, aborted = false) {
    super(`PROVIDER_${status}`);
    this.status = status;
    this.aborted = aborted;
  }
}

function exact(value: unknown, fields: string[], optional: string[] = []): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype ||
      fields.some((key) => !Object.hasOwn(value, key)) || Reflect.ownKeys(value).some((key) =>
        typeof key !== "string" || !fields.concat(optional).includes(key) ||
        !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key)!, "value"))) throw new TypeError("Invalid provider fields");
}
function uint(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TypeError("Invalid provider integer");
  }
}
function text(value: unknown, maximum: number, empty = false): asserts value is string {
  if (typeof value !== "string" || !value.isWellFormed() || (!empty && !value.length) ||
      Buffer.byteLength(value, "utf8") > maximum) throw new TypeError("Invalid provider text");
}
/** Reject accessors, exotic values and omitted fields before canonical copying. */
function wire(value: unknown): void {
  let remaining = 8192;
  const visit = (item: unknown, depth: number): void => {
    if (--remaining < 0 || depth > 16) throw new TypeError("Provider structure limit");
    if (item === null || typeof item === "boolean") return;
    if (typeof item === "number") { if (!Number.isSafeInteger(item)) throw new TypeError("Invalid wire number"); return; }
    if (typeof item === "string") { text(item, MAX_PROVIDER_FRAME_BYTES, true); return; }
    if (!item || typeof item !== "object") throw new TypeError("Invalid wire value");
    if (Array.isArray(item)) {
      if (Object.getPrototypeOf(item) !== Array.prototype || item.length > 2048 ||
          Reflect.ownKeys(item).length !== item.length + 1) throw new TypeError("Invalid wire array");
      for (let index = 0; index < item.length; index++) {
        const property = Object.getOwnPropertyDescriptor(item, String(index));
        if (!property || !Object.hasOwn(property, "value")) throw new TypeError("Invalid wire array entry");
        visit(property.value, depth + 1);
      }
      return;
    }
    if (Object.getPrototypeOf(item) !== Object.prototype) throw new TypeError("Invalid wire record");
    for (const key of Reflect.ownKeys(item)) {
      if (typeof key !== "string") throw new TypeError("Invalid wire key");
      text(key, MAX_PROVIDER_FRAME_BYTES, true);
      const property = Object.getOwnPropertyDescriptor(item, key)!;
      if (!Object.hasOwn(property, "value") || !property.enumerable) throw new TypeError("Invalid wire property");
      visit(property.value, depth + 1);
    }
  };
  visit(value, 0);
}
function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value), "ascii").digest("hex")}`;
}
function copiedModel(value: unknown): Model<Api> {
  exact(value, ["id", "name", "api", "provider", "baseUrl", "reasoning", "input", "cost", "contextWindow", "maxTokens"]);
  wire(value);
  for (const field of ["id", "name", "api", "provider", "baseUrl"]) text(value[field], 2048);
  if (typeof value.reasoning !== "boolean" || !Array.isArray(value.input) ||
      value.input.length !== 1 || value.input[0] !== "text") throw new TypeError("Unsupported provider model");
  uint(value.contextWindow, 1, 10_000_000);
  uint(value.maxTokens, 1, 1_000_000);
  exact(value.cost, ["input", "output", "cacheRead", "cacheWrite"]);
  Object.values(value.cost).forEach((cost) => uint(cost));
  return JSON.parse(canonicalJson(value)) as Model<Api>;
}
function textContent(value: unknown): void {
  if (typeof value === "string") { text(value, MAX_TEXT, true); return; }
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) throw new TypeError("Only initial text content is supported");
  for (const part of value) {
    exact(part, ["type", "text"]);
    if (part.type !== "text") throw new TypeError("Only text content is supported");
    text(part.text, MAX_TEXT, true);
  }
}

/** Pure protocol builder; correlation and a digest never approve data egress. */
export function buildProviderRequest(
  model: unknown, context: unknown, binding: Pick<ProtectedProviderOptions, "activationId" | "routeDigest">,
): ProviderRequest {
  exact(binding, ["activationId", "routeDigest"]);
  if (typeof binding.activationId !== "string" || !ID.test(binding.activationId) ||
      typeof binding.routeDigest !== "string" || !DIGEST.test(binding.routeDigest)) throw new TypeError("Invalid provider binding");
  exact(context, ["messages"]);
  wire(context);
  if (!Array.isArray(context.messages) || context.messages.length !== 2) throw new TypeError("Only one initial provider turn is authorized");
  const [system, user] = context.messages;
  exact(system, ["role", "content", "toolsAdded", "timestamp"]);
  exact(user, ["role", "content", "timestamp"]);
  if (system.role !== "system" || user.role !== "user") throw new TypeError("Provider continuation is not authorized");
  textContent(system.content);
  textContent(user.content);
  uint(system.timestamp); uint(user.timestamp);
  if (canonicalJson(system.toolsAdded) !== canonicalJson([TOOL])) throw new TypeError("Unexpected provider tool declaration");
  const request: ProviderRequest = {
    schema: "aragorn/pi-core-provider-request/v1", authority: "PI_PROVIDER_REQUEST_ONLY_NOT_DATA_AUTHORITY",
    activation_id: binding.activationId, route_digest: binding.routeDigest, sequence: 1,
    payload: { schema: "aragorn/pi-core-provider-payload/v1", model: copiedModel(model),
      // Timestamps are local display metadata, deliberately not forwarded.
      // Every semantic prompt/tool byte remains in the externally approved DTO.
      messages: [{ ...system, timestamp: 0 }, { ...user, timestamp: 0 }] },
  };
  if (Buffer.byteLength(canonicalJson(request.payload), "ascii") > MAX_PROVIDER_PAYLOAD_BYTES) throw new TypeError("Provider payload limit");
  return JSON.parse(canonicalJson(request)) as ProviderRequest;
}

function parseResult(value: unknown, request: ProviderRequest): Completion {
  exact(value, ["schema", "authority", "request_digest", "status", "completion"]);
  if (value.schema !== "aragorn/pi-core-provider-result/v1" ||
      value.authority !== "PROVIDER_DATA_MEDIATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY" ||
      value.request_digest !== digest(request) || !["COMPLETED", "NOT_SUBMITTED", "INDETERMINATE"].includes(value.status as string)) {
    throw new TypeError("Invalid provider response binding");
  }
  if (value.status !== "COMPLETED") {
    if (value.completion !== null) throw new TypeError("Refused provider response has content");
    throw new ProviderFailure(value.status as FailureStatus);
  }
  exact(value.completion, ["stop_reason", "content", "usage"]);
  const completion = value.completion;
  if (!["stop", "toolUse"].includes(completion.stop_reason as string) || !Array.isArray(completion.content) ||
      completion.content.length < 1 || completion.content.length > 16) throw new TypeError("Invalid provider completion");
  let calls = 0;
  for (const part of completion.content) {
    if (part?.type === "text") {
      exact(part, ["type", "text"]); text(part.text, MAX_TEXT, true);
    } else {
      exact(part, ["type", "id", "name", "arguments"]);
      if (part.type !== "toolCall" || part.name !== TOOL.name || ++calls > 1) throw new TypeError("Unexpected provider tool call");
      text(part.id, 4096);
      exact(part.arguments, ["content", "target_name"]);
      text(part.arguments.content, MAX_TEXT, true);
      if (typeof part.arguments.target_name !== "string" || !TARGET.test(part.arguments.target_name)) throw new TypeError("Invalid provider create target");
    }
  }
  if (calls !== (completion.stop_reason === "toolUse" ? 1 : 0)) throw new TypeError("Provider stop reason mismatch");
  exact(completion.usage, ["input_tokens", "output_tokens"]);
  uint(completion.usage.input_tokens); uint(completion.usage.output_tokens);
  uint(completion.usage.input_tokens + completion.usage.output_tokens);
  wire(completion);
  return JSON.parse(canonicalJson(completion)) as Completion;
}

function identity(config: ProtectedProviderOptions): string {
  if (process.platform !== "linux" || !process.getuid || !process.geteuid || !process.getgid || !process.getegid || !process.getgroups ||
      process.getuid() !== config.workerUid || process.geteuid() !== config.workerUid ||
      process.getgid() !== config.workerGid || process.getegid() !== config.workerGid ||
      process.getgroups().some((gid) => gid !== config.workerGid)) throw new TypeError("Provider worker identity mismatch");
  const paths = ["/", "/run", "/run/aragorn-pi-bootstrap", "/run/aragorn-pi-bootstrap/provider", PROVIDER_SOCKET];
  return paths.map((path, index) => {
    const state = lstatSync(path, { bigint: true });
    if (state.isSymbolicLink() || state.uid !== 0n || (state.mode & 0o022n) !== (index === 4 ? 0o020n : 0n) ||
        (index === 4 ? !state.isSocket() || state.nlink !== 1n || (state.mode & 0o7777n) !== 0o660n : !state.isDirectory()) ||
        (index >= 3 && state.gid !== BigInt(config.workerGid)) ||
        (index === 3 && (state.mode & 0o7777n) !== 0o711n)) throw new TypeError("Provider endpoint is not protected");
    return [state.dev, state.ino, state.uid, state.gid, state.mode].map(String).join(":");
  }).join("/");
}

function exchange(request: ProviderRequest, config: ProtectedProviderOptions, signals: AbortSignal[]): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let socket: Socket | undefined;
    let sent = false, settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let incoming = Buffer.alloc(0);
    const fail = (aborted = false) => finish(new ProviderFailure(sent ? "INDETERMINATE" : "NOT_SUBMITTED", aborted));
    const finish = (error?: Error, value?: unknown) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      for (const signal of signals) signal.removeEventListener("abort", abort);
      try { socket?.destroy(); }
      catch { reject(new ProviderFailure(sent ? "INDETERMINATE" : "NOT_SUBMITTED")); return; }
      if (error) reject(error); else resolve(value);
    };
    const abort = () => fail(true);
    const current = () => !signals.some((signal) => signal.aborted) && performance.now() < config.deadlineMs;
    try {
      if (!current()) { fail(true); return; }
      const expectedIdentity = identity(config);
      const body = Buffer.from(canonicalJson(request), "ascii");
      if (!body.length || body.length > MAX_PROVIDER_FRAME_BYTES) throw new TypeError("Provider frame limit");
      const frame = Buffer.allocUnsafe(body.length + 4);
      frame.writeUInt32BE(body.length, 0); body.copy(frame, 4);
      if (!current()) { fail(true); return; }
      for (const signal of signals) signal.addEventListener("abort", abort, { once: true });
      timer = setTimeout(abort, Math.max(0, config.deadlineMs - performance.now()));
      // This is endpoint ownership proof, not a mandatory kernel peer-PID join:
      // Node has no portable SO_PEERCRED API. The server must authenticate Pi.
      socket = createConnection({ path: PROVIDER_SOCKET, allowHalfOpen: true });
      socket.once("connect", () => {
        if (settled) return;
        try {
          if (identity(config) !== expectedIdentity) throw new TypeError("Provider endpoint changed");
          if (!current()) { fail(true); return; }
          sent = true; // An exception after this edge cannot prove no submission.
          socket!.end(frame);
        } catch { fail(); }
      });
      socket.on("data", (chunk: Buffer) => {
        if (settled) return;
        if (!Buffer.isBuffer(chunk) || incoming.length + chunk.length > MAX_PROVIDER_FRAME_BYTES + 4) { fail(); return; }
        incoming = Buffer.concat([incoming, chunk]);
        if (incoming.length >= 4) {
          const length = incoming.readUInt32BE(0);
          if (!length || length > MAX_PROVIDER_FRAME_BYTES || incoming.length > length + 4) fail();
        }
      });
      socket.once("end", () => {
        if (settled) return;
        try {
          if (!sent || !current() || identity(config) !== expectedIdentity || incoming.length < 5 ||
              incoming.readUInt32BE(0) !== incoming.length - 4 || incoming.subarray(4).some((byte) => byte > 0x7f)) {
            fail(); return;
          }
          const body = incoming.subarray(4).toString("ascii");
          const value: unknown = JSON.parse(body);
          wire(value);
          if (canonicalJson(value) !== body) throw new TypeError("Noncanonical provider response");
          if (!current()) { fail(true); return; }
          finish(undefined, value);
        } catch { fail(); }
      });
      socket.once("error", () => fail());
      socket.once("close", () => { if (!settled) fail(); });
      if (!current()) fail(true);
    } catch { fail(); }
  });
}

/** Import/factory construction opens no socket. Only the one StreamFn call may. */
export function createProtectedProviderStream(value: ProtectedProviderOptions): StreamFn {
  exact(value, ["activationId", "routeDigest", "workerUid", "workerGid", "deadlineMs"], ["signal"]);
  if (typeof value.activationId !== "string" || !ID.test(value.activationId) ||
      typeof value.routeDigest !== "string" || !DIGEST.test(value.routeDigest) ||
      typeof value.deadlineMs !== "number" || !Number.isFinite(value.deadlineMs) ||
      value.deadlineMs <= performance.now() || value.deadlineMs > performance.now() + MAX_TOTAL_MS ||
      (value.signal !== undefined && !(value.signal instanceof AbortSignal))) throw new TypeError("Invalid protected provider options");
  uint(value.workerUid, 1, 0xffffffff); uint(value.workerGid, 1, 0xffffffff);
  const config = Object.freeze({ ...value });
  let used = false;
  return (model, context, options) => {
    const stream = createAssistantMessageEventStream();
    let boundModel: Model<Api> | undefined;
    let possibleSend = false;
    const message = (stopReason: AssistantMessage["stopReason"]): AssistantMessage => ({
      role: "assistant", content: [], api: boundModel?.api ?? "aragorn-protected-provider",
      provider: boundModel?.provider ?? "aragorn", model: boundModel?.id ?? "unavailable",
      usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
        // Required Pi fields only: zero is unknown/unpriced, not cost evidence.
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
      stopReason, timestamp: Date.now(),
    });
    void (async () => {
      try {
        if (used) throw new ProviderFailure("NOT_SUBMITTED");
        used = true; // Consume once even when malformed, cancelled or refused.
        if (options?.signal !== undefined && !(options.signal instanceof AbortSignal)) throw new ProviderFailure("NOT_SUBMITTED");
        // Pi options contain callbacks and provider fields. Never forward any;
        // only the cancellation signal is local control, not serialized data.
        const signals = [...new Set([config.signal, options?.signal].filter((signal): signal is AbortSignal => signal !== undefined))];
        const request = buildProviderRequest(model, context, { activationId: config.activationId, routeDigest: config.routeDigest });
        boundModel = request.payload.model;
        possibleSend = true;
        const completion = parseResult(await exchange(request, config, signals), request);
        if (signals.some((signal) => signal.aborted) || performance.now() >= config.deadlineMs) throw new ProviderFailure("INDETERMINATE", true);
        const final = message(completion.stop_reason);
        final.content = completion.content;
        final.usage.input = completion.usage.input_tokens;
        final.usage.output = completion.usage.output_tokens;
        final.usage.totalTokens = final.usage.input + final.usage.output;
        // Buffered, bounded completion; no fabricated incremental token events.
        stream.push({ type: "start", partial: message("pending") });
        stream.push({ type: "done", reason: completion.stop_reason, message: final });
        stream.end();
      } catch (error) {
        const failure = error instanceof ProviderFailure ? error : new ProviderFailure(possibleSend ? "INDETERMINATE" : "NOT_SUBMITTED");
        const terminal = message(failure.aborted ? "aborted" : "error");
        terminal.errorMessage = failure.message;
        stream.push({ type: "error", reason: failure.aborted ? "aborted" : "error", error: terminal });
        stream.end();
      }
    })();
    return stream;
  };
}
