/**
 * Fixed, credential-free Pi bootstrap entrypoint. Importing this module is inert.
 * Native deployment has no provider route yet and never invokes an Agent or an
 * effect relay. Its bootstrap status is not admission, effect or cleanup proof.
 */
import { randomBytes } from "node:crypto";
import { lstatSync } from "node:fs";
import { createRequire } from "node:module";
import { createConnection } from "node:net";
import type { Socket } from "node:net";
import { isAbsolute, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { createNativeRelay, parseNativeRequestEndpoint, runManagedPiWorker } from "./worker.js";
import type { LegacyRelayConfig, NativeRequestEndpoint, WorkerOptions, WorkerReport } from "./worker.js";

const require = createRequire(import.meta.url);
const { canonicalJson } = require("../openclaw/aragorn-runtime-action-worker/index.js").__testing as {
  canonicalJson(value: unknown): string;
};
export const BOOTSTRAP_SOCKET = "/run/aragorn-pi-bootstrap/bootstrap.sock";
export const MAX_BOOTSTRAP_FRAME_BYTES = 64 * 1024;
const MAX_TOTAL_MS = 30_000;
const ID = /^[a-f0-9]{32}(?![\s\S])/;
const START_SCHEMA = "aragorn/pi-core-bootstrap-start/v1";
const NATIVE_START_SCHEMA = "aragorn/pi-core-bootstrap-start/v2";

export interface PreparedPiStart {
  schema: typeof START_SCHEMA;
  activation_id: string;
  system_prompt: string;
  task: string;
  model: WorkerOptions["model"];
  limits: WorkerOptions["limits"];
  relay: LegacyRelayConfig;
  provider_status: "UNAVAILABLE";
}
export interface PreparedNativePiStart extends Omit<PreparedPiStart, "schema" | "relay"> {
  schema: typeof NATIVE_START_SCHEMA;
  native_request: NativeRequestEndpoint;
}
export interface BootstrapChannel {
  /** Read/write one complete length-prefixed frame, without reconnecting. */
  read(): Promise<Uint8Array>;
  write(frame: Uint8Array): Promise<void>;
}

function exact(value: unknown, fields: string[], optional: string[] = []): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype ||
      fields.some((field) => !Object.hasOwn(value, field)) ||
      Reflect.ownKeys(value).some((key) => typeof key !== "string" ||
        !fields.concat(optional).includes(key) ||
        !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key)!, "value"))) {
    throw new TypeError("Invalid bootstrap fields");
  }
}
function uint(value: unknown, minimum: number, maximum: number): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TypeError("Invalid bootstrap integer");
  }
}
function text(value: unknown, maximum: number): asserts value is string {
  if (typeof value !== "string" || !value.isWellFormed() || !value.length ||
      Buffer.byteLength(value, "utf8") > maximum) throw new TypeError("Invalid bootstrap text");
}
function identifier(value: unknown): asserts value is string {
  if (typeof value !== "string" || !ID.test(value)) throw new TypeError("Invalid bootstrap identifier");
}

export function encodeBootstrapFrame(value: unknown): Buffer {
  const body = Buffer.from(canonicalJson(value), "ascii");
  if (!body.length || body.length > MAX_BOOTSTRAP_FRAME_BYTES) throw new TypeError("Bootstrap frame limit");
  const frame = Buffer.allocUnsafe(body.length + 4);
  frame.writeUInt32BE(body.length, 0);
  body.copy(frame, 4);
  return frame;
}

export function decodeBootstrapFrame(frame: Uint8Array): unknown {
  if (!(frame instanceof Uint8Array) || frame.byteLength < 5 ||
      frame.byteLength > MAX_BOOTSTRAP_FRAME_BYTES + 4) throw new TypeError("Bootstrap frame limit");
  const raw = Buffer.from(frame);
  const length = raw.readUInt32BE(0);
  if (!length || length > MAX_BOOTSTRAP_FRAME_BYTES || raw.length !== length + 4 ||
      raw.subarray(4).some((byte) => byte > 0x7f)) throw new TypeError("Invalid bootstrap frame");
  const body = raw.subarray(4).toString("ascii");
  const value: unknown = JSON.parse(body);
  // Reject duplicate keys, whitespace, unsafe numbers and alternate encodings.
  if (canonicalJson(value) !== body) throw new TypeError("Noncanonical bootstrap frame");
  return value;
}

export function parseStart(value: unknown): PreparedPiStart | PreparedNativePiStart {
  exact(value, ["schema", "activation_id", "system_prompt", "task", "model", "limits", "provider_status"],
    ["relay", "native_request"]);
  const native = value.schema === NATIVE_START_SCHEMA;
  if ((!native && value.schema !== START_SCHEMA) || value.provider_status !== "UNAVAILABLE") {
    throw new TypeError("Unsupported bootstrap schema or provider route");
  }
  exact(value, ["schema", "activation_id", "system_prompt", "task", "model", "limits", "provider_status",
    native ? "native_request" : "relay"]);
  identifier(value.activation_id);
  text(value.system_prompt, 32 * 1024);
  text(value.task, 32 * 1024);
  exact(value.limits, ["maxTurns", "maxToolCalls", "maxRunMs"]);
  uint(value.limits.maxTurns, 1, 8);
  uint(value.limits.maxToolCalls, 1, native ? 1 : 8);
  uint(value.limits.maxRunMs, 1, MAX_TOTAL_MS);
  if (native) {
    parseNativeRequestEndpoint(value.native_request);
  } else {
    exact(value.relay, ["expectedGatewayGid", "expectedGatewayUid", "expectedWorkerUid", "workerSocketPath"]);
    for (const key of ["expectedGatewayGid", "expectedGatewayUid", "expectedWorkerUid"]) uint(value.relay[key], 1, 0xffffffff);
    text(value.relay.workerSocketPath, 4096);
    if (value.relay.expectedGatewayUid === value.relay.expectedWorkerUid ||
        !isAbsolute(value.relay.workerSocketPath) || value.relay.workerSocketPath.includes("\0") ||
        value.relay.workerSocketPath.split("/").slice(1).some((part) => !part || part === "." || part === "..")) {
      throw new TypeError("Invalid bootstrap relay");
    }
  }
  exact(value.model, ["id", "name", "api", "provider", "baseUrl", "reasoning", "input", "cost", "contextWindow", "maxTokens"]);
  for (const key of ["id", "name", "api", "provider", "baseUrl"]) text(value.model[key], 2048);
  if (typeof value.model.reasoning !== "boolean" || !Array.isArray(value.model.input) ||
      value.model.input.length !== 1 || value.model.input[0] !== "text") throw new TypeError("Invalid bootstrap model");
  uint(value.model.contextWindow, 1, 10_000_000);
  uint(value.model.maxTokens, 1, 1_000_000);
  exact(value.model.cost, ["input", "output", "cacheRead", "cacheWrite"]);
  // The inherited canonical wire protocol represents safe integers only.
  for (const cost of Object.values(value.model.cost)) uint(cost, 0, Number.MAX_SAFE_INTEGER);
  // Copy through the exact bounded wire format; retain no caller-owned objects.
  return decodeBootstrapFrame(encodeBootstrapFrame(value)) as PreparedPiStart | PreparedNativePiStart;
}

/**
 * Explicit in-process composition for reviewed provider integration and inert
 * fixtures only. The native entrypoint never calls this without a provider
 * route. No callback, import path or credential can be supplied through START.
 */
export async function runPreparedPiEntry(
  value: unknown,
  dependencies: Pick<WorkerOptions, "streamFn" | "relay" | "signal"> & { deadlineMs?: number },
): Promise<WorkerReport> {
  const start = parseStart(value);
  if (start.schema !== START_SCHEMA) throw new TypeError("Native START cannot inject a relay");
  exact(dependencies, ["streamFn", "relay"], ["signal", "deadlineMs"]);
  if (typeof dependencies.streamFn !== "function" || typeof dependencies.relay !== "function") {
    throw new TypeError("Explicit in-process provider and relay are required");
  }
  const now = performance.now();
  const deadline = dependencies.deadlineMs ?? now + start.limits.maxRunMs;
  if (!Number.isFinite(deadline) || deadline <= now || deadline > now + MAX_TOTAL_MS) {
    throw new TypeError("Invalid original Pi deadline");
  }
  const maxRunMs = Math.min(start.limits.maxRunMs, Math.floor(deadline - performance.now()));
  if (maxRunMs < 1) throw new TypeError("Original Pi deadline exhausted");
  return runManagedPiWorker({
    systemPrompt: start.system_prompt, task: start.task, model: start.model,
    correlation: { sessionId: start.activation_id, runId: start.activation_id },
    limits: { ...start.limits, maxRunMs }, streamFn: dependencies.streamFn,
    relay: dependencies.relay, ...(dependencies.signal ? { signal: dependencies.signal } : {}),
  });
}

/**
 * Explicit future-provider composition: the relay is never caller-injected.
 * nativeMain/runBootstrapChannel do not call this while provider is UNAVAILABLE.
 */
export async function runPreparedNativePiEntry(
  value: unknown,
  dependencies: Pick<WorkerOptions, "streamFn" | "signal"> & { deadlineMs?: number },
): Promise<WorkerReport> {
  const start = parseStart(value);
  if (start.schema !== NATIVE_START_SCHEMA) throw new TypeError("Native entry requires exact v2 START");
  exact(dependencies, ["streamFn"], ["signal", "deadlineMs"]);
  if (typeof dependencies.streamFn !== "function" ||
      (dependencies.signal !== undefined && !(dependencies.signal instanceof AbortSignal))) {
    throw new TypeError("Explicit in-process provider is required");
  }
  const now = performance.now();
  const originalDeadline = dependencies.deadlineMs ?? now + start.limits.maxRunMs;
  if (typeof originalDeadline !== "number" || !Number.isFinite(originalDeadline) ||
      originalDeadline <= now || originalDeadline > now + MAX_TOTAL_MS) {
    throw new TypeError("Invalid original native Pi deadline");
  }
  const deadline = Math.min(originalDeadline, now + start.limits.maxRunMs);
  const relay = createNativeRelay(start.native_request, {
    activationId: start.activation_id, deadlineMs: deadline,
    ...(dependencies.signal ? { signal: dependencies.signal } : {}),
  });
  const maxRunMs = Math.min(start.limits.maxRunMs, Math.floor(deadline - performance.now()));
  if (maxRunMs < 1) throw new TypeError("Original native Pi deadline exhausted");
  return runManagedPiWorker({
    systemPrompt: start.system_prompt, task: start.task, model: start.model,
    correlation: { sessionId: start.activation_id, runId: start.activation_id },
    limits: { ...start.limits, maxRunMs }, streamFn: dependencies.streamFn, relay,
    ...(dependencies.signal ? { signal: dependencies.signal } : {}),
  });
}

/**
 * Protected route composition with no injected provider or effect transport.
 * This prepares a client only: nativeMain stays UNAVAILABLE until the external
 * credential/data-policy route and its native lifetime are deployed and proven.
 */
export async function runProtectedNativePiEntry(
  value: unknown,
  options: { routeDigest: string; signal?: AbortSignal; deadlineMs?: number },
): Promise<WorkerReport> {
  const start = parseStart(value);
  if (start.schema !== NATIVE_START_SCHEMA) throw new TypeError("Protected provider requires exact native START");
  exact(options, ["routeDigest"], ["signal", "deadlineMs"]);
  if (typeof options.routeDigest !== "string" || !/^sha256:[a-f0-9]{64}(?![\s\S])/.test(options.routeDigest) ||
      (options.deadlineMs !== undefined && typeof options.deadlineMs !== "number") ||
      (options.signal !== undefined && !(options.signal instanceof AbortSignal))) throw new TypeError("Invalid protected route");
  const now = performance.now();
  const originalDeadline = options.deadlineMs ?? now + start.limits.maxRunMs;
  if (typeof originalDeadline !== "number" || !Number.isFinite(originalDeadline) || originalDeadline <= now ||
      originalDeadline > now + MAX_TOTAL_MS) throw new TypeError("Invalid original protected Pi deadline");
  const deadline = Math.min(originalDeadline, now + start.limits.maxRunMs);
  const common = { activationId: start.activation_id, deadlineMs: deadline,
    ...(options.signal ? { signal: options.signal } : {}) };
  // Keep existing bootstrap/offline imports inert and independent of this new
  // optional client. The original deadline includes module preparation time.
  const { createProtectedProviderStream } = await import("./provider.js");
  const streamFn = createProtectedProviderStream({ ...common, routeDigest: options.routeDigest,
    workerUid: start.native_request.worker_uid, workerGid: start.native_request.worker_gid });
  const relay = createNativeRelay(start.native_request, common);
  const maxRunMs = Math.min(start.limits.maxRunMs, Math.floor(deadline - performance.now()));
  if (maxRunMs < 1) throw new TypeError("Original protected Pi deadline exhausted");
  return runManagedPiWorker({
    systemPrompt: start.system_prompt, task: start.task, model: start.model,
    correlation: { sessionId: start.activation_id, runId: start.activation_id },
    // No continuation or tool-result forwarding is approved in this slice.
    limits: { ...start.limits, maxTurns: 1, maxToolCalls: 1, maxRunMs }, streamFn, relay,
    completeAfterSingleToolResult: true,
    ...(options.signal ? { signal: options.signal } : {}),
  });
}

async function bounded<T>(operation: () => Promise<T>, deadline: number): Promise<T> {
  const remaining = deadline - performance.now();
  if (!Number.isFinite(remaining) || remaining <= 0 || remaining > MAX_TOTAL_MS) {
    throw new Error("Bootstrap original deadline exhausted");
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      Promise.resolve().then(operation),
      new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("Bootstrap deadline exceeded")), remaining); }),
    ]);
    if (performance.now() >= deadline) throw new Error("Bootstrap deadline exceeded");
    return result;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Always fails closed for providers; injection here substitutes only I/O. */
export async function runBootstrapChannel(
  channel: BootstrapChannel,
  options: { workerNonce: string; deadlineMs: number },
): Promise<{ activationId: string; status: "PROVIDER_UNAVAILABLE"; released: true }> {
  identifier(options.workerNonce);
  const deadline = options.deadlineMs;
  await bounded(() => channel.write(encodeBootstrapFrame({
    schema: "aragorn/pi-core-bootstrap-hello/v1", worker_nonce: options.workerNonce,
  })), deadline);
  const start = parseStart(decodeBootstrapFrame(await bounded(() => channel.read(), deadline)));
  await bounded(() => channel.write(encodeBootstrapFrame({
    schema: "aragorn/pi-core-bootstrap-result/v1", activation_id: start.activation_id,
    status: "PROVIDER_UNAVAILABLE", authority: "BOOTSTRAP_STATUS_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
  })), deadline);
  // Keep this same accepted connection/process alive for the supervisor's
  // identity binding and terminal release. No reconnect, Agent or effect retry.
  const release = decodeBootstrapFrame(await bounded(() => channel.read(), deadline));
  exact(release, ["schema", "activation_id"]);
  if (release.schema !== "aragorn/pi-core-bootstrap-release/v1" || release.activation_id !== start.activation_id) {
    throw new TypeError("Invalid bootstrap release");
  }
  return { activationId: start.activation_id, status: "PROVIDER_UNAVAILABLE", released: true };
}

function socketIdentity(): string {
  if (process.platform !== "linux" || !process.getuid || !process.getgid || !process.getgroups ||
      process.getuid() === 0 || process.getgroups().some((gid) => gid !== process.getgid!())) {
    throw new Error("Bootstrap requires the confined Linux worker identity");
  }
  for (const path of ["/", "/run", "/run/aragorn-pi-bootstrap"]) {
    const state = lstatSync(path);
    if (!state.isDirectory() || state.isSymbolicLink() || state.uid !== 0 || (state.mode & 0o022)) {
      throw new Error("Bootstrap socket parent is not protected");
    }
  }
  const state = lstatSync(BOOTSTRAP_SOCKET);
  if (!state.isSocket() || state.isSymbolicLink() || state.uid !== 0 ||
      state.gid !== process.getgid() || state.nlink !== 1 || (state.mode & 0o7777) !== 0o660) {
    throw new Error("Bootstrap socket identity is not protected");
  }
  return `${state.dev}:${state.ino}:${state.uid}:${state.gid}:${state.mode}`;
}

function framedSocket(socket: Socket): BootstrapChannel {
  const incoming = socket[Symbol.asyncIterator]();
  let pending = Buffer.alloc(0);
  return {
    async read() {
      for (;;) {
        if (pending.length >= 4) {
          const length = pending.readUInt32BE(0);
          if (!length || length > MAX_BOOTSTRAP_FRAME_BYTES) throw new TypeError("Bootstrap frame limit");
          if (pending.length >= length + 4) {
            const frame = pending.subarray(0, length + 4);
            pending = pending.subarray(length + 4);
            return frame;
          }
        }
        const chunk = await incoming.next();
        if (chunk.done) throw new Error("Bootstrap channel closed before release");
        if (!(chunk.value instanceof Buffer) || pending.length + chunk.value.length > 2 * (MAX_BOOTSTRAP_FRAME_BYTES + 4)) {
          throw new TypeError("Bootstrap channel buffer limit");
        }
        pending = Buffer.concat([pending, chunk.value]);
      }
    },
    async write(frame) {
      await new Promise<void>((resolveWrite, reject) => {
        socket.write(frame, (error) => error ? reject(error) : resolveWrite());
      });
    },
  };
}

async function nativeMain(): Promise<void> {
  const deadline = performance.now() + MAX_TOTAL_MS;
  if (process.argv.length !== 2) throw new Error("Pi bootstrap accepts no arguments");
  const identity = socketIdentity();
  // This connect occurs in the actual post-exec Node process, not a socketpair
  // inherited from the supervisor. The root supervisor authenticates its peer.
  const socket = createConnection({ path: BOOTSTRAP_SOCKET });
  socket.on("error", () => {}); // awaited operations still observe their errors
  try {
    await bounded(() => new Promise<void>((resolveConnect, reject) => {
      socket.once("connect", resolveConnect);
      socket.once("error", reject);
    }), deadline);
    if (socketIdentity() !== identity) throw new Error("Bootstrap socket changed during connect");
    await runBootstrapChannel(framedSocket(socket), {
      workerNonce: randomBytes(16).toString("hex"), deadlineMs: deadline,
    });
  } finally {
    socket.destroy();
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  void nativeMain().catch(() => {
    // No task, prompt, provider response or credential is written to logs.
    process.stderr.write("Pi bootstrap refused or failed; no provider route is enabled.\n");
    process.exitCode = 1;
  });
}
