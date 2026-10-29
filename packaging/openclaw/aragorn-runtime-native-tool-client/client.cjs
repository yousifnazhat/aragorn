"use strict";

// Appended only to the exact-pinned worker plugin by the source materializer.
// The caller must supply root-provisioned configuration and genesis identity.
// No native hooks, credentials, worker effect gate, or activation are provided.
const NATIVE_MAX_BYTES = 16 * 1024 * 1024;
const NATIVE_MAX_NODES = 100000;
const NATIVE_MAX_DEPTH = 64;
const NATIVE_AUTHORITY = "AUTHENTICATED_GATEWAY_REPORT_ONLY_NOT_CAUSATION_EFFECT_OR_RUN_AUTHORITY";
const NATIVE_ACK_AUTHORITY = "WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY";

class NativeToolClientError extends Error {
  constructor(code) {
    super(code);
    this.name = "NativeToolClientError";
    this.code = code;
  }
}

function nativeRequire(condition, code = "NATIVE_INPUT_UNSUPPORTED") {
  if (!condition) throw new NativeToolClientError(code);
}

function nativeSnapshot(value) {
  // Bound the JSON projection before JSON.stringify; never evaluate accessors,
  // toJSON or proxies. Finite fractional numbers are opaque content, not receipt
  // protocol numbers. No hard VM heap/CPU deadline is claimed by this walk.
  // Digests cover JSON.stringify(snapshot) encoded as UTF-8, with no final LF.
  let bytes = 0;
  let nodes = 0;
  const active = new Set();
  const charge = (count) => {
    bytes += count;
    nativeRequire(bytes <= NATIVE_MAX_BYTES);
  };
  const quoted = (text) => {
    charge(2);
    for (let i = 0; i < text.length; i += 1) {
      const c = text.charCodeAt(i);
      if (c === 34 || c === 92) charge(2);
      else if (c < 32) charge([8, 9, 10, 12, 13].includes(c) ? 2 : 6);
      else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length &&
               text.charCodeAt(i + 1) >= 0xdc00 && text.charCodeAt(i + 1) <= 0xdfff) {
        charge(4);
        i += 1;
      } else if (c >= 0xd800 && c <= 0xdfff) charge(6);
      else charge(c < 128 ? 1 : c < 2048 ? 2 : 3);
    }
  };
  const visit = (item, depth) => {
    nodes += 1;
    nativeRequire(nodes <= NATIVE_MAX_NODES && depth <= NATIVE_MAX_DEPTH);
    if (item === null) { charge(4); return null; }
    if (typeof item === "boolean") { charge(item ? 4 : 5); return item; }
    if (typeof item === "string") { quoted(item); return item; }
    if (typeof item === "number") {
      nativeRequire(Number.isFinite(item));
      charge(JSON.stringify(item).length);
      return item;
    }
    nativeRequire(item && typeof item === "object" && !require("node:util").types.isProxy(item));
    const array = Array.isArray(item);
    nativeRequire(Object.getPrototypeOf(item) === (array ? Array.prototype : Object.prototype));
    nativeRequire(!active.has(item) && !("toJSON" in item));
    const keys = Reflect.ownKeys(item);
    nativeRequire(keys.length <= NATIVE_MAX_NODES && keys.every((key) => typeof key === "string"));
    const output = array ? [] : {};
    active.add(item);
    charge(2);
    if (array) {
      const length = Object.getOwnPropertyDescriptor(item, "length").value;
      nativeRequire(Number.isSafeInteger(length) && length <= NATIVE_MAX_NODES && keys.length === length + 1);
      for (let i = 0; i < length; i += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(item, String(i));
        nativeRequire(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable);
        if (i) charge(1);
        output.push(visit(descriptor.value, depth + 1));
      }
    } else {
      let emitted = 0;
      for (let i = 0; i < keys.length; i += 1) {
        const key = keys[i];
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        nativeRequire(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable);
        const omitted = descriptor.value === undefined;
        if (omitted) {
          // JSON omits these members; the actual detached arguments retain them.
          // Normal native read results include an own details: undefined member.
          nodes += 1;
          nativeRequire(nodes <= NATIVE_MAX_NODES && depth + 1 <= NATIVE_MAX_DEPTH);
        } else {
          if (emitted++) charge(1);
          quoted(key);
          charge(1);
        }
        Object.defineProperty(output, key, {
          value: omitted ? undefined : visit(descriptor.value, depth + 1), enumerable: true,
        });
      }
    }
    active.delete(item);
    return Object.freeze(output);
  };
  const snapshot = visit(value, 0);
  const raw = Buffer.from(JSON.stringify(snapshot), "utf8");
  nativeRequire(raw.length === bytes && raw.length <= NATIVE_MAX_BYTES);
  return { snapshot, raw, digest: sha256(raw) };
}

function nativeReceiptAck(raw, event, genesis, attempt, nextSequence) {
  try {
    nativeRequire(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= 4096);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    const ack = JSON.parse(text);
    nativeRequire(canonicalJson(ack) === text);
    nativeRequire(exactFields(ack, [
      "schema", "authority", "genesis_digest", "receipt_digest", "event_digest",
      "sequence", "status", "effect_authorized", "run_qualified",
    ]));
    nativeRequire(ack.schema === "aragorn/native-tool-receipt-ack/v1" && ack.authority === NATIVE_ACK_AUTHORITY);
    nativeRequire(typeof genesis === "string" && DIGEST.test(genesis) && ack.genesis_digest === genesis);
    nativeRequire(typeof ack.receipt_digest === "string" && DIGEST.test(ack.receipt_digest));
    nativeRequire(ack.event_digest === sha256(Buffer.from(canonicalJson(event), "ascii")));
    nativeRequire(ack.effect_authorized === false && ack.run_qualified === false);
    nativeRequire(Number.isSafeInteger(ack.sequence) && ack.sequence >= 1 && ack.sequence <= 1024);
    if (attempt === null) {
      nativeRequire(event.schema === "aragorn/native-tool-attempt/v1" && ack.sequence % 2 === 1);
      nativeRequire(["ATTEMPT_RECORDED_EXECUTE_ONCE", "ALREADY_RECORDED_DO_NOT_EXECUTE"].includes(ack.status));
      if (ack.status === "ATTEMPT_RECORDED_EXECUTE_ONCE" && nextSequence !== null) {
        nativeRequire(ack.sequence === nextSequence);
      }
    } else {
      nativeRequire(event.schema === "aragorn/native-tool-terminal/v1");
      nativeRequire(event.attempt_digest === attempt.receipt_digest && ack.sequence === attempt.sequence + 1);
      nativeRequire(["TERMINAL_RECORDED", "TERMINAL_ALREADY_RECORDED"].includes(ack.status));
    }
    return Object.freeze(ack);
  } catch {
    throw new WorkerClientError("native receipt acknowledgement is invalid", "INDETERMINATE");
  }
}

function createNativeToolClient(inputConfig, expectedGenesisDigest) {
  const config = normalizedConfig(inputConfig);
  nativeRequire(typeof expectedGenesisDigest === "string" && DIGEST.test(expectedGenesisDigest));
  const genesis = expectedGenesisDigest; // External binding, never ACK-derived.
  let busy = false;
  let halted = false;
  let nextSequence = null; // Initial retained prefix is not supplied by genesis.
  const receipt = (event, signal, attempt = null) => requestWorker(
    config, event, signal,
    (raw, sent) => nativeReceiptAck(raw, sent, genesis, attempt, nextSequence),
  );
  return Object.freeze({
    async execute(toolName, finalParams, inputContext, invoke, signal) {
      nativeRequire(!halted, "NATIVE_RETENTION_UNCERTAIN");
      nativeRequire(!busy, "NATIVE_CALL_BUSY");
      nativeRequire(toolName === "read" || toolName === TOOL_NAME);
      nativeRequire(typeof invoke === "function");
      requireGatewayIdentity(config);
      const params = nativeSnapshot(finalParams);
      const context = nativeSnapshot(inputContext).snapshot;
      nativeRequire(exactFields(context, ["runId", "sessionId", "sessionKey", "toolCallId"]));
      const correlation = {
        run_id: requireIdentifier(context.runId, "run id"),
        session_id: requireIdentifier(context.sessionId, "session id"),
        session_key_digest: opaqueStringDigest(context.sessionKey, "session key"),
        tool_call_digest: opaqueStringDigest(context.toolCallId, "tool call id"),
      };
      let workerRequestDigest = null;
      if (toolName === TOOL_NAME) {
        const bound = effectParameters(params.snapshot);
        for (const [key, field] of Object.entries(CONTEXT_FIELDS)) {
          const reportKey = { runId: "run_id", sessionId: "session_id", sessionKeyDigest: "session_key_digest", toolCallDigest: "tool_call_digest" }[key];
          nativeRequire(bound[field] === correlation[reportKey]);
        }
        const request = buildRequest({
          runId: correlation.run_id, sessionId: correlation.session_id,
          toolCallDigest: correlation.tool_call_digest,
        }, bound.target_name, Buffer.from(bound.content, "utf8"));
        workerRequestDigest = sha256(Buffer.from(canonicalJson(request), "ascii"));
      }
      const common = { authority: NATIVE_AUTHORITY, tool_name: toolName, ...correlation };
      const attemptEvent = {
        schema: "aragorn/native-tool-attempt/v1", ...common,
        params_digest: params.digest, params_bytes: params.raw.length,
        worker_request_digest: workerRequestDigest,
      };
      busy = true;
      let unresolved = false;
      let retentionComplete = false;
      try {
        const attempt = await receipt(attemptEvent, signal);
        unresolved = true;
        nativeRequire(attempt.status === "ATTEMPT_RECORDED_EXECUTE_ONCE", "NATIVE_REPLAY_DO_NOT_EXECUTE");
        let result;
        let nativeError;
        let outcome;
        if (signal?.aborted) {
          nativeError = new Error("native tool was aborted before execution");
          nativeError.name = "AbortError";
          outcome = "CANCELLED";
        } else {
          // Only this exact callback invocation can produce RAISED. Receipt,
          // serialization and diagnostic failures never masquerade as throws.
          try {
            result = await invoke(params.snapshot);
            outcome = "RETURNED";
          } catch (error) {
            nativeError = error;
            outcome = "RAISED";
          }
        }
        const serialized = outcome === "RETURNED" ? nativeSnapshot(result) : null;
        const terminal = {
          schema: "aragorn/native-tool-terminal/v1", ...common,
          attempt_digest: attempt.receipt_digest, outcome,
          result_digest: serialized?.digest ?? null,
          result_bytes: serialized?.raw.length ?? null,
          error_code: outcome === "RETURNED" ? null : outcome === "CANCELLED" ? "ABORTED" : "NATIVE_ERROR",
        };
        // A cancelled native signal cannot suppress its terminal retention.
        const terminalAck = await receipt(terminal, undefined, attempt);
        // An alias may change the returned object while its receipt is awaited.
        // Never deliver a different projection or emit a second terminal then.
        if (serialized !== null) {
          nativeRequire(nativeSnapshot(result).raw.equals(serialized.raw), "NATIVE_RESULT_CHANGED");
        }
        nextSequence = terminalAck.sequence + 1;
        unresolved = false;
        retentionComplete = true;
        if (outcome !== "RETURNED") throw nativeError;
        return result;
      } catch (error) {
        if (unresolved || (!retentionComplete && error instanceof WorkerClientError && error.status === "INDETERMINATE")) {
          halted = true;
        }
        throw error;
      } finally {
        busy = false;
      }
    },
  });
}

module.exports.nativeClient = Object.freeze({ createNativeToolClient });
module.exports.__nativeTesting = Object.freeze({ nativeSnapshot, nativeReceiptAck });
