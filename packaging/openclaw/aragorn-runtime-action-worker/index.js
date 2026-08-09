"use strict";

const { createHash } = require("node:crypto");
const { lstatSync, realpathSync, statSync } = require("node:fs");
const { createConnection } = require("node:net");
const { dirname, isAbsolute } = require("node:path");
const { TextDecoder } = require("node:util");

const PLUGIN_ID = "aragorn-runtime-action-worker";
const TOOL_NAME = "aragorn_runtime_create";
const MAX_FRAME_BYTES = 64 * 1024;
const MAX_PAYLOAD_BYTES = 32 * 1024;
const REQUEST_TIMEOUT_MS = 750;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const TARGET_NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{0,127}$/;
const DECISION_FIELDS = Object.freeze([
  "active_context_digest",
  "authority",
  "evaluated_at_unix",
  "measured_action_digest",
  "mediator_health_digest",
  "mediator_health_epoch",
  "minimum_mediator_health_epoch",
  "minimum_revocation_generation",
  "policy_digest",
  "policy_version",
  "reason_codes",
  "request_digest",
  "revocation_generation",
  "revocation_snapshot_digest",
  "schema",
  "verdict",
]);
const CONFIG_FIELDS = new Set([
  "expectedGatewayGid",
  "expectedGatewayUid",
  "expectedWorkerUid",
  "workerSocketPath",
]);
const CONTEXT_FIELDS = Object.freeze({
  runId: "__aragorn_run_id",
  sessionId: "__aragorn_session_id",
  sessionKeyDigest: "__aragorn_session_key_digest",
  toolCallDigest: "__aragorn_tool_call_digest",
});

class WorkerClientError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

function canonicalString(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return canonicalString(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("non-canonical JSON number");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${canonicalString(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("value is not canonical JSON");
}

function sha256(raw) {
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

function exactFields(value, fields) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...fields].sort())
  );
}

function requireIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function opaqueStringDigest(value, label) {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > 4096) {
    throw new TypeError(`${label} is invalid`);
  }
  return sha256(Buffer.from(value, "utf8"));
}

function safeInteger(value, label, status = "NOT_SUBMITTED", { positive = false } = {}) {
  const number = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < (positive ? 1 : 0)) {
    throw new WorkerClientError(`${label} is not a safe integer`, status);
  }
  return number;
}

function requirePath(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || value.includes("\0")) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function normalizedConfig(value) {
  if (!exactFields(value, CONFIG_FIELDS)) throw new TypeError("plugin config fields are invalid");
  const config = {
    expectedGatewayGid: safeInteger(value.expectedGatewayGid, "gateway gid"),
    expectedGatewayUid: safeInteger(value.expectedGatewayUid, "gateway uid"),
    expectedWorkerUid: safeInteger(value.expectedWorkerUid, "worker uid"),
    workerSocketPath: requirePath(value.workerSocketPath, "worker socket"),
  };
  if (config.expectedGatewayUid === config.expectedWorkerUid) {
    throw new TypeError("gateway and worker uids must differ");
  }
  return Object.freeze(config);
}

function requireGatewayIdentity(config) {
  if (!process.getuid || !process.getgid || !process.getgroups) {
    throw new WorkerClientError("gateway identity is unavailable", "NOT_SUBMITTED");
  }
  if (
    process.getuid() !== config.expectedGatewayUid ||
    process.getgid() !== config.expectedGatewayGid ||
    process.getgroups().some((gid) => gid !== config.expectedGatewayGid)
  ) {
    throw new WorkerClientError("gateway identity does not match policy", "NOT_SUBMITTED");
  }
}

function directoryIdentity(path, config, status = "NOT_SUBMITTED") {
  let metadata;
  let resolved;
  try {
    resolved = realpathSync(path);
    metadata = statSync(path, { bigint: true });
  } catch (error) {
    throw new WorkerClientError(`worker runtime directory is unavailable: ${error.code || error.message}`, status);
  }
  if (
    resolved !== path ||
    !metadata.isDirectory() ||
    safeInteger(metadata.uid, "worker runtime directory uid", status) !== config.expectedWorkerUid ||
    safeInteger(metadata.gid, "worker runtime directory gid", status) !== config.expectedGatewayGid ||
    Number(metadata.mode & 0o7777n) !== 0o711
  ) {
    throw new WorkerClientError("worker runtime directory metadata is unsafe", status);
  }
  return [
    safeInteger(metadata.dev, "worker runtime directory device", status),
    safeInteger(metadata.ino, "worker runtime directory inode", status),
    safeInteger(metadata.uid, "worker runtime directory uid", status),
    safeInteger(metadata.gid, "worker runtime directory gid", status),
    Number(metadata.mode),
    metadata.ctimeNs.toString(),
  ];
}

function workerSocketIdentity(path, config, status = "NOT_SUBMITTED") {
  let metadata;
  try {
    metadata = lstatSync(path, { bigint: true });
  } catch (error) {
    throw new WorkerClientError(`worker socket is unavailable: ${error.code || error.message}`, status);
  }
  if (
    !metadata.isSocket() ||
    safeInteger(metadata.uid, "worker socket uid", status) !== config.expectedWorkerUid ||
    safeInteger(metadata.gid, "worker socket gid", status) !== config.expectedGatewayGid ||
    Number(metadata.mode & 0o7777n) !== 0o660 ||
    safeInteger(metadata.nlink, "worker socket link count", status) !== 1
  ) {
    throw new WorkerClientError("worker socket metadata is unsafe", status);
  }
  return [
    safeInteger(metadata.dev, "worker socket device", status),
    safeInteger(metadata.ino, "worker socket inode", status),
    safeInteger(metadata.uid, "worker socket uid", status),
    safeInteger(metadata.gid, "worker socket gid", status),
    Number(metadata.mode),
    metadata.ctimeNs.toString(),
  ];
}

function sameIdentity(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function validReasonCodes(value) {
  return (
    Array.isArray(value) &&
    value.length <= 128 &&
    value.every((reason) => typeof reason === "string" && REASON_CODE.test(reason)) &&
    canonicalJson(value) === canonicalJson([...new Set(value)].sort())
  );
}

function requirePeerIdentityIfSupported(socket, config, status) {
  if (typeof socket.getPeerCredentials !== "function") return;
  let peer;
  try {
    peer = socket.getPeerCredentials();
  } catch (error) {
    throw new WorkerClientError(`worker peer credentials are unavailable: ${error.message}`, status);
  }
  if (
    !peer ||
    typeof peer !== "object" ||
    safeInteger(peer.pid, "worker peer pid", status, { positive: true }) < 1 ||
    safeInteger(peer.uid, "worker peer uid", status) !== config.expectedWorkerUid ||
    safeInteger(peer.gid, "worker peer gid", status) < 0
  ) {
    throw new WorkerClientError("worker peer credentials do not match policy", status);
  }
}

function effectParameters(value) {
  const fields = ["content", "target_name", ...Object.values(CONTEXT_FIELDS)];
  if (
    !exactFields(value, fields) ||
    typeof value.content !== "string" ||
    typeof value.target_name !== "string" ||
    !TARGET_NAME.test(value.target_name)
  ) {
    throw new WorkerClientError("runtime create parameters are invalid", "NOT_SUBMITTED");
  }
  return value;
}

function buildRequest(context, targetName, payload) {
  if (typeof targetName !== "string" || !TARGET_NAME.test(targetName)) {
    throw new WorkerClientError("target name is invalid", "NOT_SUBMITTED");
  }
  if (!Buffer.isBuffer(payload) || payload.length > MAX_PAYLOAD_BYTES) {
    throw new WorkerClientError("payload is invalid", "NOT_SUBMITTED");
  }
  if (typeof context.toolCallDigest !== "string" || !DIGEST.test(context.toolCallDigest)) {
    throw new WorkerClientError("tool call digest is invalid", "NOT_SUBMITTED");
  }
  return {
    schema: "aragorn/runtime-action-worker-request/v1",
    authority: "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
    target_name: targetName,
    payload_base64: payload.toString("base64"),
    session_id: requireIdentifier(context.sessionId, "session id"),
    run_id: requireIdentifier(context.runId, "run id"),
    tool_call_digest: context.toolCallDigest,
  };
}

function validateDecision(decision, result) {
  if (
    !exactFields(decision, DECISION_FIELDS) ||
    decision.schema !== "aragorn/runtime-action-decision/v1" ||
    decision.authority !== "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY" ||
    decision.request_digest !== result.request_digest ||
    !DIGEST.test(decision.request_digest) ||
    !DIGEST.test(decision.policy_digest) ||
    !DIGEST.test(decision.revocation_snapshot_digest) ||
    !DIGEST.test(decision.mediator_health_digest) ||
    !validReasonCodes(decision.reason_codes) ||
    !["ALLOW", "BLOCK"].includes(decision.verdict)
  ) {
    throw new WorkerClientError("worker decision binding is invalid", "INDETERMINATE");
  }
  safeInteger(decision.policy_version, "worker decision policy version", "INDETERMINATE", { positive: true });
  for (const field of [
    "evaluated_at_unix",
    "revocation_generation",
    "minimum_revocation_generation",
    "mediator_health_epoch",
    "minimum_mediator_health_epoch",
  ]) {
    safeInteger(decision[field], `worker decision ${field}`, "INDETERMINATE");
  }
  const invalidRequest = decision.reason_codes.includes("ACTION_REQUEST_INVALID");
  for (const [field, missingReason] of [
    ["active_context_digest", "ACTION_UNATTRIBUTED"],
    ["measured_action_digest", "ACTION_UNMEASURED"],
  ]) {
    const missing = decision[field] === null;
    if (
      (missing && !invalidRequest && !decision.reason_codes.includes(missingReason)) ||
      (!missing && (typeof decision[field] !== "string" || !DIGEST.test(decision[field]))) ||
      (!missing && decision.reason_codes.includes(missingReason))
    ) {
      throw new WorkerClientError("worker decision context is inconsistent", "INDETERMINATE");
    }
  }
  if (
    (decision.verdict === "ALLOW") !== (decision.reason_codes.length === 0) ||
    (decision.verdict === "ALLOW" &&
      (decision.active_context_digest === null || decision.measured_action_digest === null))
  ) {
    throw new WorkerClientError("worker decision outcome is inconsistent", "INDETERMINATE");
  }
}

function validateBrokerResult(result, request) {
  const fields = [
    "authority",
    "decision",
    "effect_status",
    "observation_digest",
    "reason_codes",
    "request_digest",
    "schema",
    "target_name",
    "verdict",
  ];
  if (
    !exactFields(result, fields) ||
    result.schema !== "aragorn/runtime-action-broker-result/v1" ||
    result.authority !== "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY" ||
    !DIGEST.test(result.request_digest) ||
    !DIGEST.test(result.observation_digest) ||
    result.target_name !== request.target_name ||
    !validReasonCodes(result.reason_codes) ||
    !(result.decision === null || (result.decision && typeof result.decision === "object" && !Array.isArray(result.decision)))
  ) {
    throw new WorkerClientError("worker broker result binding is invalid", "INDETERMINATE");
  }
  if (result.decision !== null) validateDecision(result.decision, result);
  const allowed =
    result.verdict === "ALLOW" &&
    result.effect_status === "CREATED" &&
    result.reason_codes.length === 0 &&
    result.decision !== null &&
    result.decision.verdict === "ALLOW";
  const blocked =
    result.verdict === "BLOCK" &&
    result.effect_status === "NOT_PERFORMED" &&
    result.reason_codes.length > 0;
  if (!allowed && !blocked) {
    throw new WorkerClientError("worker broker result outcome is inconsistent", "INDETERMINATE");
  }
}

function parseWorkerResult(raw, request) {
  let text;
  let result;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    result = JSON.parse(text);
  } catch (error) {
    throw new WorkerClientError(`worker result is invalid: ${error.message}`, "INDETERMINATE");
  }
  if (canonicalJson(result) !== text) {
    throw new WorkerClientError("worker result is not canonical JSON", "INDETERMINATE");
  }
  if (
    !exactFields(result, ["authority", "broker_result", "request_digest", "schema", "status"]) ||
    result.schema !== "aragorn/runtime-action-worker-result/v1" ||
    result.authority !== "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY" ||
    result.request_digest !== sha256(Buffer.from(canonicalJson(request), "ascii")) ||
    !["COMPLETED", "NOT_SUBMITTED", "INDETERMINATE"].includes(result.status)
  ) {
    throw new WorkerClientError("worker result binding is invalid", "INDETERMINATE");
  }
  if (result.status === "COMPLETED") {
    validateBrokerResult(result.broker_result, request);
  } else if (result.broker_result !== null) {
    throw new WorkerClientError("worker result outcome is inconsistent", "INDETERMINATE");
  }
  return result;
}

function requestWorker(config, request, signal) {
  const raw = Buffer.from(canonicalJson(request), "ascii");
  if (raw.length === 0 || raw.length > MAX_FRAME_BYTES) {
    throw new WorkerClientError("worker request exceeds its frame limit", "NOT_SUBMITTED");
  }
  if (signal?.aborted) throw new WorkerClientError("worker request was aborted", "NOT_SUBMITTED");

  const runtimePath = dirname(config.workerSocketPath);
  const beforeDirectory = directoryIdentity(runtimePath, config);
  const beforeSocket = workerSocketIdentity(config.workerSocketPath, config);
  const frame = Buffer.allocUnsafe(4 + raw.length);
  frame.writeUInt32BE(raw.length, 0);
  raw.copy(frame, 4);

  return new Promise((resolve, reject) => {
    let socket = null;
    const chunks = [];
    let received = 0;
    let submitted = false;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      socket?.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    const fail = (message) =>
      finish(new WorkerClientError(message, submitted ? "INDETERMINATE" : "NOT_SUBMITTED"));
    const abort = () => fail("worker request was aborted");
    const timer = setTimeout(() => fail("worker request timed out"), REQUEST_TIMEOUT_MS);
    timer.unref();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) {
      abort();
      return;
    }
    try {
      socket = createConnection({ path: config.workerSocketPath });
    } catch (error) {
      fail(`worker transport failed: ${error.code || error.message}`);
      return;
    }
    socket.once("connect", () => {
      if (settled) return;
      try {
        if (
          !sameIdentity(beforeDirectory, directoryIdentity(runtimePath, config)) ||
          !sameIdentity(beforeSocket, workerSocketIdentity(config.workerSocketPath, config))
        ) {
          fail("worker endpoint changed before submission");
          return;
        }
        // Node does not expose peer credentials on every supported runtime. Exact
        // UID-owned endpoint metadata is the claim ceiling; the sensor measures
        // the worker process downstream. Verify peer credentials when available.
        requirePeerIdentityIfSupported(socket, config, "NOT_SUBMITTED");
        submitted = true;
        socket.end(frame);
      } catch (error) {
        const status = submitted ? "INDETERMINATE" : "NOT_SUBMITTED";
        finish(
          new WorkerClientError(
            error instanceof WorkerClientError
              ? error.message
              : `worker endpoint validation failed: ${error.message}`,
            status,
          ),
        );
      }
    });
    socket.on("data", (chunk) => {
      if (settled) return;
      received += chunk.length;
      if (received > MAX_FRAME_BYTES + 4) {
        fail("worker response exceeds its frame limit");
        return;
      }
      chunks.push(chunk);
    });
    socket.once("error", (error) => fail(`worker transport failed: ${error.code || error.message}`));
    socket.once("end", () => {
      if (settled) return;
      const response = Buffer.concat(chunks, received);
      if (response.length < 4) {
        fail("worker response ended early");
        return;
      }
      const length = response.readUInt32BE(0);
      if (length === 0 || length > MAX_FRAME_BYTES || response.length !== length + 4) {
        fail("worker response framing is invalid");
        return;
      }
      try {
        if (
          !sameIdentity(beforeDirectory, directoryIdentity(runtimePath, config, "INDETERMINATE")) ||
          !sameIdentity(beforeSocket, workerSocketIdentity(config.workerSocketPath, config, "INDETERMINATE"))
        ) {
          throw new WorkerClientError("worker endpoint changed during the request", "INDETERMINATE");
        }
        finish(null, parseWorkerResult(response.subarray(4), request));
      } catch (error) {
        finish(
          error instanceof WorkerClientError
            ? error
            : new WorkerClientError(`worker result validation failed: ${error.message}`, "INDETERMINATE"),
        );
      }
    });
    socket.once("close", () => {
      if (!settled) fail("worker response closed without an exact EOF");
    });
  });
}

function retainedToolResultText(message, result) {
  return canonicalJson({
    message,
    result,
    schema: "aragorn/runtime-action-worker-tool-result-text/v1",
  });
}

function workerToolResult(result) {
  const completed = result.status === "COMPLETED";
  const message = completed
    ? `Aragorn ${result.broker_result.verdict}: ${result.broker_result.effect_status}`
    : `Aragorn worker relay: ${result.status}`;
  return {
    content: [{ type: "text", text: retainedToolResultText(message, result) }],
    details: result,
    isError: !completed || result.broker_result.verdict !== "ALLOW",
  };
}

function clientErrorResult(error) {
  const status = error instanceof WorkerClientError ? error.status : "NOT_SUBMITTED";
  const result = {
    schema: "aragorn/runtime-action-worker-client-error/v1",
    authority: "GATEWAY_CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
    status,
    message: error instanceof Error ? error.message : String(error),
  };
  return {
    content: [{ type: "text", text: retainedToolResultText(`Aragorn worker relay failed closed: ${status}`, result) }],
    details: result,
    isError: true,
  };
}

function register(api) {
  const config = normalizedConfig(api.pluginConfig);
  api.registerTool(
    (toolContext) => ({
      name: TOOL_NAME,
      label: "Aragorn Runtime Create",
      description: "Request one policy-mediated file creation through the Aragorn runtime action worker.",
      parameters: {
        type: "object",
        additionalProperties: false,
        required: ["content", "target_name"],
        properties: {
          content: { type: "string", maxLength: MAX_PAYLOAD_BYTES },
          target_name: { type: "string", pattern: TARGET_NAME.source, maxLength: 128 },
        },
      },
      prepareBeforeToolCallParams: (params, invocation = {}) => {
        const { toolCallId, hookContext } = invocation;
        if (
          !params ||
          typeof params !== "object" ||
          Array.isArray(params) ||
          !hookContext ||
          typeof hookContext !== "object" ||
          Array.isArray(hookContext) ||
          Object.values(CONTEXT_FIELDS).some((field) => Object.hasOwn(params, field))
        ) {
          throw new Error("OpenClaw tool correlation is ambiguous");
        }
        return Object.freeze({
          ...params,
          [CONTEXT_FIELDS.runId]: requireIdentifier(hookContext.runId, "run id"),
          [CONTEXT_FIELDS.sessionId]: requireIdentifier(hookContext.sessionId, "session id"),
          [CONTEXT_FIELDS.sessionKeyDigest]: opaqueStringDigest(hookContext.sessionKey, "session key"),
          [CONTEXT_FIELDS.toolCallDigest]: opaqueStringDigest(toolCallId, "tool call id"),
        });
      },
      finalizeBeforeToolCallParams: (params, preparedParams) => {
        if (!params || typeof params !== "object" || Array.isArray(params)) return params;
        const prepared = effectParameters(preparedParams);
        return {
          ...params,
          [CONTEXT_FIELDS.runId]: prepared[CONTEXT_FIELDS.runId],
          [CONTEXT_FIELDS.sessionId]: prepared[CONTEXT_FIELDS.sessionId],
          [CONTEXT_FIELDS.sessionKeyDigest]: prepared[CONTEXT_FIELDS.sessionKeyDigest],
          [CONTEXT_FIELDS.toolCallDigest]: prepared[CONTEXT_FIELDS.toolCallDigest],
        };
      },
      execute: async (toolCallId, params, signal) => {
        try {
          requireGatewayIdentity(config);
          const bound = effectParameters(params);
          const sessionId = requireIdentifier(toolContext.sessionId, "session id");
          const sessionKeyDigest = opaqueStringDigest(toolContext.sessionKey, "session key");
          const correlation = {
            runId: requireIdentifier(bound[CONTEXT_FIELDS.runId], "run id"),
            sessionId: requireIdentifier(bound[CONTEXT_FIELDS.sessionId], "session id"),
            sessionKeyDigest: bound[CONTEXT_FIELDS.sessionKeyDigest],
            toolCallDigest: bound[CONTEXT_FIELDS.toolCallDigest],
          };
          if (
            correlation.sessionId !== sessionId ||
            correlation.sessionKeyDigest !== sessionKeyDigest ||
            correlation.toolCallDigest !== opaqueStringDigest(toolCallId, "tool call id") ||
            !DIGEST.test(correlation.toolCallDigest)
          ) {
            throw new WorkerClientError("OpenClaw tool call is unattributed", "NOT_SUBMITTED");
          }
          const payload = Buffer.from(bound.content, "utf8");
          const request = buildRequest(correlation, bound.target_name, payload);
          return workerToolResult(await requestWorker(config, request, signal));
        } catch (error) {
          return clientErrorResult(error);
        }
      },
    }),
    { name: TOOL_NAME, optional: true },
  );
}

module.exports = {
  id: PLUGIN_ID,
  name: "Aragorn Runtime Action Worker",
  register,
  __testing: Object.freeze({
    buildRequest,
    canonicalJson,
    clientErrorResult,
    directoryIdentity,
    parseWorkerResult,
    requestWorker,
    retainedToolResultText,
    sha256,
    workerSocketIdentity,
    workerToolResult,
  }),
};
