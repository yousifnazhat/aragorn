"use strict";

const { createHash } = require("node:crypto");
const { lstatSync, realpathSync, statSync } = require("node:fs");
const { createConnection } = require("node:net");
const { dirname, isAbsolute, join } = require("node:path");
const { TextDecoder } = require("node:util");

const PLUGIN_ID = "aragorn-runtime-action";
const TOOL_NAME = "aragorn_runtime_create";
const MAX_FRAME_BYTES = 64 * 1024;
const MAX_PAYLOAD_BYTES = 32 * 1024;
const REQUEST_TIMEOUT_MS = 750;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const TARGET_NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const CONTEXT_FIELDS = Object.freeze({
  runId: "__aragorn_run_id",
  sessionId: "__aragorn_session_id",
  sessionKeyDigest: "__aragorn_session_key_digest",
  toolCallIdDigest: "__aragorn_tool_call_id_digest",
});
const CONFIG_FIELDS = new Set([
  "activeSkillDigest",
  "expectedBrokerUid",
  "expectedRuntimeGid",
  "expectedRuntimeUid",
  "expectedSensorUid",
  "policyDigest",
  "policyVersion",
  "protectedRoot",
  "runtimeDigest",
  "sensorSocketPath",
]);

class BrokerClientError extends Error {
  constructor(message, effectStatus) {
    super(message);
    this.effectStatus = effectStatus;
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

function requireDigest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
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

function requireUnsignedInteger(value, label, { positive = false } = {}) {
  if (!Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function requirePath(value, label) {
  if (typeof value !== "string" || !isAbsolute(value) || value.includes("\0")) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function normalizedConfig(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("plugin config is invalid");
  }
  if (Object.keys(value).length !== CONFIG_FIELDS.size || Object.keys(value).some((key) => !CONFIG_FIELDS.has(key))) {
    throw new TypeError("plugin config fields are invalid");
  }
  const config = {
    activeSkillDigest: requireDigest(value.activeSkillDigest, "active skill digest"),
    expectedBrokerUid: requireUnsignedInteger(value.expectedBrokerUid, "broker uid"),
    expectedRuntimeGid: requireUnsignedInteger(value.expectedRuntimeGid, "runtime gid"),
    expectedRuntimeUid: requireUnsignedInteger(value.expectedRuntimeUid, "runtime uid"),
    expectedSensorUid: requireUnsignedInteger(value.expectedSensorUid, "sensor uid"),
    policyDigest: requireDigest(value.policyDigest, "policy digest"),
    policyVersion: requireUnsignedInteger(value.policyVersion, "policy version", { positive: true }),
    protectedRoot: requirePath(value.protectedRoot, "protected root"),
    runtimeDigest: requireDigest(value.runtimeDigest, "runtime digest"),
    sensorSocketPath: requirePath(value.sensorSocketPath, "sensor socket"),
  };
  if (
    new Set([
      config.expectedBrokerUid,
      config.expectedRuntimeUid,
      config.expectedSensorUid,
    ]).size !== 3
  ) {
    throw new TypeError("broker, runtime, and sensor uids must differ");
  }
  return Object.freeze(config);
}

function requireRuntimeIdentity(config) {
  if (!process.getuid || !process.getgid || !process.getgroups) {
    throw new BrokerClientError("runtime identity is unavailable", "NOT_SUBMITTED");
  }
  if (
    process.getuid() !== config.expectedRuntimeUid ||
    process.getgid() !== config.expectedRuntimeGid ||
    process.getgroups().some((gid) => gid !== config.expectedRuntimeGid)
  ) {
    throw new BrokerClientError("runtime identity does not match policy", "NOT_SUBMITTED");
  }
}

function safeInteger(value, label, effectStatus = "NOT_SUBMITTED") {
  const number = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new BrokerClientError(`${label} is not a safe integer`, effectStatus);
  }
  return number;
}

function directoryIdentity(path, uid, gid, exactMode, label, effectStatus = "NOT_SUBMITTED") {
  let resolved;
  let metadata;
  try {
    resolved = realpathSync(path);
    metadata = statSync(path, { bigint: true });
  } catch (error) {
    throw new BrokerClientError(`${label} is unavailable: ${error.code || error.message}`, effectStatus);
  }
  if (
    resolved !== path ||
    !metadata.isDirectory() ||
    safeInteger(metadata.uid, `${label} uid`, effectStatus) !== uid ||
    safeInteger(metadata.gid, `${label} gid`, effectStatus) !== gid ||
    Number(metadata.mode & 0o7777n) !== exactMode
  ) {
    throw new BrokerClientError(`${label} metadata is unsafe`, effectStatus);
  }
  return {
    device: safeInteger(metadata.dev, `${label} device`, effectStatus),
    inode: safeInteger(metadata.ino, `${label} inode`, effectStatus),
  };
}

function sensorSocketIdentity(path, config, effectStatus = "NOT_SUBMITTED") {
  let metadata;
  try {
    metadata = lstatSync(path, { bigint: true });
  } catch (error) {
    throw new BrokerClientError(`sensor socket is unavailable: ${error.code || error.message}`, effectStatus);
  }
  if (
    !metadata.isSocket() ||
    safeInteger(metadata.uid, "sensor socket uid", effectStatus) !== config.expectedSensorUid ||
    safeInteger(metadata.gid, "sensor socket gid", effectStatus) !== config.expectedRuntimeGid ||
    Number(metadata.mode & 0o7777n) !== 0o660 ||
    safeInteger(metadata.nlink, "sensor socket link count", effectStatus) !== 1
  ) {
    throw new BrokerClientError("sensor socket metadata is unsafe", effectStatus);
  }
  return [
    safeInteger(metadata.dev, "sensor socket device", effectStatus),
    safeInteger(metadata.ino, "sensor socket inode", effectStatus),
    safeInteger(metadata.uid, "sensor socket uid", effectStatus),
    safeInteger(metadata.gid, "sensor socket gid", effectStatus),
    Number(metadata.mode),
    safeInteger(metadata.ctimeNs, "sensor socket change time", effectStatus),
  ];
}

function sameIdentity(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function requireAbsentTarget(protectedRoot, targetName, effectStatus) {
  try {
    lstatSync(join(protectedRoot, targetName));
  } catch (error) {
    if (error && error.code === "ENOENT") return;
    throw new BrokerClientError(`cannot inspect protected target: ${error.code || error.message}`, effectStatus);
  }
  throw new BrokerClientError("protected target already exists", effectStatus);
}

function requireCreatedTarget(config, targetName, payloadSize) {
  let metadata;
  try {
    metadata = lstatSync(join(config.protectedRoot, targetName), { bigint: true });
  } catch (error) {
    throw new BrokerClientError(`created target is unavailable: ${error.code || error.message}`, "INDETERMINATE");
  }
  if (
    !metadata.isFile() ||
    safeInteger(metadata.uid, "created target uid", "INDETERMINATE") !== config.expectedBrokerUid ||
    safeInteger(metadata.gid, "created target gid", "INDETERMINATE") !== config.expectedRuntimeGid ||
    Number(metadata.mode & 0o7777n) !== 0o400 ||
    safeInteger(metadata.nlink, "created target link count", "INDETERMINATE") !== 1 ||
    safeInteger(metadata.size, "created target size", "INDETERMINATE") !== payloadSize
  ) {
    throw new BrokerClientError("created target metadata is unsafe", "INDETERMINATE");
  }
}

function buildEnvelope(config, context, targetName, payload, rootIdentity, nowUnix) {
  if (typeof targetName !== "string" || !TARGET_NAME.test(targetName)) {
    throw new BrokerClientError("target name is invalid", "NOT_SUBMITTED");
  }
  if (!Buffer.isBuffer(payload) || payload.length > MAX_PAYLOAD_BYTES) {
    throw new BrokerClientError("payload is invalid", "NOT_SUBMITTED");
  }
  requireUnsignedInteger(nowUnix, "request time");
  const action = {
    operation_digest: sha256(Buffer.from(canonicalJson({ operation: "create", schema: "aragorn/runtime-file-operation/v1" }), "ascii")),
    path_digest: sha256(Buffer.from(canonicalJson({
      root_device: rootIdentity.device,
      root_inode: rootIdentity.inode,
      schema: "aragorn/runtime-protected-path/v1",
      target_name: targetName,
    }), "ascii")),
    payload_digest: sha256(payload),
  };
  return {
    schema: "aragorn/runtime-action-broker-request/v1",
    request: {
      schema: "aragorn/runtime-action-request/v1",
      authority: "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
      runtime_digest: config.runtimeDigest,
      session_id: requireIdentifier(context.sessionId, "session id"),
      run_id: requireIdentifier(context.runId, "run id"),
      tool_call_id: requireIdentifier(context.toolCallId, "tool call id"),
      active_skill_digest: config.activeSkillDigest,
      ...action,
      policy_digest: config.policyDigest,
      policy_version: config.policyVersion,
      issued_at_unix: nowUnix,
      expires_at_unix: nowUnix + 5,
    },
    effect: {
      schema: "aragorn/runtime-create-file/v1",
      operation: "create",
      target_name: targetName,
      payload_base64: payload.toString("base64"),
    },
  };
}

function effectParameters(value) {
  const fields = ["content", "target_name", ...Object.values(CONTEXT_FIELDS)].sort();
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort()) !== canonicalJson(fields) ||
    typeof value.content !== "string" ||
    typeof value.target_name !== "string" ||
    !TARGET_NAME.test(value.target_name)
  ) {
    throw new BrokerClientError("runtime create parameters are invalid", "NOT_SUBMITTED");
  }
  return value;
}

function parseBrokerResponse(raw, envelope) {
  let text;
  let result;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    result = JSON.parse(text);
  } catch (error) {
    throw new BrokerClientError(`broker response is invalid: ${error.message}`, "INDETERMINATE");
  }
  if (canonicalJson(result) !== text) {
    throw new BrokerClientError("broker response is not canonical JSON", "INDETERMINATE");
  }
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
  if (!result || typeof result !== "object" || Array.isArray(result) || canonicalJson(Object.keys(result).sort()) !== canonicalJson(fields)) {
    throw new BrokerClientError("broker response fields are invalid", "INDETERMINATE");
  }
  const expectedRequestDigest = sha256(Buffer.from(canonicalJson(envelope.request), "ascii"));
  if (
    result.schema !== "aragorn/runtime-action-broker-result/v1" ||
    result.authority !== "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY" ||
    result.request_digest !== expectedRequestDigest ||
    result.target_name !== envelope.effect.target_name ||
    !DIGEST.test(result.observation_digest) ||
    !Array.isArray(result.reason_codes) ||
    result.reason_codes.some((reason) => typeof reason !== "string")
  ) {
    throw new BrokerClientError("broker response binding is invalid", "INDETERMINATE");
  }
  const allowed =
    result.verdict === "ALLOW" &&
    result.effect_status === "CREATED" &&
    result.reason_codes.length === 0 &&
    result.decision &&
    result.decision.verdict === "ALLOW";
  const blocked =
    result.verdict === "BLOCK" &&
    result.effect_status === "NOT_PERFORMED" &&
    result.reason_codes.length > 0;
  if (!allowed && !blocked) {
    throw new BrokerClientError("broker response outcome is inconsistent", "INDETERMINATE");
  }
  return result;
}

function requestBroker(socketPath, envelope, signal) {
  const body = Buffer.from(canonicalJson(envelope), "ascii");
  if (body.length === 0 || body.length > MAX_FRAME_BYTES) {
    throw new BrokerClientError("broker request exceeds its frame limit", "NOT_SUBMITTED");
  }
  if (signal?.aborted) {
    throw new BrokerClientError("broker request was aborted", "NOT_SUBMITTED");
  }
  const frame = Buffer.allocUnsafe(4 + body.length);
  frame.writeUInt32BE(body.length, 0);
  body.copy(frame, 4);

  return new Promise((resolve, reject) => {
    const socket = createConnection({ path: socketPath });
    const chunks = [];
    let received = 0;
    let submitted = false;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    const fail = (message) => finish(new BrokerClientError(message, submitted ? "INDETERMINATE" : "NOT_SUBMITTED"));
    const abort = () => fail("broker request was aborted");
    const timer = setTimeout(() => fail("broker request timed out"), REQUEST_TIMEOUT_MS);
    timer.unref();
    signal?.addEventListener("abort", abort, { once: true });
    socket.once("connect", () => {
      if (settled) return;
      submitted = true;
      socket.end(frame);
    });
    socket.on("data", (chunk) => {
      if (settled) return;
      received += chunk.length;
      if (received > MAX_FRAME_BYTES + 4) {
        fail("broker response exceeds its frame limit");
        return;
      }
      chunks.push(chunk);
    });
    socket.once("error", (error) => fail(`broker transport failed: ${error.code || error.message}`));
    socket.once("end", () => {
      if (settled) return;
      const response = Buffer.concat(chunks, received);
      if (response.length < 4) {
        fail("broker response ended early");
        return;
      }
      const length = response.readUInt32BE(0);
      if (length === 0 || length > MAX_FRAME_BYTES || response.length !== length + 4) {
        fail("broker response framing is invalid");
        return;
      }
      try {
        finish(null, parseBrokerResponse(response.subarray(4), envelope));
      } catch (error) {
        finish(
          error instanceof BrokerClientError
            ? error
            : new BrokerClientError(`broker response validation failed: ${error.message}`, "INDETERMINATE"),
        );
      }
    });
    socket.once("close", () => {
      if (!settled) fail("broker response closed without an exact EOF");
    });
  });
}

function toolResult(result) {
  return {
    content: [{ type: "text", text: `Aragorn ${result.verdict}: ${result.effect_status}` }],
    details: result,
    isError: result.verdict !== "ALLOW",
  };
}

function clientErrorResult(error) {
  const effectStatus = error instanceof BrokerClientError ? error.effectStatus : "NOT_SUBMITTED";
  return {
    content: [{ type: "text", text: `Aragorn runtime action failed closed: ${effectStatus}` }],
    details: {
      schema: "aragorn/runtime-action-client-error/v1",
      authority: "CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
      effect_status: effectStatus,
      message: error instanceof Error ? error.message : String(error),
    },
    isError: true,
  };
}

function register(api) {
  const config = normalizedConfig(api.pluginConfig);

  api.registerTool(
    (toolContext) => ({
      name: TOOL_NAME,
      label: "Aragorn Runtime Create",
      description: "Create one policy-authorized file through the Aragorn runtime broker.",
      parameters: {
        type: "object",
        additionalProperties: false,
        required: ["content", "target_name"],
        properties: {
          content: { type: "string", maxLength: MAX_PAYLOAD_BYTES },
          target_name: { type: "string", pattern: TARGET_NAME.source, maxLength: 128 },
        },
      },
      prepareBeforeToolCallParams: (params, { toolCallId, hookContext }) => {
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
          [CONTEXT_FIELDS.toolCallIdDigest]: opaqueStringDigest(toolCallId, "tool call id"),
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
          [CONTEXT_FIELDS.toolCallIdDigest]: prepared[CONTEXT_FIELDS.toolCallIdDigest],
        };
      },
      execute: async (toolCallId, params, signal) => {
        try {
          requireRuntimeIdentity(config);
          const bound = effectParameters(params);
          const sessionId = requireIdentifier(toolContext.sessionId, "session id");
          const sessionKeyDigest = opaqueStringDigest(toolContext.sessionKey, "session key");
          const correlation = {
            runId: requireIdentifier(bound[CONTEXT_FIELDS.runId], "run id"),
            sessionId: requireIdentifier(bound[CONTEXT_FIELDS.sessionId], "session id"),
            sessionKeyDigest: requireDigest(
              bound[CONTEXT_FIELDS.sessionKeyDigest],
              "session key digest",
            ),
            toolCallId: requireDigest(
              bound[CONTEXT_FIELDS.toolCallIdDigest],
              "tool call id digest",
            ),
          };
          if (
            correlation.sessionId !== sessionId ||
            correlation.sessionKeyDigest !== sessionKeyDigest ||
            correlation.toolCallId !== opaqueStringDigest(toolCallId, "tool call id")
          ) {
            throw new BrokerClientError("OpenClaw tool call is unattributed", "NOT_SUBMITTED");
          }
          const sensorRuntimeDirectory = dirname(config.sensorSocketPath);
          directoryIdentity(
            sensorRuntimeDirectory,
            config.expectedSensorUid,
            config.expectedRuntimeGid,
            0o750,
            "sensor runtime directory",
          );
          const rootIdentity = directoryIdentity(
            config.protectedRoot,
            config.expectedBrokerUid,
            config.expectedRuntimeGid,
            0o710,
            "protected root",
          );
          const beforeSocket = sensorSocketIdentity(config.sensorSocketPath, config);
          const targetName = bound.target_name;
          const payload = Buffer.from(bound.content, "utf8");
          const nowUnix = Math.floor(Date.now() / 1000);
          const envelope = buildEnvelope(config, correlation, targetName, payload, rootIdentity, nowUnix);
          requireAbsentTarget(config.protectedRoot, targetName, "NOT_SUBMITTED");
          const result = await requestBroker(config.sensorSocketPath, envelope, signal);
          const afterRoot = directoryIdentity(
            config.protectedRoot,
            config.expectedBrokerUid,
            config.expectedRuntimeGid,
            0o710,
            "protected root",
            "INDETERMINATE",
          );
          if (
            rootIdentity.device !== afterRoot.device ||
            rootIdentity.inode !== afterRoot.inode ||
            !sameIdentity(
              beforeSocket,
              sensorSocketIdentity(config.sensorSocketPath, config, "INDETERMINATE"),
            )
          ) {
            throw new BrokerClientError("sensor socket changed during the request", "INDETERMINATE");
          }
          if (result.verdict === "BLOCK") {
            requireAbsentTarget(config.protectedRoot, targetName, "INDETERMINATE");
          } else {
            requireCreatedTarget(config, targetName, payload.length);
          }
          return toolResult(result);
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
  name: "Aragorn Runtime Action",
  register,
  __testing: Object.freeze({ buildEnvelope, canonicalJson, parseBrokerResponse, requestBroker, sha256 }),
};
