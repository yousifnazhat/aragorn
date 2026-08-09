#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { createServer } from "node:http";
import { dirname, isAbsolute, resolve } from "node:path";

const INPUT_SCHEMA = "aragorn/openclaw-worker-driver-input/v1";
const OUTPUT_SCHEMA = "aragorn/openclaw-worker-driver-output/v1";
const RELAY_SUMMARY_SCHEMA = "aragorn/openclaw-worker-driver-relay-summary/v1";
const OPENCLAW_DETAILS_SCHEMA = "aragorn/runtime-action-worker-openclaw-details/v1";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const NODE = "/usr/local/bin/node";
const CONFIG = "/etc/aragorn/agent-gateway/openclaw.json";
const STATE = "/var/lib/aragorn-agent-gateway/state";
const HOME = "/var/lib/aragorn-agent-gateway/home";
const WORKSPACE = "/var/lib/aragorn-agent-gateway/workspace";
const MODEL = "fixture-model";
const PROVIDER_PORT = 18080;
const TOOL_NAME = "aragorn_runtime_create";
const NODE_DIGEST = "sha256:3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37";
const OPENCLAW_DIGEST = "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188";
const MAX_COMMAND_BYTES = 16 * 1024 * 1024;
const MAX_PROVIDER_BYTES = 4 * 1024 * 1024;
const MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const SCENARIO_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const TARGET = /^[a-z0-9][a-z0-9._-]{0,127}$/;
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
const BROKER_RESULT_FIELDS = Object.freeze([
  "authority",
  "decision",
  "effect_status",
  "observation_digest",
  "reason_codes",
  "request_digest",
  "schema",
  "target_name",
  "verdict",
]);
const TOOL_CONTRACT = Object.freeze({
  function: {
    description: "Request one policy-mediated file creation through the Aragorn runtime action worker.",
    name: TOOL_NAME,
    parameters: {
      additionalProperties: false,
      properties: {
        content: { maxLength: 32768, type: "string" },
        target_name: {
          maxLength: 128,
          pattern: "^[a-z0-9][a-z0-9._-]{0,127}$",
          type: "string",
        },
      },
      required: ["content", "target_name"],
      type: "object",
    },
  },
  type: "function",
});

function canonicalString(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function canonicalJson(value, path = "$") {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return canonicalString(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError(`invalid number at ${path}`);
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => canonicalJson(item, `${path}[${index}]`)).join(",")}]`;
  }
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${canonicalString(key)}:${canonicalJson(value[key], `${path}.${key}`)}`)
      .join(",")}}`;
  }
  throw new TypeError(`invalid canonical JSON value at ${path}`);
}

function sha256(raw) {
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

function deterministicToolCallId(scenarioId) {
  const digest = createHash("sha256").update(Buffer.from(scenarioId, "utf8")).digest("hex");
  const value = `aragorn${digest.slice(0, 32)}`;
  expect(/^[A-Za-z0-9]+$/.test(value) && value.length <= 40, "tool call id is not replay-stable");
  return value;
}

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, keys, label) {
  expect(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort()),
    `${label} fields changed`,
  );
}

function absolutePath(value, label) {
  expect(
    typeof value === "string" &&
      isAbsolute(value) &&
      !value.includes("\0") &&
      resolve(value) === value,
    `${label} is invalid`,
  );
  return value;
}

function requiredSecret(name) {
  const value = process.env[name];
  expect(
    typeof value === "string" &&
      value.length > 0 &&
      Buffer.byteLength(value) <= 4096 &&
      !/[\0\r\n]/.test(value),
    `${name} is unavailable`,
  );
  return value;
}

function readInput(path) {
  absolutePath(path, "input path");
  const stat = lstatSync(path);
  expect(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1, "input is not one regular file");
  const raw = readFileSync(path);
  const input = JSON.parse(raw.toString("utf8"));
  expect(raw.equals(Buffer.from(`${canonicalJson(input)}\n`, "ascii")), "input is not canonical JSON");
  exactKeys(input, ["scenario", "schema"], "input");
  expect(input.schema === INPUT_SCHEMA, "input schema changed");
  exactKeys(input.scenario, ["content", "expected_result", "id", "target_name"], "scenario");
  const scenario = input.scenario;
  expect(SCENARIO_ID.test(scenario.id), "scenario id is invalid");
  expect(TARGET.test(scenario.target_name), "target name is invalid");
  expect(
    typeof scenario.content === "string" && Buffer.byteLength(scenario.content) <= 32768,
    "content is invalid",
  );
  exactKeys(scenario.expected_result, ["broker_result", "schema", "status"], "expected result");
  const expected = scenario.expected_result;
  expect(
    ["COMPLETED", "NOT_SUBMITTED", "INDETERMINATE"].includes(expected.status),
    "expected relay status is invalid",
  );
  expect(
    [
      "aragorn/runtime-action-worker-result/v1",
      "aragorn/runtime-action-worker-client-error/v1",
    ].includes(expected.schema),
    "expected relay schema is invalid",
  );
  expect(
    expected.schema !== "aragorn/runtime-action-worker-client-error/v1" ||
      expected.status !== "COMPLETED",
    "client error cannot be completed",
  );
  if (expected.status === "COMPLETED") {
    exactKeys(expected.broker_result, ["effect_status", "verdict"], "expected broker result");
    expect(
      ["ALLOW/CREATED", "BLOCK/NOT_PERFORMED"].includes(
        `${expected.broker_result.verdict}/${expected.broker_result.effect_status}`,
      ),
      "expected broker outcome is invalid",
    );
  } else {
    expect(expected.broker_result === null, "non-completed expected result has a broker result");
  }
  return input;
}

function commandEnvironment(gatewayToken) {
  return {
    HOME,
    LANG: "C",
    LC_ALL: "C",
    NO_COLOR: "1",
    NO_PROXY: "127.0.0.1,localhost",
    OPENCLAW_CONFIG_PATH: CONFIG,
    OPENCLAW_GATEWAY_TOKEN: gatewayToken,
    OPENCLAW_STATE_DIR: STATE,
    PATH: "/usr/local/bin:/usr/bin:/bin",
    TZ: "UTC",
  };
}

function runCommand(args, environment, timeoutMs = 10000) {
  return new Promise((resolvePromise) => {
    const startedAt = new Date().toISOString();
    const child = spawn(NODE, [OPENCLAW, ...args], {
      cwd: WORKSPACE,
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let error = null;
    const append = (chunks, chunk, bytes) => {
      if (bytes + chunk.length > MAX_COMMAND_BYTES) {
        error = "command output exceeded its limit";
        child.kill("SIGKILL");
        return bytes;
      }
      chunks.push(chunk);
      return bytes + chunk.length;
    };
    child.stdout.on("data", (chunk) => {
      stdoutBytes = append(stdout, chunk, stdoutBytes);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes = append(stderr, chunk, stderrBytes);
    });
    child.once("error", (cause) => {
      error = cause.message;
    });
    const timer = setTimeout(() => {
      error = `command timed out after ${timeoutMs} ms`;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      resolvePromise({
        completed_at: new Date().toISOString(),
        error,
        exit_code: exitCode,
        pid: child.pid ?? null,
        signal,
        started_at: startedAt,
        stderr: Buffer.concat(stderr, stderrBytes).toString("utf8"),
        stdout: Buffer.concat(stdout, stdoutBytes).toString("utf8"),
      });
    });
  });
}

function commandSummary(result) {
  return {
    completed_at: result.completed_at,
    error: result.error === null ? null : "COMMAND_ERROR",
    exit_code: result.exit_code,
    pid: result.pid,
    signal: result.signal,
    started_at: result.started_at,
    stderr_bytes: Buffer.byteLength(result.stderr),
    stdout_bytes: Buffer.byteLength(result.stdout),
  };
}

function parseCommand(result, label) {
  expect(result.exit_code === 0 && result.error === null, `${label} failed`);
  for (const output of [result.stdout, result.stderr]) {
    try {
      return JSON.parse(output);
    } catch {
      // OpenClaw may place service-control JSON on either stream.
    }
  }
  throw new Error(`${label} did not return JSON`);
}

function gatewayCall(method, environment, params = null, timeoutMs = 5000) {
  const args = ["gateway", "call", method, "--json", "--timeout", String(timeoutMs)];
  if (params !== null) args.push("--params", canonicalJson(params));
  return runCommand(args, environment, timeoutMs + 5000);
}

async function waitForGateway(environment) {
  const deadline = Date.now() + 30000;
  let last = null;
  while (Date.now() < deadline) {
    last = await gatewayCall("system.info", environment);
    if (last.exit_code === 0 && last.error === null) {
      const response = parseCommand(last, "system.info");
      if (Number.isSafeInteger(response.pid) && response.pid > 0) {
        return { command: commandSummary(last), response };
      }
    }
    // Readiness polling never repeats an action submission.
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
  }
  throw new Error("gateway did not become ready");
}

function sse(response, chunks) {
  response.writeHead(200, {
    "cache-control": "no-cache",
    connection: "keep-alive",
    "content-type": "text/event-stream; charset=utf-8",
  });
  for (const chunk of chunks) response.write(`data: ${canonicalJson(chunk)}\n\n`);
  response.end("data: [DONE]\n\n");
}

function providerResponse(sequence, scenario, toolCallId) {
  const common = { created: 0, model: MODEL, object: "chat.completion.chunk" };
  if (sequence === 1) {
    return [
      {
        ...common,
        choices: [
          {
            delta: {
              role: "assistant",
              tool_calls: [
                {
                  function: {
                    arguments: canonicalJson({
                      content: scenario.content,
                      target_name: scenario.target_name,
                    }),
                    name: TOOL_NAME,
                  },
                  id: toolCallId,
                  index: 0,
                  type: "function",
                },
              ],
            },
            finish_reason: "tool_calls",
            index: 0,
          },
        ],
        id: `chatcmpl-${scenario.id}-tool`,
      },
    ];
  }
  return [
    {
      ...common,
      choices: [{ delta: { content: "ARAGORN_RUNTIME_ACTION_WORKER_DONE", role: "assistant" }, finish_reason: null, index: 0 }],
      id: `chatcmpl-${scenario.id}-final`,
    },
    {
      ...common,
      choices: [{ delta: {}, finish_reason: "stop", index: 0 }],
      id: `chatcmpl-${scenario.id}-final`,
      usage: { completion_tokens: 1, prompt_tokens: 1, total_tokens: 2 },
    },
  ];
}

async function readRequest(request) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    expect(bytes <= MAX_PROVIDER_BYTES, "provider request exceeded its limit");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, bytes);
}

function providerEnvelope(body, label) {
  exactKeys(body, ["max_tokens", "messages", "model", "stream", "tool_choice", "tools"], label);
  expect(
    body.model === MODEL &&
      body.stream === true &&
      body.tool_choice === "auto" &&
      body.max_tokens === 256 &&
      Array.isArray(body.messages) &&
      Array.isArray(body.tools),
    `${label} envelope changed`,
  );
  const contracts = body.tools.filter((tool) => tool?.function?.name === TOOL_NAME);
  expect(
    contracts.length === 1 && canonicalJson(contracts[0]) === canonicalJson(TOOL_CONTRACT),
    `${label} Aragorn tool contract changed`,
  );
  return sha256(Buffer.from(canonicalJson(body.tools), "ascii"));
}

function expectedSourceOutcome(result, expected) {
  if (result?.schema !== expected.schema || result.status !== expected.status) return false;
  if (expected.status !== "COMPLETED") {
    return expected.schema === "aragorn/runtime-action-worker-client-error/v1"
      ? !Object.hasOwn(result, "broker_result")
      : result.broker_result === null;
  }
  return (
    result.broker_result?.verdict === expected.broker_result.verdict &&
    result.broker_result?.effect_status === expected.broker_result.effect_status
  );
}

function providerToolResult(raw, expected) {
  const retained = JSON.parse(raw);
  expect(canonicalJson(retained) === raw, "provider tool result is not canonical JSON");
  exactKeys(retained, ["message", "result", "schema"], "provider tool result");
  expect(
    retained.schema === "aragorn/runtime-action-worker-tool-result-text/v1" &&
      typeof retained.message === "string" &&
      Buffer.byteLength(retained.message) <= 512 &&
      expectedSourceOutcome(retained.result, expected),
    "provider tool result outcome changed",
  );
  return sha256(Buffer.from(canonicalJson(sanitizedRelaySummary(retained.result)), "ascii"));
}

function providerRequestProof(body, sequence, scenario, toolCallId, state) {
  const toolContractDigest = providerEnvelope(body, `provider request ${sequence}`);
  if (sequence === 1) {
    expect(body.messages.length === 2, "first provider message count changed");
    const [system, user] = body.messages;
    exactKeys(system, ["content", "role"], "first provider system message");
    exactKeys(user, ["content", "role"], "first provider user message");
    const prompt = `Invoke ${TOOL_NAME} exactly once for bounded scenario ${scenario.id}.`;
    expect(
      system.role === "system" &&
        typeof system.content === "string" &&
        system.content.length > 0 &&
        user.role === "user" &&
        typeof user.content === "string" &&
        user.content.endsWith(prompt) &&
        /^\[[A-Z][a-z]{2} \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\] $/.test(
          user.content.slice(0, -prompt.length),
        ),
      "first provider messages changed",
    );
    const messagePrefixDigest = sha256(Buffer.from(canonicalJson(body.messages), "ascii"));
    state.message_count = body.messages.length;
    state.message_prefix_digest = messagePrefixDigest;
    state.tool_contract_digest = toolContractDigest;
    return {
      message_prefix_continuity_valid: null,
      tool_contract_valid: true,
      tool_result_summary_digest: null,
    };
  }

  expect(
    sequence === 2 &&
      state.message_count === 2 &&
      state.tool_contract_digest === toolContractDigest &&
      body.messages.length === state.message_count + 2,
    "second provider request continuity changed",
  );
  const prefix = body.messages.slice(0, state.message_count);
  const assistant = body.messages[state.message_count];
  const tool = body.messages[state.message_count + 1];
  const transportToolCallId = toolCallId;
  const expectedArguments = canonicalJson({
    content: scenario.content,
    target_name: scenario.target_name,
  });
  expect(
    sha256(Buffer.from(canonicalJson(prefix), "ascii")) === state.message_prefix_digest,
    "provider message prefix changed between requests",
  );
  exactKeys(assistant, ["content", "role", "tool_calls"], "provider transport assistant");
  expect(
    assistant.content === null &&
      assistant.role === "assistant" &&
      Array.isArray(assistant.tool_calls) &&
      assistant.tool_calls.length === 1,
    "provider transport assistant changed",
  );
  const call = assistant.tool_calls[0];
  exactKeys(call, ["function", "id", "type"], "provider transport tool call");
  exactKeys(call.function, ["arguments", "name"], "provider transport tool function");
  expect(
    call.id === transportToolCallId &&
      call.type === "function" &&
      call.function.name === TOOL_NAME &&
      call.function.arguments === expectedArguments,
    "provider transport tool call changed",
  );
  exactKeys(tool, ["content", "role", "tool_call_id"], "provider transport tool result");
  expect(
    tool.role === "tool" &&
      tool.tool_call_id === transportToolCallId &&
      typeof tool.content === "string",
    "provider transport tool result correlation changed",
  );
  return {
    message_prefix_continuity_valid: true,
    tool_contract_valid: true,
    tool_result_summary_digest: providerToolResult(tool.content, scenario.expected_result),
  };
}

async function startProvider(scenario, toolCallId, providerToken) {
  const records = [];
  const errors = [];
  const state = {};
  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/v1/models") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(
          canonicalJson({
            data: [{ created: 0, id: MODEL, object: "model", owned_by: "aragorn" }],
            object: "list",
          }),
        );
        return;
      }
      expect(request.method === "POST" && request.url === "/v1/chat/completions", "unexpected provider route");
      expect(request.headers.authorization === `Bearer ${providerToken}`, "provider authorization changed");
      expect(request.headers["content-type"] === "application/json", "provider content type changed");
      const raw = await readRequest(request);
      const body = JSON.parse(raw.toString("utf8"));
      const sequence = records.length + 1;
      expect(sequence <= 2, "provider received more than two model requests");
      const proof = providerRequestProof(body, sequence, scenario, toolCallId, state);
      const emitted = providerResponse(sequence, scenario, toolCallId);
      records.push({
        authorization_valid: true,
        contract_valid: true,
        content_type: request.headers["content-type"] ?? null,
        emitted_tool_call_id: sequence === 1 ? toolCallId : null,
        message_prefix_continuity_valid: proof.message_prefix_continuity_valid,
        method: request.method,
        path: request.url,
        received_at: new Date().toISOString(),
        request_bytes: raw.length,
        sequence,
        tool_contract_valid: proof.tool_contract_valid,
        tool_result_summary_digest: proof.tool_result_summary_digest,
      });
      sse(response, emitted);
    } catch (cause) {
      errors.push(cause instanceof Error ? cause.message : String(cause));
      response.writeHead(500, { "content-type": "application/json" });
      response.end(canonicalJson({ error: "provider request rejected" }));
    }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  await new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen(PROVIDER_PORT, "127.0.0.1", resolvePromise);
  });
  return {
    errors,
    records,
    close: () => new Promise((resolvePromise) => server.close(resolvePromise)),
  };
}

function validReasonCodes(value) {
  return (
    Array.isArray(value) &&
    value.length <= 128 &&
    value.every((reason) => typeof reason === "string" && REASON_CODE.test(reason)) &&
    canonicalJson(value) === canonicalJson([...new Set(value)].sort())
  );
}

function safeInteger(value, label, positive = false) {
  expect(Number.isSafeInteger(value) && value >= (positive ? 1 : 0), `${label} is invalid`);
}

function validateDecision(decision, brokerResult) {
  exactKeys(decision, DECISION_FIELDS, "worker decision");
  expect(
    decision.schema === "aragorn/runtime-action-decision/v1" &&
      decision.authority === "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY" &&
      decision.request_digest === brokerResult.request_digest &&
      DIGEST.test(decision.request_digest) &&
      DIGEST.test(decision.policy_digest) &&
      DIGEST.test(decision.revocation_snapshot_digest) &&
      DIGEST.test(decision.mediator_health_digest) &&
      validReasonCodes(decision.reason_codes) &&
      ["ALLOW", "BLOCK"].includes(decision.verdict),
    "worker decision binding is invalid",
  );
  safeInteger(decision.policy_version, "worker decision policy version", true);
  for (const field of [
    "evaluated_at_unix",
    "revocation_generation",
    "minimum_revocation_generation",
    "mediator_health_epoch",
    "minimum_mediator_health_epoch",
  ]) {
    safeInteger(decision[field], `worker decision ${field}`);
  }
  const invalidRequest = decision.reason_codes.includes("ACTION_REQUEST_INVALID");
  for (const [field, missingReason] of [
    ["active_context_digest", "ACTION_UNATTRIBUTED"],
    ["measured_action_digest", "ACTION_UNMEASURED"],
  ]) {
    const missing = decision[field] === null;
    expect(
      !(
        (missing && !invalidRequest && !decision.reason_codes.includes(missingReason)) ||
        (!missing && (typeof decision[field] !== "string" || !DIGEST.test(decision[field]))) ||
        (!missing && decision.reason_codes.includes(missingReason))
      ),
      "worker decision context is inconsistent",
    );
  }
  expect(
    (decision.verdict === "ALLOW") === (decision.reason_codes.length === 0) &&
      (decision.verdict !== "ALLOW" ||
        (decision.active_context_digest !== null && decision.measured_action_digest !== null)),
    "worker decision outcome is inconsistent",
  );
}

function validateBrokerResult(result, request) {
  expect(
    new Set(BROKER_RESULT_FIELDS).size === BROKER_RESULT_FIELDS.length,
    "worker broker result contract contains duplicate fields",
  );
  exactKeys(result, BROKER_RESULT_FIELDS, "worker broker result");
  expect(
    result.schema === "aragorn/runtime-action-broker-result/v1" &&
      result.authority === "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY" &&
      DIGEST.test(result.request_digest) &&
      DIGEST.test(result.observation_digest) &&
      result.target_name === request.target_name &&
      validReasonCodes(result.reason_codes) &&
      (result.decision === null ||
        (result.decision && typeof result.decision === "object" && !Array.isArray(result.decision))),
    "worker broker result binding is invalid",
  );
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
  expect(allowed || blocked, "worker broker result outcome is inconsistent");
}

function workerRequest(scenario, sessionId, runId, toolCallId) {
  return {
    authority: "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
    payload_base64: Buffer.from(scenario.content, "utf8").toString("base64"),
    run_id: runId,
    schema: "aragorn/runtime-action-worker-request/v1",
    session_id: sessionId,
    target_name: scenario.target_name,
    tool_call_digest: sha256(Buffer.from(toolCallId, "utf8")),
  };
}

function textContent(message) {
  return (message?.content ?? [])
    .filter((part) => part.type === "text")
    .map((part) => part.text)
    .join("");
}

function transcriptToolResult(sessionId, rpcToolResult) {
  exactKeys(
    rpcToolResult,
    ["__openclaw", "content", "isError", "role", "timestamp", "toolCallId", "toolName"],
    "RPC tool result",
  );
  expect(
    rpcToolResult.__openclaw &&
      typeof rpcToolResult.__openclaw === "object" &&
      !Array.isArray(rpcToolResult.__openclaw) &&
      rpcToolResult.role === "toolResult" &&
      rpcToolResult.toolName === TOOL_NAME &&
      typeof rpcToolResult.isError === "boolean" &&
      !Object.hasOwn(rpcToolResult, "details"),
    "RPC tool result shape changed",
  );
  const path = resolve(STATE, "agents", "main", "sessions", `${sessionId}.jsonl`);
  expect(
    path.startsWith(`${resolve(STATE, "agents", "main", "sessions")}/`),
    "session transcript path escaped its root",
  );
  const before = lstatSync(path);
  expect(
    before.isFile() &&
      !before.isSymbolicLink() &&
      before.nlink === 1 &&
      before.size > 0 &&
      before.size <= MAX_TRANSCRIPT_BYTES,
    "session transcript is not one bounded regular file",
  );
  const raw = readFileSync(path);
  const after = lstatSync(path);
  expect(
    after.isFile() &&
      !after.isSymbolicLink() &&
      after.nlink === 1 &&
      after.dev === before.dev &&
      after.ino === before.ino &&
      after.size === before.size &&
      after.mtimeMs === before.mtimeMs &&
      raw.length === before.size,
    "session transcript changed during its read",
  );
  const text = raw.toString("utf8");
  expect(Buffer.from(text, "utf8").equals(raw), "session transcript is not UTF-8");
  const lines = text.split("\n");
  expect(lines.pop() === "" && lines.length > 0, "session transcript is not exact JSONL");
  const matches = lines
    .map((line) => JSON.parse(line))
    .filter(
      (record) =>
        record &&
        typeof record === "object" &&
        !Array.isArray(record) &&
        record.type === "message" &&
        record.message &&
        typeof record.message === "object" &&
        !Array.isArray(record.message) &&
        record.message.role === "toolResult" &&
        record.message.toolName === TOOL_NAME &&
        record.message.toolCallId === rpcToolResult.toolCallId,
    )
    .map((record) => record.message);
  expect(matches.length === 1, "session transcript does not contain one exact Aragorn tool result");
  const [message] = matches;
  exactKeys(
    message,
    ["content", "details", "isError", "role", "timestamp", "toolCallId", "toolName"],
    "transcript tool result",
  );
  expect(
    canonicalJson(message.content) === canonicalJson(rpcToolResult.content) &&
      message.toolCallId === rpcToolResult.toolCallId &&
      message.isError === rpcToolResult.isError,
    "transcript and RPC tool results diverged",
  );
  return {
    checks: {
      exact_rpc_history_shape_without_details: true,
      exact_transcript_rpc_tool_result_join: true,
      transcript_regular_nonsymlink_bounded: true,
    },
    message,
  };
}

function sanitizedRelaySummary(result) {
  const broker = result.broker_result;
  return {
    broker_result:
      broker === null || broker === undefined
        ? null
        : {
            effect_status: broker.effect_status,
            reason_codes: broker.reason_codes,
            source_authority: broker.authority,
            source_schema: broker.schema,
            target_name: broker.target_name,
            verdict: broker.verdict,
          },
    request_digest: result.request_digest ?? null,
    schema: RELAY_SUMMARY_SCHEMA,
    source_authority: result.authority,
    source_schema: result.schema,
    status: result.status,
  };
}

function expectedOpenClawDetailsStatus(result) {
  if (
    result.schema === "aragorn/runtime-action-worker-result/v1" &&
    result.status === "COMPLETED"
  ) {
    return result.broker_result.verdict === "ALLOW" &&
      result.broker_result.effect_status === "CREATED"
      ? "completed"
      : "blocked";
  }
  return "error";
}

function validateOpenClawDetails(toolResult, sourceResult) {
  const details = toolResult.details;
  exactKeys(details, ["schema", "source_result", "status"], "OpenClaw worker details adapter");
  const checks = {
    exact_transcript_details_schema_and_status:
      details.schema === OPENCLAW_DETAILS_SCHEMA &&
      ["blocked", "completed", "error"].includes(details.status) &&
      details.status === expectedOpenClawDetailsStatus(sourceResult),
    transcript_details_source_result_matches_public_content:
      canonicalJson(details.source_result) === canonicalJson(sourceResult),
  };
  expect(Object.values(checks).every(Boolean), "OpenClaw worker details adapter changed");
  return checks;
}

function relaySummary(rpcToolResult, transcriptResult, request) {
  const text = textContent(rpcToolResult);
  const retained = JSON.parse(text);
  expect(canonicalJson(retained) === text, "retained tool result is not canonical JSON");
  exactKeys(retained, ["message", "result", "schema"], "retained tool result");
  expect(
    retained.schema === "aragorn/runtime-action-worker-tool-result-text/v1" &&
      typeof retained.message === "string" &&
      Buffer.byteLength(retained.message) <= 512,
    "retained tool result envelope is invalid",
  );
  const result = retained.result;
  if (result?.schema === "aragorn/runtime-action-worker-result/v1") {
    exactKeys(result, ["authority", "broker_result", "request_digest", "schema", "status"], "worker result");
    const requestDigest = sha256(Buffer.from(canonicalJson(request), "ascii"));
    expect(
      result.authority === "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY" &&
        result.request_digest === requestDigest &&
        ["COMPLETED", "NOT_SUBMITTED", "INDETERMINATE"].includes(result.status),
      "worker result binding is invalid",
    );
    if (result.status === "COMPLETED") validateBrokerResult(result.broker_result, request);
    else expect(result.broker_result === null, "non-completed worker result has a broker result");
    return {
      details_checks: validateOpenClawDetails(transcriptResult, result),
      observed: sanitizedRelaySummary(result),
    };
  }
  exactKeys(result, ["authority", "message", "schema", "status"], "worker client error");
  expect(
    result.schema === "aragorn/runtime-action-worker-client-error/v1" &&
      result.authority === "GATEWAY_CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY" &&
      ["NOT_SUBMITTED", "INDETERMINATE"].includes(result.status) &&
      typeof result.message === "string" &&
      result.message.length > 0 &&
      Buffer.byteLength(result.message) <= 4096,
    "worker client error is invalid",
  );
  return {
    details_checks: validateOpenClawDetails(transcriptResult, result),
    observed: sanitizedRelaySummary(result),
  };
}

function expectedOutcome(observed, expected) {
  if (
    observed.schema !== RELAY_SUMMARY_SCHEMA ||
    observed.source_schema !== expected.schema ||
    observed.status !== expected.status
  ) {
    return false;
  }
  if (expected.status !== "COMPLETED") return observed.broker_result === null;
  return (
    observed.broker_result?.verdict === expected.broker_result.verdict &&
    observed.broker_result?.effect_status === expected.broker_result.effect_status
  );
}

function publish(path, document) {
  absolutePath(path, "output path");
  const raw = Buffer.from(canonicalJson(document), "ascii");
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  let descriptor = -1;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    let offset = 0;
    while (offset < raw.length) offset += writeSync(descriptor, raw, offset);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = -1;
    linkSync(temporary, path);
    unlinkSync(temporary);
    const directory = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY);
    try {
      fsyncSync(directory);
    } finally {
      closeSync(directory);
    }
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
    try {
      unlinkSync(temporary);
    } catch (cause) {
      if (!(cause && typeof cause === "object" && cause.code === "ENOENT")) throw cause;
    }
  }
}

async function main() {
  expect(process.argv.length === 4, "usage: openclaw-worker-driver.mjs INPUT.json OUTPUT.json");
  expect(process.version === "v24.16.0", "Node version changed");
  expect(sha256(readFileSync(NODE)) === NODE_DIGEST, "Node executable changed");
  expect(sha256(readFileSync(OPENCLAW)) === OPENCLAW_DIGEST, "OpenClaw entrypoint changed");
  const input = readInput(process.argv[2]);
  const scenario = input.scenario;
  const environment = commandEnvironment(requiredSecret("OPENCLAW_GATEWAY_TOKEN"));
  const providerToken = requiredSecret("ARAGORN_MOCK_PROVIDER_TOKEN");
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  const toolCallId = deterministicToolCallId(scenario.id);
  const sessionKey = `agent:main:aragorn-worker-${scenario.id}`;
  const provider = await startProvider(scenario, toolCallId, providerToken);
  let result;
  try {
    const gateway = await waitForGateway(environment);
    const sendCommand = await gatewayCall(
      "chat.send",
      environment,
      {
        deliver: false,
        idempotencyKey: `aragorn-worker-${scenario.id}`,
        message: `Invoke ${TOOL_NAME} exactly once for bounded scenario ${scenario.id}.`,
        sessionKey,
        timeoutMs: 10000,
      },
    );
    const sendResponse = parseCommand(sendCommand, "chat.send");
    exactKeys(sendResponse, ["runId", "status"], "chat.send response");
    expect(
      IDENTIFIER.test(sendResponse.runId) && sendResponse.status === "started",
      "gateway did not start one exact run",
    );
    const waitCommand = await gatewayCall(
      "agent.wait",
      environment,
      { runId: sendResponse.runId, timeoutMs: 15000 },
      17000,
    );
    const waitResponse = parseCommand(waitCommand, "agent.wait");
    exactKeys(waitResponse, ["endedAt", "runId", "status"], "agent.wait response");
    expect(
      waitResponse.runId === sendResponse.runId &&
        waitResponse.status === "ok" &&
        Number.isSafeInteger(waitResponse.endedAt) &&
        waitResponse.endedAt > 0,
      "gateway run did not finish exactly once",
    );
    const historyCommand = await gatewayCall(
      "chat.history",
      environment,
      { limit: 20, sessionKey },
    );
    const historyResponse = parseCommand(historyCommand, "chat.history");
    await provider.close();

    expect(IDENTIFIER.test(historyResponse.sessionId), "gateway session id is invalid");
    expect(Array.isArray(historyResponse.messages), "gateway history messages changed");
    const toolResults = historyResponse.messages.filter(
      (message) => message.role === "toolResult" && message.toolName === TOOL_NAME,
    );
    expect(toolResults.length === 1, "gateway history does not contain one exact Aragorn tool result");
    const [toolResult] = toolResults;
    const transcript = transcriptToolResult(historyResponse.sessionId, toolResult);
    const request = workerRequest(
      scenario,
      historyResponse.sessionId,
      sendResponse.runId,
      toolCallId,
    );
    const relay = relaySummary(toolResult, transcript.message, request);
    const observed = relay.observed;
    const checks = {
      ...transcript.checks,
      ...relay.details_checks,
      exact_gateway_session_key: historyResponse.sessionKey === sessionKey,
      exact_tool_call_id_identity: toolResult?.toolCallId === toolCallId,
      exact_wait_run_id: waitResponse.runId === sendResponse.runId,
      exact_worker_request_digest:
        (observed.source_schema === "aragorn/runtime-action-worker-client-error/v1"
          ? observed.request_digest === null
          : observed.source_schema === "aragorn/runtime-action-worker-result/v1" &&
            observed.request_digest === sha256(Buffer.from(canonicalJson(request), "ascii"))),
      expected_nested_relay_outcome: expectedOutcome(observed, scenario.expected_result),
      gateway_pid_present: Number.isSafeInteger(gateway.response.pid) && gateway.response.pid > 0,
      one_provider_driven_tool_call:
        provider.records.length === 2 &&
        provider.records.every((record) => record.contract_valid === true) &&
        provider.records.every((record) => record.tool_contract_valid === true) &&
        provider.records[0].message_prefix_continuity_valid === null &&
        provider.records[1].message_prefix_continuity_valid === true &&
        provider.records[0].tool_result_summary_digest === null &&
        provider.records[1].tool_result_summary_digest ===
          sha256(Buffer.from(canonicalJson(observed), "ascii")) &&
        provider.records[0].emitted_tool_call_id === toolCallId &&
        provider.records[1].emitted_tool_call_id === null,
      exact_openclaw_history_error_classification:
        toolResult.isError === (transcript.message.details.status !== "completed"),
      provider_completed_without_error: provider.errors.length === 0,
    };
    const passed = Object.values(checks).every(Boolean);
    const completed = Date.now();
    result = {
      gateway: {
        system_info: {
          command: gateway.command,
          response: { pid: gateway.response.pid },
        },
      },
      provider: {
        error_count: provider.errors.length,
        records: provider.records,
        request_count: provider.records.length,
      },
      scenario: {
        proof: {
          checks,
          expected: scenario.expected_result,
          observed,
        },
        status: passed ? "PASS" : "FAIL",
      },
      schema: OUTPUT_SCHEMA,
      timing: {
        completed_at: new Date(completed).toISOString(),
        elapsed_ms: completed - started,
        started_at: startedAt,
      },
      turn: {
        history: {
          command: commandSummary(historyCommand),
          message_count: Array.isArray(historyResponse.messages) ? historyResponse.messages.length : null,
          session_id: historyResponse.sessionId,
        },
        identifiers: {
          request_digest: observed.request_digest ?? null,
          run_id: sendResponse.runId,
          session_id: historyResponse.sessionId,
          tool_call_digest: request.tool_call_digest,
          tool_call_id: toolCallId,
        },
        send: { command: commandSummary(sendCommand), run_id: sendResponse.runId },
        wait: {
          command: commandSummary(waitCommand),
          run_id: waitResponse.runId ?? null,
          status: waitResponse.status ?? null,
        },
      },
    };
    publish(process.argv[3], result);
    if (!passed) process.exitCode = 1;
  } finally {
    if (result === undefined) await provider.close();
  }
}

main().catch((cause) => {
  process.stderr.write(`${cause instanceof Error ? cause.stack : String(cause)}\n`);
  process.exitCode = 1;
});
