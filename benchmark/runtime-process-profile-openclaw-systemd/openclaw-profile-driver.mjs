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

const INPUT_SCHEMA = "aragorn/openclaw-profile-driver-input/v1";
const OUTPUT_SCHEMA = "aragorn/openclaw-profile-driver-output/v1";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const NODE = "/usr/local/bin/node";
const CONFIG = "/etc/aragorn/openclaw-profile/openclaw.json";
const STATE = "/var/lib/aragorn-openclaw-profile/state";
const HOME = "/var/lib/aragorn-openclaw-profile/home";
const WORKSPACE = "/var/lib/aragorn-openclaw-profile/workspace";
const PROVIDER = "aragorn-runtime-action-mock";
const MODEL = "fixture-model";
const PROVIDER_PORT = 18080;
const TOOL_NAME = "aragorn_runtime_create";
const MAX_COMMAND_BYTES = 16 * 1024 * 1024;
const MAX_PROVIDER_BYTES = 4 * 1024 * 1024;
const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const TARGET = /^[a-z0-9][a-z0-9._-]{0,127}$/;

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

function readInput(path) {
  absolutePath(path, "input path");
  const stat = lstatSync(path);
  expect(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1, "input is not one regular file");
  const raw = readFileSync(path);
  const input = JSON.parse(raw.toString("utf8"));
  expect(raw.equals(Buffer.from(`${canonicalJson(input)}\n`, "ascii")), "input is not canonical JSON");
  exactKeys(input, ["scenario", "schema"], "input");
  expect(input.schema === INPUT_SCHEMA, "input schema changed");
  exactKeys(
    input.scenario,
    ["content", "expected_effect_status", "expected_verdict", "id", "target_name"],
    "scenario",
  );
  const scenario = input.scenario;
  expect(IDENTIFIER.test(scenario.id), "scenario id is invalid");
  expect(TARGET.test(scenario.target_name), "target name is invalid");
  expect(typeof scenario.content === "string" && Buffer.byteLength(scenario.content) <= 32768, "content is invalid");
  expect(
    ["ALLOW/CREATED", "BLOCK/NOT_PERFORMED", "CLIENT_ERROR/NOT_SUBMITTED"].includes(
      `${scenario.expected_verdict}/${scenario.expected_effect_status}`,
    ),
    "expected outcome is invalid",
  );
  return input;
}

const commandEnvironment = {
  ...process.env,
  HOME,
  LANG: "C",
  LC_ALL: "C",
  NO_COLOR: "1",
  NO_PROXY: "127.0.0.1,localhost",
  OPENCLAW_CONFIG_PATH: CONFIG,
  OPENCLAW_GATEWAY_TOKEN: "aragorn-p34b-gateway-token-v1",
  OPENCLAW_STATE_DIR: STATE,
  PATH: "/usr/local/bin:/usr/bin:/bin",
  TZ: "UTC",
};

function runCommand(args, timeoutMs = 10000) {
  return new Promise((resolvePromise) => {
    const startedAt = new Date().toISOString();
    const child = spawn(NODE, [OPENCLAW, ...args], {
      cwd: WORKSPACE,
      env: commandEnvironment,
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
        argv: [NODE, OPENCLAW, ...args],
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
    argv: result.argv,
    completed_at: result.completed_at,
    error: result.error,
    exit_code: result.exit_code,
    pid: result.pid,
    signal: result.signal,
    started_at: result.started_at,
    stderr_bytes: Buffer.byteLength(result.stderr),
    stderr_digest: sha256(Buffer.from(result.stderr)),
    stdout_bytes: Buffer.byteLength(result.stdout),
    stdout_digest: sha256(Buffer.from(result.stdout)),
  };
}

function parseCommand(result, label) {
  expect(result.exit_code === 0 && result.error === null, `${label} failed: ${result.stderr.trim()}`);
  for (const output of [result.stdout, result.stderr]) {
    try {
      return JSON.parse(output);
    } catch {
      // OpenClaw may place service-control JSON on either stream.
    }
  }
  throw new Error(`${label} did not return JSON`);
}

function gatewayCall(method, params = null, timeoutMs = 5000) {
  const args = ["gateway", "call", method, "--json", "--timeout", String(timeoutMs)];
  if (params !== null) args.push("--params", canonicalJson(params));
  return runCommand(args, timeoutMs + 5000);
}

async function waitForGateway() {
  const deadline = Date.now() + 30000;
  let last = null;
  while (Date.now() < deadline) {
    last = await gatewayCall("system.info");
    if (last.exit_code === 0 && last.error === null) {
      const response = parseCommand(last, "system.info");
      if (Number.isSafeInteger(response.pid) && response.pid > 0) {
        return { command: commandSummary(last), response };
      }
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
  }
  throw new Error(`gateway did not become ready: ${last?.stderr.trim() ?? "no response"}`);
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
  const finalText = `ARAGORN_RUNTIME_ACTION_${scenario.expected_verdict}_${scenario.expected_effect_status}`;
  return [
    {
      ...common,
      choices: [{ delta: { content: finalText, role: "assistant" }, finish_reason: null, index: 0 }],
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

async function startProvider(scenario, toolCallId) {
  const records = [];
  const errors = [];
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
      expect(
        request.headers.authorization === "Bearer aragorn-runtime-action-mock-local",
        "provider authorization changed",
      );
      const raw = await readRequest(request);
      const body = JSON.parse(raw.toString("utf8"));
      const sequence = records.length + 1;
      expect(sequence <= 2, "provider received more than two model requests");
      const emitted = providerResponse(sequence, scenario, toolCallId);
      records.push({
        authorization_digest: sha256(Buffer.from(request.headers.authorization)),
        body,
        body_bytes: raw.length,
        body_digest: sha256(raw),
        body_raw: raw.toString("utf8"),
        content_type: request.headers["content-type"] ?? null,
        method: request.method,
        path: request.url,
        received_at: new Date().toISOString(),
        response: emitted,
        response_digest: sha256(Buffer.from(canonicalJson(emitted), "ascii")),
        sequence,
      });
      sse(response, emitted);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      errors.push(message);
      response.writeHead(500, { "content-type": "application/json" });
      response.end(canonicalJson({ error: message }));
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

function textContent(message) {
  return (message?.content ?? [])
    .filter((part) => part.type === "text")
    .map((part) => part.text)
    .join("");
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
  expect(process.argv.length === 4, "usage: openclaw-profile-driver.mjs INPUT.json OUTPUT.json");
  const input = readInput(process.argv[2]);
  const scenario = input.scenario;
  const started = Date.now();
  const startedAt = new Date(started).toISOString();
  const toolCallId = `call_aragorn_p34b_${scenario.id.replaceAll("-", "_")}_1`;
  const sessionKey = `agent:main:aragorn-p34b-${scenario.id}`;
  const provider = await startProvider(scenario, toolCallId);
  let result;
  try {
    const gateway = await waitForGateway();
    const sendCommand = await gatewayCall("chat.send", {
      deliver: false,
      idempotencyKey: `aragorn-p34b-${scenario.id}`,
      message: `Invoke ${TOOL_NAME} exactly once for bounded scenario ${scenario.id}.`,
      sessionKey,
      timeoutMs: 10000,
    });
    const sendResponse = parseCommand(sendCommand, "chat.send");
    const waitCommand = await gatewayCall(
      "agent.wait",
      { runId: sendResponse.runId, timeoutMs: 15000 },
      17000,
    );
    const waitResponse = parseCommand(waitCommand, "agent.wait");
    const historyCommand = await gatewayCall("chat.history", { limit: 20, sessionKey });
    const historyResponse = parseCommand(historyCommand, "chat.history");
    await provider.close();

    const toolResult = (historyResponse.messages ?? []).find(
      (message) => message.role === "toolResult" && message.toolName === TOOL_NAME,
    );
    let retainedToolResult = null;
    try {
      retainedToolResult = JSON.parse(textContent(toolResult));
    } catch {
      retainedToolResult = null;
    }
    const providerCall = provider.records[0]?.response?.[0]?.choices?.[0]?.delta?.tool_calls?.[0];
    const expectedArguments = canonicalJson({
      content: scenario.content,
      target_name: scenario.target_name,
    });
    const checks = {
      action_result_bound:
        retainedToolResult?.result?.verdict === scenario.expected_verdict &&
        retainedToolResult?.result?.effect_status === scenario.expected_effect_status &&
        retainedToolResult?.result?.target_name === scenario.target_name,
      gateway_pid_present: Number.isSafeInteger(gateway.response.pid) && gateway.response.pid > 0,
      history_lineage:
        toolResult?.toolCallId === toolCallId &&
        historyResponse.sessionKey === sessionKey &&
        waitResponse.runId === sendResponse.runId,
      one_provider_driven_tool_call:
        provider.records.length === 2 &&
        providerCall?.id === toolCallId &&
        providerCall?.function?.name === TOOL_NAME &&
        providerCall?.function?.arguments === expectedArguments,
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
        errors: provider.errors,
        records: provider.records,
        request_count: provider.records.length,
      },
      scenario: {
        proof: { checks, passed, retained_tool_result: retainedToolResult },
        status: passed ? "PASS" : "FAIL",
      },
      schema: OUTPUT_SCHEMA,
      timing: {
        completed_at: new Date(completed).toISOString(),
        elapsed_ms: completed - started,
        started_at: startedAt,
      },
      turn: {
        history: { command: commandSummary(historyCommand), response: historyResponse },
        identifiers: {
          run_id: sendResponse.runId ?? null,
          session_id: historyResponse.sessionId ?? null,
          session_key: sessionKey,
          tool_call_id: toolCallId,
        },
        send: { command: commandSummary(sendCommand), response: sendResponse },
        wait: { command: commandSummary(waitCommand), response: waitResponse },
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
