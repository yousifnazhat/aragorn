#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { basename, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/profile/config/openclaw.json";
const STATE = "/profile/state";
const WORKSPACE = "/profile/workspace";
const HOME = "/profile/home";
const NAME = "aragorn-admitted";
const TARGET = join(STATE, "skills", NAME);
const TARGET_FILE = join(TARGET, "SKILL.md");
const REQUEST_LOG = join(STATE, "model-activation-requests.jsonl");
const EVIDENCE_FILE = "/output/model-activation-evidence.json";
const SESSION_STORE = join(STATE, "agents", "main", "sessions", "sessions.json");
const SESSION_KEY = "agent:main:aragorn-model-activation-v1";
const TEST_TOKEN = "aragorn-contained-model-activation-token-v1";
const MOCK_KEY = "aragorn-mock-local";
const MODEL = "fixture-model";
const PROVIDER = "aragorn-mock";
const TOOL_CALL_ID = "call_aragorn_read_1";
const TRANSPORT_TOOL_CALL_ID = "callaragornread1";
const FINAL_TEXT = "ARAGORN_EXACT_ACTIVATION_OK";
const EXPECTED_VERSION = "OpenClaw 2026.7.1 (2d2ddc4)";
const EXPECTED_RUNTIME_TREE =
  "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c";
const SELF = fileURLToPath(import.meta.url);
const SKILL = [
  "---",
  `name: ${NAME}`,
  "description: Inert contained-profile fixture.",
  "---",
  "# Aragorn admitted fixture",
  "",
].join("\n");
const PROFILE_ENV = {
  HOME,
  OPENCLAW_CONFIG_PATH: CONFIG,
  OPENCLAW_GATEWAY_TOKEN: TEST_TOKEN,
  OPENCLAW_STATE_DIR: STATE,
  PATH: "/usr/local/bin:/usr/bin:/bin",
};

function sha256(raw) {
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function configuration() {
  return {
    agents: {
      defaults: {
        model: { primary: `${PROVIDER}/${MODEL}` },
        skills: [NAME],
        workspace: WORKSPACE,
      },
      list: [{ id: "main", skills: [NAME], workspace: WORKSPACE }],
    },
    models: {
      mode: "replace",
      providers: {
        [PROVIDER]: {
          api: "openai-completions",
          apiKey: MOCK_KEY,
          baseUrl: "http://127.0.0.1:18080/v1",
          localService: {
            args: ["/probe/model-activation-probe.mjs", "provider"],
            command: NODE,
            healthUrl: "http://127.0.0.1:18080/v1/models",
            idleStopMs: 0,
            readyTimeoutMs: 5000,
          },
          models: [
            {
              compat: {
                maxTokensField: "max_tokens",
                supportsDeveloperRole: false,
                supportsStore: false,
                supportsStrictMode: false,
                supportsTools: true,
                supportsUsageInStreaming: false,
              },
              contextWindow: 200000,
              cost: {
                cacheRead: 0,
                cacheWrite: 0,
                input: 0,
                output: 0,
              },
              id: MODEL,
              input: ["text"],
              maxTokens: 256,
              name: "Aragorn deterministic mock",
              reasoning: false,
            },
          ],
          timeoutSeconds: 10,
        },
      },
    },
    plugins: { enabled: false },
    skills: {
      load: {
        allowSymlinkTargets: [],
        extraDirs: [],
        watch: false,
      },
    },
  };
}

function prepare() {
  const roots = {
    admitted: "/prepare/admitted",
    config: "/prepare/config",
    guard: "/prepare/guard",
  };
  for (const path of Object.values(roots)) {
    mkdirSync(path, { recursive: true });
  }
  const admitted = join(roots.admitted, NAME);
  mkdirSync(admitted, { mode: 0o755 });
  writeFileSync(join(admitted, "SKILL.md"), SKILL, {
    flag: "wx",
    mode: 0o444,
  });
  const config = configuration();
  writeFileSync(
    join(roots.config, "openclaw.json"),
    `${canonicalJson(config)}\n`,
    { flag: "wx", mode: 0o444 },
  );
  for (const path of [admitted, ...Object.values(roots), "/prepare"]) {
    chmodSync(path, 0o555);
  }
  process.stdout.write(
    `${canonicalJson({
      admitted_digest: sha256(Buffer.from(SKILL)),
      configuration_digest: sha256(
        Buffer.from(canonicalJson(config), "ascii"),
      ),
      implementation_digest: sha256(readFileSync(SELF)),
      schema: "aragorn/openclaw-model-activation-preparation/v1",
    })}\n`,
  );
}

function sse(res, chunks) {
  res.writeHead(200, {
    "cache-control": "no-cache",
    connection: "keep-alive",
    "content-type": "text/event-stream; charset=utf-8",
  });
  for (const chunk of chunks) {
    res.write(`data: ${canonicalJson(chunk)}\n\n`);
  }
  res.end("data: [DONE]\n\n");
}

function providerResponse(sequence) {
  const common = {
    created: 0,
    model: MODEL,
    object: "chat.completion.chunk",
  };
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
                    arguments: canonicalJson({ path: TARGET_FILE }),
                    name: "read",
                  },
                  id: TOOL_CALL_ID,
                  index: 0,
                  type: "function",
                },
              ],
            },
            finish_reason: "tool_calls",
            index: 0,
          },
        ],
        id: "chatcmpl-aragorn-read-1",
      },
    ];
  }
  return [
    {
      ...common,
      choices: [
        {
          delta: { content: FINAL_TEXT, role: "assistant" },
          finish_reason: null,
          index: 0,
        },
      ],
      id: "chatcmpl-aragorn-final-1",
    },
    {
      ...common,
      choices: [{ delta: {}, finish_reason: "stop", index: 0 }],
      id: "chatcmpl-aragorn-final-1",
      usage: { completion_tokens: 1, prompt_tokens: 1, total_tokens: 2 },
    },
  ];
}

async function readRequest(req) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 4 * 1024 * 1024) {
      throw new Error("provider request exceeded 4 MiB");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function provider() {
  if (existsSync(REQUEST_LOG)) {
    throw new Error("provider request log already exists");
  }
  let sequence = 0;
  const server = createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/v1/models") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          canonicalJson({
            data: [
              { created: 0, id: MODEL, object: "model", owned_by: "aragorn" },
            ],
            object: "list",
          }),
        );
        return;
      }
      if (req.method !== "POST" || req.url !== "/v1/chat/completions") {
        res.writeHead(404).end();
        return;
      }
      const raw = await readRequest(req);
      const body = JSON.parse(raw.toString("utf8"));
      sequence += 1;
      if (sequence > 2) {
        throw new Error("provider received more than two model requests");
      }
      const authorization = req.headers.authorization;
      if (typeof authorization !== "string") {
        throw new Error("provider request lacked authorization");
      }
      const response = providerResponse(sequence);
      appendFileSync(
        REQUEST_LOG,
        `${canonicalJson({
          authorization_digest: sha256(Buffer.from(authorization)),
          body,
          body_bytes: raw.length,
          body_digest: sha256(raw),
          body_raw: raw.toString("utf8"),
          content_type: req.headers["content-type"],
          method: req.method,
          path: req.url,
          received_at: new Date().toISOString(),
          response,
          response_digest: sha256(
            Buffer.from(canonicalJson(response), "ascii"),
          ),
          sequence,
        })}\n`,
        { encoding: "utf8", mode: 0o600 },
      );
      sse(res, response);
    } catch (error) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(
        canonicalJson({
          error: error instanceof Error ? error.message : String(error),
        }),
      );
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(18080, "127.0.0.1", resolve);
  });
}

function command(args, timeout = 20_000) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(NODE, [OPENCLAW, ...args], {
    cwd: WORKSPACE,
    encoding: "utf8",
    env: PROFILE_ENV,
    maxBuffer: 16 * 1024 * 1024,
    timeout,
  });
  return {
    argv: [NODE, OPENCLAW, ...args],
    completed_at: new Date().toISOString(),
    error: result.error?.message ?? null,
    exit_code: result.status,
    pid: result.pid,
    signal: result.signal,
    started_at: startedAt,
    stderr: result.stderr ?? "",
    stdout: result.stdout ?? "",
  };
}

function summarized(result) {
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
  if (result.exit_code !== 0) {
    throw new Error(`${label} failed: ${result.stderr.trim()}`);
  }
  for (const output of [result.stdout, result.stderr]) {
    try {
      return JSON.parse(output);
    } catch {
      // Gateway service-control JSON may use either stream.
    }
  }
  throw new Error(`${label} did not return JSON`);
}

function gatewayCall(method, params = null, timeout = 5000) {
  const args = ["gateway", "call", method, "--json", "--timeout", String(timeout)];
  if (params !== null) {
    args.push("--params", canonicalJson(params));
  }
  return command(args, timeout + 5000);
}

async function waitForGateway() {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const call = gatewayCall("system.info");
    if (call.exit_code === 0) {
      const info = parseCommand(call, "system.info");
      if (info.pid === 1) {
        return { command: summarized(call), info };
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error("timed out waiting for the contained Gateway");
}

function processIdentity() {
  const raw = readFileSync("/proc/1/stat", "utf8").trim();
  const fields = raw.slice(raw.lastIndexOf(")") + 2).split(" ");
  return {
    cmdline: readFileSync("/proc/1/cmdline")
      .toString("utf8")
      .split("\0")
      .filter(Boolean),
    pid: 1,
    start_time_ticks: fields[19],
  };
}

function targetSnapshot() {
  const entries = [];
  const visit = (path) => {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
      throw new Error(`unsafe admitted fixture entry: ${path}`);
    }
    const entry = {
      mode: (stat.mode & 0o777).toString(8).padStart(3, "0"),
      path: relative(TARGET, path) || ".",
      realpath: realpathSync(path),
      size: stat.size,
      type: stat.isDirectory() ? "directory" : "file",
    };
    if (stat.isFile()) {
      entry.digest = sha256(readFileSync(path));
      entry.links = stat.nlink;
    }
    entries.push(entry);
    if (stat.isDirectory()) {
      for (const name of readdirSync(path).sort()) {
        visit(join(path, name));
      }
    }
  };
  visit(TARGET);
  return entries;
}

function runtimeTree(root = "/runtime") {
  const entries = [];
  let totalBytes = 0;
  let fileCount = 0;
  let symlinkCount = 0;
  const walk = (directory, parts = []) => {
    for (const name of readdirSync(directory).sort()) {
      if (entries.length >= 100_000 || !/^[\x00-\x7f]+$/.test(name)) {
        throw new Error("runtime inventory limit or path invariant failed");
      }
      const pathParts = [...parts, name];
      const path = pathParts.join("/");
      const absolute = join(directory, name);
      const stat = lstatSync(absolute);
      if (stat.isDirectory()) {
        walk(absolute, pathParts);
      } else if (stat.isSymbolicLink()) {
        const target = readlinkSync(absolute);
        if (!/^[\x00-\x7f]+$/.test(target)) {
          throw new Error(`non-ASCII runtime symlink: ${path}`);
        }
        entries.push({ kind: "symlink", path, target });
        symlinkCount += 1;
      } else if (stat.isFile() && stat.size <= 128 * 1024 * 1024) {
        const raw = readFileSync(absolute);
        totalBytes += raw.length;
        if (totalBytes > 1024 * 1024 * 1024) {
          throw new Error("runtime inventory exceeded 1 GiB");
        }
        entries.push({
          digest: sha256(raw),
          executable: Boolean(stat.mode & 0o111),
          kind: "file",
          links: stat.nlink,
          path,
          size: raw.length,
        });
        fileCount += 1;
      } else {
        throw new Error(`unsupported runtime entry: ${path}`);
      }
    }
  };
  walk(root);
  return {
    algorithm: "aragorn/runtime-tree/v1",
    entry_count: entries.length,
    file_count: fileCount,
    symlink_count: symlinkCount,
    total_bytes: totalBytes,
    tree_digest: sha256(Buffer.from(canonicalJson(entries), "ascii")),
  };
}

function writeGuard() {
  try {
    writeFileSync(TARGET_FILE, "must-not-write", { flag: "a" });
    return { blocked: false, code: null };
  } catch (error) {
    return {
      blocked: true,
      code:
        error && typeof error === "object" && "code" in error
          ? String(error.code)
          : null,
    };
  }
}

function gatewayLog() {
  const dir = "/tmp/openclaw";
  const names = readdirSync(dir).filter((name) => name.endsWith(".log")).sort();
  if (names.length !== 1) {
    throw new Error(`expected one Gateway log, found ${names.length}`);
  }
  const path = join(dir, names[0]);
  const raw = readFileSync(path);
  if (raw.includes(TEST_TOKEN) || raw.includes(MOCK_KEY)) {
    throw new Error("Gateway log contains a contained test credential");
  }
  const messages = raw
    .toString("utf8")
    .split("\n")
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [JSON.parse(line).message ?? ""];
      } catch {
        return [];
      }
    });
  return {
    bytes: raw.length,
    digest: sha256(raw),
    path: basename(path),
    ready_count: messages.filter((message) => message === "gateway ready").length,
    restart_count: messages.filter((message) =>
      /SIGUSR1.*restart|restarting|restart mode:/i.test(message),
    ).length,
  };
}

function readProviderRecords() {
  const raw = readFileSync(REQUEST_LOG, "utf8");
  const lines = raw.split("\n");
  if (lines.pop() !== "") {
    throw new Error("provider request log lacks a trailing newline");
  }
  return lines.map((line) => {
    const parsed = JSON.parse(line);
    if (canonicalJson(parsed) !== line) {
      throw new Error("provider request record is not canonical");
    }
    return parsed;
  });
}

function systemPrompt(body) {
  return body.messages
    .filter((message) => message.role === "system")
    .map((message) => message.content)
    .join("\n");
}

function exactProviderProof(records) {
  if (records.length !== 2) {
    return false;
  }
  const [first, second] = records;
  const prompt = systemPrompt(first.body);
  const skillStart = prompt.lastIndexOf("<available_skills>");
  const skillEnd = prompt.indexOf("</available_skills>", skillStart);
  const skillBlock =
    skillStart >= 0 && skillEnd > skillStart
      ? prompt.slice(skillStart, skillEnd + "</available_skills>".length)
      : null;
  const readTool = first.body.tools?.find(
    (tool) => tool.function?.name === "read",
  );
  const assistants = second.body.messages.filter(
    (message) =>
      message.role === "assistant" &&
      message.tool_calls?.some(
        (call) =>
          call.id === TRANSPORT_TOOL_CALL_ID &&
          call.function?.name === "read" &&
          call.function?.arguments === canonicalJson({ path: TARGET_FILE }),
      ),
  );
  const tools = second.body.messages.filter(
    (message) =>
      message.role === "tool" &&
      message.tool_call_id === TRANSPORT_TOOL_CALL_ID,
  );
  const assistant = assistants[0];
  const tool = tools[0];
  const assistantIndex = second.body.messages.indexOf(assistant);
  const toolIndex = second.body.messages.indexOf(tool);
  return (
    first.sequence === 1 &&
    second.sequence === 2 &&
    first.body.model === MODEL &&
    second.body.model === MODEL &&
    first.authorization_digest === sha256(Buffer.from(`Bearer ${MOCK_KEY}`)) &&
    second.authorization_digest === first.authorization_digest &&
    typeof skillBlock === "string" &&
    (skillBlock.match(/<skill>/g) ?? []).length === 1 &&
    skillBlock.includes(`<name>${NAME}</name>`) &&
    skillBlock.includes(
      "<description>Inert contained-profile fixture.</description>",
    ) &&
    skillBlock.includes(`<location>${TARGET_FILE}</location>`) &&
    skillBlock.includes("<version>sha256:5a951f65ad92bc20</version>") &&
    readTool?.function?.parameters?.properties?.path !== undefined &&
    first.body.messages.every(
      (message) => !["assistant", "tool"].includes(message.role),
    ) &&
    assistants.length === 1 &&
    tools.length === 1 &&
    assistant.tool_calls.length === 1 &&
    assistantIndex === first.body.messages.length &&
    toolIndex === assistantIndex + 1 &&
    canonicalJson(second.body.messages.slice(0, assistantIndex)) ===
      canonicalJson(first.body.messages) &&
    tool?.content === SKILL
  );
}

function exactHistoryProof(history, send) {
  const messages = history.messages ?? [];
  const [user, assistant, tool, final] = messages;
  return (
    send.runId === "aragorn-model-activation-v1" &&
    canonicalJson(messages.map((message) => message.role)) ===
      '["user","assistant","toolResult","assistant"]' &&
    user.content ===
      "Read the admitted Aragorn skill file, then return the fixed result." &&
    user.idempotencyKey === "aragorn-model-activation-v1:user" &&
    canonicalJson(assistant.content) ===
      canonicalJson([
        {
          arguments: { path: TARGET_FILE },
          id: TOOL_CALL_ID,
          name: "read",
          partialArgs: canonicalJson({ path: TARGET_FILE }),
          type: "toolCall",
        },
      ]) &&
    assistant.stopReason === "toolUse" &&
    tool.toolCallId === TOOL_CALL_ID &&
    tool.toolName === "read" &&
    tool.isError === false &&
    canonicalJson(tool.content) ===
      canonicalJson([{ text: SKILL, type: "text" }]) &&
    final.provider === PROVIDER &&
    final.model === MODEL &&
    final.stopReason === "stop" &&
    canonicalJson(final.content) ===
      canonicalJson([{ text: FINAL_TEXT, type: "text" }]) &&
    history.sessionKey === SESSION_KEY &&
    history.sessionInfo?.key === SESSION_KEY &&
    history.sessionInfo?.status === "done" &&
    history.sessionInfo?.model === MODEL &&
    history.sessionInfo?.modelProvider === PROVIDER &&
    canonicalJson(history.sessionInfo?.activeRunIds) === "[]"
  );
}

async function runProbe() {
  if (process.env.OPENCLAW_GATEWAY_TOKEN !== TEST_TOKEN) {
    throw new Error("unexpected contained Gateway test credential");
  }
  if (existsSync(REQUEST_LOG)) {
    throw new Error("provider request log was not empty at probe start");
  }
  const config = configuration();
  const configRaw = readFileSync(CONFIG);
  if (!configRaw.equals(Buffer.from(`${canonicalJson(config)}\n`))) {
    throw new Error("model-activation configuration changed");
  }
  const targetBefore = targetSnapshot();
  if (
    canonicalJson(targetBefore.map((entry) => entry.path)) !==
      '[".","SKILL.md"]' ||
    targetBefore[0].mode !== "555" ||
    targetBefore[1].mode !== "444" ||
    targetBefore[1].links !== 1 ||
    targetBefore[1].digest !== sha256(Buffer.from(SKILL))
  ) {
    throw new Error("admitted fixture identity changed");
  }
  const runtime = runtimeTree();
  if (runtime.tree_digest !== EXPECTED_RUNTIME_TREE) {
    throw new Error(`runtime tree changed: ${runtime.tree_digest}`);
  }
  const guard = writeGuard();
  if (!guard.blocked || !["EACCES", "EROFS"].includes(guard.code)) {
    throw new Error("admitted fixture write guard failed");
  }
  const version = command(["--version"]);
  if (version.exit_code !== 0 || version.stdout.trim() !== EXPECTED_VERSION) {
    throw new Error(`unexpected OpenClaw version: ${version.stdout.trim()}`);
  }
  const gateway = await waitForGateway();
  const sessionStoreAbsentBefore = !existsSync(SESSION_STORE);
  if (!sessionStoreAbsentBefore) {
    throw new Error("model-activation session store was not empty");
  }
  const processBefore = processIdentity();
  const logBefore = gatewayLog();
  const idempotencyKey = "aragorn-model-activation-v1";
  const sendCommand = gatewayCall("chat.send", {
    deliver: false,
    idempotencyKey,
    message: "Read the admitted Aragorn skill file, then return the fixed result.",
    sessionKey: SESSION_KEY,
    timeoutMs: 10_000,
  });
  const send = parseCommand(sendCommand, "chat.send");
  const waitCommand = gatewayCall(
    "agent.wait",
    { runId: send.runId, timeoutMs: 15_000 },
    17_000,
  );
  const wait = parseCommand(waitCommand, "agent.wait");
  const historyCommand = gatewayCall("chat.history", {
    limit: 20,
    sessionKey: SESSION_KEY,
  });
  const history = parseCommand(historyCommand, "chat.history");
  const records = readProviderRecords();
  const targetAfter = targetSnapshot();
  const processAfter = processIdentity();
  const logAfter = gatewayLog();
  const passed =
    send.status === "started" &&
    typeof send.runId === "string" &&
    wait.status === "ok" &&
    Number.isSafeInteger(wait.endedAt) &&
    canonicalJson(targetAfter) === canonicalJson(targetBefore) &&
    canonicalJson(processAfter) === canonicalJson(processBefore) &&
    logBefore.ready_count === 1 &&
    logAfter.ready_count === 1 &&
    logBefore.restart_count === 0 &&
    logAfter.restart_count === 0 &&
    exactProviderProof(records) &&
    exactHistoryProof(history, send);
  return {
    adapter: {
      configuration: config,
      configuration_digest: sha256(
        Buffer.from(canonicalJson(config), "ascii"),
      ),
      implementation_digest: sha256(readFileSync(SELF)),
    },
    decision: {
      installer_work_eligible: false,
      status: passed ? "NOT_TESTED" : "FAIL",
    },
    gateway: {
      log_after: logAfter,
      log_before: logBefore,
      process_after: processAfter,
      process_before: processBefore,
      readiness_command: gateway.command,
      system_info: {
        arch: gateway.info.arch,
        node_version: gateway.info.nodeVersion,
        pid: gateway.info.pid,
        platform: gateway.info.platform,
        port: gateway.info.port,
      },
    },
    limitations: [
      "CONFORMANCE_FIXTURE_ADMISSION_NOT_PRODUCTION_ALLOW_LINEAGE",
      "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_NOT_EXTERNAL_MODEL_PROOF",
      "DET_01_AND_REMAINING_ADM_02_ROUTES_NOT_TESTED",
      "HOST_ROOT_AND_DOCKER_CONTROL_PLANE_NOT_INDEPENDENTLY_ATTESTED",
    ],
    provider: {
      records,
      request_count: records.length,
      transport: "openai-completions",
    },
    recorded_at: new Date().toISOString(),
    runtime: {
      commit: "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
      name: "openclaw-contained",
      runtime_tree: runtime,
      version: "2026.7.1",
      version_command: summarized(version),
    },
    scenario: {
      evidence: {
        final_text: FINAL_TEXT,
        history: {
          command: summarized(historyCommand),
          response: history,
        },
        session_store_absent_before: sessionStoreAbsentBefore,
        target_after: targetAfter,
        target_before: targetBefore,
        turn: {
          send: { command: summarized(sendCommand), response: send },
          wait: { command: summarized(waitCommand), response: wait },
        },
        write_guard: guard,
      },
      id: "ADM-01/exact-admitted-bytes",
      status: passed ? "PASS" : "FAIL",
    },
    schema: "aragorn/openclaw-contained-model-activation-probe-evidence/v1",
  };
}

async function emitProbe() {
  try {
    const evidence = await runProbe();
    const raw = `${canonicalJson(evidence)}\n`;
    writeFileSync(EVIDENCE_FILE, raw, { flag: "wx", mode: 0o600 });
    process.stdout.write(raw);
    process.exitCode = evidence.scenario.status === "PASS" ? 0 : 2;
  } catch (error) {
    process.stdout.write(
      `${canonicalJson({
        decision: { installer_work_eligible: false, status: "FAIL" },
        fatal_error: {
          message: error instanceof Error ? error.message : String(error),
          name: error instanceof Error ? error.name : "Error",
        },
        limitations: ["MODEL_ACTIVATION_PROBE_DID_NOT_COMPLETE"],
        recorded_at: new Date().toISOString(),
        schema: "aragorn/openclaw-contained-model-activation-probe-evidence/v1",
      })}\n`,
    );
    process.exitCode = 2;
  }
}

switch (process.argv[2]) {
  case "prepare":
    prepare();
    break;
  case "provider":
    await provider();
    break;
  default:
    await emitProbe();
}
