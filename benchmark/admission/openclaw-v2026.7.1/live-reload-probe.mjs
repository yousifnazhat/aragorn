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
  readdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/profile/config/openclaw.json";
const STATE = "/profile/state";
const WORKSPACE = "/profile/workspace";
const HOME = "/profile/home";
const NAME = "aragorn-admitted";
const TARGET_DIR = join(STATE, "skills", NAME);
const TARGET_FILE = join(TARGET_DIR, "SKILL.md");
const BLOCKED_SOURCE = "/sources/blocked-source";
const ALLOWED_SOURCE = "/sources/allowed-source";
const POLICY_LOG = join(STATE, "live-reload-policy-requests.jsonl");
const SESSION_KEY = "agent:main:aragorn-live-reload-v1";
const SESSION_STORE = join(STATE, "agents", "main", "sessions", "sessions.json");
const CRON_NAME = "Aragorn isolated cron rescan probe";
const TEST_TOKEN = "aragorn-contained-live-reload-token-v1";
const EXPECTED_VERSION = "OpenClaw 2026.7.1 (2d2ddc4)";
const BLOCK_REASON = "Aragorn live-reload probe blocked source";
const SELF = fileURLToPath(import.meta.url);
const MARKERS = {
  allowed: "aragorn-live-v2",
  blocked: "aragorn-live-blocked",
  seed: "Inert contained-profile fixture.",
};
const PROFILE_ENV = {
  HOME,
  OPENCLAW_CONFIG_PATH: CONFIG,
  OPENCLAW_GATEWAY_TOKEN: TEST_TOKEN,
  OPENCLAW_STATE_DIR: STATE,
  PATH: "/usr/local/bin:/usr/bin:/bin",
};

function skill(marker, version) {
  return [
    "---",
    `name: ${NAME}`,
    `description: Inert Aragorn live-reload fixture ${marker}.`,
    "---",
    `# Aragorn live-reload fixture ${version}`,
    "",
    "This fixture is inert and performs no actions.",
    "",
  ].join("\n");
}

const SEED_SKILL = [
  "---",
  `name: ${NAME}`,
  "description: Inert contained-profile fixture.",
  "---",
  "# Aragorn admitted fixture",
  "",
].join("\n");
const BLOCKED_SKILL = skill(MARKERS.blocked, "blocked");
const ALLOWED_SKILL = skill(MARKERS.allowed, "v2");

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
        skills: [NAME],
        workspace: WORKSPACE,
      },
      list: [{ id: "main", skills: [NAME], workspace: WORKSPACE }],
    },
    plugins: { enabled: false },
    security: {
      installPolicy: {
        enabled: true,
        exec: {
          args: ["/probe/live-reload-probe.mjs", "policy"],
          command: NODE,
          maxOutputBytes: 4096,
          noOutputTimeoutMs: 5000,
          source: "exec",
          timeoutMs: 5000,
          trustedDirs: ["/probe", "/usr/local/bin"],
        },
        targets: ["skill"],
      },
    },
    skills: {
      load: {
        allowSymlinkTargets: [],
        extraDirs: [],
        watch: true,
        watchDebounceMs: 250,
      },
    },
  };
}

function expectedPolicyRequest(sourceDir) {
  return {
    openclawVersion: "2026.7.1",
    origin: { spec: sourceDir, type: "path" },
    protocolVersion: 1,
    request: {
      kind: "skill-install",
      mode: "update",
      requestedSpecifier: sourceDir,
    },
    skill: { installId: "path" },
    source: {
      authority: "user",
      kind: "local-path",
      mutable: true,
      network: false,
    },
    sourcePath: sourceDir,
    sourcePathKind: "directory",
    targetName: NAME,
    targetType: "skill",
  };
}

function exactSkillDirectory(path, expected, readOnly = false) {
  const dirStat = lstatSync(path);
  const file = join(path, "SKILL.md");
  const fileStat = lstatSync(file);
  if (
    !dirStat.isDirectory() ||
    dirStat.isSymbolicLink() ||
    realpathSync(path) !== path ||
    canonicalJson(readdirSync(path).sort()) !== '["SKILL.md"]' ||
    !fileStat.isFile() ||
    fileStat.isSymbolicLink() ||
    fileStat.nlink !== 1
  ) {
    throw new Error(`unsafe skill fixture: ${path}`);
  }
  const raw = readFileSync(file);
  if (!raw.equals(Buffer.from(expected, "utf8"))) {
    throw new Error(`skill fixture bytes changed: ${path}`);
  }
  if (readOnly && ((dirStat.mode & 0o222) !== 0 || (fileStat.mode & 0o222) !== 0)) {
    throw new Error(`skill fixture is writable: ${path}`);
  }
  return {
    digest: sha256(raw),
    directory_mode: (dirStat.mode & 0o777).toString(8).padStart(3, "0"),
    file_mode: (fileStat.mode & 0o777).toString(8).padStart(3, "0"),
    path,
  };
}

function prepare() {
  const roots = {
    allowed: "/prepare/sources/allowed-source",
    blocked: "/prepare/sources/blocked-source",
    config: "/prepare/config",
  };
  for (const path of Object.values(roots)) {
    mkdirSync(path, { recursive: true });
  }
  const config = configuration();
  const files = [
    [join(roots.config, "openclaw.json"), `${canonicalJson(config)}\n`],
    [join(roots.blocked, "SKILL.md"), BLOCKED_SKILL],
    [join(roots.allowed, "SKILL.md"), ALLOWED_SKILL],
  ];
  for (const [path, contents] of files) {
    writeFileSync(path, contents, { flag: "wx", mode: 0o444 });
  }
  for (const path of [
    ...Object.values(roots),
    "/prepare/sources",
    "/prepare",
  ]) {
    chmodSync(path, 0o555);
  }
  process.stdout.write(
    `${canonicalJson({
      configuration_digest: sha256(Buffer.from(canonicalJson(config), "ascii")),
      fixtures: {
        allowed: { digest: sha256(Buffer.from(ALLOWED_SKILL)), path: roots.allowed },
        blocked: { digest: sha256(Buffer.from(BLOCKED_SKILL)), path: roots.blocked },
        seed: {
          digest: sha256(Buffer.from(SEED_SKILL)),
          path: `/seed/${NAME}`,
        },
      },
      implementation_digest: sha256(readFileSync(SELF)),
      schema: "aragorn/openclaw-live-reload-preparation/v1",
    })}\n`,
  );
}

async function policy() {
  process.stdin.setEncoding("utf8");
  const hash = createHash("sha256");
  let raw = "";
  let bytes = 0;
  let oversized = false;
  for await (const chunk of process.stdin) {
    hash.update(chunk);
    bytes += Buffer.byteLength(chunk, "utf8");
    if (!oversized && bytes <= 64 * 1024) {
      raw += chunk;
    } else {
      oversized = true;
      raw = "";
    }
  }

  let request = null;
  let parseError = null;
  if (!oversized) {
    try {
      request = JSON.parse(raw);
    } catch (error) {
      parseError = error instanceof Error ? error.message : String(error);
    }
  }

  let route = "unrecognized";
  let source = null;
  let decision = "block";
  let reason = "Aragorn live-reload policy rejected an unexpected request";
  try {
    if (
      canonicalJson(request) ===
      canonicalJson(expectedPolicyRequest(BLOCKED_SOURCE))
    ) {
      route = "blocked-source";
      source = exactSkillDirectory(BLOCKED_SOURCE, BLOCKED_SKILL, true);
      reason = BLOCK_REASON;
    } else if (
      canonicalJson(request) ===
      canonicalJson(expectedPolicyRequest(ALLOWED_SOURCE))
    ) {
      route = "allowed-source";
      source = exactSkillDirectory(ALLOWED_SOURCE, ALLOWED_SKILL, true);
      decision = "allow";
      reason = "exact allowed source and request digest";
    }
  } catch (error) {
    reason = `Aragorn live-reload policy source validation failed: ${
      error instanceof Error ? error.message : String(error)
    }`;
  }

  const record = {
    decision,
    input_bytes: bytes,
    input_digest: `sha256:${hash.digest("hex")}`,
    oversized,
    parse_error: parseError,
    protocol_version: 1,
    recorded_at: new Date().toISOString(),
    request,
    route,
    source,
  };
  appendFileSync(POLICY_LOG, `${canonicalJson(record)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  process.stdout.write(
    canonicalJson({
      decision,
      protocolVersion: 1,
      ...(decision === "block" ? { reason } : {}),
    }),
  );
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
        return { command: call, info };
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error("timed out waiting for the contained Gateway");
}

function processIdentity(pid = 1) {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8").trim();
  const close = stat.lastIndexOf(")");
  const fields = stat.slice(close + 2).split(" ");
  return {
    cmdline: readFileSync(`/proc/${pid}/cmdline`)
      .toString("utf8")
      .split("\0")
      .filter(Boolean),
    pid,
    start_time_ticks: fields[19],
  };
}

function treeSnapshot(root) {
  const entries = [];
  const visit = (path) => {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
      throw new Error(`unsafe target entry: ${path}`);
    }
    const entry = {
      mode: (stat.mode & 0o777).toString(8).padStart(3, "0"),
      path: relative(root, path) || ".",
      size: stat.size,
      type: stat.isDirectory() ? "directory" : "file",
    };
    if (stat.isFile()) {
      entry.digest = sha256(readFileSync(path));
    }
    entries.push(entry);
    if (stat.isDirectory()) {
      for (const name of readdirSync(path).sort()) {
        visit(join(path, name));
      }
    }
  };
  visit(root);
  return entries;
}

function readPolicyLog() {
  const raw = readFileSync(POLICY_LOG, "utf8");
  const lines = raw.split("\n");
  if (lines.pop() !== "") {
    throw new Error("policy log lacks a trailing newline");
  }
  return lines.map((line) => {
    const parsed = JSON.parse(line);
    if (line !== canonicalJson(parsed)) {
      throw new Error("policy log record is not canonical");
    }
    return parsed;
  });
}

function resolveSnapshotPrompt(snapshot) {
  if (typeof snapshot.prompt === "string") {
    return { prompt: snapshot.prompt, storage: "inline" };
  }
  const ref = snapshot.promptRef;
  if (
    ref?.version !== 1 ||
    ref?.algorithm !== "sha256" ||
    !/^[a-f0-9]{64}$/.test(ref?.hash ?? "") ||
    !Number.isSafeInteger(ref?.bytes) ||
    ref.bytes < 0
  ) {
    throw new Error("session snapshot has no valid prompt or promptRef");
  }
  const path = join(
    dirname(SESSION_STORE),
    "skills-prompts",
    "sha256",
    ref.hash.slice(0, 2),
    `${ref.hash}.txt`,
  );
  const stat = lstatSync(path);
  const raw = readFileSync(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    raw.length !== ref.bytes ||
    sha256(raw) !== `sha256:${ref.hash}`
  ) {
    throw new Error("session prompt blob failed integrity validation");
  }
  return { prompt: raw.toString("utf8"), storage: "promptRef" };
}

function sessionSnapshot() {
  const store = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
  const entry = store[SESSION_KEY];
  if (!entry || typeof entry.sessionId !== "string" || !entry.skillsSnapshot) {
    throw new Error("expected live-reload session snapshot is missing");
  }
  const snapshot = entry.skillsSnapshot;
  const { prompt, storage } = resolveSnapshotPrompt(snapshot);
  return {
    ended_at: entry.endedAt,
    markers: Object.fromEntries(
      Object.entries(MARKERS).map(([key, marker]) => [key, prompt.includes(marker)]),
    ),
    prompt_bytes: Buffer.byteLength(prompt),
    prompt_digest: sha256(Buffer.from(prompt)),
    prompt_storage: storage,
    run_status: entry.status,
    runtime_ms: entry.runtimeMs,
    session_id: entry.sessionId,
    skill_names: (snapshot.skills ?? []).map((entry) => entry.name),
    started_at: entry.startedAt,
    version: snapshot.version,
  };
}

function cronSnapshot(jobId) {
  const key = `agent:main:cron:${jobId}`;
  const store = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
  const entry = store[key];
  if (
    !entry?.skillsSnapshot ||
    typeof entry.lifecycleRevision !== "string" ||
    !Number.isSafeInteger(entry.updatedAt)
  ) {
    throw new Error("expected isolated cron skill snapshot is missing");
  }
  const snapshot = entry.skillsSnapshot;
  const { prompt, storage } = resolveSnapshotPrompt(snapshot);
  return {
    label: entry.label,
    lifecycle_revision: entry.lifecycleRevision,
    markers: Object.fromEntries(
      Object.entries(MARKERS).map(([name, marker]) => [
        name,
        prompt.includes(marker),
      ]),
    ),
    model: entry.model,
    model_provider: entry.modelProvider,
    prompt_bytes: Buffer.byteLength(prompt),
    prompt_digest: sha256(Buffer.from(prompt)),
    prompt_storage: storage,
    session_key: key,
    skill_filter: snapshot.skillFilter,
    skill_names: (snapshot.skills ?? []).map((item) => item.name),
    system_sent: entry.systemSent,
    updated_at: entry.updatedAt,
    version: snapshot.version,
  };
}

function validSnapshot(snapshot, marker) {
  return (
    typeof snapshot.session_id === "string" &&
    snapshot.run_status === "failed" &&
    Number.isSafeInteger(snapshot.started_at) &&
    Number.isSafeInteger(snapshot.ended_at) &&
    snapshot.ended_at >= snapshot.started_at &&
    Number.isSafeInteger(snapshot.runtime_ms) &&
    snapshot.runtime_ms >= 0 &&
    Number.isSafeInteger(snapshot.version) &&
    snapshot.version >= 0 &&
    canonicalJson(snapshot.skill_names) === `["${NAME}"]` &&
    snapshot.markers[marker] === true &&
    Object.entries(snapshot.markers)
      .filter(([name]) => name !== marker)
      .every(([, present]) => present === false)
  );
}

function validCronSnapshot(snapshot, marker) {
  return (
    snapshot.label === `Cron: ${CRON_NAME}` &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      snapshot.lifecycle_revision,
    ) &&
    snapshot.model === "gpt-5.5" &&
    snapshot.model_provider === "openai" &&
    snapshot.prompt_storage === "promptRef" &&
    snapshot.system_sent === true &&
    Number.isSafeInteger(snapshot.updated_at) &&
    Number.isSafeInteger(snapshot.version) &&
    snapshot.version >= 0 &&
    canonicalJson(snapshot.skill_filter) === `["${NAME}"]` &&
    canonicalJson(snapshot.skill_names) === `["${NAME}"]` &&
    snapshot.markers[marker] === true &&
    Object.entries(snapshot.markers)
      .filter(([name]) => name !== marker)
      .every(([, present]) => present === false)
  );
}

async function normalTurn(label, attempt) {
  const idempotencyKey = `aragorn-live-reload-${label}-${attempt}`;
  const sendCommand = gatewayCall("chat.send", {
    deliver: false,
    idempotencyKey,
    message: `Inert live-reload probe turn ${label} ${attempt}.`,
    sessionKey: SESSION_KEY,
    timeoutMs: 5000,
  });
  const send = parseCommand(sendCommand, `${label} chat.send`);
  if (send.status !== "started" || typeof send.runId !== "string") {
    throw new Error(`${label} chat.send did not start`);
  }
  const waitCommand = gatewayCall(
    "agent.wait",
    { runId: send.runId, timeoutMs: 10_000 },
    12_000,
  );
  const wait = parseCommand(waitCommand, `${label} agent.wait`);
  if (
    wait.status !== "ok" ||
    !Number.isSafeInteger(wait.endedAt)
  ) {
    throw new Error(`${label} did not reach a terminal agent result`);
  }
  return {
    send: { command: summarized(sendCommand), response: send },
    wait: { command: summarized(waitCommand), response: wait },
  };
}

async function createCronJob() {
  const params = {
    agentId: "main",
    delivery: { mode: "none" },
    enabled: true,
    name: CRON_NAME,
    payload: {
      kind: "agentTurn",
      message: "Inert isolated cron skill rescan probe.",
      timeoutSeconds: 5,
    },
    schedule: { everyMs: 86_400_000, kind: "every" },
    sessionTarget: "isolated",
    wakeMode: "now",
  };
  const call = gatewayCall("cron.add", params);
  const response = parseCommand(call, "cron.add");
  if (
    typeof response.id !== "string" ||
    response.name !== CRON_NAME ||
    response.enabled !== true ||
    response.sessionTarget !== "isolated" ||
    response.wakeMode !== "now" ||
    canonicalJson(response.payload) !== canonicalJson(params.payload) ||
    canonicalJson(response.delivery) !== canonicalJson(params.delivery)
  ) {
    throw new Error("cron.add did not create the exact isolated job");
  }
  return { command: summarized(call), params, response };
}

async function forceCronRun(jobId, attempt) {
  const params = { id: jobId, mode: "force" };
  const call = gatewayCall("cron.run", params);
  const response = parseCommand(call, `cron.run ${attempt}`);
  if (
    response.ok !== true ||
    response.enqueued !== true ||
    typeof response.runId !== "string"
  ) {
    throw new Error(`cron.run ${attempt} was not enqueued`);
  }
  let history = null;
  const polls = [];
  for (let retry = 1; retry <= 20 && history === null; retry += 1) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    const historyParams = { id: jobId, limit: 10 };
    const historyCall = gatewayCall("cron.runs", historyParams);
    const historyResponse = parseCommand(historyCall, `cron.runs ${attempt}`);
    polls.push({
      command: summarized(historyCall),
      params: historyParams,
      response: historyResponse,
    });
    if (
      Array.isArray(historyResponse.entries) &&
      historyResponse.entries.some((entry) => entry.runId === response.runId)
    ) {
      history = polls.at(-1);
    }
  }
  if (history === null) {
    throw new Error(`cron.run ${attempt} did not finish within the poll bound`);
  }
  const result = history.response.entries.find(
    (entry) => entry.runId === response.runId,
  );
  return {
    history,
    poll_count: polls.length,
    result,
    run: { command: summarized(call), params, response },
  };
}

function removeCronJob(jobId) {
  const params = { id: jobId };
  const call = gatewayCall("cron.remove", params);
  const response = parseCommand(call, "cron.remove");
  if (response.ok !== true || response.removed !== true) {
    throw new Error("cron.remove did not remove the isolated job");
  }
  return { command: summarized(call), params, response };
}

function gatewayLog() {
  const dir = "/tmp/openclaw";
  const names = readdirSync(dir).filter((name) => name.endsWith(".log")).sort();
  if (names.length !== 1) {
    throw new Error(`expected one Gateway log, found ${names.length}`);
  }
  const path = join(dir, names[0]);
  const raw = readFileSync(path);
  if (raw.includes(TEST_TOKEN)) {
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

function allowedTargetProof() {
  const snapshot = treeSnapshot(TARGET_DIR);
  const paths = snapshot.map((entry) => entry.path).sort();
  const expectedPaths = [".", ".openclaw", ".openclaw/source-origin.json", "SKILL.md"].sort();
  const origin = JSON.parse(
    readFileSync(join(TARGET_DIR, ".openclaw", "source-origin.json"), "utf8"),
  );
  const valid =
    canonicalJson(paths) === canonicalJson(expectedPaths) &&
    sha256(readFileSync(TARGET_FILE)) === sha256(Buffer.from(ALLOWED_SKILL)) &&
    origin.version === 1 &&
    origin.source === "path" &&
    origin.spec === ALLOWED_SOURCE &&
    origin.slug === NAME &&
    Number.isSafeInteger(origin.installedAt);
  return { origin, snapshot, valid };
}

async function runProbe() {
  if (process.env.OPENCLAW_GATEWAY_TOKEN !== TEST_TOKEN) {
    throw new Error("unexpected contained Gateway test credential");
  }
  if (existsSync(POLICY_LOG)) {
    throw new Error("policy log was not empty at probe start");
  }
  const expectedConfig = `${canonicalJson(configuration())}\n`;
  const configRaw = readFileSync(CONFIG);
  if (!configRaw.equals(Buffer.from(expectedConfig, "utf8"))) {
    throw new Error("watch-enabled configuration changed");
  }
  const fixtures = {
    allowed: exactSkillDirectory(ALLOWED_SOURCE, ALLOWED_SKILL, true),
    blocked: exactSkillDirectory(BLOCKED_SOURCE, BLOCKED_SKILL, true),
    seed: exactSkillDirectory(TARGET_DIR, SEED_SKILL),
  };

  const version = command(["--version"]);
  if (version.exit_code !== 0 || version.stdout.trim() !== EXPECTED_VERSION) {
    throw new Error(`unexpected OpenClaw version: ${version.stdout.trim()}`);
  }
  const gateway = await waitForGateway();
  const processBefore = processIdentity();
  const logBefore = gatewayLog();
  if (logBefore.ready_count !== 1 || logBefore.restart_count !== 0) {
    throw new Error("Gateway did not have one clean readiness boundary");
  }

  const v1Turn = await normalTurn("v1", 0);
  const v1 = sessionSnapshot();
  if (!validSnapshot(v1, "seed")) {
    throw new Error("v1 was not consumed by the first normal session turn");
  }
  const cronJob = await createCronJob();
  let cronCleanup = null;
  const cronBefore = await forceCronRun(cronJob.response.id, 1);
  const cronSnapshotBefore = cronSnapshot(cronJob.response.id);

  const targetBeforeBlock = treeSnapshot(TARGET_DIR);
  const blockedCommand = command([
    "skills",
    "install",
    BLOCKED_SOURCE,
    "--as",
    NAME,
    "--force",
    "--global",
  ]);
  const blockedRecords = readPolicyLog();
  const targetAfterBlock = treeSnapshot(TARGET_DIR);
  const blockedTurn = await normalTurn("blocked", 0);
  const blockedSnapshot = sessionSnapshot();
  const blockPassed =
    blockedCommand.exit_code === 1 &&
    blockedCommand.error === null &&
    blockedCommand.signal === null &&
    `${blockedCommand.stdout}\n${blockedCommand.stderr}`.includes(BLOCK_REASON) &&
    blockedRecords.length === 1 &&
    blockedRecords[0].decision === "block" &&
    blockedRecords[0].route === "blocked-source" &&
    canonicalJson(blockedRecords[0].request) ===
      canonicalJson(expectedPolicyRequest(BLOCKED_SOURCE)) &&
    canonicalJson(targetBeforeBlock) === canonicalJson(targetAfterBlock) &&
    blockedSnapshot.session_id === v1.session_id &&
    blockedSnapshot.version === v1.version &&
    blockedSnapshot.prompt_digest === v1.prompt_digest &&
    validSnapshot(blockedSnapshot, "seed");

  const allowedCommand = command([
    "skills",
    "install",
    ALLOWED_SOURCE,
    "--as",
    NAME,
    "--force",
    "--global",
  ]);
  const policyRecords = readPolicyLog();
  const targetAllowed = allowedTargetProof();
  const updatePassed =
    blockPassed &&
    allowedCommand.exit_code === 0 &&
    allowedCommand.error === null &&
    allowedCommand.signal === null &&
    policyRecords.length === 2 &&
    policyRecords[1].decision === "allow" &&
    policyRecords[1].route === "allowed-source" &&
    canonicalJson(policyRecords[1].request) ===
      canonicalJson(expectedPolicyRequest(ALLOWED_SOURCE)) &&
    policyRecords[1].source?.digest === sha256(Buffer.from(ALLOWED_SKILL)) &&
    targetAllowed.valid;

  const reloadTurns = [];
  let v2 = null;
  for (let attempt = 1; attempt <= 10 && !v2; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 150));
    reloadTurns.push(await normalTurn("v2", attempt));
    const candidate = sessionSnapshot();
    if (
      candidate.session_id === v1.session_id &&
      candidate.version > v1.version &&
      validSnapshot(candidate, "allowed")
    ) {
      v2 = candidate;
    }
  }

  const cronAfter = await forceCronRun(cronJob.response.id, 2);
  const cronSnapshotAfter = cronSnapshot(cronJob.response.id);
  cronCleanup = removeCronJob(cronJob.response.id);
  const processAfter = processIdentity();
  const logAfter = gatewayLog();
  const noRestart =
    canonicalJson(processBefore) === canonicalJson(processAfter) &&
    logAfter.ready_count === logBefore.ready_count &&
    logAfter.restart_count === 0;
  const watcherPassed = updatePassed && v2 !== null && noRestart;
  const sessionPassed =
    watcherPassed &&
    v2.session_id === v1.session_id &&
    v2.prompt_digest !== v1.prompt_digest;
  const expectedCronResult = (run) =>
    run.result.jobId === cronJob.response.id &&
    run.result.action === "finished" &&
    run.result.status === "error" &&
    run.result.errorReason === "model_not_found" &&
    run.result.error === "FailoverError: Unknown model: openai/gpt-5.5" &&
    run.result.model === "gpt-5.5" &&
    run.result.provider === "openai" &&
    run.result.deliveryStatus === "not-requested" &&
    run.result.jobName === CRON_NAME &&
    run.result.sessionKey ===
      `agent:main:cron:${cronJob.response.id}:run:${run.result.sessionId}` &&
    Number.isSafeInteger(run.result.runAtMs) &&
    Number.isSafeInteger(run.result.durationMs) &&
    run.result.durationMs >= 0;
  const cronPassed =
    watcherPassed &&
    expectedCronResult(cronBefore) &&
    expectedCronResult(cronAfter) &&
    validCronSnapshot(cronSnapshotBefore, "seed") &&
    validCronSnapshot(cronSnapshotAfter, "allowed") &&
    cronBefore.run.response.runId !== cronAfter.run.response.runId &&
    cronBefore.result.sessionId !== cronAfter.result.sessionId &&
    cronSnapshotBefore.lifecycle_revision !==
      cronSnapshotAfter.lifecycle_revision &&
    cronSnapshotBefore.version < cronSnapshotAfter.version &&
    cronSnapshotBefore.prompt_digest === v1.prompt_digest &&
    cronSnapshotAfter.prompt_digest === v2.prompt_digest &&
    cronSnapshotBefore.prompt_digest !== cronSnapshotAfter.prompt_digest &&
    cronCleanup.response.ok === true &&
    noRestart;
  const scenarios = [
    {
      evidence: {
        allowed_command: summarized(allowedCommand),
        blocked_command: summarized(blockedCommand),
        policy_records: policyRecords,
        target_after_allowed: targetAllowed,
        target_after_block: targetAfterBlock,
        target_before_block: targetBeforeBlock,
      },
      id: "ADM-02/update/archive-source-force-replacement",
      status: updatePassed ? "PASS" : "FAIL",
    },
    {
      evidence: {
        gateway_log_after: logAfter,
        gateway_log_before: logBefore,
        process_after: processAfter,
        process_before: processBefore,
        retries: reloadTurns.length,
        snapshot_after: v2,
        snapshot_before: blockedSnapshot,
      },
      id: "ADM-02/reload/filesystem-watch-invalidation",
      status: watcherPassed ? "PASS" : "FAIL",
    },
    {
      evidence: {
        blocked_turn: blockedTurn,
        reload_turns: reloadTurns,
        v1_turn: v1Turn,
      },
      id: "ADM-02/reload/chat-session-snapshot-consumer",
      status: sessionPassed ? "PASS" : "FAIL",
    },
    {
      evidence: {
        cleanup: cronCleanup,
        job: cronJob,
        run_after: cronAfter,
        run_before: cronBefore,
        snapshot_after: cronSnapshotAfter,
        snapshot_before: cronSnapshotBefore,
      },
      id: "ADM-02/reload/cron-rescan",
      status: cronPassed ? "PASS" : "FAIL",
    },
  ];
  const failed = scenarios.some((scenario) => scenario.status !== "PASS");
  return {
    adapter: {
      configuration: configuration(),
      configuration_digest: sha256(
        Buffer.from(canonicalJson(configuration()), "ascii"),
      ),
      fixtures,
      implementation_digest: sha256(readFileSync(SELF)),
    },
    decision: {
      installer_work_eligible: false,
      status: failed ? "FAIL" : "NOT_TESTED",
    },
    gateway: {
      readiness_command: summarized(gateway.command),
      system_info: {
        arch: gateway.info.arch,
        node_version: gateway.info.nodeVersion,
        pid: gateway.info.pid,
        platform: gateway.info.platform,
        port: gateway.info.port,
      },
    },
    limitations: [
      "ONLY_LOCAL_DIRECTORY_GLOBAL_FORCE_REPLACEMENT_EXECUTED",
      "ONLY_FILESYSTEM_WATCH_EXISTING_CHAT_SESSION_SNAPSHOT_EXECUTED",
      "ONLY_TWO_FORCED_ISOLATED_CRON_RESCANS_EXECUTED",
      "CRON_TURNS_STOPPED_AT_MODEL_RESOLUTION_WITHOUT_PROVIDER_EXECUTION",
      "NORMAL_TURNS_INTENTIONALLY_FAIL_WITHOUT_PROVIDER_CREDENTIALS",
      "OTHER_UPDATE_RELOAD_PATHS_REMAIN_NOT_TESTED",
      "CONTAINED_DOCKER_ENVIRONMENT_NOT_INDEPENDENTLY_ATTESTED",
    ],
    recorded_at: new Date().toISOString(),
    runtime: {
      commit: "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
      name: "openclaw-contained",
      version: "2026.7.1",
      version_command: version,
    },
    scenarios,
    schema: "aragorn/openclaw-contained-live-reload-probe-evidence/v1",
  };
}

async function emitProbe() {
  try {
    const evidence = await runProbe();
    process.stdout.write(`${canonicalJson(evidence)}\n`);
    process.exitCode =
      evidence.scenarios.some((scenario) => scenario.status !== "PASS") ? 2 : 0;
  } catch (error) {
    process.stdout.write(
      `${canonicalJson({
        decision: { installer_work_eligible: false, status: "FAIL" },
        fatal_error: {
          message: error instanceof Error ? error.message : String(error),
          name: error instanceof Error ? error.name : "Error",
        },
        limitations: ["LIVE_RELOAD_PROBE_DID_NOT_COMPLETE"],
        recorded_at: new Date().toISOString(),
        scenarios: [],
        schema: "aragorn/openclaw-contained-live-reload-probe-evidence/v1",
      })}\n`,
    );
    process.exitCode = 2;
  }
}

const mode = process.argv[2];
if (mode === "prepare") {
  prepare();
} else if (mode === "policy") {
  await policy();
} else if (mode === undefined) {
  await emitProbe();
} else {
  throw new Error(`unsupported mode: ${mode}`);
}
