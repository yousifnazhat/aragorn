#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/profile/state/openclaw.json";
const STATE = "/profile/state";
const WORKSPACE = "/profile/workspace";
const HOME = "/profile/home";
const NAME = "aragorn-admitted";
const TARGET = join(STATE, "skills", NAME);
const TARGET_FILE = join(TARGET, "SKILL.md");
const POLICY_LOG = join(STATE, "live-reload-policy-requests.jsonl");
const SESSION_KEY = "agent:main:aragorn-config-activation-v1";
const SESSION_STORE = join(STATE, "agents", "main", "sessions", "sessions.json");
const TEST_TOKEN = "aragorn-contained-live-reload-token-v1";
const EXPECTED_VERSION = "OpenClaw 2026.7.1 (2d2ddc4)";
const MARKER = "Inert contained-profile fixture.";
const SELF = fileURLToPath(import.meta.url);
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

function baseConfig() {
  return {
    agents: {
      defaults: { skills: [NAME], workspace: WORKSPACE },
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

function expectedConfig(enabled) {
  const config = baseConfig();
  if (enabled !== null) {
    config.skills.entries = { [NAME]: { enabled } };
  }
  return config;
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

function targetWriteGuard() {
  try {
    const descriptor = openSync(TARGET_FILE, "r+");
    closeSync(descriptor);
    return { blocked: false, code: null };
  } catch (error) {
    return {
      blocked: error?.code === "EROFS" || error?.code === "EACCES",
      code: typeof error?.code === "string" ? error.code : null,
    };
  }
}

function configSnapshot(enabled) {
  const stat = lstatSync(CONFIG);
  const raw = readFileSync(CONFIG);
  const document = JSON.parse(raw);
  const { meta, ...configuration } = document;
  const validMeta =
    enabled === null
      ? meta === undefined
      : canonicalJson(Object.keys(meta).sort()) ===
          '["lastTouchedAt","lastTouchedVersion"]' &&
        meta.lastTouchedVersion === "2026.7.1" &&
        new Date(meta.lastTouchedAt).toISOString() === meta.lastTouchedAt;
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== 0o600 ||
    canonicalJson(configuration) !== canonicalJson(expectedConfig(enabled)) ||
    !validMeta
  ) {
    throw new Error(`configuration did not persist enabled=${enabled}`);
  }
  return {
    digest: sha256(raw),
    document,
    mode: "600",
    path: CONFIG,
    size: raw.length,
  };
}

function policyRecordCount() {
  if (!existsSync(POLICY_LOG)) {
    return 0;
  }
  const raw = readFileSync(POLICY_LOG, "utf8");
  const lines = raw.split("\n");
  if (lines.pop() !== "") {
    throw new Error("policy log lacks a trailing newline");
  }
  for (const line of lines) {
    if (line !== canonicalJson(JSON.parse(line))) {
      throw new Error("policy log record is not canonical");
    }
  }
  return lines.length;
}

function resolvePrompt(snapshot) {
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
    throw new Error("expected config-activation session snapshot is missing");
  }
  const snapshot = entry.skillsSnapshot;
  const { prompt, storage } = resolvePrompt(snapshot);
  return {
    ended_at: entry.endedAt,
    marker_present: prompt.includes(MARKER),
    prompt_bytes: Buffer.byteLength(prompt),
    prompt_digest: sha256(Buffer.from(prompt)),
    prompt_storage: storage,
    run_status: entry.status,
    runtime_ms: entry.runtimeMs,
    session_id: entry.sessionId,
    skill_names: (snapshot.skills ?? []).map((item) => item.name),
    started_at: entry.startedAt,
    version: snapshot.version,
  };
}

function validSnapshot(snapshot, enabled) {
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
    snapshot.prompt_storage === (enabled ? "promptRef" : "inline") &&
    snapshot.marker_present === enabled &&
    canonicalJson(snapshot.skill_names) === (enabled ? `["${NAME}"]` : "[]")
  );
}

async function normalTurn(label, attempt) {
  const runId = `aragorn-config-activation-${label}-${attempt}`;
  const sendCommand = gatewayCall("chat.send", {
    deliver: false,
    idempotencyKey: runId,
    message: `Inert config-activation probe turn ${label} ${attempt}.`,
    sessionKey: SESSION_KEY,
    timeoutMs: 5000,
  });
  const send = parseCommand(sendCommand, `${label} chat.send`);
  if (send.status !== "started" || send.runId !== runId) {
    throw new Error(`${label} chat.send did not start the exact run`);
  }
  const waitCommand = gatewayCall(
    "agent.wait",
    { runId, timeoutMs: 10_000 },
    12_000,
  );
  const wait = parseCommand(waitCommand, `${label} agent.wait`);
  if (
    wait.status !== "ok" ||
    wait.runId !== runId ||
    !Number.isSafeInteger(wait.endedAt)
  ) {
    throw new Error(`${label} did not reach a terminal agent result`);
  }
  return {
    send: { command: summarized(sendCommand), response: send },
    wait: { command: summarized(waitCommand), response: wait },
  };
}

async function waitForSnapshot(label, prior, enabled) {
  const turns = [];
  for (let attempt = 1; attempt <= 10; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 150));
    turns.push(await normalTurn(label, attempt));
    const snapshot = sessionSnapshot();
    if (
      snapshot.session_id === prior.session_id &&
      snapshot.version > prior.version &&
      validSnapshot(snapshot, enabled)
    ) {
      return { snapshot, turns };
    }
  }
  return { snapshot: null, turns };
}

function skillStatus() {
  const result = gatewayCall("skills.status");
  const response = parseCommand(result, "skills.status");
  const matches = response.skills.filter((item) => item.name === NAME);
  if (matches.length !== 1) {
    throw new Error(`expected one ${NAME} status entry`);
  }
  const skill = matches[0];
  return {
    command: summarized(result),
    skill: {
      blocked_by_agent_filter: skill.blockedByAgentFilter,
      disabled: skill.disabled,
      eligible: skill.eligible,
      model_visible: skill.modelVisible,
      source: skill.source,
      user_invocable: skill.userInvocable,
    },
  };
}

function updateSkill(enabled) {
  const params = { enabled, skillKey: NAME };
  const result = gatewayCall("skills.update", params);
  const response = parseCommand(result, `skills.update enabled=${enabled}`);
  if (
    canonicalJson(response) !==
    canonicalJson({ config: { enabled }, ok: true, skillKey: NAME })
  ) {
    throw new Error(`skills.update returned an unexpected enabled=${enabled} result`);
  }
  return { command: summarized(result), params, response };
}

async function runProbe() {
  if (process.env.OPENCLAW_GATEWAY_TOKEN !== TEST_TOKEN) {
    throw new Error("unexpected contained Gateway test credential");
  }
  const implementationDigest = sha256(readFileSync(SELF));
  const initialConfig = configSnapshot(null);
  const targetBefore = treeSnapshot(TARGET);
  const writeGuard = targetWriteGuard();
  const policyBefore = policyRecordCount();
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

  const initialTurn = await normalTurn("initial", 0);
  const initialSnapshot = sessionSnapshot();
  const initialStatus = skillStatus();
  if (
    !validSnapshot(initialSnapshot, true) ||
    initialStatus.skill.disabled ||
    !initialStatus.skill.eligible ||
    !initialStatus.skill.model_visible
  ) {
    throw new Error("initial admitted skill was not active");
  }

  const disable = updateSkill(false);
  const disabledConfig = configSnapshot(false);
  const disabledReload = await waitForSnapshot("disabled", initialSnapshot, false);
  const disabledStatus = skillStatus();
  const disabledPassed =
    disabledReload.snapshot !== null &&
    disabledStatus.skill.disabled &&
    !disabledStatus.skill.eligible &&
    !disabledStatus.skill.model_visible;

  const enable = updateSkill(true);
  const enabledConfig = configSnapshot(true);
  const enabledReload =
    disabledReload.snapshot === null
      ? { snapshot: null, turns: [] }
      : await waitForSnapshot("enabled", disabledReload.snapshot, true);
  const enabledStatus = skillStatus();
  const targetAfter = treeSnapshot(TARGET);
  const processAfter = processIdentity();
  const logAfter = gatewayLog();
  const policyAfter = policyRecordCount();
  const noRestart =
    canonicalJson(processBefore) === canonicalJson(processAfter) &&
    logAfter.ready_count === logBefore.ready_count &&
    logAfter.restart_count === 0;
  const updatePassed =
    disabledPassed &&
    enabledReload.snapshot !== null &&
    !enabledStatus.skill.disabled &&
    enabledStatus.skill.eligible &&
    enabledStatus.skill.model_visible &&
    writeGuard.blocked &&
    canonicalJson(targetAfter) === canonicalJson(targetBefore) &&
    policyAfter === policyBefore;
  const reloadPassed =
    updatePassed &&
    enabledReload.snapshot.session_id === initialSnapshot.session_id &&
    disabledReload.snapshot.version > initialSnapshot.version &&
    enabledReload.snapshot.version > disabledReload.snapshot.version &&
    noRestart;
  const scenarios = [
    {
      evidence: {
        config_after_disable: disabledConfig,
        config_after_enable: enabledConfig,
        config_before: initialConfig,
        disable,
        disabled_status: disabledStatus,
        enable,
        enabled_status: enabledStatus,
        initial_status: initialStatus,
        policy_record_count_after: policyAfter,
        policy_record_count_before: policyBefore,
        target_after: targetAfter,
        target_before: targetBefore,
        write_guard: writeGuard,
      },
      id: "ADM-02/update/config-entry-activation",
      status: updatePassed ? "PASS" : "FAIL",
    },
    {
      evidence: {
        disabled: disabledReload,
        enabled: enabledReload,
        gateway_log_after: logAfter,
        gateway_log_before: logBefore,
        initial_snapshot: initialSnapshot,
        initial_turn: initialTurn,
        process_after: processAfter,
        process_before: processBefore,
      },
      id: "ADM-02/reload/config-invalidation",
      status: reloadPassed ? "PASS" : "FAIL",
    },
  ];
  const failed = scenarios.some((scenario) => scenario.status !== "PASS");
  return {
    adapter: {
      configuration: baseConfig(),
      configuration_digest: sha256(
        Buffer.from(canonicalJson(baseConfig()), "ascii"),
      ),
      fixture: {
        admission_evidence_digest:
          "sha256:a81138e1bec12e0471068aafe4eee0b625635de5d39ba6bc3665d8251b76f6af",
        digest: targetBefore[1].digest,
        mount: "/profile/state/skills",
        path: TARGET,
        source_volume: "aragorn-openclaw-2026-7-1-contained-admitted-v1",
      },
      implementation_digest: implementationDigest,
      writable_configuration_path: CONFIG,
    },
    decision: {
      installer_work_eligible: false,
      status: failed ? "FAIL" : "NOT_TESTED",
    },
    gateway,
    limitations: [
      "ONLY_CONFIG_ENTRY_ENABLE_DISABLE_EXECUTED",
      "ONLY_CONFIG_INVALIDATION_EXISTING_CHAT_SESSION_EXECUTED",
      "NORMAL_TURNS_INTENTIONALLY_FAIL_WITHOUT_PROVIDER_CREDENTIALS",
      "CONFIGURATION_COPY_WRITABLE_TO_UNPRIVILEGED_RUNTIME_UID",
      "ADMITTED_SKILL_ROOT_READ_ONLY_VOLUME",
      "OTHER_UPDATE_RELOAD_PATHS_REMAIN_NOT_TESTED",
      "CONTAINED_DOCKER_ENVIRONMENT_NOT_INDEPENDENTLY_ATTESTED",
    ],
    recorded_at: new Date().toISOString(),
    runtime: {
      commit: "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
      name: "openclaw-contained",
      version: "2026.7.1",
      version_command: summarized(version),
    },
    scenarios,
    schema: "aragorn/openclaw-contained-config-activation-probe-evidence/v1",
  };
}

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
      limitations: ["CONFIG_ACTIVATION_PROBE_DID_NOT_COMPLETE"],
      recorded_at: new Date().toISOString(),
      scenarios: [],
      schema: "aragorn/openclaw-contained-config-activation-probe-evidence/v1",
    })}\n`,
  );
  process.exitCode = 2;
}
