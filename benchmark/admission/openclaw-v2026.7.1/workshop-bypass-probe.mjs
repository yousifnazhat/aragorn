#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/profile/state/openclaw.json";
const POLICY_LOG = "/profile/state/plug01-policy-requests.jsonl";
const SETUP_EVIDENCE = "/profile/state/plug01-setup.json";
const WORKSPACE = "/profile/workspace";
const SKILL_NAME = "aragorn-plug01-workshop";
const DRAFT_PATH = join(WORKSPACE, "PROPOSAL.md");
const TARGET_DIR = join(WORKSPACE, "skills", SKILL_NAME);
const TARGET_FILE = join(TARGET_DIR, "SKILL.md");
const CONTROL_NAME = "aragorn-policy-control";
const CONTROL_DIR = join(WORKSPACE, "policy-control");
const CONTROL_FILE = join(CONTROL_DIR, "SKILL.md");
const CONTROL_TARGET = join("/profile/state/skills", CONTROL_NAME);
const TEST_TOKEN = "aragorn-contained-plug01-token-v1";
const EXPECTED_VERSION = "OpenClaw 2026.7.1 (2d2ddc4)";
const EXPECTED_COMMIT = "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4";
const PLUG01_IMPLEMENTATION_DIGEST =
  "sha256:d70fb960c8cc6798815d47c82caf4f1bb9e064d54566ccccb45e76865de284ef";
const SELF = fileURLToPath(import.meta.url);
const OUTPUT_LIMIT = 2 * 1024 * 1024;
const RETAINED_TEXT_LIMIT = 2048;
const GATEWAY_LOG_LIMIT = 256 * 1024;
const DESCRIPTION = "Inert PLUG-01 workshop fixture";
const DRAFT = [
  "# Aragorn PLUG-01 workshop fixture",
  "",
  "This inert fixture performs no actions.",
  "",
].join("\n");
const SKILL = [
  "---",
  `name: "${SKILL_NAME}"`,
  `description: "${DESCRIPTION}"`,
  "---",
  "",
  "# Aragorn PLUG-01 workshop fixture",
  "",
  "This inert fixture performs no actions.",
  "",
].join("\n");
const CONTROL_SKILL = [
  "---",
  `name: ${CONTROL_NAME}`,
  "description: Inert install-policy positive control.",
  "---",
  "",
  "# Aragorn install-policy positive control",
  "",
  "This inert fixture performs no actions.",
  "",
].join("\n");
const PROFILE_ENV = {
  HOME: "/profile/home",
  HTTP_PROXY: "http://127.0.0.1:9",
  HTTPS_PROXY: "http://127.0.0.1:9",
  NO_COLOR: "1",
  NO_PROXY: "127.0.0.1,localhost",
  OPENCLAW_CONFIG_PATH: CONFIG,
  OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
  OPENCLAW_GATEWAY_TOKEN: TEST_TOKEN,
  OPENCLAW_NO_RESPAWN: "1",
  OPENCLAW_SKIP_CHANNELS: "1",
  OPENCLAW_SKIP_PROVIDERS: "1",
  OPENCLAW_STATE_DIR: "/profile/state",
  PATH: "/usr/local/bin:/usr/bin:/bin",
  npm_config_audit: "false",
  npm_config_fund: "false",
  npm_config_offline: "true",
};

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

function sha256(raw) {
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

function setupConfiguration() {
  return {
    agents: {
      defaults: { skills: ["aragorn-plug01-skill"], workspace: WORKSPACE },
      list: [
        {
          id: "main",
          skills: ["aragorn-plug01-skill"],
          workspace: WORKSPACE,
        },
      ],
    },
    plugins: {
      allow: ["aragorn-plug01"],
      enabled: true,
      entries: { "aragorn-plug01": { enabled: false } },
    },
    security: {
      installPolicy: {
        enabled: true,
        exec: {
          args: ["/probe/plug01-probe.mjs", "policy"],
          command: NODE,
          maxOutputBytes: 4096,
          noOutputTimeoutMs: 5000,
          source: "exec",
          timeoutMs: 5000,
          trustedDirs: ["/probe", "/usr/local/bin"],
        },
        targets: ["skill", "plugin"],
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

function workshopConfiguration() {
  const config = setupConfiguration();
  const skills = ["aragorn-plug01-skill", SKILL_NAME];
  config.agents.defaults.skills = skills;
  config.agents.list[0].skills = skills;
  return config;
}

function isCanonicalTimestamp(value) {
  if (typeof value !== "string") {
    return false;
  }
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function entryExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function command(args, timeout = 30_000) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(NODE, [OPENCLAW, ...args], {
    cwd: WORKSPACE,
    encoding: "utf8",
    env: PROFILE_ENV,
    maxBuffer: OUTPUT_LIMIT,
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
  const bounded = (value) =>
    value.length <= RETAINED_TEXT_LIMIT
      ? value
      : `${value.slice(0, RETAINED_TEXT_LIMIT)}[truncated]`;
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
    stderr_excerpt: bounded(result.stderr),
    stdout_bytes: Buffer.byteLength(result.stdout),
    stdout_digest: sha256(Buffer.from(result.stdout)),
    stdout_excerpt: bounded(result.stdout),
  };
}

function parseCommand(result, label) {
  if (result.exit_code !== 0) {
    throw new Error(`${label} failed: ${(result.stderr || result.stdout).trim()}`);
  }
  for (const output of [result.stdout, result.stderr]) {
    try {
      return JSON.parse(output);
    } catch {
      // OpenClaw service-control JSON may use either stream.
    }
  }
  throw new Error(`${label} did not return JSON`);
}

function gatewayCall(method, params = null, timeout = 5000) {
  const args = [
    "gateway",
    "call",
    method,
    "--json",
    "--timeout",
    String(timeout),
  ];
  if (params !== null) {
    args.push("--params", canonicalJson(params));
  }
  return command(args, timeout + 5000);
}

function boundedCapture(stream) {
  const hash = createHash("sha256");
  let bytes = 0;
  let retained = Buffer.alloc(0);
  stream.on("data", (chunk) => {
    const raw = Buffer.from(chunk);
    hash.update(raw);
    bytes += raw.length;
    if (retained.length < GATEWAY_LOG_LIMIT) {
      retained = Buffer.concat([
        retained,
        raw.subarray(0, GATEWAY_LOG_LIMIT - retained.length),
      ]);
    }
  });
  return {
    snapshot() {
      return {
        bytes,
        digest: `sha256:${hash.copy().digest("hex")}`,
        excerpt: retained.subarray(0, RETAINED_TEXT_LIMIT).toString("utf8"),
        retained_bytes: retained.length,
        truncated: bytes > retained.length,
      };
    },
  };
}

function startGateway() {
  const child = spawn(
    NODE,
    [
      OPENCLAW,
      "gateway",
      "run",
      "--allow-unconfigured",
      "--auth",
      "token",
      "--bind",
      "loopback",
      "--port",
      "18789",
      "--tailscale",
      "off",
      "--ws-log",
      "full",
    ],
    {
      cwd: WORKSPACE,
      env: PROFILE_ENV,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const lifecycle = { spawn_error: null };
  child.once("error", (error) => {
    lifecycle.spawn_error = error instanceof Error ? error.message : String(error);
  });
  const closed = new Promise((resolvePromise) => {
    child.once("close", (exitCode, signal) => {
      resolvePromise({ exit_code: exitCode, signal });
    });
  });
  return {
    child,
    closed,
    lifecycle,
    stderr: boundedCapture(child.stderr),
    stdout: boundedCapture(child.stdout),
  };
}

function gatewayRunning(gateway) {
  return (
    gateway.child.exitCode === null &&
    gateway.child.signalCode === null &&
    gateway.lifecycle.spawn_error === null
  );
}

async function waitForGateway(gateway) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (!gatewayRunning(gateway)) {
      throw new Error(
        `Gateway exited early: ${
          gateway.lifecycle.spawn_error ??
          gateway.child.signalCode ??
          gateway.child.exitCode
        }`,
      );
    }
    const call = gatewayCall("system.info");
    if (call.exit_code === 0) {
      const response = parseCommand(call, "system.info");
      if (response.pid === gateway.child.pid) {
        return { command: summarized(call), response };
      }
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
  }
  throw new Error("timed out waiting for the contained Gateway");
}

async function stopGateway(gateway) {
  let closed = null;
  if (gatewayRunning(gateway)) {
    gateway.child.kill("SIGTERM");
    closed = await Promise.race([
      gateway.closed,
      new Promise((resolvePromise) =>
        setTimeout(() => resolvePromise(null), 5000)),
    ]);
  }
  if (gatewayRunning(gateway)) {
    gateway.child.kill("SIGKILL");
    closed = await Promise.race([
      gateway.closed,
      new Promise((_, rejectPromise) =>
        setTimeout(
          () => rejectPromise(new Error("Gateway did not close after SIGKILL")),
          5000,
        )),
    ]);
  }
  return {
    exit_code: closed?.exit_code ?? gateway.child.exitCode,
    pid: gateway.child.pid,
    signal: closed?.signal ?? gateway.child.signalCode,
    spawn_error: gateway.lifecycle.spawn_error,
    stderr: gateway.stderr.snapshot(),
    stdout: gateway.stdout.snapshot(),
  };
}

function findGatewayLog() {
  const dir = "/tmp/openclaw";
  const names = readdirSync(dir)
    .filter((name) => name.endsWith(".log"))
    .sort();
  if (names.length !== 1) {
    throw new Error(`expected one Gateway log, found ${names.length}`);
  }
  return join(dir, names[0]);
}

function gatewayLogEvidence() {
  const path = findGatewayLog();
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > GATEWAY_LOG_LIMIT * 16) {
    throw new Error("Gateway log exceeded the bounded workshop probe limit");
  }
  const raw = readFileSync(path);
  if (raw.includes(TEST_TOKEN)) {
    throw new Error("Gateway log contains the contained test credential");
  }
  const records = raw
    .toString("utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const restartRecords = records.filter((record) =>
    /^(signal SIGUSR1 received|received SIGUSR1; restarting|restart mode: )/.test(
      String(record.message ?? ""),
    ),
  );
  const shutdownRecords = records.filter((record) =>
    /^shutdown completed cleanly /.test(String(record.message ?? "")),
  );
  return {
    bytes: raw.length,
    digest: sha256(raw),
    path: basename(path),
    ready_count: records.filter((record) => record.message === "gateway ready")
      .length,
    record_count: records.length,
    restart_records: restartRecords.map((record) => ({
      message: String(record.message).slice(0, 512),
      time: record.time ?? null,
    })),
    shutdown_records: shutdownRecords.map((record) => ({
      message: String(record.message).slice(0, 512),
      time: record.time ?? null,
    })),
  };
}

async function withGateway(run) {
  const gateway = startGateway();
  let value = null;
  let failure = null;
  try {
    value = await run(gateway);
  } catch (error) {
    failure = error;
  }
  const shutdown = await stopGateway(gateway);
  const finalLog = gatewayLogEvidence();
  if (failure !== null) {
    throw failure;
  }
  return { final_log: finalLog, shutdown, value };
}

function policySnapshot() {
  const stat = lstatSync(POLICY_LOG);
  const raw = readFileSync(POLICY_LOG);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== 0o600 ||
    raw.at(-1) !== 0x0a
  ) {
    throw new Error("PLUG-01 policy log identity changed");
  }
  const records = raw
    .toString("utf8")
    .split("\n")
    .slice(0, -1)
    .map((line) => {
      const record = JSON.parse(line);
      if (line !== canonicalJson(record)) {
        throw new Error("PLUG-01 policy record is not canonical");
      }
      return record;
    });
  return {
    count: records.length,
    digest: sha256(raw),
    path: POLICY_LOG,
    records,
  };
}

function configSnapshot(expectedCore) {
  const stat = lstatSync(CONFIG);
  const raw = readFileSync(CONFIG);
  const document = JSON.parse(raw);
  const { meta, ...core } = document;
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== 0o600 ||
    canonicalJson(core) !== canonicalJson(expectedCore) ||
    canonicalJson(Object.keys(meta ?? {}).sort()) !==
      '["lastTouchedAt","lastTouchedVersion"]' ||
    meta.lastTouchedVersion !== "2026.7.1" ||
    !isCanonicalTimestamp(meta.lastTouchedAt)
  ) {
    throw new Error("workshop configuration identity changed");
  }
  return {
    core_digest: sha256(Buffer.from(canonicalJson(core), "utf8")),
    digest: sha256(raw),
    document,
    mode: "600",
    path: CONFIG,
    size: raw.length,
  };
}

function prepareWorkshopConfiguration() {
  const setup = configSnapshot(setupConfiguration());
  const document = {
    ...workshopConfiguration(),
    meta: setup.document.meta,
  };
  const temporary = `${CONFIG}.workshop-${process.pid}`;
  writeFileSync(temporary, `${canonicalJson(document)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  renameSync(temporary, CONFIG);
  chmodSync(CONFIG, 0o600);
  return configSnapshot(workshopConfiguration());
}

function setupBinding() {
  const stat = lstatSync(SETUP_EVIDENCE);
  const raw = readFileSync(SETUP_EVIDENCE);
  const evidence = JSON.parse(raw);
  const policy = policySnapshot();
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== 0o600 ||
    !raw.equals(Buffer.from(`${canonicalJson(evidence)}\n`, "utf8")) ||
    evidence.schema !== "aragorn/openclaw-contained-plug01-setup-evidence/v1" ||
    evidence.setup?.status !== "PASS" ||
    evidence.decision?.status !== "NOT_TESTED" ||
    evidence.decision?.installer_work_eligible !== false ||
    evidence.adapter?.implementation_digest !== PLUG01_IMPLEMENTATION_DIGEST ||
    evidence.setup?.policy?.count !== 2 ||
    evidence.setup?.policy?.digest !== policy.digest
  ) {
    throw new Error("PLUG-01 setup evidence identity changed");
  }
  return {
    digest: sha256(raw),
    document: evidence,
    path: SETUP_EVIDENCE,
    policy_digest: policy.digest,
    recorded_at: evidence.recorded_at,
    schema: evidence.schema,
    target_digest: evidence.setup.target.digest,
  };
}

function fileProof(path, expected) {
  const stat = lstatSync(path);
  const raw = readFileSync(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    !raw.equals(Buffer.from(expected, "utf8"))
  ) {
    throw new Error(`workshop file identity changed: ${path}`);
  }
  return {
    bytes: raw.length,
    digest: sha256(raw),
    mode: (stat.mode & 0o777).toString(8).padStart(3, "0"),
    path,
    text: raw.toString("utf8"),
  };
}

function targetAbsence() {
  return {
    directory_absent: !entryExists(TARGET_DIR),
    file_absent: !entryExists(TARGET_FILE),
    path: TARGET_FILE,
  };
}

function validatePendingProposal(proposal) {
  const record = proposal.record;
  const target = record?.target;
  if (
    setOf(record) !==
      "createdAt,createdBy,description,draftFile,draftHash,id,kind,proposedVersion,scan,schema,status,target,title,updatedAt" ||
    record.schema !== "openclaw.skill-workshop.proposal.v1" ||
    !/^aragorn-plug01-workshop-\d{8}-[a-f0-9]{10}$/.test(record.id) ||
    record.kind !== "create" ||
    record.status !== "pending" ||
    record.title !== `Create ${SKILL_NAME}` ||
    record.description !== DESCRIPTION ||
    record.createdBy !== "cli" ||
    record.proposedVersion !== "v1" ||
    record.draftFile !== "PROPOSAL.md" ||
    record.updatedAt !== record.createdAt ||
    !isCanonicalTimestamp(record.createdAt) ||
    target?.skillName !== SKILL_NAME ||
    target?.skillKey !== SKILL_NAME ||
    target?.skillDir !== TARGET_DIR ||
    target?.skillFile !== TARGET_FILE ||
    target?.source !== "openclaw-workspace" ||
    record.scan?.state !== "clean" ||
    record.scan?.critical !== 0 ||
    record.scan?.warn !== 0 ||
    record.scan?.info !== 0 ||
    canonicalJson(record.scan?.findings) !== "[]" ||
    !isCanonicalTimestamp(record.scan?.scannedAt) ||
    typeof proposal.content !== "string" ||
    !proposal.content.endsWith(DRAFT) ||
    sha256(Buffer.from(proposal.content)).slice(7) !== record.draftHash
  ) {
    throw new Error("pending workshop proposal identity changed");
  }
  return proposal;
}

function setOf(value) {
  return Object.keys(value ?? {}).sort().join(",");
}

function validateAppliedProposal(applied, pending) {
  const record = applied.record;
  if (
    setOf(applied) !== "record,targetSkillFile" ||
    setOf(record) !==
      "appliedAt,createdAt,createdBy,description,draftFile,draftHash,id,kind,proposedVersion,scan,schema,status,target,title,updatedAt" ||
    record.id !== pending.record.id ||
    record.schema !== pending.record.schema ||
    record.kind !== "create" ||
    record.status !== "applied" ||
    record.title !== pending.record.title ||
    record.description !== DESCRIPTION ||
    record.createdAt !== pending.record.createdAt ||
    record.createdBy !== "cli" ||
    record.proposedVersion !== "v1" ||
    record.draftFile !== "PROPOSAL.md" ||
    record.draftHash !== pending.record.draftHash ||
    canonicalJson(record.target) !== canonicalJson(pending.record.target) ||
    record.scan?.state !== "clean" ||
    record.scan?.critical !== 0 ||
    record.scan?.warn !== 0 ||
    record.scan?.info !== 0 ||
    canonicalJson(record.scan?.findings) !== "[]" ||
    !isCanonicalTimestamp(record.scan?.scannedAt) ||
    !isCanonicalTimestamp(record.updatedAt) ||
    record.updatedAt !== record.appliedAt ||
    new Date(record.updatedAt) < new Date(record.createdAt) ||
    applied.targetSkillFile !== TARGET_FILE
  ) {
    throw new Error("applied workshop proposal identity changed");
  }
  return applied;
}

function workshopSkillStatus() {
  const call = gatewayCall("skills.status");
  const response = parseCommand(call, "skills.status");
  if (!Array.isArray(response.skills)) {
    throw new Error("skills.status omitted its skill array");
  }
  const matches = response.skills
    .filter((item) => item.name === SKILL_NAME)
    .map((item) => ({
      blocked_by_agent_filter: item.blockedByAgentFilter,
      command_visible: item.commandVisible,
      disabled: item.disabled,
      eligible: item.eligible,
      file_path: item.filePath,
      model_visible: item.modelVisible,
      name: item.name,
      source: item.source,
      user_invocable: item.userInvocable,
    }));
  const expected = [
    {
      blocked_by_agent_filter: false,
      command_visible: true,
      disabled: false,
      eligible: true,
      file_path: TARGET_FILE,
      model_visible: true,
      name: SKILL_NAME,
      source: "openclaw-workspace",
      user_invocable: true,
    },
  ];
  if (canonicalJson(matches) !== canonicalJson(expected)) {
    throw new Error("workshop skill did not become model-visible");
  }
  return { command: summarized(call), matches };
}

function runtimeVersion() {
  const version = command(["--version"]);
  if (version.exit_code !== 0 || version.stdout.trim() !== EXPECTED_VERSION) {
    throw new Error(`unexpected OpenClaw version: ${version.stdout.trim()}`);
  }
  return {
    commit: EXPECTED_COMMIT,
    name: "OpenClaw",
    version: "2026.7.1",
    version_command: summarized(version),
  };
}

async function run() {
  if (process.env.OPENCLAW_GATEWAY_TOKEN !== TEST_TOKEN) {
    throw new Error("unexpected contained Gateway test credential");
  }
  mkdirSync(WORKSPACE, { recursive: true, mode: 0o700 });
  const consumedSetup = setupBinding();
  const policyBefore = policySnapshot();
  const configBefore = prepareWorkshopConfiguration();
  const absentBefore = targetAbsence();
  if (!absentBefore.directory_absent || !absentBefore.file_absent) {
    throw new Error("workshop skill target existed before proposal");
  }
  mkdirSync(CONTROL_DIR, { recursive: false, mode: 0o755 });
  writeFileSync(CONTROL_FILE, CONTROL_SKILL, { flag: "wx", mode: 0o444 });
  const controlSource = fileProof(CONTROL_FILE, CONTROL_SKILL);
  writeFileSync(DRAFT_PATH, DRAFT, { flag: "wx", mode: 0o444 });
  const draft = fileProof(DRAFT_PATH, DRAFT);
  const runtime = runtimeVersion();

  const gateway = await withGateway(async (running) => {
    const ready = await waitForGateway(running);
    const processBefore = {
      alive: gatewayRunning(running),
      pid: running.child.pid,
      system_info_pid: ready.response.pid,
    };
    const control = command([
      "skills",
      "install",
      CONTROL_DIR,
      "--as",
      CONTROL_NAME,
      "--global",
    ]);
    const policyAfterControl = policySnapshot();
    if (
      control.exit_code !== 1 ||
      !control.stderr.includes("blocked by install policy") ||
      entryExists(CONTROL_TARGET) ||
      policyAfterControl.count !== policyBefore.count + 1 ||
      policyAfterControl.digest === policyBefore.digest ||
      policyAfterControl.records.at(-1)?.decision !== "block" ||
      policyAfterControl.records.at(-1)?.request?.targetType !== "skill"
    ) {
      throw new Error("skill install-policy positive control did not fail closed");
    }
    const propose = command([
      "skills",
      "workshop",
      "--agent",
      "main",
      "propose-create",
      "--name",
      SKILL_NAME,
      "--description",
      DESCRIPTION,
      "--proposal",
      DRAFT_PATH,
      "--json",
    ]);
    const pending = validatePendingProposal(
      parseCommand(propose, "workshop propose-create"),
    );
    const absentAfterProposal = targetAbsence();
    const policyAfterProposal = policySnapshot();
    if (
      !absentAfterProposal.directory_absent ||
      !absentAfterProposal.file_absent ||
      policyAfterProposal.digest !== policyAfterControl.digest ||
      policyAfterProposal.count !== policyAfterControl.count
    ) {
      throw new Error("proposal creation changed the target or install policy log");
    }

    const apply = gatewayCall("skills.proposals.apply", {
      agentId: "main",
      proposalId: pending.record.id,
    });
    const applied = validateAppliedProposal(
      parseCommand(apply, "skills.proposals.apply"),
      pending,
    );
    const target = fileProof(TARGET_FILE, SKILL);
    const status = workshopSkillStatus();
    const policyAfterApply = policySnapshot();
    const configAfter = configSnapshot(workshopConfiguration());
    const infoAfterCall = gatewayCall("system.info");
    const infoAfter = parseCommand(infoAfterCall, "system.info after workshop apply");
    const processAfter = {
      alive: gatewayRunning(running),
      pid: running.child.pid,
      system_info_pid: infoAfter.pid,
    };
    if (
      policyAfterApply.digest !== policyAfterControl.digest ||
      policyAfterApply.count !== policyAfterControl.count ||
      configAfter.digest !== configBefore.digest ||
      !processBefore.alive ||
      !processAfter.alive ||
      processBefore.pid !== processAfter.pid ||
      processBefore.system_info_pid !== processAfter.system_info_pid
    ) {
      throw new Error("workshop bypass boundary changed");
    }
    return {
      apply: {
        command: summarized(apply),
        response: applied,
      },
      config_after: configAfter,
      config_before: configBefore,
      control: {
        command: summarized(control),
        installed: entryExists(CONTROL_TARGET),
        source: controlSource,
        target: CONTROL_TARGET,
      },
      policy_after_apply: policyAfterApply,
      policy_after_control: policyAfterControl,
      policy_after_proposal: policyAfterProposal,
      policy_before: policyBefore,
      process_after: processAfter,
      process_before: processBefore,
      proposal: {
        command: summarized(propose),
        response: pending,
      },
      status_after: status,
      target_absent_after_proposal: absentAfterProposal,
      target_absent_before: absentBefore,
      target_after: target,
    };
  });

  if (
    gateway.final_log.ready_count !== 1 ||
    gateway.final_log.restart_records.length !== 0 ||
    gateway.final_log.shutdown_records.length !== 1 ||
    !/^shutdown completed cleanly /.test(
      gateway.final_log.shutdown_records[0].message,
    )
  ) {
    throw new Error("unexpected workshop Gateway lifecycle");
  }
  return {
    adapter: {
      configuration: workshopConfiguration(),
      configuration_digest: sha256(
        Buffer.from(canonicalJson(workshopConfiguration()), "utf8"),
      ),
      implementation_digest: sha256(readFileSync(SELF)),
      name: "openclaw-contained-workshop-bypass",
    },
    assurance: "SELF_REPORTED_CONTAINED_RUNTIME_NOT_INDEPENDENTLY_ATTESTED",
    consumed_setup: consumedSetup,
    decision: { installer_work_eligible: false, status: "FAIL" },
    draft,
    gateway: {
      final_log: gateway.final_log,
      shutdown: gateway.shutdown,
    },
    recorded_at: new Date().toISOString(),
    runtime,
    scenario: {
      evidence: gateway.value,
      id: "ADM-02/update/workshop-proposal-apply",
      reason_codes: ["WORKSHOP_APPLY_BYPASSES_INSTALL_POLICY"],
      status: "FAIL",
    },
    schema: "aragorn/openclaw-contained-workshop-bypass-evidence/v1",
  };
}

function selfCheck() {
  const checks = {
    adapter_digest_is_sha256:
      /^sha256:[a-f0-9]{64}$/.test(sha256(readFileSync(SELF))),
    draft_is_inert:
      DRAFT.includes("inert fixture") && !/[`$]|https?:|exec|spawn/.test(DRAFT),
    positive_control_is_inert:
      CONTROL_SKILL.includes("positive control") &&
      !/[`$]|https?:|exec|spawn/.test(CONTROL_SKILL),
    policy_targets_skills:
      setupConfiguration().security.installPolicy.targets.includes("skill"),
    skill_digest_is_sha256:
      /^sha256:[a-f0-9]{64}$/.test(sha256(Buffer.from(SKILL))),
    workshop_skill_is_agent_selected:
      workshopConfiguration().agents.defaults.skills.includes(SKILL_NAME),
  };
  return {
    checks,
    implementation_digest: sha256(readFileSync(SELF)),
    schema: "aragorn/openclaw-contained-workshop-bypass-self-check/v1",
    status: Object.values(checks).every(Boolean) ? "PASS" : "FAIL",
  };
}

async function main() {
  const mode = process.argv[2];
  if (mode === "self-check") {
    const result = selfCheck();
    process.stdout.write(`${canonicalJson(result)}\n`);
    if (result.status !== "PASS") {
      process.exitCode = 1;
    }
    return;
  }
  if (mode === "run") {
    process.stdout.write(`${canonicalJson(await run())}\n`);
    return;
  }
  throw new Error(
    `unknown workshop bypass probe mode: ${mode ?? "(missing)"}; expected run or self-check`,
  );
}

main().catch((error) => {
  process.stdout.write(
    `${canonicalJson({
      error: error instanceof Error ? error.message : String(error),
      schema: "aragorn/openclaw-contained-workshop-bypass-error/v1",
      status: "ERROR",
    })}\n`,
  );
  process.exitCode = 1;
});
