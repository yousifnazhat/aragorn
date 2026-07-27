#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const ADM03_EVIDENCE = "/tmp/contained-adm03.json";
const CONFIG = "/profile/config/openclaw.json";
const ADMITTED_FILE =
  "/profile/state/skills/aragorn-admitted/SKILL.md";
const PROBE_ROOT = "/probe";
const PROBE_FILES = [
  "adm03-probe.mjs",
  "contained-probe.mjs",
  "probe.mjs",
  "restart-probe.mjs",
];
const POLICY_SCRIPT = join(PROBE_ROOT, "contained-probe.mjs");
const TEST_TOKEN = "aragorn-contained-restart-token-v1";
const INVALID_TEST_TOKEN = "aragorn-invalid-test-token-v1";
const SELF = fileURLToPath(import.meta.url);
const PROFILE_ENV = {
  HOME: "/profile/home",
  OPENCLAW_CONFIG_PATH: CONFIG,
  OPENCLAW_GATEWAY_TOKEN: TEST_TOKEN,
  OPENCLAW_STATE_DIR: "/profile/state",
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

function command(args) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(NODE, [OPENCLAW, ...args], {
    cwd: "/profile/workspace",
    encoding: "utf8",
    env: PROFILE_ENV,
    maxBuffer: 16 * 1024 * 1024,
    timeout: 20_000,
  });
  return {
    argv: [NODE, OPENCLAW, ...args],
    completed_at: new Date().toISOString(),
    exit_code: result.status,
    pid: result.pid,
    signal: result.signal,
    started_at: startedAt,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    error: result.error?.message ?? null,
  };
}

function summarizedCommand(result) {
  const { stdout, ...summary } = result;
  const raw = Buffer.from(stdout, "utf8");
  return {
    ...summary,
    stdout_bytes: raw.length,
    stdout_digest: sha256(raw),
  };
}

function parsedCommand(result, label) {
  if (result.exit_code !== 0) {
    throw new Error(`${label} failed: ${result.stderr.trim()}`);
  }
  for (const output of [result.stdout, result.stderr]) {
    if (!output.trim()) {
      continue;
    }
    try {
      return JSON.parse(output);
    } catch {
      // OpenClaw service-control JSON is written to stderr.
    }
  }
  throw new Error(`${label} did not return JSON`);
}

function gatewayCall(method, params = null) {
  const args = [
    "gateway",
    "call",
    method,
    "--json",
    "--timeout",
    "5000",
  ];
  if (params !== null) {
    args.push("--params", canonicalJson(params));
  }
  return command(args);
}

function invalidAuthentication() {
  const result = command([
    "gateway",
    "call",
    "system.info",
    "--token",
    INVALID_TEST_TOKEN,
    "--json",
    "--timeout",
    "5000",
  ]);
  let response = null;
  try {
    response = JSON.parse(result.stdout);
  } catch {
    // The nonzero exit and explicit unauthorized text still fail closed.
  }
  const unauthorized =
    result.exit_code === 1 &&
    `${result.stdout}\n${result.stderr}`.includes("unauthorized") &&
    response?.ok === false &&
    response?.error?.code === 1008;
  return {
    command: summarizedCommand(result),
    response,
    status: unauthorized ? "PASS" : "FAIL",
  };
}

function implementationClosure() {
  const entries = readdirSync(PROBE_ROOT).sort();
  if (canonicalJson(entries) !== canonicalJson(PROBE_FILES)) {
    throw new Error("/probe executable closure changed");
  }
  const fields = {
    "adm03-probe.mjs": "adm03_probe_digest",
    "contained-probe.mjs": "contained_probe_digest",
    "probe.mjs": "baseline_probe_digest",
    "restart-probe.mjs": "restart_probe_digest",
  };
  return Object.fromEntries(
    PROBE_FILES.map((name) => {
      const path = join(PROBE_ROOT, name);
      const stat = lstatSync(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
        throw new Error(`${path} is not one regular unlinked file`);
      }
      return [fields[name], sha256(readFileSync(path))];
    }),
  );
}

function protectedState() {
  return {
    admitted_digest: sha256(readFileSync(ADMITTED_FILE)),
    configuration_digest: sha256(readFileSync(CONFIG)),
    implementation: implementationClosure(),
    policy_digest: sha256(readFileSync(POLICY_SCRIPT)),
  };
}

function processIdentity(pid) {
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

function findGatewayLog() {
  const paths = readdirSync("/tmp/openclaw")
    .filter((name) => name.endsWith(".log"))
    .sort();
  if (paths.length !== 1) {
    throw new Error(`expected one Gateway log, found ${paths.length}`);
  }
  return join("/tmp/openclaw", paths[0]);
}

function logSnapshot(path) {
  const raw = readFileSync(path);
  const lines = raw.toString("utf8").split("\n");
  if (lines.at(-1) === "") {
    lines.pop();
  }
  let offset = 0;
  const records = lines.map((line) => {
    const record = {
      document: JSON.parse(line),
      offset,
      raw: line,
    };
    offset += Buffer.byteLength(line, "utf8") + 1;
    return record;
  });
  return { lines, raw, records };
}

function matchingRecord(snapshot, pattern, after = -1) {
  return snapshot.records.find(
    (record) =>
      record.offset > after &&
      pattern.test(record.document.message ?? ""),
  );
}

function marker(record) {
  const message = record.document.message ?? "";
  const rpc = /conn=(\S+) id=(\S+)/.exec(message);
  return {
    connection_id: rpc?.[1] ?? null,
    message,
    offset: record.offset,
    request_id: rpc?.[2] ?? null,
    time: record.document.time ?? null,
    trace_id: record.document.traceId ?? null,
  };
}

async function waitForLog(path, predicate, label) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const snapshot = logSnapshot(path);
    if (predicate(snapshot)) {
      return snapshot;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`timed out waiting for ${label}`);
}

function skillProjection(status) {
  return {
    agent_id: status.agentId,
    agent_skill_filter: status.agentSkillFilter,
    managed_skills_dir: status.managedSkillsDir,
    skills: status.skills.map((skill) => ({
      base_dir: skill.baseDir,
      blocked_by_agent_filter: skill.blockedByAgentFilter,
      blocked_by_allowlist: skill.blockedByAllowlist,
      command_visible: skill.commandVisible,
      disabled: skill.disabled,
      eligible: skill.eligible,
      file_path: skill.filePath,
      model_visible: skill.modelVisible,
      name: skill.name,
      source: skill.source,
      user_invocable: skill.userInvocable,
    })),
    workspace_dir: status.workspaceDir,
  };
}

function validProjection(projection) {
  const effective = projection.skills.filter(
    (skill) =>
      !skill.disabled &&
      !skill.blocked_by_allowlist &&
      !skill.blocked_by_agent_filter &&
      (skill.eligible || skill.model_visible || skill.command_visible),
  );
  const admitted = effective[0];
  return (
    projection.agent_id === "main" &&
    canonicalJson(projection.agent_skill_filter) ===
      '["aragorn-admitted"]' &&
    projection.managed_skills_dir === "/profile/state/skills" &&
    projection.workspace_dir === "/profile/workspace" &&
    effective.length === 1 &&
    admitted?.name === "aragorn-admitted" &&
    admitted?.source === "openclaw-managed" &&
    admitted?.file_path === ADMITTED_FILE &&
    admitted?.base_dir === dirname(ADMITTED_FILE) &&
    admitted?.disabled === false &&
    admitted?.blocked_by_allowlist === false &&
    admitted?.blocked_by_agent_filter === false &&
    admitted?.eligible === true &&
    admitted?.model_visible === true &&
    admitted?.command_visible === true &&
    admitted?.user_invocable === true &&
    projection.skills
      .filter((skill) => skill.name !== "aragorn-admitted")
      .every(
        (skill) =>
          skill.blocked_by_agent_filter === true &&
          skill.model_visible === false &&
          skill.command_visible === false,
      )
  );
}

async function main() {
  if (process.env.OPENCLAW_GATEWAY_TOKEN !== TEST_TOKEN) {
    throw new Error("unexpected contained Gateway test credential");
  }
  const adm03Raw = readFileSync(ADM03_EVIDENCE);
  const adm03 = JSON.parse(adm03Raw);
  if (
    adm03.schema !==
      "aragorn/openclaw-contained-adm03-probe-evidence/v1" ||
    adm03.decision?.status !== "NOT_TESTED" ||
    !adm03Raw.equals(Buffer.from(`${canonicalJson(adm03)}\n`, "ascii")) ||
    adm03.scenarios.some((scenario) => scenario.status !== "PASS") ||
    adm03.contained_profile.evidence.scenarios.some(
      (scenario) => scenario.status !== "PASS",
    )
  ) {
    throw new Error("contained ADM-03 replay identity changed");
  }

  const implementation = implementationClosure();
  if (
    implementation.adm03_probe_digest !==
      adm03.adapter.implementation.adm03_probe_digest ||
    implementation.baseline_probe_digest !==
      adm03.adapter.implementation.baseline_probe_digest ||
    implementation.contained_probe_digest !==
      adm03.adapter.implementation.contained_probe_digest ||
    implementation.restart_probe_digest !== sha256(readFileSync(SELF))
  ) {
    throw new Error("probe implementation closure changed");
  }

  const logPath = findGatewayLog();
  const initial = await waitForLog(
    logPath,
    (snapshot) => matchingRecord(snapshot, /^gateway ready$/),
    "initial Gateway readiness",
  );
  const firstReady = matchingRecord(initial, /^gateway ready$/);
  const stateBefore = protectedState();
  const processBefore = processIdentity(1);

  const invalidBefore = invalidAuthentication();
  const systemBeforeCommand = gatewayCall("system.info");
  const systemBefore = parsedCommand(
    systemBeforeCommand,
    "pre-restart system.info",
  );
  const statusBeforeCommand = gatewayCall("skills.status", {
    agentId: "main",
  });
  const statusBefore = parsedCommand(
    statusBeforeCommand,
    "pre-restart skills.status",
  );
  const projectionBefore = skillProjection(statusBefore);
  const beforeSnapshot = logSnapshot(logPath);
  if (
    invalidBefore.status !== "PASS" ||
    systemBefore.pid !== 1 ||
    !validProjection(projectionBefore)
  ) {
    throw new Error("pre-restart authenticated Gateway state was not proven");
  }

  const restartBoundary = beforeSnapshot.raw.length;
  const restartCommand = command([
    "gateway",
    "restart",
    "--safe",
    "--json",
  ]);
  const restart = parsedCommand(restartCommand, "safe Gateway restart");
  const emptyCounts = {
    activeTasks: 0,
    cronRuns: 0,
    embeddedRuns: 0,
    pendingReplies: 0,
    queueSize: 0,
    totalActive: 0,
  };
  if (
    restart.ok !== true ||
    restart.result !== "scheduled" ||
    restart.preflight?.safe !== true ||
    canonicalJson(restart.preflight?.counts) !==
      canonicalJson(emptyCounts) ||
    restart.preflight?.blockers?.length !== 0 ||
    restart.restart?.ok !== true ||
    restart.restart?.pid !== 1 ||
    restart.restart?.signal !== "SIGUSR1" ||
    restart.restart?.reason !== "gateway.restart.safe" ||
    restart.restart?.mode !== "emit" ||
    restart.restart?.coalesced !== false
  ) {
    throw new Error("Gateway did not accept the bounded safe restart");
  }

  const restarted = await waitForLog(
    logPath,
    (snapshot) =>
      Boolean(
        matchingRecord(
          snapshot,
          /^gateway ready$/,
          restartBoundary - 1,
        ),
      ),
    "post-restart Gateway readiness",
  );
  const signal = matchingRecord(
    restarted,
    /^signal SIGUSR1 received$/,
    restartBoundary - 1,
  );
  const restarting = matchingRecord(
    restarted,
    /^received SIGUSR1; restarting$/,
    signal?.offset,
  );
  const shutdown = matchingRecord(
    restarted,
    /^shutdown completed cleanly /,
    restarting?.offset,
  );
  const restartMode = matchingRecord(
    restarted,
    /^restart mode: in-process restart /,
    shutdown?.offset,
  );
  const secondReady = matchingRecord(
    restarted,
    /^gateway ready$/,
    restartMode?.offset,
  );
  if (!signal || !restarting || !shutdown || !restartMode || !secondReady) {
    throw new Error("Gateway restart lifecycle was incomplete or unordered");
  }

  const systemAfterCommand = gatewayCall("system.info");
  const systemAfter = parsedCommand(
    systemAfterCommand,
    "post-restart system.info",
  );
  const statusAfterCommand = gatewayCall("skills.status", {
    agentId: "main",
  });
  const statusAfter = parsedCommand(
    statusAfterCommand,
    "post-restart skills.status",
  );
  const projectionAfter = skillProjection(statusAfter);
  const postAuthBoundary = logSnapshot(logPath).raw.length - 1;
  const invalidAfter = invalidAuthentication();
  const finalSnapshot = await waitForLog(
    logPath,
    (snapshot) =>
      Boolean(
        matchingRecord(
          snapshot,
          /^unauthorized conn=/,
          postAuthBoundary,
        ),
      ),
    "post-restart authentication denial trace",
  );
  const stateAfter = protectedState();
  const processAfter = processIdentity(1);
  const statusBytesEqual =
    statusBeforeCommand.stdout === statusAfterCommand.stdout;
  const projectionEqual =
    canonicalJson(projectionBefore) === canonicalJson(projectionAfter);
  const stateEqual =
    canonicalJson(stateBefore) === canonicalJson(stateAfter);
  const processEqual =
    canonicalJson(processBefore) === canonicalJson(processAfter);
  const freshClients =
    statusBeforeCommand.pid > 1 &&
    statusAfterCommand.pid > 1 &&
    statusBeforeCommand.pid !== statusAfterCommand.pid &&
    Date.parse(statusBeforeCommand.completed_at) <=
      Date.parse(restartCommand.started_at) &&
    Date.parse(statusAfterCommand.started_at) >=
      Date.parse(secondReady.document.time);
  const logHasNoCredential =
    !finalSnapshot.raw.includes(TEST_TOKEN) &&
    !finalSnapshot.raw.includes(INVALID_TEST_TOKEN);
  const passed =
    invalidAfter.status === "PASS" &&
    systemAfter.pid === 1 &&
    validProjection(projectionAfter) &&
    statusBytesEqual &&
    projectionEqual &&
    stateEqual &&
    processEqual &&
    freshClients &&
    logHasNoCredential;

  const scenario = {
    commands: {
      authentication_after: invalidAfter,
      authentication_before: invalidBefore,
      restart: summarizedCommand(restartCommand),
      skills_after: summarizedCommand(statusAfterCommand),
      skills_before: summarizedCommand(statusBeforeCommand),
      system_after: summarizedCommand(systemAfterCommand),
      system_before: summarizedCommand(systemBeforeCommand),
    },
    evidence: {
      admitted: {
        digest_after: stateAfter.admitted_digest,
        digest_before: stateBefore.admitted_digest,
        path: ADMITTED_FILE,
      },
      gateway_log: {
        bytes: finalSnapshot.raw.length,
        digest: sha256(finalSnapshot.raw),
        lines: finalSnapshot.lines,
        path: basename(logPath),
      },
      lifecycle: {
        first_ready: marker(firstReady),
        process_after: processAfter,
        process_before: processBefore,
        restart_mode: marker(restartMode),
        restarting: marker(restarting),
        second_ready: marker(secondReady),
        shutdown: marker(shutdown),
        signal: marker(signal),
      },
      protected_state_after: stateAfter,
      protected_state_before: stateBefore,
      restart_response: restart,
      rpc_clients: {
        skills_after: {
          completed_at: statusAfterCommand.completed_at,
          pid: statusAfterCommand.pid,
          started_at: statusAfterCommand.started_at,
        },
        skills_before: {
          completed_at: statusBeforeCommand.completed_at,
          pid: statusBeforeCommand.pid,
          started_at: statusBeforeCommand.started_at,
        },
      },
      skills: {
        projection_after: projectionAfter,
        projection_before: projectionBefore,
        raw_bytes_equal: statusBytesEqual,
      },
      system_info: {
        after: systemAfter,
        before: systemBefore,
      },
    },
    id: "ADM-02/restart",
    status: passed ? "PASS" : "FAIL",
  };
  const failed = !passed;
  const evidence = {
    adapter: {
      configuration: adm03.adapter.configuration,
      configuration_digest: adm03.adapter.configuration_digest,
      implementation,
      implementation_digest: sha256(
        Buffer.from(canonicalJson(implementation), "ascii"),
      ),
    },
    adm03_profile: {
      digest: sha256(adm03Raw),
      evidence: adm03,
    },
    decision: {
      installer_work_eligible: false,
      status: failed ? "FAIL" : "NOT_TESTED",
    },
    limitations: [
      "DET_01_ADM_01_UPDATE_AND_RELOAD_REMAIN_NOT_TESTED",
      "FIXED_GATEWAY_TOKEN_IS_A_NON_SECRET_LOOPBACK_TEST_CREDENTIAL",
      "RESTART_SCOPED_TO_OPENCLAW_CONTAINER_IN_PROCESS_SIGUSR1",
    ],
    recorded_at: new Date().toISOString(),
    runtime: adm03.runtime,
    scenarios: [scenario],
    schema: "aragorn/openclaw-contained-restart-probe-evidence/v1",
  };
  process.stdout.write(`${canonicalJson(evidence)}\n`);
  process.exitCode = failed ? 2 : 0;
}

await main();
