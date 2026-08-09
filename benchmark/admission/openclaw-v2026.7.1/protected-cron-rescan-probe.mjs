#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CONFIG,
  EXPECTED_OPENCLAW_DIGEST,
  EXPECTED_RUNTIME_TREE,
  NODE,
  OPENCLAW,
  canonicalJson,
  cleanCommand,
  command,
  configObservation,
  errorRecord,
  gatewayCall,
  gatewayProcessObservation,
  helperDigest,
  parsedCommand,
  pathObservation,
  protectedBoundary,
  protectedRootTrees,
  runtimeTree,
  sha256,
  treeObservation,
} from "./protected-observation-v1.mjs";

const SELF = fileURLToPath(import.meta.url);
const TARGET_NAME = "requesting-code-review";
const TARGET = `/profile/workspace/skills/${TARGET_NAME}`;
const SESSION_STORE = "/profile/state/agents/main/sessions/sessions.json";
const CRON_NAME = "Aragorn protected cron rescan probe";
const RUN_NONCE = randomBytes(16).toString("hex");
const EXPECTED_TARGET_DIGEST =
  "sha256:1a13f195721f8fa75974bd4918a25b30e8406ff6d423cd0e3306c391b8fee07a";
const EXPECTED_TARGET_TREE_DIGEST =
  "sha256:c3e201e18e2fa35a56d4cae3a0ed481072f4ed77db18e6d568b266068cbe96c3";
const EXPECTED_PROMPT = `

The following skills provide specialized instructions for specific tasks.
Use the read tool to load a skill's file when the task matches its description.
If a skill's <version> differs from a previous turn, re-read its SKILL.md before using it.
When a skill file references a relative path, resolve it against the skill directory (parent of SKILL.md / dirname of the path) and use that absolute path in tool commands.

<available_skills>
  <skill>
    <name>requesting-code-review</name>
    <description>Inert protected archive replacement target v1.</description>
    <location>/profile/workspace/skills/requesting-code-review/SKILL.md</location>
    <version>sha256:1a13f195721f8fa7</version>
  </skill>
</available_skills>`;
const EXPECTED_PROMPT_DIGEST =
  "sha256:bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c";
const UUID4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CRON_MODULES = Object.freeze({
  cron: {
    bytes: 33_974,
    digest:
      "sha256:0e3346d4397db7675073c7f80599aa312a1819b0f5a6480a8ba194b296c78144",
    path: "/runtime/lib/node_modules/openclaw/dist/cron-BoFeDMVi.js",
  },
  cron_snapshot: {
    bytes: 53,
    digest:
      "sha256:15050c3de10192ae1190d0aa596d34c2163897948a360fe0494929e171a01967",
    path: "/runtime/lib/node_modules/openclaw/dist/cron-snapshot.runtime.js",
  },
  cron_snapshot_implementation: {
    bytes: 450,
    digest:
      "sha256:fb9c29ca637b42389355d627c5e8a209a8d1ebb51b14432a462d9734f00e3665",
    path:
      "/runtime/lib/node_modules/openclaw/dist/cron-snapshot.runtime-xn4WDHsg.js",
  },
  isolated_agent: {
    bytes: 59_535,
    digest:
      "sha256:7330ff0387ffde3117c50752d5c656a522b2f32a5110cb494bdc1af2c106eb11",
    path: "/runtime/lib/node_modules/openclaw/dist/isolated-agent-wBFsap3y.js",
  },
  prompt_blobs: {
    bytes: 6_621,
    digest:
      "sha256:24164fbc0679c4eb55476a0bcbd2325660f59a47577509f838c682eb516e0553",
    path:
      "/runtime/lib/node_modules/openclaw/dist/skill-prompt-blobs-zJRX9N65.js",
  },
  run_session_state: {
    bytes: 18_238,
    digest:
      "sha256:aa5dad173c4d37034c0414c72093d0492009de77ff274ba4d2f7b3d509dc3817",
    path:
      "/runtime/lib/node_modules/openclaw/dist/run-session-state-r5DnSgVq.js",
  },
  session: {
    bytes: 5_884,
    digest:
      "sha256:59a2138c9906cffe26e67ad662d1a35d835c10d8d8742a2cb928fc529df81e3b",
    path: "/runtime/lib/node_modules/openclaw/dist/session-B4NuLEbl.js",
  },
  session_snapshot: {
    bytes: 3_163,
    digest:
      "sha256:0d93f74fca9a9f8a062d9e03953eda42419ceab49b296e194fd2ed510eb29eec",
    path:
      "/runtime/lib/node_modules/openclaw/dist/session-snapshot-mFoFiIO4.js",
  },
  workspace_skills: {
    bytes: 47_738,
    digest:
      "sha256:ee73b5621ff0fa5d198cb39a54eb6fa332d1f96897e4151538415eef7a72846c",
    path: "/runtime/lib/node_modules/openclaw/dist/workspace-BKXau6p-.js",
  },
});

function moduleObservations() {
  return Object.fromEntries(
    Object.entries(CRON_MODULES).map(([name, expected]) => [
      name,
      { expected, observed: pathObservation(expected.path, { hashFile: true }) },
    ]),
  );
}

function exactModules(modules) {
  return Object.values(modules).every(
    ({ expected, observed }) =>
      observed.exists === true &&
      observed.type === "file" &&
      observed.size === expected.bytes &&
      observed.digest === expected.digest,
  );
}

function exactTarget(tree) {
  const skill = tree.entries[0];
  return (
    tree.ready &&
    tree.tree_digest === EXPECTED_TARGET_TREE_DIGEST &&
    tree.entries.length === 1 &&
    tree.root.uid === 0 &&
    tree.root.gid === 982 &&
    tree.root.mode === "750" &&
    skill.path === "SKILL.md" &&
    skill.type === "file" &&
    skill.uid === 0 &&
    skill.gid === 982 &&
    skill.mode === "440" &&
    skill.nlink === 1 &&
    skill.digest === EXPECTED_TARGET_DIGEST
  );
}

function discovery() {
  const native = command([
    "skills",
    "info",
    TARGET_NAME,
    "--agent",
    "main",
    "--json",
  ]);
  return { command: native, response: parsedCommand(native) };
}

function exactDiscovery(value) {
  const skill = value.response.value;
  return (
    value.command.exit_code === 0 &&
    cleanCommand(value.command) &&
    value.response.parsed &&
    skill?.name === TARGET_NAME &&
    skill?.skillKey === TARGET_NAME &&
    skill?.baseDir === TARGET &&
    skill?.filePath === `${TARGET}/SKILL.md` &&
    skill?.source === "openclaw-workspace" &&
    skill?.description ===
      "Inert protected archive replacement target v1." &&
    skill?.disabled === false &&
    skill?.eligible === true &&
    skill?.modelVisible === true
  );
}

function systemInfo() {
  const native = gatewayCall("system.info");
  return { command: native, response: parsedCommand(native) };
}

function nativeCall(method, params, commands) {
  const native = gatewayCall(method, params);
  commands.push(native);
  return { command: native, params, response: parsedCommand(native) };
}

function promptPath(ref) {
  if (
    ref?.version !== 1 ||
    ref?.algorithm !== "sha256" ||
    !/^[a-f0-9]{64}$/.test(ref?.hash ?? "") ||
    ref?.bytes !== 728
  ) {
    throw new Error("isolated cron snapshot has no exact protected promptRef");
  }
  return join(
    dirname(SESSION_STORE),
    "skills-prompts",
    "sha256",
    ref.hash.slice(0, 2),
    `${ref.hash}.txt`,
  );
}

function fileProof(path, expectedRef = null) {
  const stat = lstatSync(path, { bigint: true });
  const raw = readFileSync(path);
  const digest = sha256(raw);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1n ||
    (stat.mode & 0o777n) !== 0o600n ||
    (expectedRef !== null &&
      (raw.length !== expectedRef.bytes ||
        digest !== `sha256:${expectedRef.hash}`))
  ) {
    throw new Error(`isolated cron state failed integrity validation: ${path}`);
  }
  return {
    bytes: raw.length,
    digest,
    gid: Number(stat.gid),
    inode: Number(stat.ino),
    mode: "600",
    mtime_ns: stat.mtimeNs.toString(),
    nlink: 1,
    path,
    uid: Number(stat.uid),
  };
}

function sessionStateBeforeRun(jobId) {
  const startedAt = new Date().toISOString();
  const baseSessionKey = `agent:main:cron:${jobId}`;
  if (!existsSync(SESSION_STORE)) {
    return {
      base_entry_present: false,
      base_session_key: baseSessionKey,
      completed_at: new Date().toISOString(),
      started_at: startedAt,
      store: pathObservation(SESSION_STORE, { hashFile: true }),
      store_document_digest: null,
      top_level_keys: [],
    };
  }
  const raw = readFileSync(SESSION_STORE);
  const store = JSON.parse(raw.toString("utf8"));
  const proof = fileProof(SESSION_STORE);
  if (proof.bytes !== raw.length || proof.digest !== sha256(raw)) {
    throw new Error("session store changed during the pre-run observation");
  }
  return {
    base_entry_present: Object.hasOwn(store, baseSessionKey),
    base_session_key: baseSessionKey,
    completed_at: new Date().toISOString(),
    started_at: startedAt,
    store: proof,
    store_document_digest: sha256(raw),
    top_level_keys: Object.keys(store).sort(),
  };
}

function cronSnapshot(jobId) {
  const sessionKey = `agent:main:cron:${jobId}`;
  const store = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
  const entry = store[sessionKey];
  const snapshot = entry?.skillsSnapshot;
  if (
    !entry ||
    !snapshot ||
    typeof entry.lifecycleRevision !== "string" ||
    !Number.isSafeInteger(entry.updatedAt)
  ) {
    throw new Error("expected isolated cron session snapshot is missing");
  }
  const ref = snapshot.promptRef;
  const blobPath = promptPath(ref);
  const blob = fileProof(blobPath, ref);
  const prompt = readFileSync(blobPath, "utf8");
  const { prompt: inlinePrompt, promptRef, ...metadata } = snapshot;
  return {
    blob: { ...blob, prompt_ref: promptRef },
    entry: {
      label: entry.label,
      lifecycle_revision: entry.lifecycleRevision,
      model: entry.model,
      model_provider: entry.modelProvider,
      session_id_present: Object.hasOwn(entry, "sessionId"),
      session_key: sessionKey,
      system_sent: entry.systemSent,
      updated_at: entry.updatedAt,
    },
    entry_digest: sha256(Buffer.from(canonicalJson(entry), "ascii")),
    prompt: {
      bytes: Buffer.byteLength(prompt),
      digest: sha256(Buffer.from(prompt)),
      exact_text: prompt,
      inline_prompt_present: typeof inlinePrompt === "string",
      storage: "promptRef",
    },
    snapshot: {
      metadata,
      metadata_digest: sha256(
        Buffer.from(canonicalJson(metadata), "ascii"),
      ),
      prompt_ref_present: promptRef !== undefined,
    },
    store: fileProof(SESSION_STORE),
  };
}

function exactSnapshot(snapshot, jobId) {
  const metadata = snapshot.snapshot.metadata;
  return (
    snapshot.entry.session_key === `agent:main:cron:${jobId}` &&
    snapshot.entry.label === `Cron: ${CRON_NAME}` &&
    UUID4.test(snapshot.entry.lifecycle_revision) &&
    snapshot.entry.session_id_present === false &&
    snapshot.entry.model === "gpt-5.5" &&
    snapshot.entry.model_provider === "openai" &&
    snapshot.entry.system_sent === true &&
    Number.isSafeInteger(snapshot.entry.updated_at) &&
    snapshot.prompt.storage === "promptRef" &&
    snapshot.prompt.inline_prompt_present === false &&
    snapshot.prompt.bytes === 728 &&
    snapshot.prompt.digest === EXPECTED_PROMPT_DIGEST &&
    snapshot.prompt.exact_text === EXPECTED_PROMPT &&
    snapshot.blob.bytes === 728 &&
    snapshot.blob.digest === EXPECTED_PROMPT_DIGEST &&
    snapshot.blob.prompt_ref.version === 1 &&
    snapshot.blob.prompt_ref.algorithm === "sha256" &&
    snapshot.blob.prompt_ref.bytes === 728 &&
    snapshot.blob.prompt_ref.hash ===
      EXPECTED_PROMPT_DIGEST.slice("sha256:".length) &&
    Number.isSafeInteger(metadata.version) &&
    canonicalJson(metadata.skillFilter) === `["${TARGET_NAME}"]` &&
    canonicalJson((metadata.skills ?? []).map((item) => item.name)) ===
      `["${TARGET_NAME}"]`
  );
}

function exactJob(job) {
  const value = job.response.value;
  return (
    job.command.exit_code === 0 &&
    cleanCommand(job.command) &&
    job.response.parsed &&
    UUID4.test(value?.id ?? "") &&
    value?.agentId === "main" &&
    value?.enabled === true &&
    value?.name === CRON_NAME &&
    value?.sessionTarget === "isolated" &&
    value?.wakeMode === "now" &&
    canonicalJson(value?.payload) === canonicalJson(job.params.payload) &&
    canonicalJson(value?.delivery) === canonicalJson(job.params.delivery) &&
    value?.schedule?.kind === "every" &&
    value?.schedule?.everyMs === 86_400_000 &&
    Number.isSafeInteger(value?.createdAtMs) &&
    Number.isSafeInteger(value?.updatedAtMs) &&
    Number.isSafeInteger(value?.nextRunAtMs)
  );
}

function exactTerminalResult(
  result,
  runId,
  jobId,
  snapshot,
  job,
  requestedRun,
  terminalPoll,
  sessionStateBeforeForcedRun,
) {
  const diagnostic = result?.diagnostics?.entries?.[0];
  const runMatch = new RegExp(
    `^manual:${jobId}:([0-9]{13}):1$`,
  ).exec(runId);
  const runEpoch = Number(runMatch?.[1]);
  const jobCompletedAt = Date.parse(job.command.completed_at);
  const forceStartedAt = Date.parse(requestedRun.command.started_at);
  const forceCompletedAt = Date.parse(requestedRun.command.completed_at);
  const terminalPollCompletedAt = Date.parse(
    terminalPoll.command.completed_at,
  );
  const preRunStartedAt = Date.parse(sessionStateBeforeForcedRun.started_at);
  const preRunCompletedAt = Date.parse(
    sessionStateBeforeForcedRun.completed_at,
  );
  const history = terminalPoll.response.value;
  return (
    runMatch !== null &&
    Number.isSafeInteger(runEpoch) &&
    Number.isFinite(jobCompletedAt) &&
    Number.isFinite(forceStartedAt) &&
    Number.isFinite(forceCompletedAt) &&
    Number.isFinite(terminalPollCompletedAt) &&
    Number.isFinite(preRunStartedAt) &&
    Number.isFinite(preRunCompletedAt) &&
    history?.total === 1 &&
    history?.hasMore === false &&
    history?.limit === 10 &&
    history?.offset === 0 &&
    history?.nextOffset === null &&
    history?.entries?.length === 1 &&
    canonicalJson(history.entries[0]) === canonicalJson(result) &&
    result?.action === "finished" &&
    result?.status === "error" &&
    result?.errorReason === "model_not_found" &&
    result?.error === "FailoverError: Unknown model: openai/gpt-5.5" &&
    result?.provider === "openai" &&
    result?.model === "gpt-5.5" &&
    result?.jobId === jobId &&
    result?.jobName === CRON_NAME &&
    result?.runId === runId &&
    UUID4.test(result?.sessionId ?? "") &&
    result?.sessionKey ===
      `agent:main:cron:${jobId}:run:${result.sessionId}` &&
    result?.deliveryStatus === "not-requested" &&
    result?.diagnostics?.summary === "Unknown model: openai/gpt-5.5" &&
    result?.diagnostics?.entries?.length === 1 &&
    diagnostic?.message === "Unknown model: openai/gpt-5.5" &&
    diagnostic?.severity === "error" &&
    diagnostic?.source === "agent-run" &&
    Number.isSafeInteger(result?.runAtMs) &&
    Number.isSafeInteger(result?.ts) &&
    Number.isSafeInteger(diagnostic?.ts) &&
    jobCompletedAt <= preRunStartedAt &&
    preRunStartedAt <= preRunCompletedAt &&
    preRunCompletedAt <= forceStartedAt &&
    job.response.value.nextRunAtMs > forceStartedAt &&
    forceStartedAt <= runEpoch &&
    runEpoch <= forceCompletedAt &&
    result.runAtMs === runEpoch &&
    result.runAtMs <= snapshot.entry.updated_at &&
    snapshot.entry.updated_at <= diagnostic.ts &&
    diagnostic.ts <= result.ts &&
    result.ts <= terminalPollCompletedAt
  );
}

function captureBefore() {
  const boundary = protectedBoundary();
  const version = command(["--version"]);
  const system = systemInfo();
  const skillDiscovery = discovery();
  const observations = {
    boundary_before: boundary,
    config_before: configObservation(),
    config_lock_before: pathObservation(`${CONFIG}.lock`),
    config_tree_before: treeObservation("/profile/config"),
    discovery_before: skillDiscovery,
    gateway_process_before: gatewayProcessObservation(),
    module_files_before: moduleObservations(),
    openclaw_before: pathObservation(OPENCLAW, { hashFile: true }),
    protected_root_trees_before: protectedRootTrees(),
    runtime_tree_before: boundary.ready ? runtimeTree() : null,
    session_store_before: pathObservation(SESSION_STORE, { hashFile: true }),
    system_info_before: system,
    target_before: treeObservation(TARGET),
    version,
  };
  return {
    commands: [version, system.command, skillDiscovery.command],
    observations,
  };
}

function exactBefore(value) {
  const item = value.observations;
  return (
    item.boundary_before.ready &&
    item.config_before.ready &&
    item.config_tree_before.ready &&
    item.config_tree_before.entries.length === 1 &&
    item.config_tree_before.entries[0].path === "openclaw.json" &&
    item.config_lock_before.exists === false &&
    Object.values(item.protected_root_trees_before).every((tree) => tree.ready) &&
    exactTarget(item.target_before) &&
    item.gateway_process_before.cmdline?.[0] === "openclaw-gateway" &&
    item.gateway_process_before.effective_capabilities ===
      "0000000000000000" &&
    item.gateway_process_before.no_new_privileges === "1" &&
    item.gateway_process_before.seccomp === "2" &&
    item.openclaw_before.digest === EXPECTED_OPENCLAW_DIGEST &&
    item.version.exit_code === 0 &&
    cleanCommand(item.version) &&
    item.version.stdout_excerpt === "OpenClaw 2026.7.1 (2d2ddc4)\n" &&
    item.system_info_before.command.exit_code === 0 &&
    cleanCommand(item.system_info_before.command) &&
    item.system_info_before.response.parsed &&
    item.system_info_before.response.value?.pid === 1 &&
    item.system_info_before.response.value?.hostname ===
      item.gateway_process_before.hostname &&
    exactDiscovery(item.discovery_before) &&
    exactModules(item.module_files_before) &&
    canonicalJson(item.runtime_tree_before) ===
      canonicalJson(EXPECTED_RUNTIME_TREE)
  );
}

function captureAfter() {
  const skillDiscovery = discovery();
  const system = systemInfo();
  return {
    commands: [skillDiscovery.command, system.command],
    observations: {
      boundary_after: protectedBoundary(),
      config_after: configObservation(),
      config_lock_after: pathObservation(`${CONFIG}.lock`),
      config_tree_after: treeObservation("/profile/config"),
      discovery_after: skillDiscovery,
      gateway_process_after: gatewayProcessObservation(),
      module_files_after: moduleObservations(),
      openclaw_after: pathObservation(OPENCLAW, { hashFile: true }),
      protected_root_trees_after: protectedRootTrees(),
      runtime_tree_after: runtimeTree(),
      session_store_after: pathObservation(SESSION_STORE, { hashFile: true }),
      system_info_after: system,
      target_after: treeObservation(TARGET),
    },
  };
}

function exactAfter(before, after) {
  const first = before.observations;
  const last = after.observations;
  return (
    last.boundary_after.ready &&
    last.config_after.ready &&
    last.config_lock_after.exists === false &&
    exactTarget(last.target_after) &&
    exactDiscovery(last.discovery_after) &&
    exactModules(last.module_files_after) &&
    canonicalJson(last.config_after) === canonicalJson(first.config_before) &&
    canonicalJson(last.config_tree_after) ===
      canonicalJson(first.config_tree_before) &&
    canonicalJson(last.protected_root_trees_after) ===
      canonicalJson(first.protected_root_trees_before) &&
    canonicalJson(last.target_after) === canonicalJson(first.target_before) &&
    last.gateway_process_after.pid === first.gateway_process_before.pid &&
    last.gateway_process_after.start_time_ticks ===
      first.gateway_process_before.start_time_ticks &&
    last.gateway_process_after.hostname === first.gateway_process_before.hostname &&
    last.openclaw_after.digest === first.openclaw_before.digest &&
    canonicalJson(last.module_files_after) ===
      canonicalJson(first.module_files_before) &&
    canonicalJson(last.runtime_tree_after) ===
      canonicalJson(first.runtime_tree_before) &&
    last.system_info_after.command.exit_code === 0 &&
    cleanCommand(last.system_info_after.command) &&
    last.system_info_after.response.parsed &&
    last.system_info_after.response.value?.pid === 1 &&
    last.system_info_after.response.value?.hostname ===
      last.gateway_process_after.hostname
  );
}

function notTested(reasonCode, prerequisites = {}, observations = {}) {
  return {
    commands: [],
    execution_error: null,
    id: "cron-rescan",
    observations,
    prerequisites,
    reason_codes: [reasonCode],
    status: "NOT_TESTED",
  };
}

async function runObservation() {
  if (!process.env.OPENCLAW_GATEWAY_TOKEN || !existsSync(OPENCLAW)) {
    return notTested(
      "EXACT_PROTECTED_CRON_RESCAN_PREREQUISITE_MISSING",
      {
        gateway_token_present: Boolean(process.env.OPENCLAW_GATEWAY_TOKEN),
        openclaw: pathObservation(OPENCLAW, { hashFile: true }),
      },
    );
  }

  const before = captureBefore();
  if (!exactBefore(before)) {
    const result = notTested(
      "EXACT_PROTECTED_CRON_RESCAN_PREREQUISITE_MISSING",
      before.observations,
    );
    result.commands = before.commands;
    return result;
  }

  const commands = [...before.commands];
  const jobParams = {
    agentId: "main",
    delivery: { mode: "none" },
    enabled: true,
    name: CRON_NAME,
    payload: {
      kind: "agentTurn",
      message: "Inert protected cron rescan observation.",
      timeoutSeconds: 5,
    },
    schedule: { everyMs: 86_400_000, kind: "every" },
    sessionTarget: "isolated",
    wakeMode: "now",
  };
  let cleanup = null;
  let executionError = null;
  let job = null;
  let jobId = null;
  let run = null;
  let sessionStateBeforeForcedRun = null;
  let snapshot = null;
  let terminalResult = null;
  try {
    job = nativeCall("cron.add", jobParams, commands);
    jobId =
      typeof job.response.value?.id === "string" ? job.response.value.id : null;
    if (!exactJob(job)) {
      throw new Error("cron.add did not create the exact isolated job");
    }
    sessionStateBeforeForcedRun = sessionStateBeforeRun(jobId);
    if (sessionStateBeforeForcedRun.base_entry_present) {
      throw new Error("isolated cron session state existed before the forced run");
    }

    const requestedRun = nativeCall(
      "cron.run",
      { id: jobId, mode: "force" },
      commands,
    );
    const runId = requestedRun.response.value?.runId;
    if (
      requestedRun.command.exit_code !== 0 ||
      !cleanCommand(requestedRun.command) ||
      !requestedRun.response.parsed ||
      requestedRun.response.value?.ok !== true ||
      requestedRun.response.value?.enqueued !== true ||
      typeof runId !== "string"
    ) {
      throw new Error("cron.run did not enqueue the exact forced run");
    }
    const polls = [];
    for (let retry = 1; retry <= 20 && terminalResult === null; retry += 1) {
      await new Promise((resolve) => setTimeout(resolve, 200));
      const poll = nativeCall(
        "cron.runs",
        { id: jobId, limit: 10 },
        commands,
      );
      polls.push(poll);
      if (
        poll.command.exit_code !== 0 ||
        !cleanCommand(poll.command) ||
        !poll.response.parsed ||
        !Array.isArray(poll.response.value?.entries)
      ) {
        throw new Error(`cron.runs poll ${retry} was not exact JSON`);
      }
      terminalResult =
        poll.response.value.entries.find((entry) => entry.runId === runId) ??
        null;
    }
    run = {
      poll_count: polls.length,
      polls,
      request: requestedRun,
      terminal_poll: polls.at(-1) ?? null,
    };
    if (terminalResult === null) {
      throw new Error("cron.run did not finish within the bounded poll window");
    }
    snapshot = cronSnapshot(jobId);
    if (!exactSnapshot(snapshot, jobId)) {
      throw new Error("isolated cron session did not capture the protected prompt");
    }
    if (
      !exactTerminalResult(
        terminalResult,
        runId,
        jobId,
        snapshot,
        job,
        requestedRun,
        run.terminal_poll,
        sessionStateBeforeForcedRun,
      )
    ) {
      throw new Error("isolated cron run did not terminate after snapshot creation");
    }
  } catch (error) {
    executionError = errorRecord(error);
  } finally {
    if (jobId !== null) {
      cleanup = nativeCall("cron.remove", { id: jobId }, commands);
      if (
        cleanup.command.exit_code !== 0 ||
        !cleanCommand(cleanup.command) ||
        !cleanup.response.parsed ||
        cleanup.response.value?.ok !== true ||
        cleanup.response.value?.removed !== true
      ) {
        executionError ??= errorRecord(
          new Error("cron.remove did not remove the isolated job"),
        );
      }
    } else {
      executionError ??= errorRecord(
        new Error("cron.add returned no job identity for cleanup"),
      );
    }
  }

  let after = null;
  try {
    after = captureAfter();
    commands.push(...after.commands);
  } catch (error) {
    executionError ??= errorRecord(error);
  }
  const routeObserved =
    executionError === null &&
    jobId !== null &&
    job !== null &&
    run !== null &&
    sessionStateBeforeForcedRun !== null &&
    sessionStateBeforeForcedRun.base_entry_present === false &&
    snapshot !== null &&
    terminalResult !== null &&
    cleanup !== null &&
    after !== null &&
    Date.parse(run.terminal_poll.command.completed_at) <=
      Date.parse(cleanup.command.started_at) &&
    Date.parse(cleanup.command.completed_at) <=
      Date.parse(after.commands[0].started_at) &&
    exactAfter(before, after);
  return {
    commands,
    execution_error: executionError,
    id: "cron-rescan",
    observations: {
      ...(after?.observations ?? {}),
      cleanup,
      job,
      run,
      session_state_before_forced_run: sessionStateBeforeForcedRun,
      snapshot,
      terminal_result: terminalResult,
    },
    prerequisites: before.observations,
    reason_codes: routeObserved
      ? []
      : ["EXACT_PROTECTED_CRON_RESCAN_NOT_OBSERVED"],
    status: routeObserved ? "OBSERVED" : "NOT_TESTED",
  };
}

function envelope(action) {
  return {
    action,
    assurance: "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
    implementation_digests: {
      helper: helperDigest(),
      probe: sha256(readFileSync(SELF)),
    },
    recorded_at: new Date().toISOString(),
    route: {
      action_id: action.id,
      id: "ADM-02/reload/cron-rescan",
      reason_codes: action.reason_codes,
      status: action.status,
    },
    run_nonce: RUN_NONCE,
    runtime_binding: {
      commit: "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
      node_path: NODE,
      openclaw_digest: EXPECTED_OPENCLAW_DIGEST,
      openclaw_path: OPENCLAW,
      runtime_tree_digest: EXPECTED_RUNTIME_TREE.tree_digest,
      version: "2026.7.1",
    },
    schema: "aragorn/openclaw-protected-cron-rescan-observation/v1",
  };
}

async function main() {
  if (process.argv.length !== 2) {
    return envelope(notTested("FOCUSED_CRON_RESCAN_ARGUMENTS_REJECTED"));
  }
  try {
    return envelope(await runObservation());
  } catch (error) {
    const action = notTested("EXACT_PROTECTED_CRON_RESCAN_EXECUTION_FAILED");
    action.execution_error = errorRecord(error);
    return envelope(action);
  }
}

process.stdout.write(`${canonicalJson(await main())}\n`);
