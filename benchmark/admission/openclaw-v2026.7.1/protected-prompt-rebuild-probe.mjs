#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CONFIG,
  EXPECTED_OPENCLAW_DIGEST,
  EXPECTED_RUNTIME_TREE,
  NODE,
  OPENCLAW,
  PROTECTED_ROOTS,
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
const SESSION_STORE =
  "/profile/state/agents/main/sessions/sessions.json";
const RUN_NONCE = randomBytes(16).toString("hex");
const SESSION_KEY =
  `agent:main:aragorn-protected-prompt-rebuild-${RUN_NONCE}`;
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

function sessionEntryExists() {
  if (!existsSync(SESSION_STORE)) {
    return false;
  }
  const store = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
  return Object.hasOwn(store, SESSION_KEY);
}

function promptPath(ref) {
  if (
    ref?.version !== 1 ||
    ref?.algorithm !== "sha256" ||
    !/^[a-f0-9]{64}$/.test(ref?.hash ?? "") ||
    !Number.isSafeInteger(ref?.bytes) ||
    ref.bytes < 0
  ) {
    throw new Error("session snapshot has no valid promptRef");
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
    throw new Error(`protected prompt state failed integrity validation: ${path}`);
  }
  return {
    bytes: raw.length,
    digest,
    mode: "600",
    mtime_ns: stat.mtimeNs.toString(),
    nlink: 1,
    path,
  };
}

function sessionStoreProof() {
  return fileProof(SESSION_STORE);
}

function sessionSnapshot() {
  const store = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
  const entry = store[SESSION_KEY];
  const snapshot = entry?.skillsSnapshot;
  if (!entry || !snapshot || typeof entry.sessionId !== "string") {
    throw new Error("expected protected prompt-rebuild session is missing");
  }
  const ref = snapshot.promptRef;
  const blobPath = promptPath(ref);
  const blob = fileProof(blobPath, ref);
  const prompt = readFileSync(blobPath, "utf8");
  return {
    blob: { ...blob, prompt_ref: ref },
    entry: {
      ended_at: entry.endedAt,
      run_status: entry.status,
      runtime_ms: entry.runtimeMs,
      session_id: entry.sessionId,
      skill_filter: snapshot.skillFilter,
      skill_names: (snapshot.skills ?? []).map((item) => item.name),
      snapshot_version: snapshot.version,
      started_at: entry.startedAt,
    },
    prompt: {
      bytes: Buffer.byteLength(prompt),
      digest: sha256(Buffer.from(prompt)),
      exact_text: prompt,
      storage: "promptRef",
    },
  };
}

async function invalidatePromptBlob(blob) {
  const startedAt = new Date().toISOString();
  const rawBefore = readFileSync(SESSION_STORE);
  const storeBefore = sessionStoreProof();
  const current = fileProof(blob.path, blob.prompt_ref);
  if (
    current.digest !== blob.digest ||
    current.bytes !== blob.bytes ||
    current.path !== blob.path
  ) {
    throw new Error("prompt blob changed before invalidation");
  }
  unlinkSync(blob.path);
  await new Promise((resolve) => setTimeout(resolve, 2));
  writeFileSync(SESSION_STORE, rawBefore, { mode: 0o600 });
  let statAfter = lstatSync(SESSION_STORE, { bigint: true });
  if (statAfter.mtimeNs <= BigInt(storeBefore.mtime_ns)) {
    const changed = new Date(Number(BigInt(storeBefore.mtime_ns) / 1_000_000n) + 1);
    utimesSync(SESSION_STORE, changed, changed);
    statAfter = lstatSync(SESSION_STORE, { bigint: true });
  }
  const rawAfter = readFileSync(SESSION_STORE);
  const storeAfter = sessionStoreProof();
  if (
    !rawBefore.equals(rawAfter) ||
    BigInt(storeAfter.mtime_ns) <= BigInt(storeBefore.mtime_ns) ||
    existsSync(blob.path)
  ) {
    throw new Error("failed to force an exact missing-blob cache miss");
  }
  return {
    blob_exists_after_unlink: false,
    blob_path: blob.path,
    completed_at: new Date().toISOString(),
    started_at: startedAt,
    store_after_rewrite: storeAfter,
    store_before: storeBefore,
  };
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

function systemInfo() {
  const native = gatewayCall("system.info");
  return { command: native, response: parsedCommand(native) };
}

async function normalTurn(label) {
  const runId = `aragorn-protected-prompt-rebuild-${label}-${RUN_NONCE}`;
  const send = gatewayCall("chat.send", {
    deliver: false,
    idempotencyKey: runId,
    message: `Inert protected prompt rebuild ${label}.`,
    sessionKey: SESSION_KEY,
    timeoutMs: 5000,
  });
  const sendResponse = parsedCommand(send);
  if (
    send.exit_code !== 0 ||
    !cleanCommand(send) ||
    sendResponse.value?.runId !== runId ||
    sendResponse.value?.status !== "started"
  ) {
    throw new Error(`${label} chat.send did not start the exact run`);
  }
  const wait = gatewayCall(
    "agent.wait",
    { runId, timeoutMs: 10_000 },
    12_000,
  );
  const waitResponse = parsedCommand(wait);
  if (
    wait.exit_code !== 0 ||
    !cleanCommand(wait) ||
    waitResponse.value?.runId !== runId ||
    waitResponse.value?.status !== "ok" ||
    !Number.isSafeInteger(waitResponse.value?.endedAt)
  ) {
    throw new Error(`${label} did not reach a terminal agent result`);
  }
  return {
    commands: [send, wait],
    confirmed: true,
    send: { command: send, response: sendResponse },
    wait: { command: wait, response: waitResponse },
  };
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
    skill?.disabled === false &&
    skill?.eligible === true &&
    skill?.modelVisible === true
  );
}

function exactSnapshot(value) {
  return (
    value.entry.run_status === "failed" &&
    Number.isSafeInteger(value.entry.started_at) &&
    value.entry.ended_at === value.entry.started_at &&
    value.entry.runtime_ms === 0 &&
    Number.isSafeInteger(value.entry.snapshot_version) &&
    canonicalJson(value.entry.skill_names) === `["${TARGET_NAME}"]` &&
    canonicalJson(value.entry.skill_filter) === `["${TARGET_NAME}"]` &&
    value.prompt.storage === "promptRef" &&
    value.prompt.exact_text === EXPECTED_PROMPT &&
    value.prompt.bytes === Buffer.byteLength(EXPECTED_PROMPT) &&
    value.prompt.digest === sha256(Buffer.from(EXPECTED_PROMPT)) &&
    value.blob.bytes === value.prompt.bytes &&
    value.blob.digest === value.prompt.digest
  );
}

async function runObservation() {
  const boundaryBefore = protectedBoundary();
  const configTreeBefore = treeObservation("/profile/config");
  const configLockBefore = pathObservation(`${CONFIG}.lock`);
  const rootsBefore = protectedRootTrees();
  const targetBefore = treeObservation(TARGET);
  const gatewayBefore = gatewayProcessObservation();
  const openclawBefore = pathObservation(OPENCLAW, { hashFile: true });
  const version = command(["--version"]);
  const systemBefore = systemInfo();
  const discoveryBefore = discovery();
  const runtimeBefore = boundaryBefore.ready ? runtimeTree() : null;
  const prerequisitesReady =
    boundaryBefore.ready &&
    configTreeBefore.ready &&
    configTreeBefore.entries.length === 1 &&
    configTreeBefore.entries[0].path === "openclaw.json" &&
    configLockBefore.exists === false &&
    Object.values(rootsBefore).every((tree) => tree.ready) &&
    exactTarget(targetBefore) &&
    !sessionEntryExists() &&
    gatewayBefore.cmdline?.[0] === "openclaw-gateway" &&
    gatewayBefore.effective_capabilities === "0000000000000000" &&
    gatewayBefore.no_new_privileges === "1" &&
    gatewayBefore.seccomp === "2" &&
    openclawBefore.digest === EXPECTED_OPENCLAW_DIGEST &&
    version.exit_code === 0 &&
    cleanCommand(version) &&
    version.stdout_excerpt === "OpenClaw 2026.7.1 (2d2ddc4)\n" &&
    systemBefore.command.exit_code === 0 &&
    cleanCommand(systemBefore.command) &&
    systemBefore.response.value?.pid === 1 &&
    systemBefore.response.value?.hostname === gatewayBefore.hostname &&
    exactDiscovery(discoveryBefore) &&
    canonicalJson(runtimeBefore) === canonicalJson(EXPECTED_RUNTIME_TREE);

  const prerequisites = {
    boundary_before: boundaryBefore,
    config_lock_before: configLockBefore,
    config_tree_before: configTreeBefore,
    discovery_before: discoveryBefore,
    gateway_process_before: gatewayBefore,
    openclaw_before: openclawBefore,
    protected_root_trees_before: rootsBefore,
    runtime_tree_before: runtimeBefore,
    session_entry_absent_before: !sessionEntryExists(),
    system_info_before: systemBefore,
    target_before: targetBefore,
    version,
  };
  if (!prerequisitesReady) {
    return {
      commands: [version, systemBefore.command, discoveryBefore.command],
      execution_error: null,
      id: "missing-prompt-blob-rebuild",
      observations: {},
      prerequisites,
      reason_codes: ["EXACT_PROTECTED_PROMPT_REBUILD_PREREQUISITE_MISSING"],
      status: "NOT_TESTED",
    };
  }

  const initialTurn = await normalTurn("initial");
  const initialSnapshot = sessionSnapshot();
  if (!exactSnapshot(initialSnapshot)) {
    throw new Error("initial protected prompt snapshot changed");
  }
  const invalidation = await invalidatePromptBlob(initialSnapshot.blob);
  const rebuildTurn = await normalTurn("rebuild");
  const rebuiltSnapshot = sessionSnapshot();
  const discoveryAfter = discovery();
  const systemAfter = systemInfo();
  const boundaryAfter = protectedBoundary();
  const configTreeAfter = treeObservation("/profile/config");
  const configLockAfter = pathObservation(`${CONFIG}.lock`);
  const rootsAfter = protectedRootTrees();
  const targetAfter = treeObservation(TARGET);
  const gatewayAfter = gatewayProcessObservation();
  const openclawAfter = pathObservation(OPENCLAW, { hashFile: true });
  const runtimeAfter = runtimeTree();
  if (
    !exactSnapshot(rebuiltSnapshot) ||
    rebuiltSnapshot.entry.session_id !== initialSnapshot.entry.session_id ||
    rebuiltSnapshot.entry.snapshot_version !==
      initialSnapshot.entry.snapshot_version ||
    canonicalJson(rebuiltSnapshot.blob.prompt_ref) !==
      canonicalJson(initialSnapshot.blob.prompt_ref) ||
    rebuiltSnapshot.blob.path !== initialSnapshot.blob.path ||
    BigInt(rebuiltSnapshot.blob.mtime_ns) <=
      BigInt(invalidation.store_after_rewrite.mtime_ns) ||
    rebuiltSnapshot.entry.started_at <= initialSnapshot.entry.ended_at
  ) {
    throw new Error("exact protected prompt blob was not causally rebuilt");
  }

  return {
    commands: [
      version,
      systemBefore.command,
      discoveryBefore.command,
      ...initialTurn.commands,
      ...rebuildTurn.commands,
      discoveryAfter.command,
      systemAfter.command,
    ],
    execution_error: null,
    id: "missing-prompt-blob-rebuild",
    observations: {
      boundary_after: boundaryAfter,
      config_lock_after: configLockAfter,
      config_tree_after: configTreeAfter,
      discovery_after: discoveryAfter,
      gateway_process_after: gatewayAfter,
      initial_snapshot: initialSnapshot,
      initial_turn: initialTurn,
      invalidation,
      openclaw_after: openclawAfter,
      protected_root_trees_after: rootsAfter,
      rebuild_turn: rebuildTurn,
      rebuilt_snapshot: rebuiltSnapshot,
      runtime_tree_after: runtimeAfter,
      system_info_after: systemAfter,
      target_after: targetAfter,
    },
    prerequisites,
    reason_codes: [],
    status: "OBSERVED",
  };
}

async function main() {
  if (process.argv.length !== 2) {
    throw new Error("the focused prompt-rebuild probe accepts no arguments");
  }
  if (!process.env.OPENCLAW_GATEWAY_TOKEN) {
    throw new Error("OPENCLAW_GATEWAY_TOKEN is required");
  }
  const action = await runObservation();
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
      id: "ADM-02/reload/missing-prompt-blob-rebuild",
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
    schema: "aragorn/openclaw-protected-prompt-rebuild-observation/v1",
  };
}

try {
  process.stdout.write(`${canonicalJson(await main())}\n`);
} catch (error) {
  process.stdout.write(
    `${canonicalJson({
      assurance: "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
      fatal_error: errorRecord(error),
      schema: "aragorn/openclaw-protected-prompt-rebuild-error/v1",
    })}\n`,
  );
  process.exitCode = 2;
}
