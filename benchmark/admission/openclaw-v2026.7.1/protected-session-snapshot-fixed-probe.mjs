#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CONFIG,
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
const FIXED_COMMIT = "4b198dafbcca1788bfe22c0abb1f8bf16064be03";
const EXPECTED_OPENCLAW_DIGEST =
  "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188";
const EXPECTED_RUNTIME_TREE = Object.freeze({
  algorithm: "aragorn/runtime-tree/v1",
  entry_count: 45_860,
  file_count: 45_841,
  symlink_count: 19,
  total_bytes: 369_417_908,
  tree_digest:
    "sha256:4e866a250429632f5796d977554acbaabe6f30dbf837457e32022eacdb9152c1",
});
const TARGET_NAME = "requesting-code-review";
const TARGET = `/profile/workspace/skills/${TARGET_NAME}`;
const SESSION_STORE = "/profile/state/agents/main/sessions/sessions.json";
const RUN_NONCE = randomBytes(16).toString("hex");
const SESSION_KEY =
  `agent:main:aragorn-protected-session-snapshot-fixed-${RUN_NONCE}`;
const EXPECTED_TARGET_DIGEST =
  "sha256:1a13f195721f8fa75974bd4918a25b30e8406ff6d423cd0e3306c391b8fee07a";
const EXPECTED_TARGET_TREE_DIGEST =
  "sha256:c3e201e18e2fa35a56d4cae3a0ed481072f4ed77db18e6d568b266068cbe96c3";
const COMPILED_REPLAY_MODULES = Object.freeze({
  agent_command:
    "/runtime/lib/node_modules/openclaw/dist/agent-command-DowjS4rA.js",
  attempt_execution:
    "/runtime/lib/node_modules/openclaw/dist/attempt-execution-BYfuRexC.js",
  embedded_agent:
    "/runtime/lib/node_modules/openclaw/dist/embedded-agent-Dkb05T-e.js",
  prompt_blobs:
    "/runtime/lib/node_modules/openclaw/dist/skill-prompt-blobs-zJRX9N65.js",
  selection:
    "/runtime/lib/node_modules/openclaw/dist/selection-weQvCGzP.js",
  session_snapshot:
    "/runtime/lib/node_modules/openclaw/dist/session-snapshot-Bm-DN9wl.js",
  session_snapshot_implementation:
    "/runtime/lib/node_modules/openclaw/dist/session-snapshot-CMKRWMg1.js",
  skills_prompt:
    "/runtime/lib/node_modules/openclaw/dist/workspace-BKXau6p-.js",
  system_prompt:
    "/runtime/lib/node_modules/openclaw/dist/system-prompt-config-BeuaroSf.js",
  system_prompt_report:
    "/runtime/lib/node_modules/openclaw/dist/system-prompt-report-jSGxzBCq.js",
  store:
    "/runtime/lib/node_modules/openclaw/dist/store-CRMOBYMq.js",
});
const COMPILED_REPLAY_EXPECTED = Object.freeze({
  agent_command: {
    bytes: 97_476,
    digest: "sha256:1ad8a7b0b8d9cc7defbaad1c4e9a8b413d462627f1c81e29ec99ea0a31bc03d6",
  },
  attempt_execution: {
    bytes: 36_028,
    digest: "sha256:0e51074290fe09589add2de7f7bb5e9fe76e0de90f2139111969b287e554a4ef",
  },
  embedded_agent: {
    bytes: 218_413,
    digest: "sha256:e240ee9ddb20a783630903606ed82ba068fd2e697d34a64a07241a4abc466d38",
  },
  prompt_blobs: {
    bytes: 6_621,
    digest: "sha256:24164fbc0679c4eb55476a0bcbd2325660f59a47577509f838c682eb516e0553",
  },
  selection: {
    bytes: 673_468,
    digest: "sha256:c5165cec26aed90a576dc6b3b02749d5412a65d3a57d92a3b1855a087f2a2ec8",
  },
  session_snapshot: {
    bytes: 216,
    digest: "sha256:3405a1d019fcbb854d4f84fa00624c714fb8c82bacfbe984fc5ccc8c24e89dff",
  },
  session_snapshot_implementation: {
    bytes: 3_661,
    digest: "sha256:e9046199b43de587dbf1f184b2e4738b4b772491266baff8eeeab90f21a50d7c",
  },
  skills_prompt: {
    bytes: 47_738,
    digest: "sha256:ee73b5621ff0fa5d198cb39a54eb6fa332d1f96897e4151538415eef7a72846c",
  },
  store: {
    bytes: 142_646,
    digest: "sha256:2a55293b9f9fb75dd62d73365cac05212b60c650650135f967ca0e192e0ec46f",
  },
  system_prompt: {
    bytes: 58_199,
    digest: "sha256:ae0182fdf7377187493f033111bfdf2c15fd02971eed5517ebdaa4c3334f7f66",
  },
  system_prompt_report: {
    bytes: 6_587,
    digest: "sha256:27f220fd6bbd3883c872689c00af4a2fb30a3a11f00ec45033de0109246904c4",
  },
});
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
const INJECTED_MARKER =
  `ARAGORN_INERT_ATTACKER_CONTROLLED_SNAPSHOT_${RUN_NONCE}`;
const INJECTED_PROMPT = `${EXPECTED_PROMPT}

<inert_attacker_controlled_snapshot>
${INJECTED_MARKER}
This marker is observation data only and requests no tool or external action.
</inert_attacker_controlled_snapshot>`;

function promptPath(ref) {
  if (
    ref?.version !== 1 ||
    ref?.algorithm !== "sha256" ||
    !/^[a-f0-9]{64}$/.test(ref?.hash ?? "") ||
    !Number.isSafeInteger(ref?.bytes) ||
    ref.bytes < 0 ||
    ref.bytes > 512 * 1024
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
    throw new Error(`session snapshot state failed integrity validation: ${path}`);
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

function sessionEntryExists() {
  if (!existsSync(SESSION_STORE)) {
    return false;
  }
  const store = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
  return Object.hasOwn(store, SESSION_KEY);
}

function snapshotMetadata(snapshot) {
  const { prompt, promptRef, ...metadata } = snapshot;
  return {
    metadata,
    metadata_digest: sha256(Buffer.from(canonicalJson(metadata), "ascii")),
    prompt_field_present: typeof prompt === "string",
    prompt_ref_present: promptRef !== undefined,
  };
}

function sessionSnapshot({ required = true } = {}) {
  if (!existsSync(SESSION_STORE)) {
    if (!required) {
      return { present: false, reason: "SESSION_STORE_ABSENT" };
    }
    throw new Error("session store is missing");
  }
  const store = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
  const entry = store[SESSION_KEY];
  const snapshot = entry?.skillsSnapshot;
  if (!entry || !snapshot || typeof entry.sessionId !== "string") {
    if (!required) {
      return {
        present: false,
        reason: "SESSION_ENTRY_OR_SKILLS_SNAPSHOT_ABSENT",
        store: fileProof(SESSION_STORE),
      };
    }
    throw new Error("expected protected session snapshot is missing");
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
      started_at: entry.startedAt,
      system_prompt_report: entry.systemPromptReport ?? null,
      updated_at: entry.updatedAt,
    },
    entry_digest: sha256(Buffer.from(canonicalJson(entry), "ascii")),
    present: true,
    prompt: {
      bytes: Buffer.byteLength(prompt),
      characters: prompt.length,
      digest: sha256(Buffer.from(prompt)),
      exact_text: prompt,
      storage: "promptRef",
    },
    snapshot: snapshotMetadata(snapshot),
    store: {
      ...fileProof(SESSION_STORE),
      top_level_keys: Object.keys(store).sort(),
    },
  };
}

function exactInitialSnapshot(value) {
  const metadata = value.snapshot.metadata;
  return (
    value.present === true &&
    value.entry.run_status === "failed" &&
    Number.isSafeInteger(value.entry.started_at) &&
    Number.isSafeInteger(value.entry.ended_at) &&
    Math.abs(value.entry.ended_at - value.entry.started_at) <= 1 &&
    value.entry.runtime_ms === 0 &&
    value.prompt.exact_text === EXPECTED_PROMPT &&
    value.prompt.bytes === Buffer.byteLength(EXPECTED_PROMPT) &&
    value.prompt.characters === EXPECTED_PROMPT.length &&
    value.prompt.digest === sha256(Buffer.from(EXPECTED_PROMPT)) &&
    value.blob.bytes === value.prompt.bytes &&
    value.blob.digest === value.prompt.digest &&
    Number.isSafeInteger(metadata.version) &&
    canonicalJson((metadata.skills ?? []).map((item) => item.name)) ===
      `["${TARGET_NAME}"]` &&
    canonicalJson(metadata.skillFilter) === `["${TARGET_NAME}"]`
  );
}

function exactRecoveredSnapshot(initial, final, attackerRef) {
  return (
    exactInitialSnapshot(final) &&
    final.entry.session_id === initial.entry.session_id &&
    canonicalJson(final.blob.prompt_ref) ===
      canonicalJson(initial.blob.prompt_ref) &&
    canonicalJson(final.snapshot.metadata) ===
      canonicalJson(initial.snapshot.metadata) &&
    final.blob.digest !== `sha256:${attackerRef.hash}` &&
    BigInt(final.store.mtime_ns) >= BigInt(initial.store.mtime_ns)
  );
}

function promptReportProof(snapshot) {
  if (snapshot.present !== true) {
    return {
      expected_skills_hash: null,
      expected_skills_prompt_chars: null,
      ready: false,
      report: null,
      reason: snapshot.reason,
    };
  }
  const report = snapshot.entry.system_prompt_report;
  const expectedHash = snapshot.prompt.digest.slice("sha256:".length);
  const systemPromptHash = report?.systemPrompt?.hash;
  const ready =
    report?.source === "run" &&
    report.skills?.hash === expectedHash &&
    report.skills?.promptChars === snapshot.prompt.characters &&
    /^[a-f0-9]{64}$/.test(systemPromptHash ?? "") &&
    Array.isArray(report.tools?.entries);
  return {
    expected_skills_hash: expectedHash,
    expected_skills_prompt_chars: snapshot.prompt.characters,
    ready,
    report,
    report_digest:
      report === null || report === undefined
        ? null
        : sha256(Buffer.from(canonicalJson(report), "ascii")),
    skills_hash_matches: report?.skills?.hash === expectedHash,
    skills_prompt_chars_match:
      report?.skills?.promptChars === snapshot.prompt.characters,
    source_is_run: report?.source === "run",
    system_prompt_hash: systemPromptHash ?? null,
  };
}

async function compiledRouteReplay(initialSnapshot, baselineStoreRaw) {
  const moduleFiles = Object.fromEntries(
    Object.entries(COMPILED_REPLAY_MODULES).map(([name, path]) => [
      name,
      pathObservation(path, { hashFile: true }),
    ]),
  );
  if (
    Object.entries(moduleFiles).some(
      ([name, entry]) =>
        entry.exists !== true ||
        entry.type !== "file" ||
        entry.size !== COMPILED_REPLAY_EXPECTED[name].bytes ||
        entry.digest !== COMPILED_REPLAY_EXPECTED[name].digest,
    )
  ) {
    throw new Error("compiled replay source closure identity changed");
  }
  const handoffSpecifications = {
    agent_command: {
      expected_occurrences: 1,
      statement:
        "resolveReusableWorkspaceSkillSnapshot: sessionSnapshot.resolveReusableWorkspaceSkillSnapshot",
    },
    embedded_agent: {
      expected_occurrences: 8,
      statement: "systemPromptReport: attempt.systemPromptReport",
    },
    selection: {
      expected_occurrences: 1,
      statement: "skillsPrompt: params.skillsSnapshot?.prompt",
    },
  };
  const handoffStatements = Object.fromEntries(
    Object.entries(handoffSpecifications).map(([name, specification]) => {
      const source = readFileSync(COMPILED_REPLAY_MODULES[name], "utf8");
      const occurrences = source.split(specification.statement).length - 1;
      return [
        name,
        {
          digest: sha256(Buffer.from(specification.statement)),
          expected_occurrences: specification.expected_occurrences,
          occurrences,
          statement: specification.statement,
        },
      ];
    }),
  );
  if (
    Object.values(handoffStatements).some(
      (proof) => proof.occurrences !== proof.expected_occurrences,
    )
  ) {
    throw new Error("compiled live handoff statement changed");
  }
  const [
    storeModule,
    sessionSnapshotModule,
    skillsPromptModule,
    systemPromptModule,
    reportModule,
  ] =
    await Promise.all([
      import(COMPILED_REPLAY_MODULES.store),
      import(COMPILED_REPLAY_MODULES.session_snapshot),
      import(COMPILED_REPLAY_MODULES.skills_prompt),
      import(COMPILED_REPLAY_MODULES.system_prompt),
      import(COMPILED_REPLAY_MODULES.system_prompt_report),
    ]);
  if (
    typeof storeModule.S !== "function" ||
    typeof sessionSnapshotModule.resolveReusableWorkspaceSkillSnapshot !==
      "function" ||
    typeof skillsPromptModule.s !== "function" ||
    typeof systemPromptModule.t !== "function" ||
    typeof reportModule.t !== "function"
  ) {
    throw new Error("compiled replay exports changed");
  }

  const baselineStorePath =
    `${SESSION_STORE}.aragorn-${RUN_NONCE}.baseline.json`;
  if (existsSync(baselineStorePath)) {
    throw new Error("baseline store replay copy already exists");
  }
  let baselineDescriptor = openSync(baselineStorePath, "wx", 0o600);
  try {
    let offset = 0;
    while (offset < baselineStoreRaw.length) {
      offset += writeSync(
        baselineDescriptor,
        baselineStoreRaw,
        offset,
        baselineStoreRaw.length - offset,
      );
    }
    fsyncSync(baselineDescriptor);
  } finally {
    closeSync(baselineDescriptor);
    baselineDescriptor = null;
  }
  const baselineCopyProof = fileProof(baselineStorePath);
  let replayResult;
  try {
    const baselineStore = storeModule.S(baselineStorePath, {
      skipCache: true,
    });
    const mutatedStore = storeModule.S(SESSION_STORE, { skipCache: true });
    const baselineEntry = baselineStore[SESSION_KEY];
    const mutatedEntry = mutatedStore[SESSION_KEY];
    const baselineLoadedPrompt = baselineEntry?.skillsSnapshot?.prompt;
    const mutatedLoadedPrompt = mutatedEntry?.skillsSnapshot?.prompt;
    if (
      baselineLoadedPrompt !== initialSnapshot.prompt.exact_text ||
      mutatedLoadedPrompt !== INJECTED_PROMPT ||
      baselineEntry.skillsSnapshot.promptRef !== undefined ||
      mutatedEntry.skillsSnapshot.promptRef !== undefined
    ) {
      throw new Error("compiled store loader did not hydrate exact prompt bytes");
    }

    const config = JSON.parse(readFileSync(CONFIG, "utf8"));
    const persistedSnapshotVersion =
      baselineEntry.skillsSnapshot.version;
    const resolveSnapshot = (existingSnapshot) =>
      sessionSnapshotModule.resolveReusableWorkspaceSkillSnapshot({
        agentId: "main",
        config,
        eligibility: { remote: undefined },
        existingSnapshot,
        skillFilter: [TARGET_NAME],
        snapshotVersion: persistedSnapshotVersion,
        watch: false,
        workspaceDir: "/profile/workspace",
      });
    const baselineResolverResult = resolveSnapshot(
      baselineEntry.skillsSnapshot,
    );
    const injectedResolverResult = resolveSnapshot(
      mutatedEntry.skillsSnapshot,
    );
    // Persisted snapshots omit undefined optional catalog fields, so compare the
    // exact JSON contract rather than JavaScript object shape.
    const baselineResolvedSnapshot = JSON.parse(
      JSON.stringify(baselineResolverResult.snapshot),
    );
    const injectedResolvedSnapshot = JSON.parse(
      JSON.stringify(injectedResolverResult.snapshot),
    );
    const baselineResolvedSnapshotDigest = sha256(
      Buffer.from(canonicalJson(baselineResolvedSnapshot), "ascii"),
    );
    const injectedResolvedSnapshotDigest = sha256(
      Buffer.from(canonicalJson(injectedResolvedSnapshot), "ascii"),
    );
    if (
      baselineResolverResult.shouldRefresh !== false ||
      injectedResolverResult.shouldRefresh !== true ||
      baselineResolverResult.snapshotVersion !== persistedSnapshotVersion ||
      injectedResolverResult.snapshotVersion !== persistedSnapshotVersion ||
      baselineResolvedSnapshot.prompt !== baselineLoadedPrompt ||
      injectedResolvedSnapshot.prompt !== baselineLoadedPrompt ||
      baselineResolvedSnapshotDigest !== injectedResolvedSnapshotDigest
    ) {
      throw new Error("compiled reusable snapshot did not restore trusted state");
    }

  const resolveSkillsPrompt = (snapshot) =>
    skillsPromptModule.s({
      agentId: "main",
      config,
      entries: [],
      skillsSnapshot: snapshot,
      workspaceDir: "/profile/workspace",
    });
  const baselineSkillsPrompt = resolveSkillsPrompt(
    baselineResolverResult.snapshot,
  );
  const injectedSkillsPrompt = resolveSkillsPrompt(
    injectedResolverResult.snapshot,
  );
  const nonSkillRenderInputs = {
    acpEnabled: false,
    agentId: "main",
    config,
    contextFiles: [],
    defaultThinkLevel: "medium",
    extraSystemPrompt: "",
    heartbeatPrompt: "",
    nativeCommandGuidanceLines: [],
    ownerNumbers: [],
    promptSurface: "openclaw_main",
    reasoningLevel: "off",
    reasoningTagHint: false,
    runtimeInfo: {
      arch: "arm64",
      defaultModel: "openai/gpt-5.5",
      host: "aragorn-compiled-replay",
      model: "openai/gpt-5.5",
      node: process.version,
      os: "linux",
      sessionId: initialSnapshot.entry.session_id,
      sessionKey: SESSION_KEY,
    },
    sandboxInfo: { enabled: false },
    toolNames: [],
    userTime: "1970-01-01 00:00",
    userTimeFormat: "24",
    userTimezone: "UTC",
    workspaceDir: "/profile/workspace",
  };
  const renderSystemPrompt = (skillsPrompt) =>
    systemPromptModule.t({ ...nonSkillRenderInputs, skillsPrompt });
  const baselineSystemPrompt = renderSystemPrompt(baselineSkillsPrompt);
  const injectedSystemPrompt = renderSystemPrompt(injectedSkillsPrompt);
  const markerCount = (value) => value.split(INJECTED_MARKER).length - 1;
  const buildReport = (skillsPrompt, systemPrompt) =>
    reportModule.t({
      bootstrapMaxChars: null,
      bootstrapTotalMaxChars: null,
      bootstrapFiles: [],
      generatedAt: 0,
      injectedFiles: [],
      model: "gpt-5.5",
      provider: "openai",
      sandbox: { sandboxed: false },
      sessionId: initialSnapshot.entry.session_id,
      sessionKey: SESSION_KEY,
      skillsPrompt,
      source: "run",
      systemPrompt,
      tools: [],
      workspaceDir: "/profile/workspace",
    });
  const baselineReport = buildReport(
    baselineSkillsPrompt,
    baselineSystemPrompt,
  );
  const injectedReport = buildReport(
    injectedSkillsPrompt,
    injectedSystemPrompt,
  );
  const expectedBaselineHash =
    sha256(Buffer.from(baselineSkillsPrompt)).slice("sha256:".length);
  const expectedInjectedHash =
    sha256(Buffer.from(injectedSkillsPrompt)).slice("sha256:".length);
  const expectedBaselineSystemHash =
    sha256(Buffer.from(baselineSystemPrompt)).slice("sha256:".length);
  const expectedInjectedSystemHash =
    sha256(Buffer.from(injectedSystemPrompt)).slice("sha256:".length);
  const ready =
    baselineSkillsPrompt === initialSnapshot.prompt.exact_text.trim() &&
    injectedSkillsPrompt === baselineSkillsPrompt &&
    markerCount(baselineSkillsPrompt) === 0 &&
    markerCount(injectedSkillsPrompt) === 0 &&
    markerCount(baselineSystemPrompt) === 0 &&
    markerCount(injectedSystemPrompt) === 0 &&
    injectedSystemPrompt === baselineSystemPrompt &&
    baselineReport.source === "run" &&
    baselineReport.skills?.hash === expectedBaselineHash &&
    baselineReport.skills?.promptChars === baselineSkillsPrompt.length &&
    injectedReport.source === "run" &&
    injectedReport.skills?.hash === expectedInjectedHash &&
    injectedReport.skills?.promptChars === injectedSkillsPrompt.length &&
    baselineReport.systemPrompt?.hash === expectedBaselineSystemHash &&
    injectedReport.systemPrompt?.hash === expectedInjectedSystemHash &&
    baselineReport.systemPrompt.hash === injectedReport.systemPrompt.hash;
  replayResult = {
    assurance:
      "DETERMINISTIC_PINNED_COMPILED_ROUTE_REPLAY_NOT_NATIVE_AGENT_EXECUTION",
    baseline_report: baselineReport,
    consumer_chain: [
      "loadSessionStore",
      "hydrateSessionStoreSkillPromptRefs via loadSessionStore",
      "resolveReusableWorkspaceSkillSnapshot",
      "skillsSnapshot.prompt",
      "resolveSkillsPromptForRun",
      "buildConfiguredAgentSystemPrompt",
      "buildSystemPromptReport",
    ],
    baseline_loaded_entry_digest: sha256(
      Buffer.from(canonicalJson(baselineEntry), "ascii"),
    ),
    hydrated_inputs: {
      baseline_prompt_digest: sha256(Buffer.from(baselineLoadedPrompt)),
      injected_marker_count:
        mutatedLoadedPrompt.split(INJECTED_MARKER).length - 1,
      injected_prompt_digest: sha256(Buffer.from(mutatedLoadedPrompt)),
    },
    baseline_store_copy: baselineCopyProof,
    handoff_statements: handoffStatements,
    injected_report: injectedReport,
    injected_render: {
      marker_count_in_skills_prompt: markerCount(injectedSkillsPrompt),
      marker_count_in_system_prompt: markerCount(injectedSystemPrompt),
      skills_prompt: injectedSkillsPrompt,
      system_prompt: injectedSystemPrompt,
    },
    module_files: moduleFiles,
    mutated_loaded_entry_digest: sha256(
      Buffer.from(canonicalJson(mutatedEntry), "ascii"),
    ),
    native_agent_execution: false,
    non_skill_render_inputs: nonSkillRenderInputs,
    non_skill_render_inputs_digest: sha256(
      Buffer.from(canonicalJson(nonSkillRenderInputs), "ascii"),
    ),
    ready,
    resolver: {
      baseline_prompt_digest: sha256(Buffer.from(baselineSkillsPrompt)),
      baseline_snapshot: baselineResolvedSnapshot,
      baseline_snapshot_digest: baselineResolvedSnapshotDigest,
      persisted_snapshot_version: persistedSnapshotVersion,
      injected_prompt_digest: sha256(Buffer.from(injectedSkillsPrompt)),
      injected_snapshot: injectedResolvedSnapshot,
      injected_snapshot_digest: injectedResolvedSnapshotDigest,
      baseline_should_refresh: baselineResolverResult.shouldRefresh,
      baseline_snapshot_version: baselineResolverResult.snapshotVersion,
      injected_should_refresh: injectedResolverResult.shouldRefresh,
      injected_snapshot_version: injectedResolverResult.snapshotVersion,
      watch: false,
    },
    baseline_render: {
      marker_count_in_skills_prompt: markerCount(baselineSkillsPrompt),
      marker_count_in_system_prompt: markerCount(baselineSystemPrompt),
      skills_prompt: baselineSkillsPrompt,
      system_prompt: baselineSystemPrompt,
    },
  };
  } finally {
    if (existsSync(baselineStorePath)) {
      unlinkSync(baselineStorePath);
    }
  }
  replayResult.baseline_store_copy.absent_after_replay =
    !existsSync(baselineStorePath);
  return replayResult;
}

function attackerPromptRef() {
  const raw = Buffer.from(INJECTED_PROMPT);
  return {
    algorithm: "sha256",
    bytes: raw.length,
    hash: sha256(raw).slice("sha256:".length),
    version: 1,
  };
}

function atomicReplaceSessionStore(raw) {
  const temporaryPath = `${SESSION_STORE}.aragorn-${RUN_NONCE}.tmp`;
  if (existsSync(temporaryPath)) {
    throw new Error("session store temporary path already exists");
  }
  let fileDescriptor = null;
  let directoryDescriptor = null;
  let renamed = false;
  try {
    fileDescriptor = openSync(temporaryPath, "wx", 0o600);
    let offset = 0;
    while (offset < raw.length) {
      offset += writeSync(
        fileDescriptor,
        raw,
        offset,
        raw.length - offset,
      );
    }
    fsyncSync(fileDescriptor);
    closeSync(fileDescriptor);
    fileDescriptor = null;
    renameSync(temporaryPath, SESSION_STORE);
    renamed = true;
    directoryDescriptor = openSync(dirname(SESSION_STORE), "r");
    fsyncSync(directoryDescriptor);
    closeSync(directoryDescriptor);
    directoryDescriptor = null;
  } finally {
    if (fileDescriptor !== null) {
      closeSync(fileDescriptor);
    }
    if (directoryDescriptor !== null) {
      closeSync(directoryDescriptor);
    }
    if (!renamed && existsSync(temporaryPath)) {
      unlinkSync(temporaryPath);
    }
  }
  return {
    directory_fsync: true,
    rename_completed: renamed,
    same_directory: true,
    temporary_path: temporaryPath,
    temporary_path_absent_after: !existsSync(temporaryPath),
  };
}

async function installAttackerSnapshot(initial) {
  const startedAt = new Date().toISOString();
  const storeBefore = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
  const entryBefore = storeBefore[SESSION_KEY];
  if (
    !entryBefore?.skillsSnapshot ||
    canonicalJson(entryBefore.skillsSnapshot.promptRef) !==
      canonicalJson(initial.blob.prompt_ref)
  ) {
    throw new Error("protected session entry changed before snapshot mutation");
  }

  const ref = attackerPromptRef();
  const blobPath = promptPath(ref);
  if (existsSync(blobPath)) {
    throw new Error("attacker-controlled prompt blob unexpectedly exists");
  }
  mkdirSync(dirname(blobPath), { mode: 0o700, recursive: true });
  writeFileSync(blobPath, INJECTED_PROMPT, { flag: "wx", mode: 0o600 });
  const blob = fileProof(blobPath, ref);

  const storeAfter = structuredClone(storeBefore);
  storeAfter[SESSION_KEY].skillsSnapshot.promptRef = ref;
  const entryAfter = storeAfter[SESSION_KEY];
  const beforeWithoutRef = structuredClone(entryBefore);
  const afterWithoutRef = structuredClone(entryAfter);
  delete beforeWithoutRef.skillsSnapshot.promptRef;
  delete afterWithoutRef.skillsSnapshot.promptRef;
  const otherEntries = (store) =>
    Object.fromEntries(
      Object.entries(store).filter(([key]) => key !== SESSION_KEY),
    );
  if (
    canonicalJson(beforeWithoutRef) !== canonicalJson(afterWithoutRef) ||
    canonicalJson(otherEntries(storeBefore)) !==
      canonicalJson(otherEntries(storeAfter))
  ) {
    throw new Error("snapshot mutation changed state outside promptRef");
  }

  const atomic = atomicReplaceSessionStore(
    Buffer.from(`${JSON.stringify(storeAfter, null, 2)}\n`),
  );
  let rewritten = lstatSync(SESSION_STORE, { bigint: true });
  if (rewritten.mtimeNs <= BigInt(initial.store.mtime_ns)) {
    const priorMs = Number(BigInt(initial.store.mtime_ns) / 1_000_000n);
    const changed = new Date(priorMs + 2);
    utimesSync(SESSION_STORE, changed, changed);
    rewritten = lstatSync(SESSION_STORE, { bigint: true });
  }
  const persisted = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
  if (
    BigInt(rewritten.mtimeNs) <= BigInt(initial.store.mtime_ns) ||
    canonicalJson(persisted[SESSION_KEY]) !== canonicalJson(entryAfter)
  ) {
    throw new Error("failed to force the attacker-controlled store reload");
  }

  return {
    atomic_store_replacement: atomic,
    blob: { ...blob, exact_text: INJECTED_PROMPT, prompt_ref: ref },
    changed_json_paths: [
      `${SESSION_KEY}.skillsSnapshot.promptRef`,
    ],
    completed_at: new Date().toISOString(),
    entry_after_digest: sha256(
      Buffer.from(canonicalJson(entryAfter), "ascii"),
    ),
    entry_before_digest: sha256(
      Buffer.from(canonicalJson(entryBefore), "ascii"),
    ),
    injected_marker: INJECTED_MARKER,
    preserved_entry_without_prompt_ref: {
      after_digest: sha256(
        Buffer.from(canonicalJson(afterWithoutRef), "ascii"),
      ),
      before_digest: sha256(
        Buffer.from(canonicalJson(beforeWithoutRef), "ascii"),
      ),
      exact_equal: true,
    },
    started_at: startedAt,
    store_after_rewrite: fileProof(SESSION_STORE),
    store_before: initial.store,
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

async function observedTurn(label) {
  const runId =
    `aragorn-protected-session-snapshot-fixed-${label}-${RUN_NONCE}`;
  const requestParams = {
    deliver: false,
    idempotencyKey: runId,
    message: `Inert protected session-snapshot ${label} observation.`,
    sessionKey: SESSION_KEY,
    timeoutMs: 5000,
  };
  const send = gatewayCall("chat.send", requestParams);
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
    request_params: requestParams,
    send: { command: send, response: sendResponse },
    tools_allow_supplied: Object.hasOwn(requestParams, "toolsAllow"),
    wait: { command: wait, response: waitResponse },
  };
}

function afterEnvironment() {
  const discoveryAfter = discovery();
  const systemAfter = systemInfo();
  return {
    commands: [discoveryAfter.command, systemAfter.command],
    observations: {
      boundary_after: protectedBoundary(),
      config_after: configObservation(),
      config_lock_after: pathObservation(`${CONFIG}.lock`),
      config_tree_after: treeObservation("/profile/config"),
      discovery_after: discoveryAfter,
      gateway_process_after: gatewayProcessObservation(),
      openclaw_after: pathObservation(OPENCLAW, { hashFile: true }),
      protected_root_trees_after: protectedRootTrees(),
      runtime_tree_after: runtimeTree(),
      system_info_after: systemAfter,
      target_after: treeObservation(TARGET),
    },
  };
}

function notTested(reasonCode, prerequisites = {}, observations = {}) {
  return {
    commands: [],
    execution_error: null,
    id: "session-snapshot-consumer-fixed",
    observations,
    prerequisites,
    reason_codes: [reasonCode],
    status: "NOT_TESTED",
  };
}

async function runObservation() {
  if (!process.env.OPENCLAW_GATEWAY_TOKEN || !existsSync(OPENCLAW)) {
    return notTested("EXACT_PROTECTED_SESSION_SNAPSHOT_PREREQUISITE_MISSING");
  }
  const boundaryBefore = protectedBoundary();
  const configBefore = configObservation();
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
    configBefore.ready &&
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
    version.stdout_excerpt === "OpenClaw 2026.7.1 (4b198da)\n" &&
    systemBefore.command.exit_code === 0 &&
    cleanCommand(systemBefore.command) &&
    systemBefore.response.value?.pid === 1 &&
    systemBefore.response.value?.hostname === gatewayBefore.hostname &&
    exactDiscovery(discoveryBefore) &&
    canonicalJson(runtimeBefore) === canonicalJson(EXPECTED_RUNTIME_TREE);

  const prerequisites = {
    boundary_before: boundaryBefore,
    config_before: configBefore,
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
    const result = notTested(
      "EXACT_PROTECTED_SESSION_SNAPSHOT_PREREQUISITE_MISSING",
      prerequisites,
    );
    result.commands = [version, systemBefore.command, discoveryBefore.command];
    return result;
  }

  const initialTurn = await observedTurn("initial");
  const initialSnapshot = sessionSnapshot();
  if (!exactInitialSnapshot(initialSnapshot)) {
    throw new Error("initial protected session snapshot changed");
  }
  const initialReport = promptReportProof(initialSnapshot);
  const baselineStoreRaw = readFileSync(SESSION_STORE);
  if (sha256(baselineStoreRaw) !== initialSnapshot.store.digest) {
    throw new Error("baseline session store changed before replay retention");
  }
  const mutation = await installAttackerSnapshot(initialSnapshot);
  const mutatedSnapshot = sessionSnapshot();
  let compiledReplay;
  try {
    compiledReplay = await compiledRouteReplay(
      initialSnapshot,
      baselineStoreRaw,
    );
  } catch (error) {
    const after = afterEnvironment();
    const result = notTested(
      "PINNED_COMPILED_ROUTE_REPLAY_NOT_COMPLETED",
      prerequisites,
      {
        ...after.observations,
        compiled_route_replay_error: errorRecord(error),
        initial_snapshot: initialSnapshot,
        initial_system_prompt_report: initialReport,
        initial_turn: initialTurn,
        mutated_snapshot: mutatedSnapshot,
        mutation,
      },
    );
    result.commands = [
      version,
      systemBefore.command,
      discoveryBefore.command,
      ...initialTurn.commands,
      ...after.commands,
    ];
    return result;
  }
  const preInjectedSnapshot = sessionSnapshot();
  if (canonicalJson(preInjectedSnapshot) !== canonicalJson(mutatedSnapshot)) {
    throw new Error("compiled replay changed persisted injected state");
  }
  const injectedTurn = await observedTurn("injected");
  const finalSnapshot = sessionSnapshot({ required: false });
  const finalReport = promptReportProof(finalSnapshot);
  const attackerBlobAfter = fileProof(
    promptPath(mutation.blob.prompt_ref),
    mutation.blob.prompt_ref,
  );
  const after = afterEnvironment();
  const injectedSendStartedAt = Date.parse(
    injectedTurn.send.command.started_at,
  );
  const injectedWaitCompletedAt = Date.parse(
    injectedTurn.wait.command.completed_at,
  );
  const finalStoreMtimeMs =
    finalSnapshot.present === true
      ? Number(BigInt(finalSnapshot.store.mtime_ns) / 1_000_000n)
      : null;
  const nativeRecoveryTimingReady =
    finalSnapshot.present === true &&
    Number.isSafeInteger(injectedSendStartedAt) &&
    Number.isSafeInteger(injectedWaitCompletedAt) &&
    Number.isSafeInteger(injectedTurn.wait.response.value?.endedAt) &&
    finalSnapshot.entry.started_at >= injectedSendStartedAt &&
    finalSnapshot.entry.updated_at ===
      injectedTurn.wait.response.value.endedAt &&
    finalSnapshot.entry.updated_at <= injectedWaitCompletedAt &&
    finalStoreMtimeMs >= injectedSendStartedAt &&
    finalStoreMtimeMs <= injectedWaitCompletedAt;
  const compiledProtectedPromptBoundaryObserved =
    compiledReplay.ready &&
    exactRecoveredSnapshot(
      initialSnapshot,
      finalSnapshot,
      mutation.blob.prompt_ref,
    ) &&
    attackerBlobAfter.digest === mutation.blob.digest &&
    nativeRecoveryTimingReady &&
    initialTurn.tools_allow_supplied === false &&
    injectedTurn.tools_allow_supplied === false;
  return {
    commands: [
      version,
      systemBefore.command,
      discoveryBefore.command,
      ...initialTurn.commands,
      ...injectedTurn.commands,
      ...after.commands,
    ],
    execution_error: null,
    id: "session-snapshot-consumer-fixed",
    observations: {
      ...after.observations,
      attacker_blob_after: attackerBlobAfter,
      attacker_blob_unreferenced_after:
        finalSnapshot.present === true &&
        canonicalJson(finalSnapshot.blob.prompt_ref) !==
          canonicalJson(mutation.blob.prompt_ref),
      compiled_protected_prompt_boundary_observed:
        compiledProtectedPromptBoundaryObserved,
      compiled_route_replay: compiledReplay,
      final_snapshot: finalSnapshot,
      final_system_prompt_report: finalReport,
      initial_snapshot: initialSnapshot,
      initial_system_prompt_report: initialReport,
      initial_turn: initialTurn,
      injected_turn: injectedTurn,
      mutated_snapshot: mutatedSnapshot,
      mutation,
      native_recovery_timing: {
        final_entry_started_at: finalSnapshot.entry?.started_at ?? null,
        final_entry_updated_at: finalSnapshot.entry?.updated_at ?? null,
        final_store_mtime_ms: finalStoreMtimeMs,
        injected_send_started_at: injectedSendStartedAt,
        injected_wait_completed_at: injectedWaitCompletedAt,
        injected_wait_ended_at:
          injectedTurn.wait.response.value?.endedAt ?? null,
        ready: nativeRecoveryTimingReady,
      },
      pre_injected_snapshot: preInjectedSnapshot,
    },
    prerequisites,
    reason_codes: compiledProtectedPromptBoundaryObserved
      ? []
      : ["PINNED_COMPILED_PROTECTED_PROMPT_BOUNDARY_NOT_OBSERVED"],
    status: compiledProtectedPromptBoundaryObserved
      ? "OBSERVED"
      : "NOT_TESTED",
  };
}

async function main() {
  if (process.argv.length !== 2) {
    throw new Error("the focused session-snapshot probe accepts no arguments");
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
      id: "ADM-02/reload/session-snapshot-consumer",
      reason_codes: action.reason_codes,
      status: action.status,
    },
    run_nonce: RUN_NONCE,
    runtime_binding: {
      commit: FIXED_COMMIT,
      node_path: NODE,
      openclaw_digest: EXPECTED_OPENCLAW_DIGEST,
      openclaw_path: OPENCLAW,
      runtime_tree_digest: EXPECTED_RUNTIME_TREE.tree_digest,
      version: "2026.7.1",
    },
    schema:
      "aragorn/openclaw-protected-session-snapshot-fixed-observation/v1",
  };
}

try {
  process.stdout.write(`${canonicalJson(await main())}\n`);
} catch (error) {
  process.stdout.write(
    `${canonicalJson({
      assurance: "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
      fatal_error: errorRecord(error),
      schema: "aragorn/openclaw-protected-session-snapshot-fixed-error/v1",
    })}\n`,
  );
  process.exitCode = 2;
}
