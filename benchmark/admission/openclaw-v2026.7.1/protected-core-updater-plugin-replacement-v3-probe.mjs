#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROUTE = "ADM-02/update/core-updater-plugin-replacement";
const ACTION = "core-updater-plugin-replacement";
const SCHEMA =
  "aragorn/openclaw-protected-core-updater-plugin-replacement-observation/v1";
const DELEGATED_SCHEMA =
  "aragorn/openclaw-protected-route-action-observations/v1";
const ROUTE_ROOT = "/route-input/core-updater-plugin-replacement";
const DELEGATED_PROBE = join(ROUTE_ROOT, "protected-route-action-probe.mjs");
const AUDIT_LISTENER = join(
  ROUTE_ROOT,
  "core-updater-plugin-replacement-audit-listener.mjs",
);
const CANDIDATE_ROOT = join(ROUTE_ROOT, "candidate-source");
const WORKSPACE = "/var/lib/aragorn-agent-gateway/workspace";
const STATE = "/var/lib/aragorn-agent-gateway/state";
const CONFIG =
  "/run/credentials/aragorn-agent-gateway.service/openclaw-config";
const DIST = "/runtime/lib/node_modules/openclaw/dist";
const AUDIT_PATH =
  "/var/lib/aragorn-agent-gateway/state/core-updater-policy-audit.jsonl";
const WORKING_CONFIG =
  "/var/lib/aragorn-agent-gateway/state/core-updater-openclaw.json";
const TARGET =
  "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker";
const SELF = fileURLToPath(import.meta.url);
const REPOSITORY = join(
  WORKSPACE,
  "aragorn-core-updater-plugin-replacement-source",
);
const PLUGIN_ID = "aragorn-runtime-action-worker";
const FIXED_TIME = "2026-01-01T00:00:00.000Z";
const EXPECTED_COMMIT = "222d0c39429841044b95549407422873ec106a54";
const EXPECTED_TREE = "fc3f1336c488b32d3b668f637ec4bdc6ccf56213";
const POLICY_REASON = "plugin installs disabled by Aragorn protected profile";
const OUTPUT_LIMIT = 4 * 1024 * 1024;
const CONFIG_EXPECTED = Object.freeze({
  bytes: 2_159,
  canonicalDigest:
    "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c",
  digest:
    "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c",
});
const DELEGATED_EXPECTED = Object.freeze({
  bytes: 45_137,
  digest:
    "sha256:2e655f7039cf6f2c06f815b281bb7a5ca7a84ed48ef44cf4d2ce8dfdc7df6902",
});
const AUDIT_LISTENER_EXPECTED = Object.freeze({
  bytes: 3_177,
  digest:
    "sha256:37aa36c0d9b6d66dd3af8a7ca3d0bd557bb9a727383d8fb9126dd5d7e2426edc",
});

const CANDIDATE_FILES = Object.freeze({
  "index.js": Object.freeze({
    bytes: 154,
    digest:
      "sha256:67ecfc8f10e39dcc60ec880a587fadeacdb0040b1911ef93a995575f2aa5bbf2",
  }),
  "openclaw.plugin.json": Object.freeze({
    bytes: 698,
    digest:
      "sha256:a9d62834481462f8f474fe16bab4fb3d466942d9fc2602c618592897bf427d82",
  }),
  "package.json": Object.freeze({
    bytes: 134,
    digest:
      "sha256:86f83ebce70efcb741663859444a059de21eb8906fbe45dc220aed6c94eb5803",
  }),
});

const TARGET_FILES = Object.freeze({
  "index.js": Object.freeze({
    bytes: 23_860,
    digest:
      "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b",
  }),
  "openclaw.plugin.json": Object.freeze({
    bytes: 723,
    digest:
      "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036",
  }),
  "package.json": Object.freeze({
    bytes: 134,
    digest:
      "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2",
  }),
});

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

function exactFile(path, expected, mode = "444") {
  const metadata = lstatSync(path);
  const raw = readFileSync(path);
  const observed = {
    bytes: raw.length,
    digest: sha256(raw),
    gid: metadata.gid,
    mode: (metadata.mode & 0o777).toString(8).padStart(3, "0"),
    nlink: metadata.nlink,
    path,
    type: metadata.isFile() ? "file" : "other",
    uid: metadata.uid,
  };
  if (
    observed.type !== "file" ||
    observed.uid !== 0 ||
    observed.gid !== 0 ||
    observed.mode !== mode ||
    observed.nlink !== 1 ||
    observed.bytes !== expected.bytes ||
    observed.digest !== expected.digest
  ) {
    throw new Error(`pinned file changed: ${path}`);
  }
  return observed;
}

function workingConfigSnapshot() {
  const metadata = lstatSync(WORKING_CONFIG);
  const raw = readFileSync(WORKING_CONFIG);
  const document = JSON.parse(raw.toString("utf8"));
  if (
    !document ||
    typeof document !== "object" ||
    Array.isArray(document) ||
    !metadata.isFile() ||
    metadata.uid !== 992 ||
    metadata.gid !== 992 ||
    metadata.nlink !== 1 ||
    (metadata.mode & 0o777) !== 0o600
  ) {
    throw new Error("working core-updater config custody changed");
  }
  return {
    bytes: raw.length,
    canonical_digest: sha256(Buffer.from(canonicalJson(document))),
    digest: sha256(raw),
    document,
    gid: metadata.gid,
    mode: "600",
    nlink: metadata.nlink,
    path: WORKING_CONFIG,
    type: "file",
    uid: metadata.uid,
  };
}

function prepareWorkingConfig() {
  try {
    lstatSync(WORKING_CONFIG);
    throw new Error("working core-updater config already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
  const sourceRaw = readFileSync(CONFIG);
  const sourceDocument = JSON.parse(sourceRaw.toString("utf8"));
  if (
    sourceRaw.length !== CONFIG_EXPECTED.bytes ||
    sha256(sourceRaw) !== CONFIG_EXPECTED.digest ||
    sha256(Buffer.from(canonicalJson(sourceDocument))) !==
      CONFIG_EXPECTED.canonicalDigest
  ) {
    throw new Error("pinned protected configuration changed");
  }
  writeFileSync(WORKING_CONFIG, sourceRaw, { flag: "wx", mode: 0o600 });
  chmodSync(WORKING_CONFIG, 0o600);
  const snapshot = workingConfigSnapshot();
  if (
    snapshot.bytes !== CONFIG_EXPECTED.bytes ||
    snapshot.digest !== CONFIG_EXPECTED.digest ||
    snapshot.canonical_digest !== CONFIG_EXPECTED.canonicalDigest
  ) {
    throw new Error("working core-updater configuration copy changed");
  }
  return snapshot;
}

function verifyWorkingConfigTransition(before, after) {
  const expected = structuredClone(before.document);
  const observed = structuredClone(after.document);
  expected.plugins.entries[PLUGIN_ID].enabled = false;
  delete expected.plugins.allow;
  expected.plugins.bundledDiscovery = "compat";
  delete expected.meta;
  const observedMeta = observed.meta;
  const observedWizard = observed.wizard;
  delete observed.meta;
  delete observed.wizard;
  if (
    canonicalJson(observed) !== canonicalJson(expected) ||
    canonicalJson(Object.keys(observedMeta ?? {}).sort()) !==
      '["lastTouchedAt","lastTouchedVersion"]' ||
    observedMeta?.lastTouchedVersion !== "2026.7.1" ||
    typeof observedMeta?.lastTouchedAt !== "string" ||
    Number.isNaN(Date.parse(observedMeta.lastTouchedAt)) ||
    canonicalJson(Object.keys(observedWizard ?? {}).sort()) !==
      '["lastRunAt","lastRunCommand","lastRunMode","lastRunVersion"]' ||
    observedWizard?.lastRunVersion !== "2026.7.1" ||
    observedWizard?.lastRunCommand !== "doctor" ||
    observedWizard?.lastRunMode !== "local" ||
    typeof observedWizard?.lastRunAt !== "string" ||
    Number.isNaN(Date.parse(observedWizard.lastRunAt))
  ) {
    throw new Error("core-updater config bookkeeping changed");
  }
}

function targetSnapshot() {
  return Object.fromEntries(
    Object.entries(TARGET_FILES).map(([name, expected]) => {
      const path = join(TARGET, name);
      const metadata = lstatSync(path);
      const raw = readFileSync(path);
      const record = {
        bytes: raw.length,
        digest: sha256(raw),
        gid: metadata.gid,
        mode: (metadata.mode & 0o777).toString(8).padStart(3, "0"),
        nlink: metadata.nlink,
        path,
        type: metadata.isFile() ? "file" : "other",
        uid: metadata.uid,
      };
      if (
        record.type !== "file" ||
        record.uid !== 0 ||
        record.gid !== 0 ||
        record.mode !== "644" ||
        record.nlink !== 1 ||
        record.bytes !== expected.bytes ||
        record.digest !== expected.digest
      ) {
        throw new Error(`installed Aragorn plugin changed: ${name}`);
      }
      return [name, record];
    }),
  );
}

function managedRepositorySnapshot(path) {
  const metadata = lstatSync(path);
  const entries = readdirSync(path).sort();
  const record = {
    entries,
    gid: metadata.gid,
    mode: (metadata.mode & 0o777).toString(8).padStart(3, "0"),
    path,
    type: metadata.isDirectory() ? "directory" : "other",
    uid: metadata.uid,
  };
  if (
    record.type !== "directory" ||
    record.uid !== 992 ||
    record.gid !== 992 ||
    record.mode !== "700" ||
    record.entries.length !== 0
  ) {
    throw new Error("managed Git update repository changed");
  }
  return record;
}

function command(argv, options = {}) {
  const result = spawnSync(argv[0], argv.slice(1), {
    cwd: options.cwd,
    encoding: "utf8",
    env: options.env,
    maxBuffer: OUTPUT_LIMIT,
    timeout: options.timeout ?? 30_000,
  });
  const record = {
    argv,
    error:
      result.error instanceof Error
        ? { message: result.error.message, name: result.error.name }
        : null,
    exit_code: result.status,
    signal: result.signal,
    stderr_bytes: Buffer.byteLength(result.stderr ?? ""),
    stderr_digest: sha256(Buffer.from(result.stderr ?? "")),
    stdout_bytes: Buffer.byteLength(result.stdout ?? ""),
    stdout_digest: sha256(Buffer.from(result.stdout ?? "")),
  };
  Object.defineProperties(record, {
    _stderr: { value: result.stderr ?? "" },
    _stdout: { value: result.stdout ?? "" },
  });
  return record;
}

function requireSuccess(record, label) {
  if (
    record.exit_code !== 0 ||
    record.signal !== null ||
    record.error !== null
  ) {
    throw new Error(`${label} failed`);
  }
  return record._stdout.trim();
}

function gitEnvironment() {
  return {
    GIT_AUTHOR_DATE: FIXED_TIME,
    GIT_AUTHOR_EMAIL: "fixture@aragorn.invalid",
    GIT_AUTHOR_NAME: "Aragorn capture fixture",
    GIT_COMMITTER_DATE: FIXED_TIME,
    GIT_COMMITTER_EMAIL: "fixture@aragorn.invalid",
    GIT_COMMITTER_NAME: "Aragorn capture fixture",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_EDITOR: "",
    GIT_EXTERNAL_DIFF: "",
    GIT_SEQUENCE_EDITOR: "",
    GIT_TEMPLATE_DIR: "",
    GIT_TERMINAL_PROMPT: "0",
    HOME: "/var/lib/aragorn-agent-gateway/home",
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/local/bin:/usr/bin:/bin",
    TZ: "UTC",
  };
}

function runtimeEnvironment() {
  return {
    ...process.env,
    HOME: "/var/lib/aragorn-agent-gateway/home",
    OPENCLAW_CONFIG_PATH: WORKING_CONFIG,
    OPENCLAW_STATE_DIR: STATE,
    PATH: "/usr/local/bin:/usr/bin:/bin",
  };
}

function exactCommand(record, argv) {
  const keys = [
    "argv",
    "completed_at",
    "error",
    "exit_code",
    "pid",
    "signal",
    "started_at",
    "stderr_bytes",
    "stderr_digest",
    "stderr_excerpt",
    "stdout_bytes",
    "stdout_digest",
    "stdout_excerpt",
  ];
  if (
    !record ||
    canonicalJson(Object.keys(record).sort()) !== canonicalJson(keys) ||
    canonicalJson(record.argv) !== canonicalJson(argv) ||
    record.error !== null ||
    record.exit_code !== 0 ||
    !Number.isInteger(record.pid) ||
    record.pid <= 0 ||
    record.signal !== null ||
    typeof record.started_at !== "string" ||
    Number.isNaN(Date.parse(record.started_at)) ||
    typeof record.completed_at !== "string" ||
    Number.isNaN(Date.parse(record.completed_at)) ||
    Date.parse(record.started_at) > Date.parse(record.completed_at) ||
    !Number.isInteger(record.stderr_bytes) ||
    record.stderr_bytes < 0 ||
    !Number.isInteger(record.stdout_bytes) ||
    record.stdout_bytes < 0 ||
    !/^sha256:[0-9a-f]{64}$/.test(record.stderr_digest) ||
    !/^sha256:[0-9a-f]{64}$/.test(record.stdout_digest) ||
    typeof record.stderr_excerpt !== "string" ||
    typeof record.stdout_excerpt !== "string"
  ) {
    throw new Error("delegated command record changed");
  }
}

function createPinnedCandidateRepository() {
  try {
    lstatSync(REPOSITORY);
    throw new Error("candidate repository already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
  const candidates = Object.entries(CANDIDATE_FILES).map(([name, expected]) =>
    exactFile(join(CANDIDATE_ROOT, name), expected),
  );
  mkdirSync(REPOSITORY, { mode: 0o700 });
  for (const name of Object.keys(CANDIDATE_FILES)) {
    const destination = join(REPOSITORY, name);
    copyFileSync(join(CANDIDATE_ROOT, name), destination);
    chmodSync(destination, 0o644);
  }
  const commands = [];
  const run = (args, label) => {
    const record = command(["/usr/bin/git", ...args], {
      cwd: REPOSITORY,
      env: gitEnvironment(),
    });
    commands.push(record);
    return requireSuccess(record, label);
  };
  run(["init", "--quiet", "--object-format=sha1", "."], "git init");
  run(["add", "--", ...Object.keys(CANDIDATE_FILES)], "git add");
  run(
    [
      "commit",
      "--quiet",
      "--no-gpg-sign",
      "-m",
      "Pinned core updater replacement fixture",
    ],
    "git commit",
  );
  const objectFormat = run(["rev-parse", "--show-object-format"], "git object format");
  const commit = run(["rev-parse", "HEAD"], "git commit identity");
  const tree = run(["rev-parse", "HEAD^{tree}"], "git tree identity");
  if (
    objectFormat !== "sha1" ||
    commit !== EXPECTED_COMMIT ||
    tree !== EXPECTED_TREE
  ) {
    throw new Error("candidate repository identity changed");
  }
  return { candidates, commands, commit, object_format: objectFormat, path: REPOSITORY, tree };
}

function locateWriterModule() {
  const matches = [];
  for (const name of readdirSync(DIST).sort()) {
    if (!/^installed-plugin-index-records-[A-Za-z0-9_-]+\.js$/.test(name)) {
      continue;
    }
    const path = join(DIST, name);
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > 1024 * 1024) {
      continue;
    }
    const raw = readFileSync(path);
    const source = raw.toString("utf8");
    if (
      !source.includes("function writePersistedInstalledPluginIndexInstallRecords(") ||
      !source.includes('reason: "source-changed"')
    ) {
      continue;
    }
    const aliases = [
      ...source.matchAll(
        /writePersistedInstalledPluginIndexInstallRecords as ([A-Za-z_$][A-Za-z0-9_$]*)/g,
      ),
    ].map((match) => match[1]);
    if (aliases.length !== 1) {
      throw new Error("pinned writer export shape changed");
    }
    matches.push({
      alias: aliases[0],
      bytes: raw.length,
      digest: sha256(raw),
      path,
    });
  }
  if (matches.length !== 1) {
    throw new Error("pinned writer module is not an exact singleton");
  }
  return matches[0];
}

async function seedInstalledPluginRecord(repository) {
  const spec = `git:file://${repository.path}@${repository.commit}`;
  const gitKey = createHash("sha256").update(spec).digest("hex").slice(0, 16);
  const managedRepository = join(STATE, "git", `git-${gitKey}`, "repo");
  try {
    lstatSync(managedRepository);
    throw new Error("managed Git update repository already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
  mkdirSync(managedRepository, { mode: 0o700, recursive: true });
  const managedRepositoryBefore = managedRepositorySnapshot(managedRepository);
  const writerModule = locateWriterModule();
  const imported = await import(pathToFileURL(writerModule.path).href);
  const writer = imported[writerModule.alias];
  if (typeof writer !== "function") {
    throw new Error("pinned writer export is not callable");
  }
  const record = {
    gitCommit: repository.commit,
    gitRef: repository.commit,
    gitUrl: `file://${repository.path}`,
    installPath: TARGET,
    installedAt: FIXED_TIME,
    resolvedAt: FIXED_TIME,
    source: "git",
    spec,
    version: "0.1.0",
  };
  const storePath = await writer(
    { [PLUGIN_ID]: record },
    {
      config: JSON.parse(readFileSync(WORKING_CONFIG, "utf8")),
      env: runtimeEnvironment(),
      now: () => new Date(FIXED_TIME),
      stateDir: STATE,
      workspaceDir: WORKSPACE,
    },
  );
  const expectedStore = join(STATE, "state", "openclaw.sqlite");
  if (storePath !== expectedStore) {
    throw new Error("installed plugin index store path changed");
  }
  const store = lstatSync(storePath);
  if (
    !store.isFile() ||
    store.uid !== 992 ||
    store.gid !== 992 ||
    store.nlink !== 1 ||
    (store.mode & 0o777) !== 0o600
  ) {
    throw new Error("installed plugin index store custody changed");
  }
  return {
    managed_repository_before: managedRepositoryBefore,
    record: { plugin_id: PLUGIN_ID, ...record },
    store: {
      bytes: store.size,
      gid: store.gid,
      mode: (store.mode & 0o777).toString(8).padStart(3, "0"),
      nlink: store.nlink,
      path: storePath,
      type: "file",
      uid: store.uid,
    },
    writer_module: writerModule,
  };
}

function verifyDelegated(document, targetBefore) {
  const action = document?.actions?.[0];
  const route = document?.routes?.[0];
  if (
    document?.schema !== DELEGATED_SCHEMA ||
    document?.assurance !==
      "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY" ||
    document?.implementation_digest !== DELEGATED_EXPECTED.digest ||
    canonicalJson(document?.selected_route_ids) !== canonicalJson([ROUTE]) ||
    !Array.isArray(document?.actions) ||
    document.actions.length !== 1 ||
    action?.id !== ACTION ||
    action?.status !== "OBSERVED" ||
    canonicalJson(action?.reason_codes) !== "[]" ||
    action?.execution_error !== null ||
    action?.prerequisites?.ready !== true ||
    !Array.isArray(document?.routes) ||
    document.routes.length !== 1 ||
    canonicalJson(route) !==
      canonicalJson({
        action_id: ACTION,
        id: ROUTE,
        reason_codes: [],
        status: "OBSERVED",
      })
  ) {
    throw new Error("delegated route identity or status changed");
  }
  const observations = action.observations;
  const repair = observations?.update_repair;
  const commandRecord = repair?.command;
  const expectedArgv = [
    "/usr/local/bin/node",
    "/runtime/lib/node_modules/openclaw/openclaw.mjs",
    "update",
    "repair",
    "--timeout",
    "10",
    "--yes",
    "--json",
    "--no-restart",
  ];
  const rawFailure =
    `Disabled "${PLUGIN_ID}" after plugin update failure; ` +
    "OpenClaw will continue without it. " +
    `Failed to update ${PLUGIN_ID}: blocked by install policy: ` +
    `${POLICY_REASON} (git ${specForRepository()}).`;
  const guidance = [
    "Run openclaw update repair to retry post-update plugin repair.",
    `Run openclaw plugins inspect ${PLUGIN_ID} --runtime --json for details.`,
  ];
  const guidedMessage =
    `Plugin "${PLUGIN_ID}" could not be processed after the core update: ` +
    `${rawFailure} ${guidance.join(" ")}`;
  const expectedOutcome = {
    message: guidedMessage,
    pluginId: PLUGIN_ID,
    status: "skipped",
  };
  const expectedWarning = {
    guidance,
    message: guidedMessage,
    pluginId: PLUGIN_ID,
    reason: rawFailure,
  };
  const expectedResponse = {
    channel: "stable",
    mode: "finalize",
    postUpdate: {
      doctor: { status: "ok" },
      plugins: {
        changed: true,
        integrityDrifts: [],
        npm: { changed: true, outcomes: [expectedOutcome] },
        status: "warning",
        sync: {
          changed: false,
          errors: [],
          switchedToBundled: [],
          switchedToNpm: [],
          warnings: [],
        },
        warnings: [expectedWarning],
      },
    },
    restart: false,
    root: "/runtime/lib/node_modules/openclaw",
    status: "warning",
  };
  if (!Array.isArray(action.commands) || action.commands.length !== 3) {
    throw new Error("delegated core-updater command sequence changed");
  }
  exactCommand(
    action.commands[0],
    [
      "/usr/local/bin/node",
      "/runtime/lib/node_modules/openclaw/openclaw.mjs",
      "plugins",
      "list",
      "--json",
    ],
  );
  exactCommand(commandRecord, expectedArgv);
  exactCommand(
    action.commands[2],
    [
      "/usr/local/bin/node",
      "/runtime/lib/node_modules/openclaw/openclaw.mjs",
      "plugins",
      "list",
      "--json",
    ],
  );
  if (
    canonicalJson(action.commands) !==
      canonicalJson([
        observations?.inventory_before?.command,
        commandRecord,
        observations?.inventory_after?.command,
      ]) ||
    observations?.inventory_before?.response?.parsed !== true ||
    observations?.inventory_after?.response?.parsed !== true ||
    canonicalJson(observations?.roots_before) !==
      canonicalJson(observations?.roots_after) ||
    canonicalJson(observations?.configuration_after) !==
      canonicalJson(document?.protected_boundary?.configuration) ||
    repair?.response?.parsed !== true ||
    canonicalJson(repair.response.value) !== canonicalJson(expectedResponse)
  ) {
    throw new Error("target-specific policy-blocked update outcome absent");
  }
  const targetAfter = targetSnapshot();
  if (canonicalJson(targetAfter) !== canonicalJson(targetBefore)) {
    throw new Error("installed Aragorn plugin changed after denied update");
  }
  return { policy_outcome: expectedOutcome, target_after: targetAfter };
}

function specForRepository() {
  return `git:file://${REPOSITORY}@${EXPECTED_COMMIT}`;
}

function trustedPolicyAudit() {
  const raw = readFileSync(AUDIT_PATH);
  if (!raw.toString("utf8").endsWith("\n") || raw.subarray(0, -1).includes(0x0a)) {
    throw new Error("trusted policy audit is not one JSONL record");
  }
  const record = JSON.parse(raw.toString("utf8"));
  if (raw.toString("utf8") !== `${canonicalJson(record)}\n`) {
    throw new Error("trusted policy audit is not canonical JSON plus LF");
  }
  const event = record?.event;
  const eventKeys = [
    "action",
    "actor",
    "attributes",
    "category",
    "control",
    "eventId",
    "outcome",
    "policy",
    "reason",
    "seq",
    "severity",
    "target",
    "ts",
    "type",
  ];
  const actualEventKeys = Object.keys(event ?? {}).sort();
  const exactEventKeys =
    canonicalJson(actualEventKeys) === canonicalJson(eventKeys) ||
    canonicalJson(actualEventKeys) ===
      canonicalJson([...eventKeys, "trace"].sort());
  if (
    canonicalJson(record?.metadata) !== canonicalJson({ trusted: true }) ||
    !exactEventKeys ||
    event?.type !== "security.event" ||
    event?.category !== "plugin" ||
    event?.action !== "plugin.audit.failed" ||
    event?.outcome !== "denied" ||
    event?.severity !== "medium" ||
    canonicalJson(event?.actor) !== canonicalJson({ kind: "operator" }) ||
    canonicalJson(event?.target) !==
      canonicalJson({ kind: "plugin", name: PLUGIN_ID }) ||
    canonicalJson(event?.policy) !==
      canonicalJson({
        decision: "deny",
        id: "plugin.install",
        reason: "security_scan_blocked",
      }) ||
    canonicalJson(event?.control) !==
      canonicalJson({ family: "supply_chain", id: "plugin.install.audit" }) ||
    event?.reason !== "security_scan_blocked" ||
    canonicalJson(event?.attributes) !==
      canonicalJson({ mode: "update", source_family: "git" }) ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      event?.eventId ?? "",
    ) ||
    !Number.isInteger(event?.seq) ||
    event.seq <= 0 ||
    !Number.isInteger(event?.ts) ||
    event.ts <= 0
  ) {
    throw new Error("trusted target-specific denied plugin audit changed");
  }
  const metadata = lstatSync(AUDIT_PATH);
  if (
    !metadata.isFile() ||
    metadata.uid !== 992 ||
    metadata.gid !== 992 ||
    metadata.nlink !== 1 ||
    (metadata.mode & 0o777) !== 0o600
  ) {
    throw new Error("trusted policy audit custody changed");
  }
  return {
    ...record,
    journal: {
      bytes: raw.length,
      digest: sha256(raw),
      gid: metadata.gid,
      mode: "600",
      nlink: metadata.nlink,
      path: AUDIT_PATH,
      type: "file",
      uid: metadata.uid,
    },
  };
}

function parseArguments(argv) {
  if (
    argv.length !== 2 ||
    argv[0] !== "--route-id" ||
    argv[1] !== ROUTE
  ) {
    throw new Error(`usage: ${SELF} --route-id ${ROUTE}`);
  }
}

async function main() {
  parseArguments(process.argv.slice(2));
  exactFile(SELF, { bytes: lstatSync(SELF).size, digest: sha256(readFileSync(SELF)) });
  exactFile(DELEGATED_PROBE, DELEGATED_EXPECTED);
  exactFile(AUDIT_LISTENER, AUDIT_LISTENER_EXPECTED);
  const workingConfigBefore = prepareWorkingConfig();
  const targetBefore = targetSnapshot();
  const repository = createPinnedCandidateRepository();
  const installedIndex = await seedInstalledPluginRecord(repository);
  try {
    lstatSync(AUDIT_PATH);
    throw new Error("trusted policy audit journal already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
  const delegated = command(
    ["/usr/local/bin/node", DELEGATED_PROBE, "--route-id", ROUTE],
    { cwd: WORKSPACE, env: runtimeEnvironment(), timeout: 120_000 },
  );
  requireSuccess(delegated, "delegated protected route probe");
  if (delegated._stderr !== "" || !delegated._stdout.endsWith("\n")) {
    throw new Error("delegated route output framing changed");
  }
  const document = JSON.parse(delegated._stdout);
  if (delegated._stdout !== `${canonicalJson(document)}\n`) {
    throw new Error("delegated route output is not canonical JSON plus LF");
  }
  const semantic = verifyDelegated(document, targetBefore);
  installedIndex.managed_repository_after = managedRepositorySnapshot(
    installedIndex.managed_repository_before.path,
  );
  if (
    canonicalJson(installedIndex.managed_repository_after) !==
    canonicalJson(installedIndex.managed_repository_before)
  ) {
    throw new Error("denied update changed managed Git repository");
  }
  const workingConfigAfter = workingConfigSnapshot();
  verifyWorkingConfigTransition(workingConfigBefore, workingConfigAfter);
  const audit = trustedPolicyAudit();
  const implementationDigest = sha256(readFileSync(SELF));
  const result = {
    ...document,
    core_updater_preflight: {
      candidate_repository: repository,
      delegated_probe: {
        bytes: lstatSync(DELEGATED_PROBE).size,
        digest: sha256(readFileSync(DELEGATED_PROBE)),
        path: DELEGATED_PROBE,
      },
      installed_index: installedIndex,
      policy_reason: POLICY_REASON,
      ready: true,
      target_before: targetBefore,
      trusted_policy_audit: audit,
      working_config_after: workingConfigAfter,
      working_config_before: workingConfigBefore,
      ...semantic,
    },
    delegated_implementation_digest: document.implementation_digest,
    implementation_digest: implementationDigest,
    schema: SCHEMA,
  };
  process.stdout.write(`${canonicalJson(result)}\n`);
}

try {
  await main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`core-updater preflight failed closed: ${message}\n`);
  process.exitCode = 2;
}
