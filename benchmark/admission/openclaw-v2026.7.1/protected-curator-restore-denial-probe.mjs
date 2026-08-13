#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CONFIG,
  EMPTY_DIGEST,
  NODE,
  OPENCLAW,
  PROTECTED_ROOTS,
  WORKSPACE,
  canonicalJson,
  cleanCommand,
  command,
  errorRecord,
  gatewayCall,
  gatewayProcessObservation,
  helperDigest,
  mountObservation,
  parsedCommand,
  pathObservation,
  protectedRootTrees,
  runtimeEnvironment,
  runtimeTree,
  sha256,
  treeObservation,
} from "./protected-observation-v1.mjs";

const SELF = fileURLToPath(import.meta.url);
const TARGET_NAME = "requesting-code-review";
const TARGET = join(WORKSPACE, "skills", TARGET_NAME);
const TARGET_FILE = join(TARGET, "SKILL.md");
const STATE_DB = "/profile/state/state/openclaw.sqlite";
const RUN_NONCE = randomBytes(16).toString("hex");
const INVALID_CHILD_TOKEN =
  "aragorn-intentionally-invalid-curator-restore-fallback-token-v1";
const AUTHORITY_ERROR =
  "Skill curator restore is delegated to an external authority";
const EXPECTED_CONFIG_DIGEST =
  "sha256:701da2485f2844603c13b40c56876984de5ff9cdc22927f1a5bcd218ba369751";
const EXPECTED_CONFIG_CANONICAL_DIGEST =
  "sha256:417fc06b87a539654433451aff12509ca7dca28003c9f2cedc91bcc611eba16e";
const EXPECTED_OPENCLAW_DIGEST =
  "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188";
const EXPECTED_TARGET_DIGEST =
  "sha256:1a13f195721f8fa75974bd4918a25b30e8406ff6d423cd0e3306c391b8fee07a";
const EXPECTED_TARGET_TREE_DIGEST =
  "sha256:c3e201e18e2fa35a56d4cae3a0ed481072f4ed77db18e6d568b266068cbe96c3";
const EXPECTED_RUNTIME_TREE = Object.freeze({
  algorithm: "aragorn/runtime-tree/v1",
  entry_count: 45_859,
  file_count: 45_840,
  symlink_count: 19,
  total_bytes: 369_418_625,
  tree_digest:
    "sha256:6448edb21fd2a27dd3cf2b740e0d0dfc3a395e2ccae446853867a95485d54e74",
});
const MODULES = Object.freeze({
  cli: {
    bytes: 52_200,
    digest:
      "sha256:b0cb989a0543181aa737cc5ca37c10bf3f21b010a76cb742aefd1b5b4cef8db8",
    path: "/runtime/lib/node_modules/openclaw/dist/skills-cli-B0D3yE3o.js",
  },
  config: {
    bytes: 1_496,
    digest:
      "sha256:a348e485490fbdc69d94e9254db39628147a07166e20228ff763d89838346f5f",
    path: "/runtime/lib/node_modules/openclaw/dist/config-DhjFoEdz.js",
  },
  curator: {
    bytes: 45_462,
    digest:
      "sha256:ef522ff1ee42cd11569e0dbe53d1be12bbca6ddb5024cf70f8896929d6d30bb3",
    path: "/runtime/lib/node_modules/openclaw/dist/curator-rOIsv8kR.js",
  },
  gateway: {
    bytes: 46_858,
    digest:
      "sha256:5baa73a9a2ef36d65243ac9068ada55f2bfc5e25041ccf2bae6635aede89bdfa",
    path: "/runtime/lib/node_modules/openclaw/dist/skills-BY50TjFr.js",
  },
  schema: {
    bytes: 59_911,
    digest:
      "sha256:a90be5b2226ad12935be90094b01c8544c5641f7cf7df175e6f962ca402d8309",
    path: "/runtime/lib/node_modules/openclaw/dist/zod-schema-Cvjp91Cd.js",
  },
});
const EXPECTED_GATEWAY_DENIAL = Object.freeze({
  ok: false,
  error: {
    type: "gateway_request_error",
    code: "INVALID_REQUEST",
    message: AUTHORITY_ERROR,
    retryable: false,
  },
});
const EXPECTED_GATEWAY_STDOUT = `${JSON.stringify(
  EXPECTED_GATEWAY_DENIAL,
  null,
  2,
)}\n`;
const EXPECTED_CLI_STDERR = `Error: ${AUTHORITY_ERROR}\n`;
const EXPECTED_INVALID_TOKEN_DENIAL = Object.freeze({
  ok: false,
  error: {
    type: "gateway_transport_error",
    kind: "closed",
    message:
      "gateway closed (1006 abnormal closure (no close frame)): no close reason",
    code: 1006,
    reason: "no close reason",
  },
  gateway: {
    url: "ws://127.0.0.1:18789",
    urlSource: "local loopback",
    bindDetail: "Bind: loopback",
  },
});
const EXPECTED_INVALID_TOKEN_STDOUT = `${JSON.stringify(
  EXPECTED_INVALID_TOKEN_DENIAL,
  null,
  2,
)}\n`;
const FIXTURE_ROW = Object.freeze({
  archived_reason: "aragorn exact protected restore-authority fixture",
  created_at_ms: 1,
  pinned: 0,
  skill_file: TARGET_FILE,
  skill_key: TARGET_NAME,
  skill_name: TARGET_NAME,
  state: "archived",
  state_changed_at_ms: 2,
});
const EXPECTED_CURATOR_STATUS = Object.freeze({
  counts: { active: 0, archived: 1, stale: 0 },
  lastAttemptAtMs: null,
  lastError: null,
  lastSuccessAtMs: null,
  overlaps: [],
  skills: [
    {
      archivedReason: FIXTURE_ROW.archived_reason,
      createdAtMs: FIXTURE_ROW.created_at_ms,
      lastUsedAtMs: null,
      pinned: false,
      skillFile: FIXTURE_ROW.skill_file,
      skillKey: FIXTURE_ROW.skill_key,
      skillName: FIXTURE_ROW.skill_name,
      state: FIXTURE_ROW.state,
      stateChangedAtMs: FIXTURE_ROW.state_changed_at_ms,
      useCount: 0,
    },
  ],
});
const OUTPUT_LIMIT = 2 * 1024 * 1024;
const EXCERPT_LIMIT = 2048;

function bounded(raw) {
  return raw.length <= EXCERPT_LIMIT
    ? raw
    : `${raw.slice(0, EXCERPT_LIMIT)}[truncated]`;
}

function commandWithEnvironment(args, overrides, timeout = 30_000) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(NODE, [OPENCLAW, ...args], {
    cwd: WORKSPACE,
    encoding: "utf8",
    env: { ...runtimeEnvironment(), ...overrides },
    maxBuffer: OUTPUT_LIMIT,
    timeout,
  });
  const stderr = result.stderr ?? "";
  const stdout = result.stdout ?? "";
  const record = {
    argv: [NODE, OPENCLAW, ...args],
    completed_at: new Date().toISOString(),
    error: result.error ? errorRecord(result.error) : null,
    exit_code: result.status,
    pid: result.pid ?? null,
    signal: result.signal,
    started_at: startedAt,
    stderr_bytes: Buffer.byteLength(stderr),
    stderr_digest: sha256(Buffer.from(stderr)),
    stderr_excerpt: bounded(stderr),
    stdout_bytes: Buffer.byteLength(stdout),
    stdout_digest: sha256(Buffer.from(stdout)),
    stdout_excerpt: bounded(stdout),
  };
  Object.defineProperties(record, {
    _stderr: { value: stderr },
    _stdout: { value: stdout },
  });
  return record;
}

function configurationObservation() {
  const mount = mountObservation("/profile/config");
  const file = pathObservation(CONFIG, { hashFile: true });
  let canonicalDigest = null;
  let document = null;
  let parseError = null;
  try {
    document = JSON.parse(readFileSync(CONFIG, "utf8"));
    canonicalDigest = sha256(Buffer.from(canonicalJson(document)));
  } catch (error) {
    parseError = errorRecord(error);
  }
  return {
    canonical_digest: canonicalDigest,
    document,
    file,
    mount,
    parse_error: parseError,
    ready:
      mount.ready &&
      file.exists === true &&
      file.type === "file" &&
      file.uid === 0 &&
      file.gid === 982 &&
      file.mode === "440" &&
      file.nlink === 1 &&
      file.size === 359 &&
      file.digest === EXPECTED_CONFIG_DIGEST &&
      canonicalDigest === EXPECTED_CONFIG_CANONICAL_DIGEST &&
      document?.gateway?.mode === "local" &&
      document?.plugins?.enabled === false &&
      document?.skills?.load?.watch === false &&
      document?.skills?.workshop?.restoreAuthority === "external",
  };
}

function boundaryObservation() {
  const roots = Object.fromEntries(
    Object.entries(PROTECTED_ROOTS).map(([name, path]) => [
      name,
      mountObservation(path),
    ]),
  );
  const configuration = configurationObservation();
  const runtime = mountObservation("/runtime");
  const probe = mountObservation("/probe");
  const effectiveIdentity = {
    gid: typeof process.getgid === "function" ? process.getgid() : null,
    groups:
      typeof process.getgroups === "function" ? process.getgroups() : [],
    uid: typeof process.getuid === "function" ? process.getuid() : null,
  };
  return {
    configuration,
    effective_identity: effectiveIdentity,
    probe,
    ready:
      configuration.ready &&
      Object.values(roots).every((entry) => entry.ready) &&
      runtime.ready &&
      probe.ready &&
      effectiveIdentity.uid === 1000 &&
      effectiveIdentity.gid === 1000 &&
      effectiveIdentity.groups.includes(982),
    roots,
    runtime,
  };
}

function moduleObservations() {
  return Object.fromEntries(
    Object.entries(MODULES).map(([name, expected]) => [
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
      observed.nlink === 1 &&
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
    skill?.path === "SKILL.md" &&
    skill.type === "file" &&
    skill.uid === 0 &&
    skill.gid === 982 &&
    skill.mode === "440" &&
    skill.nlink === 1 &&
    skill.digest === EXPECTED_TARGET_DIGEST
  );
}

function systemInfo() {
  const native = gatewayCall("system.info");
  return { command: native, response: parsedCommand(native) };
}

function curatorStatus() {
  const native = gatewayCall("skills.curator.status");
  return { command: native, response: parsedCommand(native) };
}

function skillStatus() {
  const native = gatewayCall("skills.status", { agentId: "main" });
  const response = parsedCommand(native);
  const skills = Array.isArray(response.value?.skills)
    ? response.value.skills
    : [];
  return {
    command: native,
    response,
    target_matches: skills.filter((skill) => skill?.name === TARGET_NAME),
  };
}

function exactCuratorStatus(observation) {
  return (
    observation.command.exit_code === 0 &&
    cleanCommand(observation.command) &&
    observation.response.parsed &&
    same(observation.response.value, EXPECTED_CURATOR_STATUS)
  );
}

function exactSkillStatusDiagnostic(observation) {
  const skill = observation.target_matches[0];
  return (
    observation.command.exit_code === 0 &&
    cleanCommand(observation.command) &&
    observation.response.parsed &&
    observation.target_matches.length === 1 &&
    skill?.name === TARGET_NAME &&
    skill?.skillKey === TARGET_NAME &&
    skill?.baseDir === TARGET &&
    skill?.filePath === TARGET_FILE &&
    skill?.source === "openclaw-workspace" &&
    skill?.eligible === true &&
    skill?.modelVisible === true
  );
}

function databaseObservation(database) {
  const row = database
    .prepare(
      `SELECT archived_reason, created_at_ms, pinned, skill_file, skill_key,
              skill_name, state, state_changed_at_ms
         FROM skill_lifecycle
        WHERE skill_file = ?`,
    )
    .get(TARGET_FILE);
  const version = database.prepare("PRAGMA data_version").get();
  return {
    data_version: version?.data_version ?? null,
    file: pathObservation(STATE_DB, { hashFile: true }),
    row: row ?? null,
  };
}

function seedArchivedFixture() {
  const database = new DatabaseSync(STATE_DB);
  database.exec("PRAGMA busy_timeout = 30000");
  const collision = database
    .prepare("SELECT 1 AS present FROM skill_lifecycle WHERE skill_file = ?")
    .get(TARGET_FILE);
  if (collision) {
    database.close();
    throw new Error("curator lifecycle fixture target already exists");
  }
  database
    .prepare(
      `INSERT INTO skill_lifecycle
        (skill_file, skill_key, skill_name, state, pinned,
         state_changed_at_ms, created_at_ms, archived_reason)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      FIXTURE_ROW.skill_file,
      FIXTURE_ROW.skill_key,
      FIXTURE_ROW.skill_name,
      FIXTURE_ROW.state,
      FIXTURE_ROW.pinned,
      FIXTURE_ROW.state_changed_at_ms,
      FIXTURE_ROW.created_at_ms,
      FIXTURE_ROW.archived_reason,
    );
  return database;
}

function exactDatabaseObservation(observation) {
  return (
    canonicalJson(observation.row) === canonicalJson(FIXTURE_ROW) &&
    Number.isSafeInteger(observation.data_version) &&
    observation.data_version > 0
  );
}

function exactGatewayDenial(commandResult, response) {
  return (
    commandResult.exit_code === 1 &&
    cleanCommand(commandResult) &&
    commandResult.stderr_bytes === 0 &&
    commandResult.stderr_digest === EMPTY_DIGEST &&
    commandResult.stdout_bytes === Buffer.byteLength(EXPECTED_GATEWAY_STDOUT) &&
    commandResult.stdout_digest ===
      sha256(Buffer.from(EXPECTED_GATEWAY_STDOUT)) &&
    response.parsed &&
    canonicalJson(response.value) === canonicalJson(EXPECTED_GATEWAY_DENIAL)
  );
}

function exactCliDenial(commandResult) {
  return (
    commandResult.exit_code === 1 &&
    cleanCommand(commandResult) &&
    commandResult.stdout_bytes === 0 &&
    commandResult.stdout_digest === EMPTY_DIGEST &&
    commandResult.stderr_bytes === Buffer.byteLength(EXPECTED_CLI_STDERR) &&
    commandResult.stderr_digest === sha256(Buffer.from(EXPECTED_CLI_STDERR)) &&
    commandResult.stderr_excerpt === EXPECTED_CLI_STDERR
  );
}

function exactInvalidTokenDenial(commandResult, response) {
  return (
    commandResult.exit_code === 1 &&
    cleanCommand(commandResult) &&
    commandResult.stderr_bytes === 0 &&
    commandResult.stderr_digest === EMPTY_DIGEST &&
    commandResult.stdout_bytes ===
      Buffer.byteLength(EXPECTED_INVALID_TOKEN_STDOUT) &&
    commandResult.stdout_digest ===
      sha256(Buffer.from(EXPECTED_INVALID_TOKEN_STDOUT)) &&
    response.parsed &&
    canonicalJson(response.value) ===
      canonicalJson(EXPECTED_INVALID_TOKEN_DENIAL)
  );
}

function exactSystemInfo(observation, gateway) {
  return (
    observation.command.exit_code === 0 &&
    cleanCommand(observation.command) &&
    observation.response.parsed &&
    observation.response.value?.pid === 1 &&
    observation.response.value?.hostname === gateway.hostname &&
    observation.response.value?.platform === "linux" &&
    observation.response.value?.arch === process.arch &&
    observation.response.value?.nodeVersion === process.version &&
    observation.response.value?.port === 18789
  );
}

function same(value, expected) {
  return canonicalJson(value) === canonicalJson(expected);
}

async function runObservation() {
  const boundaryBefore = boundaryObservation();
  const configTreeBefore = treeObservation("/profile/config");
  const configLockBefore = pathObservation(`${CONFIG}.lock`);
  const rootsBefore = protectedRootTrees();
  const targetBefore = treeObservation(TARGET);
  const gatewayBefore = gatewayProcessObservation();
  const modulesBefore = moduleObservations();
  const openclawBefore = pathObservation(OPENCLAW, { hashFile: true });
  const version = command(["--version"]);
  const systemBefore = systemInfo();
  const runtimeBefore = boundaryBefore.ready ? runtimeTree() : null;
  const initialize = curatorStatus();
  const prerequisitesReady =
    boundaryBefore.ready &&
    configTreeBefore.ready &&
    configTreeBefore.entries.length === 1 &&
    configTreeBefore.entries[0]?.path === "openclaw.json" &&
    configLockBefore.exists === false &&
    Object.values(rootsBefore).every((tree) => tree.ready) &&
    exactTarget(targetBefore) &&
    gatewayBefore.cmdline?.[0] === "openclaw-gateway" &&
    gatewayBefore.effective_capabilities === "0000000000000000" &&
    gatewayBefore.no_new_privileges === "1" &&
    gatewayBefore.seccomp === "2" &&
    exactModules(modulesBefore) &&
    openclawBefore.digest === EXPECTED_OPENCLAW_DIGEST &&
    version.exit_code === 0 &&
    cleanCommand(version) &&
    version.stdout_excerpt === "OpenClaw 2026.7.1 (805a4b1)\n" &&
    exactSystemInfo(systemBefore, gatewayBefore) &&
    initialize.command.exit_code === 0 &&
    cleanCommand(initialize.command) &&
    initialize.response.parsed &&
    Array.isArray(initialize.response.value?.skills) &&
    initialize.response.value.skills.length === 0 &&
    same(runtimeBefore, EXPECTED_RUNTIME_TREE);

  const prerequisites = {
    boundary_before: boundaryBefore,
    config_lock_before: configLockBefore,
    config_tree_before: configTreeBefore,
    curator_status_before_seed: initialize,
    gateway_process_before: gatewayBefore,
    modules_before: modulesBefore,
    openclaw_before: openclawBefore,
    protected_root_trees_before: rootsBefore,
    runtime_tree_before: runtimeBefore,
    system_info_before: systemBefore,
    target_before: targetBefore,
    version,
  };
  if (!prerequisitesReady) {
    return {
      commands: [version, systemBefore.command, initialize.command],
      execution_error: null,
      id: "curator-restore-authority-denial",
      observations: {},
      prerequisites,
      reason_codes: ["EXACT_PROTECTED_CURATOR_RESTORE_PREREQUISITE_MISSING"],
      status: "NOT_TESTED",
    };
  }

  const database = seedArchivedFixture();
  try {
    const databaseBefore = databaseObservation(database);
    if (!exactDatabaseObservation(databaseBefore)) {
      throw new Error("exact archived lifecycle fixture was not established");
    }
    const curatorBefore = curatorStatus();
    if (!exactCuratorStatus(curatorBefore)) {
      throw new Error("exact archived curator status was not established");
    }
    const discoveryBefore = skillStatus();
    if (!exactSkillStatusDiagnostic(discoveryBefore)) {
      throw new Error("protected skills.status diagnostic changed");
    }

    const gatewayRestore = gatewayCall("skills.curator.restore", {
      skill: TARGET_NAME,
    });
    const gatewayResponse = parsedCommand(gatewayRestore);
    if (!exactGatewayDenial(gatewayRestore, gatewayResponse)) {
      throw new Error("gateway curator restore denial changed");
    }
    const databaseAfterGateway = databaseObservation(database);
    if (
      !exactDatabaseObservation(databaseAfterGateway)
    ) {
      throw new Error("gateway restore changed archived lifecycle state");
    }

    const invalidTokenControl = commandWithEnvironment(
      ["gateway", "call", "system.info", "--json", "--timeout", "5000"],
      { OPENCLAW_GATEWAY_TOKEN: INVALID_CHILD_TOKEN },
      10_000,
    );
    const invalidTokenResponse = parsedCommand(invalidTokenControl);
    if (!exactInvalidTokenDenial(invalidTokenControl, invalidTokenResponse)) {
      throw new Error("invalid-token gateway control did not fail authentication");
    }

    const cliRestore = commandWithEnvironment(
      ["skills", "curator", "restore", TARGET_NAME, "--json"],
      { OPENCLAW_GATEWAY_TOKEN: INVALID_CHILD_TOKEN },
      15_000,
    );
    if (!exactCliDenial(cliRestore)) {
      throw new Error("high-level CLI fallback denial changed");
    }
    const databaseAfterCli = databaseObservation(database);
    if (
      !exactDatabaseObservation(databaseAfterCli)
    ) {
      throw new Error("CLI fallback changed archived lifecycle state");
    }

    const curatorAfter = curatorStatus();
    const discoveryAfter = skillStatus();
    const systemAfter = systemInfo();
    const boundaryAfter = boundaryObservation();
    const configTreeAfter = treeObservation("/profile/config");
    const configLockAfter = pathObservation(`${CONFIG}.lock`);
    const rootsAfter = protectedRootTrees();
    const targetAfter = treeObservation(TARGET);
    const gatewayAfter = gatewayProcessObservation();
    const modulesAfter = moduleObservations();
    const openclawAfter = pathObservation(OPENCLAW, { hashFile: true });
    const runtimeAfter = runtimeTree();
    if (
      !exactCuratorStatus(curatorAfter) ||
      !same(curatorAfter.response.value, curatorBefore.response.value) ||
      !exactSkillStatusDiagnostic(discoveryAfter) ||
      !same(discoveryAfter.response.value, discoveryBefore.response.value) ||
      !exactSystemInfo(systemAfter, gatewayAfter) ||
      !same(boundaryAfter, boundaryBefore) ||
      !same(configTreeAfter, configTreeBefore) ||
      !same(configLockAfter, configLockBefore) ||
      !same(rootsAfter, rootsBefore) ||
      !same(targetAfter, targetBefore) ||
      !same(gatewayAfter, gatewayBefore) ||
      !same(modulesAfter, modulesBefore) ||
      !same(openclawAfter, openclawBefore) ||
      !same(runtimeAfter, runtimeBefore)
    ) {
      throw new Error("protected post-denial boundary changed");
    }

    return {
      commands: [
        version,
        systemBefore.command,
        initialize.command,
        curatorBefore.command,
        discoveryBefore.command,
        gatewayRestore,
        invalidTokenControl,
        cliRestore,
        curatorAfter.command,
        discoveryAfter.command,
        systemAfter.command,
      ],
      execution_error: null,
      id: "curator-restore-authority-denial",
      observations: {
        boundary_after: boundaryAfter,
        cli_fallback_restore: { command: cliRestore },
        config_lock_after: configLockAfter,
        config_tree_after: configTreeAfter,
        curator_status_after: curatorAfter,
        curator_status_before: curatorBefore,
        database_after_cli: databaseAfterCli,
        database_after_gateway: databaseAfterGateway,
        database_before: databaseBefore,
        discovery_after: discoveryAfter,
        discovery_before: discoveryBefore,
        gateway_process_after: gatewayAfter,
        gateway_restore: {
          command: gatewayRestore,
          response: gatewayResponse,
        },
        invalid_token_gateway_control: {
          command: invalidTokenControl,
          response: invalidTokenResponse,
        },
        modules_after: modulesAfter,
        openclaw_after: openclawAfter,
        protected_root_trees_after: rootsAfter,
        runtime_tree_after: runtimeAfter,
        system_info_after: systemAfter,
        target_after: targetAfter,
      },
      prerequisites,
      reason_codes: [],
      status: "OBSERVED",
    };
  } finally {
    database.close();
  }
}

async function main() {
  if (process.argv.length !== 2) {
    throw new Error("the focused curator-restore probe accepts no arguments");
  }
  if (!process.env.OPENCLAW_GATEWAY_TOKEN) {
    throw new Error("OPENCLAW_GATEWAY_TOKEN is required");
  }
  if (process.env.OPENCLAW_GATEWAY_TOKEN === INVALID_CHILD_TOKEN) {
    throw new Error("live gateway token must differ from the invalid-token control");
  }
  const action = await runObservation();
  return {
    action,
    assurance: "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
    implementation_digests: {
      helper: helperDigest(),
      probe: sha256(readFileSync(SELF)),
    },
    limitations: [
      "OBSERVED_IS_NOT_PASS",
      "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
      "SHARED_DATABASE_DATA_VERSION_NOT_STABLE_ONLY_EXACT_SELECTED_LIFECYCLE_ROW_BOUND",
      "SINGLE_ROUTE_SINGLE_CAPTURE",
      "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
      "NO_AGGREGATE_ADMISSION_INSTALLER_PHASE3_EDR_OR_RELEASE_AUTHORITY",
    ],
    recorded_at: new Date().toISOString(),
    route: {
      action_id: action.id,
      id: "ADM-02/update/curator-restore-activation",
      reason_codes: action.reason_codes,
      status: action.status,
    },
    run_nonce: RUN_NONCE,
    runtime_binding: {
      commit: "805a4b152b0cee271ee78ad5608c15a4f8d1624b",
      node_path: NODE,
      openclaw_digest: EXPECTED_OPENCLAW_DIGEST,
      openclaw_path: OPENCLAW,
      runtime_tree_digest: EXPECTED_RUNTIME_TREE.tree_digest,
      version: "2026.7.1",
    },
    schema: "aragorn/openclaw-protected-curator-restore-denial-observation/v1",
  };
}

try {
  process.stdout.write(`${canonicalJson(await main())}\n`);
} catch (error) {
  process.stdout.write(
    `${canonicalJson({
      assurance: "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
      fatal_error: errorRecord(error),
      schema: "aragorn/openclaw-protected-curator-restore-denial-error/v1",
    })}\n`,
  );
  process.exitCode = 1;
}
