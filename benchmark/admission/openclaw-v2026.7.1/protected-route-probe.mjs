#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/profile/config.json";
const STATE = "/profile/state";
const WORKSPACE = "/profile/workspace";
const SESSION_KEY = "agent:main:aragorn-protected-routes-v1";
const SESSION_STORE = join(STATE, "agents", "main", "sessions", "sessions.json");
const WORKSHOP_NAME = "aragorn-protected-workshop";
const WORKSHOP_DRAFT = join(WORKSPACE, "PROPOSAL.md");
const WORKSHOP_TARGET = join(WORKSPACE, "skills", WORKSHOP_NAME);
const FORCE_SOURCE_NAME = "aragorn-force-source";
const FORCE_SOURCE = "/runtime/lib/node_modules/openclaw/skills/1password";
const FORCE_SOURCE_TARGET = join(WORKSPACE, "skills", FORCE_SOURCE_NAME);
const SELF = fileURLToPath(import.meta.url);
const EXPECTED_VERSION = "OpenClaw 2026.7.1 (2d2ddc4)";
const EXPECTED_COMMIT = "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4";
const EXPECTED_OPENCLAW_DIGEST =
  "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188";
const RUNTIME_UID = 1000;
const RUNTIME_GID = 1000;
const OUTPUT_LIMIT = 2 * 1024 * 1024;
const EXCERPT_LIMIT = 2048;
const CONTROL_LIMIT = 4 * 1024 * 1024;
const EXPECTED_WORKSHOP_FIXTURE_DIGEST =
  "sha256:a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a";
const EXPECTED_CONFIG_CANONICAL_DIGEST =
  "sha256:6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a";
const RUN_NONCE = randomBytes(16).toString("hex");

const ROUTE_IDS = Object.freeze([
  "ADM-02/update/archive-source-force-replacement",
  "ADM-02/update/clawhub-tracked-replacement",
  "ADM-02/update/core-updater-plugin-replacement",
  "ADM-02/update/curator-restore-activation",
  "ADM-02/update/plugin-package-skill-replacement",
  "ADM-02/update/workshop-proposal-apply",
  "ADM-02/reload/fresh-session-reset",
  "ADM-02/reload/manual-plugin-invalidation",
  "ADM-02/reload/remote-eligibility-invalidation",
  "ADM-02/reload/sandbox-per-run-rescan",
  "ADM-02/reload/session-snapshot-consumer",
  "ADM-02/reload/workshop-invalidation",
]);
const ROUTE_SET = new Set(ROUTE_IDS);
const PROTECTED_DISCOVERY_ROOTS = Object.freeze({
  extensions: "/profile/state/extensions",
  managed_skills: "/profile/state/skills",
  personal_agents: "/profile/home/.agents/skills",
  plugin_skills: "/profile/state/plugin-skills",
  project_agents: "/profile/workspace/.agents/skills",
  workspace_skills: "/profile/workspace/skills",
});
const ACTION_BY_ROUTE = Object.freeze({
  "ADM-02/update/archive-source-force-replacement":
    "archive-source-force-replacement",
  "ADM-02/update/workshop-proposal-apply": "workshop-protected-apply",
  "ADM-02/reload/fresh-session-reset": "fresh-session-reset",
  "ADM-02/reload/session-snapshot-consumer": "session-snapshot-consumer",
});
const PROFILE_BLOCKED_ROUTES = Object.freeze({
  "ADM-02/reload/workshop-invalidation":
    "WORKSHOP_INVALIDATION_NOT_REACHED_AFTER_PROTECTED_APPLY_DENIAL",
});
const ADAPTER_BY_ROUTE = Object.freeze({
  "ADM-02/update/clawhub-tracked-replacement":
    "/route-adapters/clawhub-tracked-replacement.mjs",
  "ADM-02/update/core-updater-plugin-replacement":
    "/route-adapters/core-updater-plugin-replacement.mjs",
  "ADM-02/update/curator-restore-activation":
    "/route-adapters/curator-restore-activation.mjs",
  "ADM-02/update/plugin-package-skill-replacement":
    "/route-adapters/plugin-package-skill-replacement.mjs",
  "ADM-02/reload/manual-plugin-invalidation":
    "/route-adapters/manual-plugin-invalidation.mjs",
  "ADM-02/reload/remote-eligibility-invalidation":
    "/route-adapters/remote-eligibility-invalidation.mjs",
  "ADM-02/reload/sandbox-per-run-rescan":
    "/route-adapters/sandbox-per-run-rescan.mjs",
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

function errorRecord(error) {
  return {
    code: typeof error?.code === "string" ? error.code : null,
    message: error instanceof Error ? error.message : String(error),
    name: error instanceof Error ? error.name : "Error",
  };
}

function bounded(value) {
  return value.length <= EXCERPT_LIMIT
    ? value
    : `${value.slice(0, EXCERPT_LIMIT)}[truncated]`;
}

function runtimeEnvironment() {
  return {
    HOME: "/profile/home",
    HTTP_PROXY: "http://127.0.0.1:9",
    HTTPS_PROXY: "http://127.0.0.1:9",
    NO_COLOR: "1",
    NO_PROXY: "127.0.0.1,localhost",
    OPENCLAW_CONFIG_PATH: CONFIG,
    OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
    OPENCLAW_GATEWAY_TOKEN: process.env.OPENCLAW_GATEWAY_TOKEN ?? "",
    OPENCLAW_NO_RESPAWN: "1",
    OPENCLAW_SKIP_CHANNELS: "1",
    OPENCLAW_SKIP_PROVIDERS: "1",
    OPENCLAW_STATE_DIR: STATE,
    PATH: "/usr/local/bin:/usr/bin:/bin",
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_offline: "true",
  };
}

function command(args, timeout = 30_000) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(NODE, [OPENCLAW, ...args], {
    cwd: WORKSPACE,
    encoding: "utf8",
    env: runtimeEnvironment(),
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

function parsedCommand(commandResult) {
  for (const value of [
    commandResult._stdout ?? commandResult.stdout_excerpt,
    commandResult._stderr ?? commandResult.stderr_excerpt,
  ]) {
    try {
      return { parsed: true, value: JSON.parse(value) };
    } catch {
      // Native JSON may be written to either stream.
    }
  }
  return { parsed: false, value: null };
}

function pathObservation(path, { hashFile = false } = {}) {
  try {
    const stat = lstatSync(path);
    const type = stat.isSymbolicLink()
      ? "symlink"
      : stat.isDirectory()
        ? "directory"
        : stat.isFile()
          ? "file"
          : "other";
    const observation = {
      device: stat.dev,
      exists: true,
      gid: stat.gid,
      inode: stat.ino,
      mode: (stat.mode & 0o777).toString(8).padStart(3, "0"),
      nlink: stat.nlink,
      path,
      size: stat.size,
      type,
      uid: stat.uid,
    };
    if (type === "symlink") {
      observation.target = readlinkSync(path);
    } else if (type === "directory") {
      const entries = readdirSync(path).sort();
      observation.entries = entries.slice(0, 256);
      observation.entry_count = entries.length;
      observation.entries_truncated = entries.length > 256;
    } else if (type === "file" && hashFile) {
      if (stat.size > CONTROL_LIMIT) {
        observation.digest = null;
        observation.digest_error = "FILE_EXCEEDS_CONTROL_LIMIT";
      } else {
        observation.digest = sha256(readFileSync(path));
        observation.digest_error = null;
      }
    }
    return observation;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return { exists: false, path };
    }
    return { error: errorRecord(error), exists: false, path };
  }
}

function decodeMountInfoPath(raw) {
  return raw.replace(/\\([0-7]{3})/g, (_match, octal) =>
    String.fromCharCode(Number.parseInt(octal, 8)),
  );
}

function mountObservation(path, expectedType = "directory") {
  const entry = pathObservation(path);
  let raw;
  try {
    raw = readFileSync("/proc/self/mountinfo", "utf8");
  } catch (error) {
    return {
      entry,
      error: errorRecord(error),
      explicit: false,
      path,
      read_only: false,
      records: [],
      ready: false,
    };
  }
  const expected = resolve(path);
  const records = raw
    .split("\n")
    .filter(Boolean)
    .flatMap((line) => {
      const fields = line.split(" ");
      const separator = fields.indexOf("-");
      if (separator < 6 || fields.length < separator + 4) {
        return [];
      }
      const mountPoint = decodeMountInfoPath(fields[4]);
      if (resolve(mountPoint) !== expected) {
        return [];
      }
      return [
        {
          filesystem: fields[separator + 1],
          mount_options: fields[5].split(",").sort(),
          mount_point: mountPoint,
          root: decodeMountInfoPath(fields[3]),
          source: decodeMountInfoPath(fields[separator + 2]),
          super_options: fields[separator + 3].split(",").sort(),
        },
      ];
    });
  const explicit = records.length === 1;
  const readOnly =
    explicit &&
    records[0].mount_options.includes("ro") &&
    !records[0].mount_options.includes("rw");
  return {
    entry,
    error: null,
    explicit,
    path,
    read_only: readOnly,
    records,
    ready:
      entry.exists === true &&
      entry.type === expectedType &&
      explicit &&
      readOnly,
  };
}

function configObservation() {
  const mount = mountObservation(CONFIG, "file");
  const file = pathObservation(CONFIG, { hashFile: true });
  let canonicalDigest = null;
  let jsonObject = false;
  let parseError = null;
  if (file.exists === true && file.type === "file" && file.digest !== null) {
    try {
      const value = JSON.parse(readFileSync(CONFIG, "utf8"));
      jsonObject = value !== null && typeof value === "object" && !Array.isArray(value);
      canonicalDigest = jsonObject
        ? sha256(Buffer.from(canonicalJson(value), "utf8"))
        : null;
    } catch (error) {
      parseError = errorRecord(error);
    }
  }
  return {
    canonical_digest: canonicalDigest,
    expected_canonical_digest: EXPECTED_CONFIG_CANONICAL_DIGEST,
    file,
    json_object: jsonObject,
    mount,
    parse_error: parseError,
    ready:
      mount.ready &&
      file.exists === true &&
      file.type === "file" &&
      file.nlink === 1 &&
      jsonObject &&
      canonicalDigest === EXPECTED_CONFIG_CANONICAL_DIGEST,
  };
}

function protectedBoundary() {
  const roots = Object.fromEntries(
    Object.entries(PROTECTED_DISCOVERY_ROOTS).map(([name, path]) => [
      name,
      mountObservation(path),
    ]),
  );
  const configuration = configObservation();
  const runtime = mountObservation("/runtime");
  const effectiveIdentity = {
    gid: typeof process.getgid === "function" ? process.getgid() : null,
    uid: typeof process.getuid === "function" ? process.getuid() : null,
  };
  return {
    configuration,
    effective_identity: effectiveIdentity,
    ready:
      configuration.ready &&
      Object.values(roots).every((entry) => entry.ready) &&
      runtime.ready &&
      effectiveIdentity.uid === RUNTIME_UID &&
      effectiveIdentity.gid === RUNTIME_GID,
    roots,
    runtime,
  };
}

function executableObservation(path) {
  const file = pathObservation(path, { hashFile: true });
  return {
    executable:
      file.exists === true &&
      file.type === "file" &&
      file.nlink === 1 &&
      (Number.parseInt(file.mode, 8) & 0o111) !== 0,
    file,
  };
}

function baseRuntimePreflight(boundary) {
  const commands = [];
  const runtimeFiles = {
    node: executableObservation(NODE),
    openclaw: executableObservation(OPENCLAW),
  };
  if (!boundary.ready) {
    return {
      boundary,
      commands,
      reason_codes: ["PROTECTED_BOUNDARY_PREREQUISITE_MISSING"],
      ready: false,
      runtime_files: runtimeFiles,
    };
  }
  if (
    !runtimeFiles.node.executable ||
    !runtimeFiles.openclaw.executable ||
    runtimeFiles.openclaw.file.digest !== EXPECTED_OPENCLAW_DIGEST
  ) {
    return {
      boundary,
      commands,
      reason_codes: ["PINNED_RUNTIME_PREREQUISITE_MISSING"],
      ready: false,
      runtime_files: runtimeFiles,
    };
  }
  const version = command(["--version"]);
  commands.push(version);
  const ready =
    version.exit_code === 0 &&
    version.error === null &&
    version.signal === null &&
    version.stdout_excerpt.trim() === EXPECTED_VERSION;
  return {
    boundary,
    commands,
    reason_codes: ready ? [] : ["PINNED_RUNTIME_IDENTITY_MISMATCH"],
    ready,
    runtime_files: runtimeFiles,
  };
}

function gatewayProcessObservation() {
  try {
    const cmdline = readFileSync("/proc/1/cmdline", "utf8")
      .split("\0")
      .filter(Boolean);
    const stat = readFileSync("/proc/1/stat", "utf8").trim();
    const close = stat.lastIndexOf(")");
    const fields = close < 0 ? [] : stat.slice(close + 2).split(" ");
    return {
      cmdline,
      hostname: readFileSync("/etc/hostname", "utf8").trim(),
      pid: 1,
      start_time_ticks: fields[19] ?? null,
    };
  } catch (error) {
    return { error: errorRecord(error) };
  }
}

function gatewayPreflight(base) {
  const commands = [...base.commands];
  if (!base.ready) {
    return { ...base, commands };
  }
  if (!process.env.OPENCLAW_GATEWAY_TOKEN) {
    return {
      ...base,
      commands,
      reason_codes: ["GATEWAY_ADAPTER_ABSENT"],
      ready: false,
    };
  }
  const systemInfo = gatewayCall("system.info");
  commands.push(systemInfo);
  const response = parsedCommand(systemInfo);
  const info = response.value;
  const processObservation = gatewayProcessObservation();
  const ready =
    systemInfo.exit_code === 0 &&
    systemInfo.error === null &&
    systemInfo.signal === null &&
    response.parsed &&
    info !== null &&
    typeof info === "object" &&
    info.pid === 1 &&
    info.machineName === processObservation.hostname &&
    info.hostname === processObservation.hostname &&
    info.platform === "linux" &&
    info.arch === process.arch &&
    info.nodeVersion === process.version &&
    info.port === 18789 &&
    processObservation.cmdline?.[0] === "openclaw-gateway" &&
    /^[1-9][0-9]*$/.test(processObservation.start_time_ticks ?? "");
  return {
    ...base,
    commands,
    gateway_process: processObservation,
    reason_codes: ready ? [] : ["GATEWAY_IDENTITY_UNBOUND"],
    ready,
    system_info: { command: systemInfo, response },
  };
}

function actionNotTested(id, prerequisites, reasonCodes) {
  return {
    commands: [],
    id,
    observations: {},
    prerequisites,
    reason_codes: [...new Set(reasonCodes)].sort(),
    status: "NOT_TESTED",
  };
}

async function observedAction(id, prerequisites, run) {
  if (!prerequisites.ready) {
    return actionNotTested(id, prerequisites, prerequisites.reason_codes);
  }
  const trace = {
    attempted: false,
    commands: [],
    not_tested_reason: null,
    observations: {},
  };
  let executionError = null;
  try {
    await run(trace);
  } catch (error) {
    executionError = errorRecord(error);
  }
  if (!trace.attempted) {
    return {
      ...actionNotTested(
        id,
        prerequisites,
        [trace.not_tested_reason ?? "ROUTE_ACTION_NOT_EXECUTED"],
      ),
      commands: trace.commands,
      execution_error: executionError,
      observations: trace.observations,
    };
  }
  return {
    commands: trace.commands,
    execution_error: executionError,
    id,
    observations: trace.observations,
    prerequisites,
    reason_codes: [],
    status: "OBSERVED",
  };
}

function targetObservation(root) {
  return {
    directory: pathObservation(root),
    skill: pathObservation(join(root, "SKILL.md"), { hashFile: true }),
  };
}

function validProposalId(value) {
  return (
    typeof value === "string" &&
    /^[a-z0-9][a-z0-9-]{0,127}$/.test(value)
  );
}

function targetDiscovery() {
  const native = gatewayCall("skills.status");
  const parsed = parsedCommand(native);
  const skills = Array.isArray(parsed.value?.skills) ? parsed.value.skills : [];
  return {
    command: native,
    parsed: parsed.parsed,
    target_matches: skills.filter((entry) => entry?.name === WORKSHOP_NAME),
  };
}

function namedSkillDiscovery(name) {
  const native = gatewayCall("skills.status");
  const parsed = parsedCommand(native);
  const skills = Array.isArray(parsed.value?.skills) ? parsed.value.skills : [];
  return {
    command: native,
    parsed: parsed.parsed,
    target_matches: skills.filter((entry) => entry?.name === name),
  };
}

async function archiveSourceAction(gateway) {
  const source = targetObservation(FORCE_SOURCE);
  const targetBefore = targetObservation(FORCE_SOURCE_TARGET);
  const routeReady =
    gateway.ready &&
    gateway.boundary.runtime.read_only &&
    gateway.boundary.roots.workspace_skills.explicit &&
    gateway.boundary.roots.workspace_skills.read_only &&
    source.directory.exists === true &&
    source.skill.exists === true &&
    targetBefore.directory.exists === false &&
    targetBefore.skill.exists === false;
  const prerequisites = {
    ...gateway,
    ready: routeReady,
    reason_codes: [
      ...gateway.reason_codes,
      ...(gateway.boundary.runtime.read_only
        ? []
        : ["RUNTIME_READ_ONLY_MOUNT_REQUIRED"]),
      ...(gateway.boundary.roots.workspace_skills.explicit &&
      gateway.boundary.roots.workspace_skills.read_only
        ? []
        : ["WORKSPACE_SKILLS_EXPLICIT_RO_MOUNT_REQUIRED"]),
      ...(source.directory.exists === true && source.skill.exists === true
        ? []
        : ["PINNED_LOCAL_SOURCE_SKILL_MISSING"]),
      ...(targetBefore.directory.exists === false &&
      targetBefore.skill.exists === false
        ? []
        : ["FORCE_SOURCE_TARGET_COLLISION"]),
    ],
    source,
    target_before: targetBefore,
  };
  return await observedAction(
    "archive-source-force-replacement",
    prerequisites,
    (trace) => {
      trace.observations.discovery_before =
        namedSkillDiscovery(FORCE_SOURCE_NAME);
      trace.commands.push(trace.observations.discovery_before.command);
      const uploadBegin = gatewayCall("skills.upload.begin", {});
      const uploadInstall = gatewayCall("skills.install", {
        agentId: "main",
        force: true,
        sha256: "a".repeat(64),
        slug: FORCE_SOURCE_NAME,
        source: "upload",
        uploadId: "a".repeat(32),
      });
      const sourceInstall = command([
        "skills",
        "install",
        FORCE_SOURCE,
        "--as",
        FORCE_SOURCE_NAME,
        "--force",
        "--agent",
        "main",
      ]);
      trace.commands.push(uploadBegin, uploadInstall, sourceInstall);
      trace.observations.upload_begin = {
        command: uploadBegin,
        response: parsedCommand(uploadBegin),
      };
      trace.observations.upload_install = {
        command: uploadInstall,
        response: parsedCommand(uploadInstall),
      };
      trace.observations.source_install = {
        command: sourceInstall,
        response: parsedCommand(sourceInstall),
      };
      trace.observations.discovery_after =
        namedSkillDiscovery(FORCE_SOURCE_NAME);
      trace.commands.push(trace.observations.discovery_after.command);
      trace.observations.target_after =
        targetObservation(FORCE_SOURCE_TARGET);
      trace.attempted = true;
    },
  );
}

async function workshopAction(gateway) {
  const targetBefore = targetObservation(WORKSHOP_TARGET);
  const draft = pathObservation(WORKSHOP_DRAFT, { hashFile: true });
  const draftMount = mountObservation(WORKSHOP_DRAFT, "file");
  const exactDraft =
    draftMount.ready &&
    draft.exists === true &&
    draft.type === "file" &&
    draft.nlink === 1 &&
    draft.digest === EXPECTED_WORKSHOP_FIXTURE_DIGEST;
  const routeReady =
    gateway.ready &&
    gateway.boundary.roots.workspace_skills.explicit &&
    gateway.boundary.roots.workspace_skills.read_only &&
    targetBefore.directory.exists === false &&
    targetBefore.skill.exists === false &&
    exactDraft;
  const prerequisites = {
    ...gateway,
    draft: {
      expected_digest: EXPECTED_WORKSHOP_FIXTURE_DIGEST,
      mount: draftMount,
      observation: draft,
    },
    ready: routeReady,
    reason_codes: [
      ...gateway.reason_codes,
      ...(gateway.boundary.roots.workspace_skills.explicit &&
      gateway.boundary.roots.workspace_skills.read_only
        ? []
        : ["WORKSPACE_SKILLS_EXPLICIT_RO_MOUNT_REQUIRED"]),
      ...(targetBefore.directory.exists === false &&
      targetBefore.skill.exists === false
        ? []
        : ["WORKSHOP_FIXTURE_COLLISION"]),
      ...(exactDraft ? [] : ["WORKSHOP_PROPOSAL_FIXTURE_MISSING"]),
    ],
    target_before: targetBefore,
  };
  return await observedAction(
    "workshop-protected-apply",
    prerequisites,
    (trace) => {
      trace.observations.discovery_before = targetDiscovery();
      trace.commands.push(trace.observations.discovery_before.command);
      const propose = command([
        "skills",
        "workshop",
        "--agent",
        "main",
        "propose-create",
        "--name",
        WORKSHOP_NAME,
        "--description",
        "Inert Aragorn protected workshop fixture",
        "--proposal",
        WORKSHOP_DRAFT,
        "--json",
      ]);
      trace.commands.push(propose);
      const proposed = parsedCommand(propose);
      const proposalId = proposed.value?.record?.id ?? null;
      trace.observations.proposal_result = {
        parsed: proposed.parsed,
        proposal_id: validProposalId(proposalId) ? proposalId : null,
      };
      if (validProposalId(proposalId)) {
        trace.attempted = true;
        const apply = gatewayCall("skills.proposals.apply", {
          agentId: "main",
          proposalId,
        });
        trace.commands.push(apply);
        trace.observations.native_apply_result = {
          command: apply,
          response: parsedCommand(apply),
        };
      } else {
        trace.observations.native_apply_result = {
          command: null,
          response: { parsed: false, value: null },
        };
      }
      trace.observations.discovery_after = targetDiscovery();
      trace.commands.push(trace.observations.discovery_after.command);
      trace.observations.target_after = targetObservation(WORKSHOP_TARGET);
    },
  );
}

function resolveSnapshotPrompt(snapshot) {
  if (typeof snapshot?.prompt === "string") {
    const raw = Buffer.from(snapshot.prompt);
    return {
      bytes: raw.length,
      digest: sha256(raw),
      storage: "inline",
    };
  }
  const ref = snapshot?.promptRef;
  if (
    ref?.version !== 1 ||
    ref?.algorithm !== "sha256" ||
    !/^[a-f0-9]{64}$/.test(ref?.hash ?? "") ||
    !Number.isSafeInteger(ref?.bytes) ||
    ref.bytes < 0 ||
    ref.bytes > CONTROL_LIMIT
  ) {
    return { bytes: null, digest: null, storage: "absent-or-invalid" };
  }
  const path = join(
    dirname(SESSION_STORE),
    "skills-prompts",
    "sha256",
    ref.hash.slice(0, 2),
    `${ref.hash}.txt`,
  );
  const file = pathObservation(path, { hashFile: true });
  return {
    bytes: ref.bytes,
    digest: file.digest ?? null,
    expected_digest: `sha256:${ref.hash}`,
    file,
    storage: "promptRef",
  };
}

function sessionObservation() {
  const file = pathObservation(SESSION_STORE, { hashFile: true });
  if (
    file.exists !== true ||
    file.type !== "file" ||
    file.size > CONTROL_LIMIT
  ) {
    return { entry: null, file, present: false };
  }
  try {
    const store = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
    const entry = store[SESSION_KEY];
    if (!entry || typeof entry !== "object") {
      return { entry: null, file, present: false };
    }
    const snapshot = entry.skillsSnapshot;
    return {
      entry: {
        ended_at: entry.endedAt ?? null,
        prompt: resolveSnapshotPrompt(snapshot),
        runtime_ms: entry.runtimeMs ?? null,
        session_id: entry.sessionId ?? null,
        skill_names: Array.isArray(snapshot?.skills)
          ? snapshot.skills.map((skill) => skill?.name ?? null)
          : [],
        snapshot_present: Boolean(snapshot),
        snapshot_version: snapshot?.version ?? null,
        started_at: entry.startedAt ?? null,
        status: entry.status ?? null,
        updated_at: entry.updatedAt ?? null,
      },
      file,
      present: true,
    };
  } catch (error) {
    return {
      entry: null,
      error: errorRecord(error),
      file,
      present: false,
    };
  }
}

function normalTurn(label, message) {
  const send = gatewayCall("chat.send", {
    deliver: false,
    idempotencyKey: `aragorn-protected-route-${label}-${RUN_NONCE}`,
    message,
    sessionKey: SESSION_KEY,
    timeoutMs: 5000,
  });
  const parsedSend = parsedCommand(send);
  const runId = parsedSend.value?.runId;
  let wait = null;
  let parsedWait = { parsed: false, value: null };
  if (typeof runId === "string" && runId.length > 0) {
    wait = gatewayCall(
      "agent.wait",
      { runId, timeoutMs: 10_000 },
      12_000,
    );
    parsedWait = parsedCommand(wait);
  }
  const confirmed =
    send.exit_code === 0 &&
    send.error === null &&
    send.signal === null &&
    typeof runId === "string" &&
    runId.length > 0 &&
    wait?.exit_code === 0 &&
    wait.error === null &&
    wait.signal === null &&
    parsedWait.parsed &&
    parsedWait.value?.runId === runId &&
    parsedWait.value?.status === "ok";
  return {
    commands: wait === null ? [send] : [send, wait],
    confirmed,
    send: { command: send, response: parsedSend },
    wait: { command: wait, response: parsedWait },
  };
}

async function sessionConsumerAction(gateway) {
  return await observedAction(
    "session-snapshot-consumer",
    gateway,
    (trace) => {
      trace.observations.session_before = sessionObservation();
      const turn = normalTurn(
        "snapshot-consumer",
        "Inert protected-route snapshot consumer observation.",
      );
      trace.commands.push(...turn.commands);
      trace.observations.turn = turn;
      trace.observations.session_after = sessionObservation();
      trace.attempted = turn.confirmed;
      if (!turn.confirmed) {
        trace.not_tested_reason = "ROUTE_ACTION_NOT_CONFIRMED";
      }
    },
  );
}

async function freshSessionAction(gateway) {
  return await observedAction("fresh-session-reset", gateway, (trace) => {
    let before = sessionObservation();
    if (!before.present) {
      const initialize = normalTurn(
        "fresh-session-initialize",
        "Inert protected-route session initialization.",
      );
      trace.commands.push(...initialize.commands);
      trace.observations.initialization_turn = initialize;
      before = sessionObservation();
    }
    trace.observations.session_before_reset = before;
    const reset = normalTurn("fresh-session-reset", "/new");
    trace.commands.push(...reset.commands);
    trace.observations.reset_turn = reset;
    trace.observations.session_after_reset = sessionObservation();
    trace.attempted = reset.confirmed;
    if (!reset.confirmed) {
      trace.not_tested_reason = "ROUTE_ACTION_NOT_CONFIRMED";
    }
  });
}

function adapterPrerequisite(routeId) {
  const path = ADAPTER_BY_ROUTE[routeId];
  const adapter = executableObservation(path);
  const reason = adapter.file.exists
    ? "ROUTE_ADAPTER_HAS_NO_PINNED_IMPLEMENTATION_DIGEST"
    : "REQUIRED_ROUTE_ADAPTER_ABSENT";
  return {
    adapter: {
      expected_path: path,
      expected_sha256: null,
      observation: adapter,
    },
    id: routeId,
    reason_codes: [reason],
    status: "NOT_TESTED",
  };
}

function profileBlockedRoute(routeId) {
  return {
    id: routeId,
    reason_codes: [PROFILE_BLOCKED_ROUTES[routeId]],
    status: "NOT_TESTED",
  };
}

function parseSelectors(argv) {
  if (argv.length === 0) {
    throw new Error("at least one --route-id selector is required");
  }
  const selected = [];
  for (let index = 0; index < argv.length; index += 2) {
    if (argv[index] !== "--route-id" || index + 1 >= argv.length) {
      throw new Error("selectors must use repeatable --route-id ID pairs");
    }
    const routeId = argv[index + 1];
    if (!ROUTE_SET.has(routeId)) {
      throw new Error(`unsupported protected route selector: ${routeId}`);
    }
    if (selected.includes(routeId)) {
      throw new Error(`duplicate protected route selector: ${routeId}`);
    }
    selected.push(routeId);
  }
  return selected;
}

async function dispatch(selected) {
  const boundary = protectedBoundary();
  const nativeSelected = selected.some((routeId) => routeId in ACTION_BY_ROUTE);
  const base = nativeSelected
    ? baseRuntimePreflight(boundary)
    : {
        boundary,
        commands: [],
        reason_codes: [],
        ready: false,
        runtime_files: {},
      };
  const gateway = nativeSelected ? gatewayPreflight(base) : null;
  const actionCache = new Map();
  const actions = [];
  const routes = [];

  for (const routeId of selected) {
    const actionId = ACTION_BY_ROUTE[routeId];
    if (!actionId) {
      routes.push(
        routeId in PROFILE_BLOCKED_ROUTES
          ? profileBlockedRoute(routeId)
          : adapterPrerequisite(routeId),
      );
      continue;
    }
    if (!actionCache.has(actionId)) {
      let action;
      if (actionId === "archive-source-force-replacement") {
        action = await archiveSourceAction(gateway);
      } else if (actionId === "workshop-protected-apply") {
        action = await workshopAction(gateway);
      } else if (actionId === "fresh-session-reset") {
        action = await freshSessionAction(gateway);
      } else {
        action = await sessionConsumerAction(gateway);
      }
      actionCache.set(actionId, action);
      actions.push(action);
    }
    const action = actionCache.get(actionId);
    routes.push({
      action_id: actionId,
      id: routeId,
      reason_codes: action.reason_codes,
      status: action.status,
    });
  }

  return {
    actions: actions.map((action) => {
      const { boundary: _boundary, ...prerequisites } = action.prerequisites;
      return { ...action, prerequisites };
    }),
    assurance: "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY",
    implementation_digest: sha256(readFileSync(SELF)),
    protected_boundary: boundary,
    recorded_at: new Date().toISOString(),
    routes,
    run_nonce: RUN_NONCE,
    runtime_binding: {
      commit: EXPECTED_COMMIT,
      node_path: NODE,
      openclaw_digest: EXPECTED_OPENCLAW_DIGEST,
      openclaw_path: OPENCLAW,
      version: "2026.7.1",
    },
    schema: "aragorn/openclaw-protected-route-action-observations/v1",
    selected_route_ids: selected,
  };
}

async function main() {
  let selected = [];
  try {
    selected = parseSelectors(process.argv.slice(2));
    const result = await dispatch(selected);
    process.stdout.write(`${canonicalJson(result)}\n`);
  } catch (error) {
    process.stdout.write(
      `${canonicalJson({
        assurance: "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY",
        fatal_error: errorRecord(error),
        routes: [],
        schema: "aragorn/openclaw-protected-route-action-error/v1",
        selected_route_ids: selected,
      })}\n`,
    );
    process.exitCode = 2;
  }
}

await main();
