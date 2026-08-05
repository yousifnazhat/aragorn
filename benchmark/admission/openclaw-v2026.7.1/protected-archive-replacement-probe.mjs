#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/profile/config/openclaw.json";
const TARGET_NAME = "requesting-code-review";
const TARGET = `/profile/workspace/skills/${TARGET_NAME}`;
const SOURCE = "/sources/replacement";
const CONTROL_ROOT = "/profile/control";
const CONTROL_CONFIG = join(CONTROL_ROOT, "openclaw.json");
const CONTROL_WORKSPACE = join(CONTROL_ROOT, "workspace");
const CONTROL_TARGET = join(CONTROL_WORKSPACE, "skills", TARGET_NAME);
const SELF = fileURLToPath(import.meta.url);
const EXPECTED_CONFIG_DIGEST =
  "sha256:ec2b2022ed27f62840583d31264826c88514a04e7e7cc94d78820b021d6288b6";
const EXPECTED_CONFIG_CANONICAL_DIGEST =
  "sha256:6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a";
const EXPECTED_OPENCLAW_DIGEST =
  "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188";
const EXPECTED_TARGET_DIGEST =
  "sha256:1a13f195721f8fa75974bd4918a25b30e8406ff6d423cd0e3306c391b8fee07a";
const EXPECTED_SOURCE_DIGEST =
  "sha256:d30e0a2e568941e37c5f9427b920917a9edf694beadb41f8a5469e820c0dfdf1";
const EXPECTED_RUNTIME_TREE = Object.freeze({
  algorithm: "aragorn/runtime-tree/v1",
  entry_count: 45856,
  file_count: 45837,
  symlink_count: 19,
  total_bytes: 369317461,
  tree_digest:
    "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c",
});
const OUTPUT_LIMIT = 2 * 1024 * 1024;
const FILE_LIMIT = 4 * 1024 * 1024;
const EXCERPT_LIMIT = 2048;
const RUN_NONCE = randomBytes(16).toString("hex");

const PROTECTED_ROOTS = Object.freeze({
  extensions: "/profile/state/extensions",
  managed_skills: "/profile/state/skills",
  personal_agents: "/profile/home/.agents/skills",
  plugin_skills: "/profile/state/plugin-skills",
  project_agents: "/profile/workspace/.agents/skills",
  workspace_skills: "/profile/workspace/skills",
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
    OPENCLAW_STATE_DIR: "/profile/state",
    PATH: "/usr/local/bin:/usr/bin:/bin",
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_offline: "true",
  };
}

function command(
  args,
  timeout = 30_000,
  environment = runtimeEnvironment(),
  cwd = "/profile/workspace",
) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(NODE, [OPENCLAW, ...args], {
    cwd,
    encoding: "utf8",
    env: environment,
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
  for (const value of [commandResult._stdout, commandResult._stderr]) {
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
      observation.entries = entries.slice(0, 64);
      observation.entry_count = entries.length;
      observation.entries_truncated = entries.length > 64;
    } else if (type === "file" && hashFile) {
      if (stat.size > FILE_LIMIT) {
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

function treeObservation(root) {
  const rootEntry = pathObservation(root);
  if (rootEntry.exists !== true || rootEntry.type !== "directory") {
    return { entries: [], ready: false, root: rootEntry, tree_digest: null };
  }
  const entries = [];
  const pending = [root];
  while (pending.length > 0 && entries.length <= 64) {
    const directory = pending.shift();
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name);
      const entry = pathObservation(path, { hashFile: true });
      entries.push({ ...entry, path: relative(root, path) });
      if (entry.type === "directory") {
        pending.push(path);
      }
    }
  }
  const ready = entries.length <= 64 && entries.every((entry) => !entry.error);
  return {
    entries,
    ready,
    root: rootEntry,
    tree_digest: ready ? sha256(Buffer.from(canonicalJson(entries))) : null,
  };
}

function runtimeTree(root = "/runtime") {
  const entries = [];
  let entriesSeen = 0;
  let fileCount = 0;
  let symlinkCount = 0;
  let totalBytes = 0;

  function walk(directory, parts = []) {
    for (const name of readdirSync(directory).sort()) {
      entriesSeen += 1;
      if (entriesSeen > 100_000 || !/^[\x00-\x7f]+$/.test(name)) {
        throw new Error("runtime tree boundary exceeded");
      }
      const pathParts = [...parts, name];
      const path = pathParts.join("/");
      const absolute = join(directory, name);
      const stat = lstatSync(absolute);
      if (stat.isDirectory()) {
        walk(absolute, pathParts);
        continue;
      }
      if (stat.isSymbolicLink()) {
        const target = readlinkSync(absolute);
        if (!/^[\x00-\x7f]+$/.test(target)) {
          throw new Error(`non-ASCII runtime symlink rejected: ${path}`);
        }
        entries.push({ kind: "symlink", path, target });
        symlinkCount += 1;
        continue;
      }
      if (!stat.isFile() || stat.size > 128 * 1024 * 1024) {
        throw new Error(`unsupported runtime entry rejected: ${path}`);
      }
      totalBytes += stat.size;
      if (totalBytes > 1024 * 1024 * 1024) {
        throw new Error("runtime byte limit exceeded");
      }
      const raw = readFileSync(absolute);
      entries.push({
        digest: sha256(raw),
        executable: Boolean(stat.mode & 0o111),
        kind: "file",
        links: stat.nlink,
        path,
        size: raw.length,
      });
      fileCount += 1;
    }
  }

  walk(root);
  return {
    algorithm: "aragorn/runtime-tree/v1",
    entry_count: entries.length,
    file_count: fileCount,
    symlink_count: symlinkCount,
    total_bytes: totalBytes,
    tree_digest: sha256(Buffer.from(canonicalJson(entries), "ascii")),
  };
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
  const mount = mountObservation("/profile/config");
  const file = pathObservation(CONFIG, { hashFile: true });
  let canonicalDigest = null;
  try {
    canonicalDigest = sha256(
      Buffer.from(canonicalJson(JSON.parse(readFileSync(CONFIG, "utf8")))),
    );
  } catch {
    // The explicit ready predicate below remains false.
  }
  return {
    canonical_digest: canonicalDigest,
    file,
    mount,
    ready:
      mount.ready &&
      file.exists === true &&
      file.type === "file" &&
      file.nlink === 1 &&
      file.digest === EXPECTED_CONFIG_DIGEST &&
      canonicalDigest === EXPECTED_CONFIG_CANONICAL_DIGEST,
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

function protectedBoundary() {
  const roots = Object.fromEntries(
    Object.entries(PROTECTED_ROOTS).map(([name, path]) => [
      name,
      mountObservation(path),
    ]),
  );
  const configuration = configObservation();
  const inputs = {
    probe: mountObservation("/probe"),
    source: mountObservation("/sources"),
  };
  const runtime = mountObservation("/runtime");
  const effectiveIdentity = {
    gid: typeof process.getgid === "function" ? process.getgid() : null,
    groups: typeof process.getgroups === "function" ? process.getgroups() : [],
    uid: typeof process.getuid === "function" ? process.getuid() : null,
  };
  return {
    configuration,
    effective_identity: effectiveIdentity,
    inputs,
    ready:
      configuration.ready &&
      Object.values(inputs).every((entry) => entry.ready) &&
      Object.values(roots).every((entry) => entry.ready) &&
      runtime.ready &&
      effectiveIdentity.uid === 1000 &&
      effectiveIdentity.gid === 1000 &&
      effectiveIdentity.groups.includes(982),
    roots,
    runtime,
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
  const response = parsedCommand(native);
  return { command: native, response };
}

function stagingResidue() {
  try {
    return readdirSync(PROTECTED_ROOTS.workspace_skills)
      .filter((name) => name.startsWith(".openclaw-install-stage-"))
      .sort();
  } catch (error) {
    return { error: errorRecord(error) };
  }
}

function cleanCommand(result) {
  return result.error === null && result.signal === null;
}

function exactFixture(tree, expectedDigest) {
  const root = tree.root;
  const skill = tree.entries[0];
  return (
    tree.ready &&
    tree.entries.length === 1 &&
    root.exists === true &&
    root.type === "directory" &&
    root.uid === 0 &&
    root.gid === 982 &&
    root.mode === "750" &&
    root.entry_count === 1 &&
    root.entries_truncated === false &&
    skill.path === "SKILL.md" &&
    skill.type === "file" &&
    skill.uid === 0 &&
    skill.gid === 982 &&
    skill.mode === "440" &&
    skill.nlink === 1 &&
    skill.digest === expectedDigest &&
    skill.digest_error === null
  );
}

function controlEnvironment() {
  return {
    ...runtimeEnvironment(),
    OPENCLAW_CONFIG_PATH: CONTROL_CONFIG,
    OPENCLAW_STATE_DIR: join(CONTROL_ROOT, "state"),
  };
}

function sourcePositiveControl() {
  const configuration = {
    agents: {
      defaults: { skills: [TARGET_NAME], workspace: CONTROL_WORKSPACE },
      list: [
        { id: "main", skills: [TARGET_NAME], workspace: CONTROL_WORKSPACE },
      ],
    },
    gateway: { mode: "local" },
    plugins: { enabled: false },
    skills: { load: { allowSymlinkTargets: [], extraDirs: [], watch: false } },
  };
  for (const path of [CONTROL_ROOT, CONTROL_WORKSPACE, join(CONTROL_ROOT, "state")]) {
    mkdirSync(path, { mode: 0o700, recursive: true });
  }
  writeFileSync(CONTROL_CONFIG, `${canonicalJson(configuration)}\n`, {
    mode: 0o600,
  });
  const targetBefore = pathObservation(CONTROL_TARGET);
  const install = command(
    [
      "skills",
      "install",
      SOURCE,
      "--as",
      TARGET_NAME,
      "--force",
      "--agent",
      "main",
    ],
    30_000,
    controlEnvironment(),
    CONTROL_WORKSPACE,
  );
  const targetAfter = treeObservation(CONTROL_TARGET);
  const skill = targetAfter.entries.find((entry) => entry.path === "SKILL.md");
  return {
    configuration_digest: sha256(
      Buffer.from(`${canonicalJson(configuration)}\n`),
    ),
    install,
    ready:
      targetBefore.exists === false &&
      install.exit_code === 0 &&
      cleanCommand(install) &&
      targetAfter.ready &&
      skill?.digest === EXPECTED_SOURCE_DIGEST,
    target_after: targetAfter,
    target_before: targetBefore,
  };
}

function preflight(boundary, source, target) {
  if (
    !boundary.ready ||
    !exactFixture(source, EXPECTED_SOURCE_DIGEST) ||
    !exactFixture(target, EXPECTED_TARGET_DIGEST)
  ) {
    return {
      discovery: null,
      gateway_process: gatewayProcessObservation(),
      openclaw: pathObservation(OPENCLAW, { hashFile: true }),
      positive_control: null,
      ready: false,
      reason_codes: ["EXACT_PROTECTED_REPLACEMENT_PREREQUISITE_MISSING"],
      runtime_tree: null,
      system_info: null,
      version: null,
    };
  }
  const version = command(["--version"]);
  const systemInfo = gatewayCall("system.info");
  const systemResponse = parsedCommand(systemInfo);
  const processObservation = gatewayProcessObservation();
  const openclaw = pathObservation(OPENCLAW, { hashFile: true });
  const runtime = runtimeTree();
  const positiveControl = sourcePositiveControl();
  const discovered = discovery();
  const discoveredValue = discovered.response.value;
  const ready =
    canonicalJson(runtime) === canonicalJson(EXPECTED_RUNTIME_TREE) &&
    positiveControl.ready &&
    version.exit_code === 0 &&
    cleanCommand(version) &&
    version.stdout_excerpt.trim() === "OpenClaw 2026.7.1 (2d2ddc4)" &&
    openclaw.digest === EXPECTED_OPENCLAW_DIGEST &&
    systemInfo.exit_code === 0 &&
    cleanCommand(systemInfo) &&
    systemResponse.parsed &&
    systemResponse.value?.pid === 1 &&
    systemResponse.value?.hostname === processObservation.hostname &&
    processObservation.cmdline?.[0] === "openclaw-gateway" &&
    discovered.command.exit_code === 0 &&
    cleanCommand(discovered.command) &&
    discovered.response.parsed &&
    discoveredValue?.name === TARGET_NAME &&
    discoveredValue?.baseDir === TARGET &&
    discoveredValue?.filePath === `${TARGET}/SKILL.md` &&
    discoveredValue?.source === "openclaw-workspace" &&
    discoveredValue?.blockedByAgentFilter === false &&
    discoveredValue?.eligible === true &&
    discoveredValue?.modelVisible === true;
  return {
    gateway_process: processObservation,
    discovery: discovered,
    openclaw,
    positive_control: positiveControl,
    ready,
    reason_codes: ready ? [] : ["EXACT_PROTECTED_REPLACEMENT_PREREQUISITE_MISSING"],
    runtime_tree: runtime,
    system_info: { command: systemInfo, response: systemResponse },
    version,
  };
}

function runObservation() {
  const boundary = protectedBoundary();
  const source = treeObservation(SOURCE);
  const targetBefore = treeObservation(TARGET);
  const prerequisites = preflight(boundary, source, targetBefore);
  if (!prerequisites.ready) {
    return {
      action: {
        id: "archive-source-force-replacement",
        observations: {},
        prerequisites: { ...prerequisites, source, target_before: targetBefore },
        reason_codes: prerequisites.reason_codes,
        status: "NOT_TESTED",
      },
      boundary,
    };
  }

  const stageBefore = stagingResidue();
  const uploadBegin = gatewayCall("skills.upload.begin", {});
  const uploadInstall = gatewayCall("skills.install", {
    agentId: "main",
    force: true,
    sha256: "a".repeat(64),
    slug: TARGET_NAME,
    source: "upload",
    uploadId: "a".repeat(32),
  });
  const sourceInstall = command([
    "skills",
    "install",
    SOURCE,
    "--as",
    TARGET_NAME,
    "--force",
    "--agent",
    "main",
  ]);
  const discoveryAfter = discovery();
  const targetAfter = treeObservation(TARGET);
  const stageAfter = stagingResidue();
  const boundaryAfter = protectedBoundary();
  const sourceAfter = treeObservation(SOURCE);
  const runtimeAfter = runtimeTree();
  const gatewayAfter = gatewayProcessObservation();
  return {
    action: {
      commands: [
        prerequisites.version,
        prerequisites.system_info.command,
        prerequisites.positive_control.install,
        prerequisites.discovery.command,
        uploadBegin,
        uploadInstall,
        sourceInstall,
        discoveryAfter.command,
      ],
      execution_error: null,
      id: "archive-source-force-replacement",
      observations: {
        boundary_after: boundaryAfter,
        discovery_after: discoveryAfter,
        gateway_after: gatewayAfter,
        runtime_tree_after: runtimeAfter,
        source_after: sourceAfter,
        source_install: {
          command: sourceInstall,
          response: parsedCommand(sourceInstall),
        },
        staging_after: stageAfter,
        staging_before: stageBefore,
        target_after: targetAfter,
        upload_begin: {
          command: uploadBegin,
          response: parsedCommand(uploadBegin),
        },
        upload_install: {
          command: uploadInstall,
          response: parsedCommand(uploadInstall),
        },
      },
      prerequisites: { ...prerequisites, source, target_before: targetBefore },
      reason_codes: [],
      status: "OBSERVED",
    },
    boundary,
  };
}

function main() {
  if (process.argv.length !== 2) {
    throw new Error("the focused archive replacement probe accepts no arguments");
  }
  if (!process.env.OPENCLAW_GATEWAY_TOKEN) {
    throw new Error("OPENCLAW_GATEWAY_TOKEN is required");
  }
  const { action, boundary } = runObservation();
  return {
    action,
    assurance: "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
    implementation_digest: sha256(readFileSync(SELF)),
    protected_boundary: boundary,
    recorded_at: new Date().toISOString(),
    route: {
      action_id: action.id,
      id: "ADM-02/update/archive-source-force-replacement",
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
    schema: "aragorn/openclaw-protected-archive-replacement-observation/v1",
  };
}

try {
  process.stdout.write(`${canonicalJson(main())}\n`);
} catch (error) {
  process.stdout.write(
    `${canonicalJson({
      assurance: "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
      fatal_error: errorRecord(error),
      schema: "aragorn/openclaw-protected-archive-replacement-error/v1",
    })}\n`,
  );
  process.exitCode = 2;
}
