#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/profile/config/openclaw.json";
const STATE = "/profile/state";
const WORKSPACE = "/profile/workspace";
const TARGET_NAME = "requesting-code-review";
const TARGET = join(WORKSPACE, "skills", TARGET_NAME);
const SELF = fileURLToPath(import.meta.url);
const OUTPUT_LIMIT = 2 * 1024 * 1024;
const EXCERPT_LIMIT = 2048;
const EXPECTED_CONFIG_DIGEST =
  "sha256:ec2b2022ed27f62840583d31264826c88514a04e7e7cc94d78820b021d6288b6";
const EXPECTED_CONFIG_CANONICAL_DIGEST =
  "sha256:6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a";
const EXPECTED_OPENCLAW_DIGEST =
  "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188";
const EXPECTED_TARGET_DIGEST =
  "sha256:1a13f195721f8fa75974bd4918a25b30e8406ff6d423cd0e3306c391b8fee07a";
const EXPECTED_TARGET_TREE_DIGEST =
  "sha256:c3e201e18e2fa35a56d4cae3a0ed481072f4ed77db18e6d568b266068cbe96c3";
const EXPECTED_RUNTIME_TREE = Object.freeze({
  algorithm: "aragorn/runtime-tree/v1",
  entry_count: 45_856,
  file_count: 45_837,
  symlink_count: 19,
  total_bytes: 369_317_461,
  tree_digest:
    "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c",
});
const EXPECTED_DISCOVERY = Object.freeze({
  always: false,
  baseDir: TARGET,
  blockedByAgentFilter: false,
  blockedByAllowlist: false,
  bundled: false,
  commandVisible: true,
  configChecks: [],
  description: "Inert protected archive replacement target v1.",
  disabled: false,
  eligible: true,
  filePath: `${TARGET}/SKILL.md`,
  install: [],
  missing: { anyBins: [], bins: [], config: [], env: [], os: [] },
  modelVisible: true,
  name: TARGET_NAME,
  platformIncompatible: false,
  requirements: { anyBins: [], bins: [], config: [], env: [], os: [] },
  skillKey: TARGET_NAME,
  source: "openclaw-workspace",
  userInvocable: true,
});
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

function bounded(raw) {
  return raw.length <= EXCERPT_LIMIT
    ? raw
    : `${raw.slice(0, EXCERPT_LIMIT)}[truncated]`;
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

function parsedCommand(result) {
  for (const raw of [result._stdout ?? "", result._stderr ?? ""]) {
    try {
      return { parsed: true, value: JSON.parse(raw) };
    } catch {
      // Native JSON can be written to either stream.
    }
  }
  return { parsed: false, value: null };
}

function pathObservation(path, { hashFile = false } = {}) {
  try {
    const stat = lstatSync(path);
    const type = stat.isDirectory()
      ? "directory"
      : stat.isFile()
        ? "file"
        : stat.isSymbolicLink()
          ? "symlink"
          : "other";
    const observation = {
      device: stat.dev,
      exists: true,
      gid: stat.gid,
      inode: stat.ino,
      mode: (stat.mode & 0o7777).toString(8),
      nlink: stat.nlink,
      path,
      size: stat.size,
      type,
      uid: stat.uid,
    };
    if (type === "directory") {
      const entries = readdirSync(path).sort();
      observation.entries = entries.slice(0, 64);
      observation.entries_truncated = entries.length > 64;
      observation.entry_count = entries.length;
    }
    if (type === "file" && hashFile) {
      try {
        observation.digest = sha256(readFileSync(path));
        observation.digest_error = null;
      } catch (error) {
        observation.digest = null;
        observation.digest_error = errorRecord(error);
      }
    }
    if (type === "symlink") {
      observation.target = readlinkSync(path);
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
      entries.push({
        digest: sha256(readFileSync(absolute)),
        executable: Boolean(stat.mode & 0o111),
        kind: "file",
        links: stat.nlink,
        path,
        size: stat.size,
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
    const status = Object.fromEntries(
      readFileSync("/proc/1/status", "utf8")
        .split("\n")
        .filter((line) => line.includes(":"))
        .map((line) => {
          const separator = line.indexOf(":");
          return [line.slice(0, separator), line.slice(separator + 1).trim()];
        }),
    );
    return {
      cmdline,
      effective_capabilities: status.CapEff ?? null,
      hostname: readFileSync("/etc/hostname", "utf8").trim(),
      no_new_privileges: status.NoNewPrivs ?? null,
      pid: 1,
      seccomp: status.Seccomp ?? null,
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
  const runtime = mountObservation("/runtime");
  const probe = mountObservation("/probe");
  const effectiveIdentity = {
    gid: typeof process.getgid === "function" ? process.getgid() : null,
    groups: typeof process.getgroups === "function" ? process.getgroups() : [],
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

function cleanCommand(result) {
  return result.error === null && result.signal === null;
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

function exactDiscovery(observation) {
  return (
    observation.command.exit_code === 0 &&
    cleanCommand(observation.command) &&
    observation.response.parsed &&
    canonicalJson(observation.response.value) === canonicalJson(EXPECTED_DISCOVERY)
  );
}

function runObservation() {
  const boundaryBefore = protectedBoundary();
  const configBefore = configObservation();
  const configLockBefore = pathObservation(`${CONFIG}.lock`);
  const targetBefore = treeObservation(TARGET);
  const processBefore = gatewayProcessObservation();
  const version = command(["--version"]);
  const systemInfoBefore = gatewayCall("system.info");
  const systemResponseBefore = parsedCommand(systemInfoBefore);
  const discoveryBefore = discovery();
  const openclawBefore = pathObservation(OPENCLAW, { hashFile: true });
  const runtimeBefore = boundaryBefore.ready ? runtimeTree() : null;
  const prerequisitesReady =
    boundaryBefore.ready &&
    configBefore.ready &&
    configLockBefore.exists === false &&
    exactTarget(targetBefore) &&
    processBefore.cmdline?.[0] === "openclaw-gateway" &&
    processBefore.effective_capabilities === "0000000000000000" &&
    processBefore.no_new_privileges === "1" &&
    version.exit_code === 0 &&
    cleanCommand(version) &&
    version.stdout_excerpt.trim() === "OpenClaw 2026.7.1 (2d2ddc4)" &&
    systemInfoBefore.exit_code === 0 &&
    cleanCommand(systemInfoBefore) &&
    systemResponseBefore.parsed &&
    systemResponseBefore.value?.pid === 1 &&
    systemResponseBefore.value?.hostname === processBefore.hostname &&
    exactDiscovery(discoveryBefore) &&
    openclawBefore.digest === EXPECTED_OPENCLAW_DIGEST &&
    canonicalJson(runtimeBefore) === canonicalJson(EXPECTED_RUNTIME_TREE);

  if (!prerequisitesReady) {
    return {
      action: {
        id: "config-entry-activation",
        observations: {},
        prerequisites: {
          boundary_before: boundaryBefore,
          config_before: configBefore,
          config_lock_before: configLockBefore,
          discovery_before: discoveryBefore,
          gateway_process_before: processBefore,
          openclaw_before: openclawBefore,
          runtime_tree_before: runtimeBefore,
          system_info_before: {
            command: systemInfoBefore,
            response: systemResponseBefore,
          },
          target_before: targetBefore,
          version,
        },
        reason_codes: ["EXACT_PROTECTED_CONFIG_ACTIVATION_PREREQUISITE_MISSING"],
        status: "NOT_TESTED",
      },
    };
  }

  const params = { enabled: true, skillKey: TARGET_NAME };
  const update = gatewayCall("skills.update", params);
  const configAfter = configObservation();
  const configLockAfter = pathObservation(`${CONFIG}.lock`);
  const targetAfter = treeObservation(TARGET);
  const discoveryAfter = discovery();
  const processAfter = gatewayProcessObservation();
  const systemInfoAfter = gatewayCall("system.info");
  const boundaryAfter = protectedBoundary();
  const openclawAfter = pathObservation(OPENCLAW, { hashFile: true });
  const runtimeAfter = runtimeTree();
  return {
    action: {
      commands: [
        version,
        systemInfoBefore,
        discoveryBefore.command,
        update,
        discoveryAfter.command,
        systemInfoAfter,
      ],
      execution_error: null,
      id: "config-entry-activation",
      observations: {
        boundary_after: boundaryAfter,
        config_after: configAfter,
        config_lock_after: configLockAfter,
        discovery_after: discoveryAfter,
        gateway_process_after: processAfter,
        openclaw_after: openclawAfter,
        runtime_tree_after: runtimeAfter,
        system_info_after: {
          command: systemInfoAfter,
          response: parsedCommand(systemInfoAfter),
        },
        target_after: targetAfter,
        update: { command: update, params, response: parsedCommand(update) },
      },
      prerequisites: {
        boundary_before: boundaryBefore,
        config_before: configBefore,
        config_lock_before: configLockBefore,
        discovery_before: discoveryBefore,
        gateway_process_before: processBefore,
        openclaw_before: openclawBefore,
        runtime_tree_before: runtimeBefore,
        system_info_before: {
          command: systemInfoBefore,
          response: systemResponseBefore,
        },
        target_before: targetBefore,
        version,
      },
      reason_codes: [],
      status: "OBSERVED",
    },
  };
}

function main() {
  if (process.argv.length !== 2) {
    throw new Error("the focused config activation probe accepts no arguments");
  }
  if (!process.env.OPENCLAW_GATEWAY_TOKEN) {
    throw new Error("OPENCLAW_GATEWAY_TOKEN is required");
  }
  const { action } = runObservation();
  return {
    action,
    assurance: "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
    implementation_digest: sha256(readFileSync(SELF)),
    recorded_at: new Date().toISOString(),
    route: {
      action_id: action.id,
      id: "ADM-02/update/config-entry-activation",
      reason_codes: action.reason_codes,
      status: action.status,
    },
    run_nonce: randomBytes(16).toString("hex"),
    runtime_binding: {
      commit: "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
      node_path: NODE,
      openclaw_digest: EXPECTED_OPENCLAW_DIGEST,
      openclaw_path: OPENCLAW,
      runtime_tree_digest: EXPECTED_RUNTIME_TREE.tree_digest,
      version: "2026.7.1",
    },
    schema: "aragorn/openclaw-protected-config-activation-observation/v1",
  };
}

try {
  process.stdout.write(`${canonicalJson(main())}\n`);
} catch (error) {
  process.stdout.write(
    `${canonicalJson({
      assurance: "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
      fatal_error: errorRecord(error),
      schema: "aragorn/openclaw-protected-config-activation-error/v1",
    })}\n`,
  );
  process.exitCode = 2;
}
