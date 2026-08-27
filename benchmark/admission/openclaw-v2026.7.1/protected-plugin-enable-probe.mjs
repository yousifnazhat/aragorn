#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  accessSync,
  constants,
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ASSURANCE = "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY";
const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/run/credentials/aragorn-agent-gateway.service/openclaw-config";
const STATE = "/var/lib/aragorn-agent-gateway/state";
const WORKSPACE = "/var/lib/aragorn-agent-gateway/workspace";
const ROUTE_INPUT = "/route-input";
const PLUGIN_ID = "tts-local-cli";
const PLUGIN_ROOT = `/runtime/lib/node_modules/openclaw/extensions/${PLUGIN_ID}`;
const PLUGIN_ENTRY = `${PLUGIN_ROOT}/index.ts`;
const ROUTE_ID = "ADM-02/update/plugin-enable-activation";
const ACTION_ID = "plugin-enable-activation";
const SELF = fileURLToPath(import.meta.url);
const OUTPUT_LIMIT = 2 * 1024 * 1024;
const EXCERPT_LIMIT = 2048;
const EXPECTED_CONFIG_DIGEST =
  "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e";
const EXPECTED_OPENCLAW_DIGEST =
  "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188";
const EXPECTED_RUNTIME_TREE = Object.freeze({
  algorithm: "aragorn/runtime-tree/v1",
  entry_count: 45_860,
  file_count: 45_841,
  symlink_count: 19,
  total_bytes: 369_443_243,
  tree_digest:
    "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154",
});
const ENABLE_ARGS = Object.freeze(["plugins", "enable", PLUGIN_ID]);

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
    HOME: "/var/lib/aragorn-agent-gateway/home",
    HTTP_PROXY: "http://127.0.0.1:9",
    HTTPS_PROXY: "http://127.0.0.1:9",
    NO_COLOR: "1",
    NO_PROXY: "127.0.0.1,localhost",
    OPENCLAW_CONFIG_PATH: CONFIG,
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

function gatewayCall(method, timeout = 5000) {
  return command(
    ["gateway", "call", method, "--json", "--timeout", String(timeout)],
    timeout + 5000,
  );
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
      observation.entries = entries.slice(0, 128);
      observation.entries_truncated = entries.length > 128;
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
  while (pending.length > 0 && entries.length <= 128) {
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
  const ready = entries.length <= 128 && entries.every((entry) => !entry.error);
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
  const mount = mountObservation(dirname(CONFIG));
  const file = pathObservation(CONFIG, { hashFile: true });
  let canonicalDigest = null;
  let document = null;
  try {
    document = JSON.parse(readFileSync(CONFIG, "utf8"));
    canonicalDigest = sha256(Buffer.from(canonicalJson(document)));
  } catch {
    // The explicit ready predicate below remains false.
  }
  const plugins = document?.plugins;
  const entries = plugins?.entries;
  const pluginPolicy = {
    allow: Array.isArray(plugins?.allow) ? [...plugins.allow] : null,
    enabled: plugins?.enabled ?? null,
    target_allowlisted: Array.isArray(plugins?.allow)
      ? plugins.allow.includes(PLUGIN_ID)
      : null,
    target_entry: entries && Object.hasOwn(entries, PLUGIN_ID) ? entries[PLUGIN_ID] : null,
    target_entry_present: Boolean(entries && Object.hasOwn(entries, PLUGIN_ID)),
  };
  const policyExact =
    plugins?.enabled === true &&
    canonicalJson(plugins?.allow) === '["aragorn-runtime-action-worker"]' &&
    canonicalJson(plugins?.load?.paths) ===
      '["/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker"]' &&
    canonicalJson(Object.keys(entries ?? {}).sort()) ===
      '["aragorn-runtime-action-worker"]' &&
    entries?.["aragorn-runtime-action-worker"]?.enabled === true &&
    pluginPolicy.target_allowlisted === false &&
    pluginPolicy.target_entry_present === false;
  return {
    canonical_digest: canonicalDigest,
    file,
    mount,
    plugin_policy: pluginPolicy,
    ready:
      mount.ready &&
      file.exists === true &&
      file.type === "file" &&
      file.uid === 992 &&
      file.gid === 0 &&
      file.mode === "400" &&
      file.nlink === 1 &&
      file.size === 1880 &&
      file.digest === EXPECTED_CONFIG_DIGEST &&
      canonicalDigest === EXPECTED_CONFIG_DIGEST &&
      policyExact,
  };
}

function writableWorkspaceObservation() {
  const observation = pathObservation(WORKSPACE);
  let writable = false;
  try {
    accessSync(WORKSPACE, constants.W_OK);
    writable = true;
  } catch {
    // The explicit ready predicate below remains false.
  }
  return {
    observation,
    ready:
      observation.exists === true &&
      observation.type === "directory" &&
      observation.uid === 992 &&
      observation.gid === 992 &&
      (Number.parseInt(observation.mode, 8) & 0o200) !== 0 &&
      writable,
    writable,
  };
}

function gatewayProcessObservation() {
  const rawPid = process.env.ARAGORN_GATEWAY_PID ?? "";
  if (!/^[1-9][0-9]*$/.test(rawPid)) {
    return {
      error: errorRecord(
        new Error("ARAGORN_GATEWAY_PID must be a positive decimal PID"),
      ),
      pid: null,
    };
  }
  const pid = Number.parseInt(rawPid, 10);
  if (!Number.isSafeInteger(pid)) {
    return {
      error: errorRecord(new Error("ARAGORN_GATEWAY_PID exceeds safe integer range")),
      pid: null,
    };
  }
  const procRoot = `/proc/${rawPid}`;
  try {
    const cmdline = readFileSync(`${procRoot}/cmdline`, "utf8")
      .split("\0")
      .filter(Boolean);
    const stat = readFileSync(`${procRoot}/stat`, "utf8").trim();
    const close = stat.lastIndexOf(")");
    const fields = close < 0 ? [] : stat.slice(close + 2).split(" ");
    const status = Object.fromEntries(
      readFileSync(`${procRoot}/status`, "utf8")
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
      pid,
      seccomp: status.Seccomp ?? null,
      start_time_ticks: fields[19] ?? null,
    };
  } catch (error) {
    return { error: errorRecord(error), pid };
  }
}

function protectedBoundary() {
  const configuration = configObservation();
  const routeInput = mountObservation(ROUTE_INPUT);
  const runtime = mountObservation("/runtime");
  const workspace = writableWorkspaceObservation();
  const effectiveIdentity = {
    gid: typeof process.getgid === "function" ? process.getgid() : null,
    groups: typeof process.getgroups === "function" ? process.getgroups() : [],
    uid: typeof process.getuid === "function" ? process.getuid() : null,
  };
  return {
    configuration,
    effective_identity: effectiveIdentity,
    ready:
      configuration.ready &&
      routeInput.ready &&
      runtime.ready &&
      workspace.ready &&
      effectiveIdentity.uid === 992 &&
      effectiveIdentity.gid === 992 &&
      effectiveIdentity.groups.includes(992),
    route_input: routeInput,
    runtime,
    workspace,
  };
}

function pluginInspection() {
  const native = command(["plugins", "inspect", PLUGIN_ID, "--json"]);
  return { command: native, response: parsedCommand(native) };
}

function cleanCommand(result) {
  return result.error === null && result.signal === null;
}

function exactPluginDisabledNotAllowlisted(observation) {
  const plugin = observation.response.value?.plugin;
  return (
    observation.command.exit_code === 0 &&
    cleanCommand(observation.command) &&
    observation.response.parsed &&
    plugin?.id === PLUGIN_ID &&
    plugin?.origin === "bundled" &&
    plugin?.rootDir === PLUGIN_ROOT &&
    plugin?.source === PLUGIN_ENTRY &&
    plugin?.enabled === false &&
    plugin?.activated === false &&
    plugin?.explicitlyEnabled === false &&
    plugin?.status === "disabled" &&
    plugin?.activationSource === "disabled" &&
    plugin?.activationReason === "not in allowlist" &&
    canonicalJson(plugin?.speechProviderIds) === '["tts-local-cli","cli"]'
  );
}

function exactPluginTree(tree) {
  return (
    tree.ready &&
    tree.root.path === PLUGIN_ROOT &&
    tree.root.exists === true &&
    tree.root.type === "directory" &&
    tree.root.uid === 0 &&
    tree.root.gid === 0 &&
    tree.entries.length > 0 &&
    tree.entries.every(
      (entry) =>
        entry.uid === 0 &&
        entry.gid === 0 &&
        (Number.parseInt(entry.mode, 8) & 0o022) === 0,
    )
  );
}

function processStarted(result) {
  return (
    result.error === null &&
    Number.isSafeInteger(result.pid) &&
    result.pid > 0
  );
}

function runObservation() {
  const boundaryBefore = protectedBoundary();
  const configBefore = configObservation();
  const configLockBefore = pathObservation(`${CONFIG}.lock`, { hashFile: true });
  const gatewayBefore = gatewayProcessObservation();
  const version = command(["--version"]);
  const systemInfoBefore = gatewayCall("system.info");
  const systemResponseBefore = parsedCommand(systemInfoBefore);
  const pluginBefore = pluginInspection();
  const pluginTreeBefore = treeObservation(PLUGIN_ROOT);
  const openclawBefore = pathObservation(OPENCLAW, { hashFile: true });
  const runtimeBefore = boundaryBefore.ready ? runtimeTree() : null;
  const prerequisitesReady =
    boundaryBefore.ready &&
    configBefore.ready &&
    configLockBefore.exists === false &&
    gatewayBefore.cmdline?.[0] === "openclaw-gateway" &&
    gatewayBefore.effective_capabilities === "0000000000000000" &&
    gatewayBefore.no_new_privileges === "1" &&
    version.exit_code === 0 &&
    cleanCommand(version) &&
    version.stdout_excerpt.trim() === "OpenClaw 2026.7.1 (7fa98d8)" &&
    systemInfoBefore.exit_code === 0 &&
    cleanCommand(systemInfoBefore) &&
    systemResponseBefore.parsed &&
    systemResponseBefore.value?.pid === gatewayBefore.pid &&
    systemResponseBefore.value?.hostname === gatewayBefore.hostname &&
    exactPluginDisabledNotAllowlisted(pluginBefore) &&
    exactPluginTree(pluginTreeBefore) &&
    openclawBefore.digest === EXPECTED_OPENCLAW_DIGEST &&
    canonicalJson(runtimeBefore) === canonicalJson(EXPECTED_RUNTIME_TREE);

  const prerequisites = {
    boundary_before: boundaryBefore,
    config_before: configBefore,
    config_lock_before: configLockBefore,
    gateway_process_before: gatewayBefore,
    openclaw_before: openclawBefore,
    plugin_before: pluginBefore,
    plugin_tree_before: pluginTreeBefore,
    runtime_tree_before: runtimeBefore,
    system_info_before: {
      command: systemInfoBefore,
      response: systemResponseBefore,
    },
    version,
  };

  if (!prerequisitesReady) {
    return {
      action: {
        id: ACTION_ID,
        observations: {},
        prerequisites,
        reason_codes: ["EXACT_PROTECTED_PLUGIN_ENABLE_PREREQUISITE_MISSING"],
        status: "NOT_TESTED",
      },
    };
  }

  const enable = command([...ENABLE_ARGS]);
  const configAfter = configObservation();
  const configLockAfter = pathObservation(`${CONFIG}.lock`, { hashFile: true });
  const gatewayAfter = gatewayProcessObservation();
  const pluginAfter = pluginInspection();
  const pluginTreeAfter = treeObservation(PLUGIN_ROOT);
  const systemInfoAfter = gatewayCall("system.info");
  const boundaryAfter = protectedBoundary();
  const openclawAfter = pathObservation(OPENCLAW, { hashFile: true });
  const runtimeAfter = runtimeTree();
  const started = processStarted(enable);
  const reasonCodes = started ? [] : ["NATIVE_PLUGIN_ENABLE_PROCESS_NOT_STARTED"];
  return {
    action: {
      commands: [
        version,
        systemInfoBefore,
        pluginBefore.command,
        enable,
        pluginAfter.command,
        systemInfoAfter,
      ],
      execution_error: enable.error,
      id: ACTION_ID,
      observations: {
        boundary_after: boundaryAfter,
        config_after: configAfter,
        config_lock_after: configLockAfter,
        gateway_process_after: gatewayAfter,
        native_enable: {
          command: enable,
          process_started: started,
          target_plugin_id: PLUGIN_ID,
        },
        openclaw_after: openclawAfter,
        plugin_after: pluginAfter,
        plugin_tree_after: pluginTreeAfter,
        runtime_tree_after: runtimeAfter,
        system_info_after: {
          command: systemInfoAfter,
          response: parsedCommand(systemInfoAfter),
        },
      },
      prerequisites,
      reason_codes: reasonCodes,
      status: started ? "OBSERVED" : "NOT_TESTED",
    },
  };
}

function selfCheck() {
  const environment = runtimeEnvironment();
  const checks = {
    action_id_exact: ACTION_ID === "plugin-enable-activation",
    action_statuses_observational_only:
      canonicalJson(["NOT_TESTED", "OBSERVED"]) ===
      '["NOT_TESTED","OBSERVED"]',
    bundled_plugin_discovery_not_suppressed:
      !Object.hasOwn(environment, "OPENCLAW_DISABLE_BUNDLED_PLUGINS"),
    current_v2_configuration_pinned:
      EXPECTED_CONFIG_DIGEST ===
      "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e",
    current_v2_runtime_pinned:
      EXPECTED_RUNTIME_TREE.tree_digest ===
      "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154",
    native_action_exact:
      canonicalJson(ENABLE_ARGS) === '["plugins","enable","tts-local-cli"]',
    raw_observation_assurance_exact:
      ASSURANCE === "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
    route_id_exact: ROUTE_ID === "ADM-02/update/plugin-enable-activation",
    target_is_bundled_runtime_plugin:
      PLUGIN_ROOT ===
      "/runtime/lib/node_modules/openclaw/extensions/tts-local-cli",
  };
  return {
    assurance: ASSURANCE,
    checks,
    implementation_digest: sha256(readFileSync(SELF)),
    native_action: {
      argv: [NODE, OPENCLAW, ...ENABLE_ARGS],
      target_plugin_id: PLUGIN_ID,
    },
    route_id: ROUTE_ID,
    schema: "aragorn/openclaw-protected-plugin-enable-self-check/v1",
    status: Object.values(checks).every(Boolean)
      ? "SELF_CHECK_OK"
      : "SELF_CHECK_ERROR",
  };
}

function main() {
  const args = process.argv.slice(2);
  if (canonicalJson(args) === '["self-check"]') {
    const result = selfCheck();
    if (result.status !== "SELF_CHECK_OK") {
      process.exitCode = 1;
    }
    return result;
  }
  if (args.length !== 0) {
    throw new Error(
      "the focused plugin enable probe accepts no arguments or self-check",
    );
  }
  if (!process.env.OPENCLAW_GATEWAY_TOKEN) {
    throw new Error("OPENCLAW_GATEWAY_TOKEN is required");
  }
  const { action } = runObservation();
  return {
    action,
    assurance: ASSURANCE,
    implementation_digest: sha256(readFileSync(SELF)),
    recorded_at: new Date().toISOString(),
    route: {
      action_id: action.id,
      id: ROUTE_ID,
      reason_codes: action.reason_codes,
      status: action.status,
    },
    run_nonce: randomBytes(16).toString("hex"),
    runtime_binding: {
      commit: "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
      node_path: NODE,
      openclaw_digest: EXPECTED_OPENCLAW_DIGEST,
      openclaw_path: OPENCLAW,
      runtime_tree_digest: EXPECTED_RUNTIME_TREE.tree_digest,
      version: "2026.7.1",
    },
    schema: "aragorn/openclaw-protected-plugin-enable-observation/v1",
  };
}

try {
  process.stdout.write(`${canonicalJson(main())}\n`);
} catch (error) {
  process.stdout.write(
    `${canonicalJson({
      assurance: ASSURANCE,
      fatal_error: errorRecord(error),
      schema: "aragorn/openclaw-protected-plugin-enable-error/v1",
    })}\n`,
  );
  process.exitCode = 2;
}
