#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const INPUT_SCHEMA =
  "aragorn/openclaw-runtime-action-systemd-probe-input/v1";
const EVIDENCE_SCHEMA =
  "aragorn/openclaw-runtime-action-systemd-probe-evidence/v1";
const AUTHORITY =
  "BOUNDED_PINNED_OPENCLAW_CREATE_COMPOSITION_ONLY_NOT_RUN_OR_EDR_AUTHORITY";
const PLUGIN_ID = "aragorn-runtime-action";
const PLUGIN_PATH = "/opt/aragorn/openclaw/aragorn-runtime-action";
const TOOL_NAME = "aragorn_runtime_create";
const TOOL_RESULT_TEXT_SCHEMA = "aragorn/runtime-action-tool-result-text/v1";
const MODEL = "fixture-model";
const PROVIDER = "aragorn-runtime-action-mock";
const PROVIDER_PORT = 18080;
const MOCK_KEY = "aragorn-runtime-action-mock-local";
const MAX_COMMAND_BYTES = 16 * 1024 * 1024;
const MAX_PROVIDER_BYTES = 4 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 32 * 1024;
const MAX_GATEWAY_LOG_BYTES = 256 * 1024;
const SELF = fileURLToPath(import.meta.url);
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const SKILL_NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const TARGET_NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const RUNTIME_SUFFIX = "/lib/node_modules/openclaw/openclaw.mjs";
const PLUGIN_CONFIG_FIELDS = [
  "activeSkillDigest",
  "expectedBrokerUid",
  "expectedRuntimeGid",
  "expectedRuntimeUid",
  "expectedSensorUid",
  "policyDigest",
  "policyVersion",
  "protectedRoot",
  "runtimeDigest",
  "sensorSocketPath",
].sort();
const LIMITATIONS = [
  "SINGLE_DETERMINISTIC_PROVIDER_DRIVEN_CREATE_TOOL_CALL_ONLY",
  "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_NOT_EXTERNAL_MODEL_PROOF",
  "OPAQUE_SESSION_RUN_AND_TOOL_IDS_NOT_CAUSAL_ATTRIBUTION",
  "ACTIVE_SKILL_DIGEST_IS_DEPLOYMENT_PIN_NOT_CAUSAL_ATTRIBUTION",
  "NO_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
  "OUTER_SYSTEMD_CONTAINER_AND_CONTROL_PLANE_NOT_ATTESTED_BY_THIS_PROBE",
  "OPENCLAW_ADMISSION_CONFORMANCE_NOT_ESTABLISHED",
  "OPENCLAW_RETURNED_TOOL_RESULT_ISERROR_FLAG_NOT_SECURITY_AUTHORITY",
  "RUN_01_NOT_ESTABLISHED",
  "RUN_02_NOT_ESTABLISHED",
  "PHASE_3_EXIT_NOT_ESTABLISHED",
  "EDR_CLAIM_NOT_ESTABLISHED",
  "PUBLIC_RELEASE_NOT_AUTHORIZED",
];

function canonicalString(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function canonicalJson(value, path = "$") {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return canonicalString(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError(`canonical JSON only accepts safe integers at ${path}`);
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => canonicalJson(item, `${path}[${index}]`)).join(",")}]`;
  }
  if (
    value &&
    typeof value === "object" &&
    Object.getPrototypeOf(value) === Object.prototype
  ) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${canonicalString(key)}:${canonicalJson(value[key], `${path}.${key}`)}`)
      .join(",")}}`;
  }
  throw new TypeError("value is not canonical JSON");
}

function sha256(raw) {
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  expect(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort()),
    `${label} fields changed`,
  );
}

function requireDigest(value, label) {
  expect(typeof value === "string" && DIGEST.test(value), `${label} is invalid`);
  return value;
}

function requireInteger(value, label, positive = false) {
  expect(
    Number.isSafeInteger(value) && value >= (positive ? 1 : 0),
    `${label} is invalid`,
  );
  return value;
}

function requireAbsolutePath(value, label) {
  expect(
    typeof value === "string" &&
      isAbsolute(value) &&
      !value.includes("\0") &&
      resolve(value) === value,
    `${label} is invalid`,
  );
  return value;
}

function metadata(path) {
  const value = lstatSync(path);
  const type = value.isDirectory()
    ? "directory"
    : value.isFile()
      ? "file"
      : value.isSocket()
        ? "socket"
        : value.isSymbolicLink()
          ? "symlink"
          : "other";
  return {
    device: value.dev,
    gid: value.gid,
    inode: value.ino,
    mode: (value.mode & 0o7777).toString(8).padStart(4, "0"),
    nlink: value.nlink,
    size: value.size,
    type,
    uid: value.uid,
  };
}

function readInput(path) {
  requireAbsolutePath(path, "input path");
  const stat = lstatSync(path);
  expect(
    stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1,
    "input must be one regular file",
  );
  const raw = readFileSync(path);
  const document = JSON.parse(raw.toString("utf8"));
  expect(
    raw.equals(Buffer.from(`${canonicalJson(document)}\n`, "ascii")),
    "input is not canonical JSON with one trailing newline",
  );
  validateInput(document);
  return {
    digest: sha256(raw),
    document,
    path,
    stat: metadata(path),
  };
}

function validateInput(input) {
  exactKeys(
    input,
    ["plugin", "profile_root", "runtime", "scenario", "schema", "skill"],
    "input",
  );
  expect(input.schema === INPUT_SCHEMA, "input schema changed");
  requireAbsolutePath(input.profile_root, "profile root");
  expect(realpathSync(input.profile_root) === input.profile_root, "profile root changed");

  exactKeys(
    input.scenario,
    ["content", "expected_effect_status", "expected_verdict", "id", "target_name"],
    "scenario",
  );
  expect(IDENTIFIER.test(input.scenario.id), "scenario id is invalid");
  expect(TARGET_NAME.test(input.scenario.target_name), "target name is invalid");
  expect(typeof input.scenario.content === "string", "scenario content is invalid");
  expect(
    Buffer.byteLength(input.scenario.content) <= MAX_PAYLOAD_BYTES,
    "scenario content exceeds the plugin limit",
  );
  const expectedPair = `${input.scenario.expected_verdict}/${input.scenario.expected_effect_status}`;
  expect(
    [
      "ALLOW/CREATED",
      "BLOCK/NOT_PERFORMED",
      "CLIENT_ERROR/NOT_SUBMITTED",
    ].includes(expectedPair),
    "expected broker outcome is invalid",
  );

  exactKeys(input.skill, ["content", "digest", "name"], "skill");
  expect(SKILL_NAME.test(input.skill.name), "skill name is invalid");
  expect(typeof input.skill.content === "string", "skill content is invalid");
  requireDigest(input.skill.digest, "skill digest");
  expect(
    sha256(Buffer.from(input.skill.content)) === input.skill.digest,
    "skill content digest changed",
  );
  expect(
    new RegExp(`^name:\\s*${input.skill.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*$`, "m").test(
      input.skill.content,
    ),
    "skill content does not declare its input name",
  );

  exactKeys(
    input.runtime,
    ["entrypoint", "expected_tree_digest", "expected_version"],
    "runtime",
  );
  requireAbsolutePath(input.runtime.entrypoint, "runtime entrypoint");
  requireDigest(input.runtime.expected_tree_digest, "runtime tree digest");
  expect(
    typeof input.runtime.expected_version === "string" &&
      input.runtime.expected_version.length > 0 &&
      input.runtime.expected_version.length <= 128,
    "runtime version is invalid",
  );
  expect(
    input.runtime.entrypoint.endsWith(RUNTIME_SUFFIX),
    "runtime entrypoint layout changed",
  );

  exactKeys(input.plugin, ["config", "digest", "path"], "plugin");
  expect(input.plugin.path === PLUGIN_PATH, "plugin path changed");
  requireDigest(input.plugin.digest, "plugin tree digest");
  exactKeys(input.plugin.config, PLUGIN_CONFIG_FIELDS, "plugin config");
  const config = input.plugin.config;
  requireDigest(config.activeSkillDigest, "active skill digest");
  requireDigest(config.policyDigest, "policy digest");
  requireDigest(config.runtimeDigest, "configured runtime digest");
  requireInteger(config.policyVersion, "policy version", true);
  for (const field of [
    "expectedBrokerUid",
    "expectedRuntimeGid",
    "expectedRuntimeUid",
    "expectedSensorUid",
  ]) {
    requireInteger(config[field], field);
  }
  requireAbsolutePath(config.protectedRoot, "protected root");
  requireAbsolutePath(config.sensorSocketPath, "sensor socket path");
  expect(config.activeSkillDigest === input.skill.digest, "active skill pin changed");
  expect(
    config.runtimeDigest === input.runtime.expected_tree_digest,
    "runtime policy pin changed",
  );
  expect(
    new Set([
      config.expectedBrokerUid,
      config.expectedRuntimeUid,
      config.expectedSensorUid,
    ]).size === 3,
    "broker, runtime, and sensor UIDs must differ",
  );
}

function profilePaths(input) {
  const root = input.profile_root;
  return {
    config: join(root, "config", "openclaw.json"),
    home: join(root, "home"),
    skill: join(root, "state", "skills", input.skill.name, "SKILL.md"),
    state: join(root, "state"),
    workspace: join(root, "workspace"),
  };
}

function expectedConfiguration(input, paths) {
  return {
    agents: {
      defaults: {
        model: { primary: `${PROVIDER}/${MODEL}` },
        skills: [input.skill.name],
        workspace: paths.workspace,
      },
      list: [
        {
          id: "main",
          skills: [input.skill.name],
          workspace: paths.workspace,
        },
      ],
    },
    models: {
      mode: "replace",
      providers: {
        [PROVIDER]: {
          api: "openai-completions",
          apiKey: MOCK_KEY,
          baseUrl: `http://127.0.0.1:${PROVIDER_PORT}/v1`,
          models: [
            {
              compat: {
                maxTokensField: "max_tokens",
                supportsDeveloperRole: false,
                supportsStore: false,
                supportsStrictMode: false,
                supportsTools: true,
                supportsUsageInStreaming: false,
              },
              contextWindow: 200000,
              cost: { cacheRead: 0, cacheWrite: 0, input: 0, output: 0 },
              id: MODEL,
              input: ["text"],
              maxTokens: 256,
              name: "Aragorn deterministic runtime-action fixture",
              reasoning: false,
            },
          ],
          timeoutSeconds: 10,
        },
      },
    },
    plugins: {
      allow: [PLUGIN_ID],
      enabled: true,
      entries: {
        [PLUGIN_ID]: { config: input.plugin.config, enabled: true },
      },
      load: { paths: [input.plugin.path] },
    },
    skills: {
      load: { allowSymlinkTargets: [], extraDirs: [], watch: false },
    },
    tools: { alsoAllow: [TOOL_NAME] },
  };
}

function prepareProfile(input, paths) {
  expect(
    readdirSync(input.profile_root).length === 0,
    "profile root was not fresh",
  );
  for (const path of [
    dirname(paths.config),
    paths.home,
    paths.state,
    paths.workspace,
    dirname(dirname(paths.skill)),
    dirname(paths.skill),
  ]) {
    mkdirSync(path, { mode: 0o700, recursive: true });
  }
  writeFileSync(
    paths.config,
    `${canonicalJson(expectedConfiguration(input, paths))}\n`,
    { flag: "wx", mode: 0o600 },
  );
  writeFileSync(paths.skill, input.skill.content, { flag: "wx", mode: 0o444 });
  chmodSync(dirname(paths.skill), 0o555);
  chmodSync(dirname(dirname(paths.skill)), 0o555);
  return {
    profile_root: metadata(input.profile_root),
    created_paths: {
      config: paths.config,
      home: paths.home,
      skill: paths.skill,
      state: paths.state,
      workspace: paths.workspace,
    },
  };
}

function configurationSnapshot(input, paths) {
  const expected = expectedConfiguration(input, paths);
  const raw = readFileSync(paths.config);
  const stat = lstatSync(paths.config);
  expect(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.nlink === 1 &&
      (stat.mode & 0o777) === 0o600,
    "OpenClaw configuration identity changed",
  );
  expect(
    raw.equals(Buffer.from(`${canonicalJson(expected)}\n`, "ascii")),
    "OpenClaw configuration bytes changed",
  );
  return {
    digest: sha256(Buffer.from(canonicalJson(expected), "ascii")),
    document: expected,
    file_digest: sha256(raw),
    path: paths.config,
    stat: metadata(paths.config),
  };
}

function skillSnapshot(input, paths) {
  const skillsRoot = dirname(dirname(paths.skill));
  const skillRoot = dirname(paths.skill);
  const stat = lstatSync(paths.skill);
  const raw = readFileSync(paths.skill);
  expect(
    canonicalJson(readdirSync(skillsRoot).sort()) === canonicalJson([input.skill.name]) &&
      canonicalJson(readdirSync(skillRoot).sort()) === canonicalJson(["SKILL.md"]) &&
      (lstatSync(skillsRoot).mode & 0o777) === 0o555 &&
      (lstatSync(skillRoot).mode & 0o777) === 0o555 &&
      stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.nlink === 1 &&
      (stat.mode & 0o777) === 0o444 &&
      raw.equals(Buffer.from(input.skill.content)) &&
      realpathSync(paths.skill) === paths.skill,
    "exact skill deployment changed",
  );
  return {
    bytes: raw.length,
    digest: sha256(raw),
    path: paths.skill,
    stat: metadata(paths.skill),
  };
}

function treeInventory(root, options) {
  const entries = [];
  let fileCount = 0;
  let symlinkCount = 0;
  let totalBytes = 0;
  const walk = (directory, parts = []) => {
    for (const name of readdirSync(directory).sort()) {
      expect(/^[\x00-\x7f]+$/.test(name), "tree contains a non-ASCII path");
      expect(entries.length < options.maxEntries, "tree inventory entry limit exceeded");
      const pathParts = [...parts, name];
      const path = pathParts.join("/");
      const absolute = join(directory, name);
      const stat = lstatSync(absolute);
      if (stat.isDirectory()) {
        walk(absolute, pathParts);
      } else if (stat.isSymbolicLink() && options.allowSymlinks) {
        const target = readlinkSync(absolute);
        expect(/^[\x00-\x7f]+$/.test(target), "tree contains a non-ASCII symlink");
        entries.push({ kind: "symlink", path, target });
        symlinkCount += 1;
      } else if (stat.isFile() && stat.size <= options.maxFileBytes) {
        const raw = readFileSync(absolute);
        totalBytes += raw.length;
        expect(totalBytes <= options.maxTotalBytes, "tree inventory byte limit exceeded");
        entries.push({
          digest: sha256(raw),
          executable: Boolean(stat.mode & 0o111),
          kind: "file",
          links: stat.nlink,
          path,
          size: raw.length,
        });
        fileCount += 1;
      } else {
        throw new Error(`unsupported tree entry: ${path}`);
      }
    }
  };
  walk(root);
  return {
    algorithm: options.algorithm,
    entry_count: entries.length,
    file_count: fileCount,
    symlink_count: symlinkCount,
    total_bytes: totalBytes,
    tree_digest: sha256(Buffer.from(canonicalJson(entries), "ascii")),
  };
}

function runtimeSnapshot(input) {
  const root = input.runtime.entrypoint.slice(0, -RUNTIME_SUFFIX.length);
  expect(realpathSync(input.runtime.entrypoint) === input.runtime.entrypoint, "runtime entrypoint changed");
  const tree = treeInventory(root, {
    algorithm: "aragorn/runtime-tree/v1",
    allowSymlinks: true,
    maxEntries: 100000,
    maxFileBytes: 128 * 1024 * 1024,
    maxTotalBytes: 1024 * 1024 * 1024,
  });
  expect(tree.tree_digest === input.runtime.expected_tree_digest, "runtime tree changed");
  return {
    entrypoint: input.runtime.entrypoint,
    entrypoint_digest: sha256(readFileSync(input.runtime.entrypoint)),
    root,
    tree,
  };
}

function pluginSnapshot(input) {
  expect(realpathSync(input.plugin.path) === input.plugin.path, "plugin root changed");
  expect(
    canonicalJson(readdirSync(input.plugin.path).sort()) ===
      canonicalJson(["index.js", "openclaw.plugin.json", "package.json"]),
    "plugin closure changed",
  );
  const root = metadata(input.plugin.path);
  expect(
    root.type === "directory" &&
      root.uid === 0 &&
      root.gid === 0 &&
      (Number.parseInt(root.mode, 8) & 0o022) === 0,
    "plugin root is not root-owned and immutable to the runtime",
  );
  const files = readdirSync(input.plugin.path)
    .sort()
    .map((name) => {
      const path = join(input.plugin.path, name);
      const stat = metadata(path);
      expect(
        stat.type === "file" &&
          stat.uid === 0 &&
          stat.gid === 0 &&
          stat.nlink === 1 &&
          (Number.parseInt(stat.mode, 8) & 0o022) === 0,
        `plugin file identity changed: ${name}`,
      );
      const raw = readFileSync(path);
      return { bytes: raw.length, digest: sha256(raw), path, stat };
    });
  const tree = treeInventory(input.plugin.path, {
    algorithm: "aragorn/plugin-tree/v1",
    allowSymlinks: false,
    maxEntries: 16,
    maxFileBytes: 1024 * 1024,
    maxTotalBytes: 4 * 1024 * 1024,
  });
  expect(tree.tree_digest === input.plugin.digest, "plugin tree changed");
  return { files, root, tree };
}

function processIdentity(pid) {
  requireInteger(pid, "process id", true);
  const rawStat = readFileSync(`/proc/${pid}/stat`, "utf8").trim();
  const fields = rawStat.slice(rawStat.lastIndexOf(")") + 2).split(" ");
  const status = Object.fromEntries(
    readFileSync(`/proc/${pid}/status`, "utf8")
      .split("\n")
      .filter((line) => line.includes(":"))
      .map((line) => {
        const index = line.indexOf(":");
        return [line.slice(0, index), line.slice(index + 1).trim()];
      }),
  );
  return {
    capabilities_effective: status.CapEff,
    cmdline: readFileSync(`/proc/${pid}/cmdline`)
      .toString("utf8")
      .split("\0")
      .filter(Boolean),
    gids: status.Gid.split(/\s+/).map(Number),
    groups: status.Groups.split(/\s+/).filter(Boolean).map(Number).sort((a, b) => a - b),
    mount_namespace: readlinkSync(`/proc/${pid}/ns/mnt`),
    network_namespace: readlinkSync(`/proc/${pid}/ns/net`),
    no_new_privileges: Number(status.NoNewPrivs),
    pid,
    start_time_ticks: fields[19],
    uids: status.Uid.split(/\s+/).map(Number),
  };
}

function runtimeIdentityMatches(identity, config) {
  return (
    canonicalJson(identity.uids) === canonicalJson(Array(4).fill(config.expectedRuntimeUid)) &&
    canonicalJson(identity.gids) === canonicalJson(Array(4).fill(config.expectedRuntimeGid)) &&
    identity.groups.every((gid) => gid === config.expectedRuntimeGid) &&
    identity.capabilities_effective === "0000000000000000" &&
    identity.no_new_privileges === 1
  );
}

function targetSnapshot(input) {
  const rootPath = input.plugin.config.protectedRoot;
  const targetPath = join(rootPath, input.scenario.target_name);
  const root = metadata(rootPath);
  expect(
    root.type === "directory" &&
      root.uid === input.plugin.config.expectedBrokerUid &&
      root.gid === input.plugin.config.expectedRuntimeGid &&
      root.mode === "0710",
    "protected root identity changed",
  );
  try {
    const target = metadata(targetPath);
    return { exists: true, path: targetPath, root, target };
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") {
      return { exists: false, path: targetPath, root, target: null };
    }
    throw error;
  }
}

function profileEnvironment(paths) {
  const token = process.env.OPENCLAW_GATEWAY_TOKEN;
  expect(typeof token === "string" && token.length > 0, "Gateway token is absent");
  return {
    ...process.env,
    HOME: paths.home,
    NO_COLOR: "1",
    NO_PROXY: "127.0.0.1,localhost",
    OPENCLAW_CONFIG_PATH: paths.config,
    OPENCLAW_GATEWAY_TOKEN: token,
    OPENCLAW_STATE_DIR: paths.state,
    PATH: "/usr/local/bin:/usr/bin:/bin",
  };
}

function commandRunner(input, paths, env) {
  return (args, timeout = 20000) =>
    new Promise((resolvePromise) => {
      const startedAt = new Date().toISOString();
      const child = spawn(process.execPath, [input.runtime.entrypoint, ...args], {
        cwd: paths.workspace,
        env,
        stdio: ["ignore", "pipe", "pipe"],
      });
      const stdout = [];
      const stderr = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let error = null;
      const append = (chunks, chunk, current) => {
        const next = current + chunk.length;
        if (next > MAX_COMMAND_BYTES) {
          error = "command output exceeded its retained limit";
          child.kill("SIGKILL");
          return current;
        }
        chunks.push(chunk);
        return next;
      };
      child.stdout.on("data", (chunk) => {
        stdoutBytes = append(stdout, chunk, stdoutBytes);
      });
      child.stderr.on("data", (chunk) => {
        stderrBytes = append(stderr, chunk, stderrBytes);
      });
      child.once("error", (cause) => {
        error = cause.message;
      });
      const timer = setTimeout(() => {
        error = `command timed out after ${timeout} ms`;
        child.kill("SIGKILL");
      }, timeout);
      timer.unref();
      child.once("close", (exitCode, signal) => {
        clearTimeout(timer);
        resolvePromise({
          argv: [process.execPath, input.runtime.entrypoint, ...args],
          completed_at: new Date().toISOString(),
          error,
          exit_code: exitCode,
          pid: child.pid ?? null,
          signal,
          started_at: startedAt,
          stderr: Buffer.concat(stderr, stderrBytes).toString("utf8"),
          stdout: Buffer.concat(stdout, stdoutBytes).toString("utf8"),
        });
      });
    });
}

function boundedCapture(stream) {
  const hash = createHash("sha256");
  let bytes = 0;
  let retained = Buffer.alloc(0);
  stream.on("data", (chunk) => {
    const raw = Buffer.from(chunk);
    hash.update(raw);
    bytes += raw.length;
    if (retained.length < MAX_GATEWAY_LOG_BYTES) {
      retained = Buffer.concat([
        retained,
        raw.subarray(0, MAX_GATEWAY_LOG_BYTES - retained.length),
      ]);
    }
  });
  return {
    snapshot() {
      return {
        bytes,
        digest: `sha256:${hash.copy().digest("hex")}`,
        excerpt: retained.subarray(0, 2048).toString("utf8"),
        retained_bytes: retained.length,
        truncated: bytes > retained.length,
      };
    },
  };
}

function startGateway(input, paths, env) {
  const child = spawn(
    process.execPath,
    [
      input.runtime.entrypoint,
      "gateway",
      "run",
      "--allow-unconfigured",
      "--auth",
      "token",
      "--bind",
      "loopback",
      "--port",
      "18789",
      "--tailscale",
      "off",
      "--ws-log",
      "full",
    ],
    {
      cwd: paths.workspace,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const lifecycle = { spawn_error: null };
  child.once("error", (error) => {
    lifecycle.spawn_error = error instanceof Error ? error.message : String(error);
  });
  const closed = new Promise((resolvePromise) => {
    child.once("close", (exitCode, signal) => {
      resolvePromise({ exit_code: exitCode, signal });
    });
  });
  return {
    child,
    closed,
    lifecycle,
    stderr: boundedCapture(child.stderr),
    stdout: boundedCapture(child.stdout),
  };
}

function gatewayRunning(gateway) {
  return (
    gateway.child.exitCode === null &&
    gateway.child.signalCode === null &&
    gateway.lifecycle.spawn_error === null
  );
}

async function stopGateway(gateway) {
  let closed = null;
  if (gatewayRunning(gateway)) {
    gateway.child.kill("SIGTERM");
    closed = await Promise.race([
      gateway.closed,
      new Promise((resolvePromise) =>
        setTimeout(() => resolvePromise(null), 5000),
      ),
    ]);
  }
  if (gatewayRunning(gateway)) {
    gateway.child.kill("SIGKILL");
    closed = await Promise.race([
      gateway.closed,
      new Promise((_, rejectPromise) =>
        setTimeout(
          () => rejectPromise(new Error("Gateway did not close after SIGKILL")),
          5000,
        ),
      ),
    ]);
  }
  const result = {
    exit_code: closed?.exit_code ?? gateway.child.exitCode,
    pid: gateway.child.pid ?? null,
    signal: closed?.signal ?? gateway.child.signalCode,
    spawn_error: gateway.lifecycle.spawn_error,
    stderr: gateway.stderr.snapshot(),
    stdout: gateway.stdout.snapshot(),
  };
  expect(
    result.stderr.bytes <= MAX_GATEWAY_LOG_BYTES * 4 &&
      result.stdout.bytes <= MAX_GATEWAY_LOG_BYTES * 4,
    "Gateway emitted excessive bounded probe logs",
  );
  return result;
}

function summarized(result) {
  return {
    argv: result.argv,
    completed_at: result.completed_at,
    error: result.error,
    exit_code: result.exit_code,
    pid: result.pid,
    signal: result.signal,
    started_at: result.started_at,
    stderr_bytes: Buffer.byteLength(result.stderr),
    stderr_digest: sha256(Buffer.from(result.stderr)),
    stdout_bytes: Buffer.byteLength(result.stdout),
    stdout_digest: sha256(Buffer.from(result.stdout)),
  };
}

function parseCommand(result, label) {
  expect(result.exit_code === 0 && result.error === null, `${label} failed: ${result.stderr.trim()}`);
  for (const output of [result.stdout, result.stderr]) {
    try {
      return JSON.parse(output);
    } catch {
      // OpenClaw service-control JSON may use either stream.
    }
  }
  throw new Error(`${label} did not return JSON`);
}

function gatewayCall(runCommand, method, params = null, timeout = 5000) {
  const args = ["gateway", "call", method, "--json", "--timeout", String(timeout)];
  if (params !== null) args.push("--params", canonicalJson(params));
  return runCommand(args, timeout + 5000);
}

async function waitForGateway(runCommand, gateway) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (!gatewayRunning(gateway)) {
      throw new Error(
        `Gateway exited early: ${
          gateway.lifecycle.spawn_error ??
          gateway.child.signalCode ??
          gateway.child.exitCode
        }`,
      );
    }
    const call = await gatewayCall(runCommand, "system.info");
    if (call.exit_code === 0) {
      const info = parseCommand(call, "system.info");
      if (info.pid === gateway.child.pid) {
        return { command: summarized(call), info };
      }
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
  }
  throw new Error("timed out waiting for the OpenClaw Gateway");
}

function sse(response, chunks) {
  response.writeHead(200, {
    "cache-control": "no-cache",
    connection: "keep-alive",
    "content-type": "text/event-stream; charset=utf-8",
  });
  for (const chunk of chunks) response.write(`data: ${canonicalJson(chunk)}\n\n`);
  response.end("data: [DONE]\n\n");
}

function providerResponse(sequence, input, toolCallId, finalText) {
  const common = { created: 0, model: MODEL, object: "chat.completion.chunk" };
  if (sequence === 1) {
    return [
      {
        ...common,
        choices: [
          {
            delta: {
              role: "assistant",
              tool_calls: [
                {
                  function: {
                    arguments: canonicalJson({
                      content: input.scenario.content,
                      target_name: input.scenario.target_name,
                    }),
                    name: TOOL_NAME,
                  },
                  id: toolCallId,
                  index: 0,
                  type: "function",
                },
              ],
            },
            finish_reason: "tool_calls",
            index: 0,
          },
        ],
        id: `chatcmpl-${input.scenario.id}-tool`,
      },
    ];
  }
  return [
    {
      ...common,
      choices: [
        {
          delta: { content: finalText, role: "assistant" },
          finish_reason: null,
          index: 0,
        },
      ],
      id: `chatcmpl-${input.scenario.id}-final`,
    },
    {
      ...common,
      choices: [{ delta: {}, finish_reason: "stop", index: 0 }],
      id: `chatcmpl-${input.scenario.id}-final`,
      usage: { completion_tokens: 1, prompt_tokens: 1, total_tokens: 2 },
    },
  ];
}

async function readRequest(request) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    expect(bytes <= MAX_PROVIDER_BYTES, "provider request exceeded 4 MiB");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, bytes);
}

async function startProvider(input, toolCallId, finalText) {
  const records = [];
  const errors = [];
  let health_requests = 0;
  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/v1/models") {
        health_requests += 1;
        response.writeHead(200, { "content-type": "application/json" });
        response.end(
          canonicalJson({
            data: [{ created: 0, id: MODEL, object: "model", owned_by: "aragorn" }],
            object: "list",
          }),
        );
        return;
      }
      expect(
        request.method === "POST" && request.url === "/v1/chat/completions",
        "unexpected provider route",
      );
      const raw = await readRequest(request);
      const body = JSON.parse(raw.toString("utf8"));
      const sequence = records.length + 1;
      expect(sequence <= 2, "provider received more than two model requests");
      expect(typeof request.headers.authorization === "string", "provider authorization is absent");
      const emitted = providerResponse(sequence, input, toolCallId, finalText);
      records.push({
        authorization_digest: sha256(Buffer.from(request.headers.authorization)),
        body,
        body_bytes: raw.length,
        body_digest: sha256(raw),
        body_raw: raw.toString("utf8"),
        content_type: request.headers["content-type"] ?? null,
        method: request.method,
        path: request.url,
        received_at: new Date().toISOString(),
        response: emitted,
        response_digest: sha256(Buffer.from(canonicalJson(emitted), "ascii")),
        sequence,
      });
      sse(response, emitted);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(message);
      response.writeHead(500, { "content-type": "application/json" });
      response.end(canonicalJson({ error: message }));
    }
  });
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(PROVIDER_PORT, "127.0.0.1", resolvePromise);
  });
  return {
    close: () => new Promise((resolvePromise) => server.close(resolvePromise)),
    errors,
    get health_requests() {
      return health_requests;
    },
    records,
  };
}

function systemPrompt(body) {
  return (body.messages ?? [])
    .filter((message) => message.role === "system")
    .map((message) => message.content)
    .join("\n");
}

function textContent(message) {
  return (message?.content ?? [])
    .filter((part) => part.type === "text")
    .map((part) => part.text)
    .join("");
}

function retainedToolResult(message) {
  try {
    expect(
      message?.content?.length === 1 &&
        message.content[0]?.type === "text" &&
        typeof message.content[0]?.text === "string",
      "tool result text content changed",
    );
    const raw = message.content[0].text;
    const document = JSON.parse(raw);
    exactKeys(document, ["message", "result", "schema"], "retained tool result");
    expect(
      document.schema === TOOL_RESULT_TEXT_SCHEMA &&
        typeof document.message === "string" &&
        document.result &&
        typeof document.result === "object" &&
        !Array.isArray(document.result) &&
        canonicalJson(document) === raw,
      "retained tool result is not exact canonical JSON",
    );
    return { digest: sha256(Buffer.from(raw, "ascii")), document, raw };
  } catch {
    return null;
  }
}

function deriveProof({
  gatewayAfter,
  gatewayBefore,
  history,
  input,
  inspect,
  provider,
  probeIdentity,
  send,
  targetAfter,
  targetBefore,
  toolCallId,
  wait,
}) {
  const records = provider.records;
  const first = records[0];
  const second = records[1];
  const contracts = (first?.body?.tools ?? []).filter(
    (tool) => tool.function?.name === TOOL_NAME,
  );
  const contract = contracts[0] ?? null;
  const expectedArguments = {
    content: input.scenario.content,
    target_name: input.scenario.target_name,
  };
  const expectedRunId = `aragorn-p33c-${input.scenario.id}`;
  const expectedSessionKey = `agent:main:${expectedRunId}`;
  const expectedTransportToolCallId = toolCallId.replaceAll("_", "");
  const expectedFinalText =
    `ARAGORN_RUNTIME_ACTION_${input.scenario.expected_verdict}_${input.scenario.expected_effect_status}`;
  const contractExact =
    contracts.length === 1 &&
    contract?.type === "function" &&
    contract.function?.description ===
      "Create one policy-authorized file through the Aragorn runtime broker." &&
    contract.function?.parameters?.type === "object" &&
    contract.function?.parameters?.additionalProperties === false &&
    canonicalJson([...(contract.function?.parameters?.required ?? [])].sort()) ===
      '["content","target_name"]' &&
    canonicalJson(contract.function?.parameters?.properties) ===
      canonicalJson({
        content: { maxLength: MAX_PAYLOAD_BYTES, type: "string" },
        target_name: {
          maxLength: 128,
          pattern: TARGET_NAME.source,
          type: "string",
        },
      });
  const providerCall = first?.response?.[0]?.choices?.[0]?.delta?.tool_calls?.[0];
  const firstMessageCount = first?.body?.messages?.length ?? -1;
  const transportAssistant = second?.body?.messages?.[firstMessageCount];
  const transportTool = second?.body?.messages?.[firstMessageCount + 1];
  const messages = history.messages ?? [];
  const [user, assistant, toolResult, final] = messages;
  const retained = retainedToolResult(toolResult);
  const details = retained?.document.result;
  const clientError = input.scenario.expected_verdict === "CLIENT_ERROR";
  const expectedReasonCodes =
    input.scenario.expected_verdict === "ALLOW"
      ? []
      : input.scenario.expected_verdict === "BLOCK"
        ? ["MEDIATOR_UNHEALTHY"]
        : null;
  const expectedText = clientError
    ? `Aragorn runtime action failed closed: ${input.scenario.expected_effect_status}`
    : `Aragorn ${input.scenario.expected_verdict}: ${input.scenario.expected_effect_status}`;
  const retainedDetailsConsistent =
    !Object.hasOwn(toolResult ?? {}, "details") ||
    canonicalJson(toolResult.details) === canonicalJson(details);
  const skillPrompt = systemPrompt(first?.body ?? {});
  const plugin = inspect.response?.plugin;
  const targetOutcome =
    input.scenario.expected_verdict === "ALLOW"
      ? targetAfter.exists &&
        targetAfter.target?.type === "file" &&
        targetAfter.target?.uid === input.plugin.config.expectedBrokerUid &&
        targetAfter.target?.gid === input.plugin.config.expectedRuntimeGid &&
        targetAfter.target?.mode === "0400" &&
        targetAfter.target?.nlink === 1 &&
        targetAfter.target?.size === Buffer.byteLength(input.scenario.content)
      : !targetAfter.exists;
  const stableRootIdentity = ["device", "gid", "inode", "mode", "type", "uid"].every(
    (field) => targetAfter.root[field] === targetBefore.root[field],
  );
  const resultBound = clientError
    ? canonicalJson(Object.keys(details ?? {}).sort()) ===
        '["authority","effect_status","message","schema"]' &&
      details?.schema === "aragorn/runtime-action-client-error/v1" &&
      details?.authority ===
        "CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY" &&
      details?.effect_status === "NOT_SUBMITTED" &&
      details?.message === "sensor socket is unavailable: ENOENT"
    : details?.schema === "aragorn/runtime-action-broker-result/v1" &&
      details?.authority ===
        "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY" &&
      details?.verdict === input.scenario.expected_verdict &&
      details?.effect_status === input.scenario.expected_effect_status &&
      details?.target_name === input.scenario.target_name &&
      DIGEST.test(details?.request_digest ?? "") &&
      DIGEST.test(details?.observation_digest ?? "") &&
      details?.decision?.verdict === input.scenario.expected_verdict &&
      canonicalJson(details?.reason_codes ?? null) === canonicalJson(expectedReasonCodes) &&
      canonicalJson(details?.decision?.reason_codes ?? null) ===
        canonicalJson(expectedReasonCodes);
  const checks = {
    action_result_bound: resultBound,
    exact_exposed_tool_contract: contractExact,
    gateway_process_stable:
      canonicalJson(gatewayAfter) === canonicalJson(gatewayBefore) &&
      canonicalJson(gatewayBefore.cmdline) === '["openclaw-gateway"]' &&
      gatewayBefore.mount_namespace === probeIdentity.mount_namespace &&
      gatewayBefore.network_namespace === probeIdentity.network_namespace,
    history_lineage:
      canonicalJson(messages.map((message) => message.role)) ===
        '["user","assistant","toolResult","assistant"]' &&
      user?.content ===
        `Invoke ${TOOL_NAME} exactly once for bounded scenario ${input.scenario.id}.` &&
      user?.idempotencyKey === `${send.runId}:user` &&
      assistant?.content?.length === 1 &&
      assistant.content[0]?.id === toolCallId &&
      assistant.content[0]?.name === TOOL_NAME &&
      canonicalJson(assistant.content[0]?.arguments) === canonicalJson(expectedArguments) &&
      assistant.content[0]?.partialArgs === canonicalJson(expectedArguments) &&
      assistant?.stopReason === "toolUse" &&
      toolResult?.toolCallId === toolCallId &&
      toolResult?.toolName === TOOL_NAME &&
      toolResult?.isError === false &&
      retained !== null &&
      retained.document.message === expectedText &&
      retainedDetailsConsistent &&
      textContent(toolResult) === retained.raw &&
      final?.provider === PROVIDER &&
      final?.model === MODEL &&
      final?.stopReason === "stop" &&
      textContent(final) === expectedFinalText,
    one_provider_driven_tool_call:
      records.length === 2 &&
      first?.sequence === 1 &&
      second?.sequence === 2 &&
      first?.body?.model === MODEL &&
      second?.body?.model === MODEL &&
      first?.authorization_digest === sha256(Buffer.from(`Bearer ${MOCK_KEY}`)) &&
      second?.authorization_digest === first?.authorization_digest &&
      records.every(
        (record) =>
          sha256(Buffer.from(record.body_raw)) === record.body_digest &&
          canonicalJson(JSON.parse(record.body_raw)) === canonicalJson(record.body),
      ) &&
      first?.body?.messages?.every(
        (message) => !["assistant", "tool"].includes(message.role),
      ) &&
      first?.response?.length === 1 &&
      first.response[0]?.choices?.length === 1 &&
      first.response[0]?.choices?.[0]?.finish_reason === "tool_calls" &&
      first.response[0]?.choices?.[0]?.delta?.tool_calls?.length === 1 &&
      providerCall?.id === toolCallId &&
      providerCall?.function?.name === TOOL_NAME &&
      providerCall?.function?.arguments === canonicalJson(expectedArguments) &&
      transportAssistant?.role === "assistant" &&
      transportAssistant?.tool_calls?.length === 1 &&
      transportAssistant.tool_calls[0]?.id === expectedTransportToolCallId &&
      transportAssistant.tool_calls[0]?.function?.name === TOOL_NAME &&
      transportAssistant.tool_calls[0]?.function?.arguments === canonicalJson(expectedArguments) &&
      transportTool?.role === "tool" &&
      transportTool?.tool_call_id === transportAssistant.tool_calls[0]?.id &&
      transportTool?.content === retained?.raw &&
      second.body.messages.length === firstMessageCount + 2 &&
      canonicalJson(second.body.messages.slice(0, firstMessageCount)) ===
        canonicalJson(first.body.messages) &&
      second?.response?.length === 2 &&
      second.response[0]?.choices?.length === 1 &&
      second.response[0]?.choices?.[0]?.delta?.content === expectedFinalText &&
      second.response[1]?.choices?.length === 1 &&
      second.response[1]?.choices?.[0]?.finish_reason === "stop",
    plugin_loaded_from_pinned_path:
      plugin?.id === PLUGIN_ID &&
      plugin?.source === join(input.plugin.path, "index.js") &&
      plugin?.status === "loaded" &&
      plugin?.version === "0.1.0",
    provider_completed_without_error: provider.errors.length === 0,
    session_bound:
      send.status === "started" &&
      send.runId === expectedRunId &&
      wait.runId === expectedRunId &&
      wait.status === "ok" &&
      Number.isSafeInteger(wait.endedAt) &&
      history.sessionKey === expectedSessionKey &&
      typeof history.sessionId === "string" &&
      history.sessionId.length > 0 &&
      history.sessionInfo?.key === history.sessionKey &&
      history.sessionInfo?.status === "done" &&
      canonicalJson(history.sessionInfo?.activeRunIds) === "[]",
    skill_deployment_pin_visible:
      skillPrompt.includes(`<name>${input.skill.name}</name>`) &&
      skillPrompt.includes(`<version>${input.skill.digest.slice(0, 23)}</version>`),
    target_effect_matches_result:
      !targetBefore.exists &&
      targetOutcome &&
      stableRootIdentity,
  };
  return {
    checks,
    exposed_tool_contract: contract,
    passed: Object.values(checks).every(Boolean),
    retained_tool_result: retained?.document ?? null,
    retained_tool_result_digest: retained?.digest ?? null,
    tool_result: toolResult ?? null,
  };
}

async function runProbe(inputRecord) {
  const input = inputRecord.document;
  const paths = profilePaths(input);
  const preparation = prepareProfile(input, paths);
  const configuration = configurationSnapshot(input, paths);
  const skill = skillSnapshot(input, paths);
  const plugin = pluginSnapshot(input);
  const runtime = runtimeSnapshot(input);
  const probeIdentity = processIdentity(process.pid);
  expect(
    process.getuid?.() === input.plugin.config.expectedRuntimeUid &&
      process.getgid?.() === input.plugin.config.expectedRuntimeGid &&
      process.getgroups?.().every(
        (gid) => gid === input.plugin.config.expectedRuntimeGid,
      ) &&
      runtimeIdentityMatches(probeIdentity, input.plugin.config),
    "probe is not running as the exact contained runtime principal",
  );

  const env = profileEnvironment(paths);
  const runCommand = commandRunner(input, paths, env);
  const versionCommand = await runCommand(["--version"]);
  expect(
    versionCommand.exit_code === 0 &&
      versionCommand.stdout.trim() === input.runtime.expected_version,
    "OpenClaw version changed",
  );
  const gateway = startGateway(input, paths, env);
  let operationError = null;
  let result = null;
  try {
    const readiness = await waitForGateway(runCommand, gateway);
    const gatewayBefore = processIdentity(readiness.info.pid);
    expect(
      runtimeIdentityMatches(gatewayBefore, input.plugin.config),
      "Gateway is not running as the exact contained runtime principal",
    );
    const inspectCommand = await runCommand([
      "plugins",
      "inspect",
      PLUGIN_ID,
      "--json",
    ]);
    const inspect = {
      command: summarized(inspectCommand),
      response: parseCommand(inspectCommand, "plugins inspect"),
    };
    const targetBefore = targetSnapshot(input);
    expect(!targetBefore.exists, "scenario target existed before the turn");

    const runId = `aragorn-p33c-${input.scenario.id}`;
    const sessionKey = `agent:main:${runId}`;
    const toolCallId =
      `call_aragorn_${input.scenario.id.replace(/[^a-z0-9]/g, "")}_1`;
    const finalText =
      `ARAGORN_RUNTIME_ACTION_${input.scenario.expected_verdict}_${input.scenario.expected_effect_status}`;
    const userText =
      `Invoke ${TOOL_NAME} exactly once for bounded scenario ${input.scenario.id}.`;
    const provider = await startProvider(input, toolCallId, finalText);
    let sendCommand;
    let send;
    let waitCommand;
    let wait;
    let historyCommand;
    let history;
    try {
      sendCommand = await gatewayCall(runCommand, "chat.send", {
        deliver: false,
        idempotencyKey: runId,
        message: userText,
        sessionKey,
        timeoutMs: 10000,
      });
      send = parseCommand(sendCommand, "chat.send");
      waitCommand = await gatewayCall(
        runCommand,
        "agent.wait",
        { runId: send.runId, timeoutMs: 15000 },
        17000,
      );
      wait = parseCommand(waitCommand, "agent.wait");
      historyCommand = await gatewayCall(runCommand, "chat.history", {
        limit: 20,
        sessionKey,
      });
      history = parseCommand(historyCommand, "chat.history");
    } finally {
      await provider.close();
    }
    const targetAfter = targetSnapshot(input);
    const gatewayAfter = processIdentity(readiness.info.pid);
    const proof = deriveProof({
      gatewayAfter,
      gatewayBefore,
      history,
      input,
      inspect,
      probeIdentity,
      provider,
      send,
      targetAfter,
      targetBefore,
      toolCallId,
      wait,
    });
    result = {
      authority: AUTHORITY,
      configuration,
      decision: {
        edr_claim_eligible: false,
        phase3_exit_eligible: false,
        pinned_openclaw_composition_observed: proof.passed,
        public_release_eligible: false,
        run_01_eligible: false,
        run_02_eligible: false,
        status: proof.passed ? "P3_3C_OBSERVED" : "FAIL",
      },
      gateway: {
        process_after: gatewayAfter,
        process_before: gatewayBefore,
        readiness_command: readiness.command,
        spawned_pid: gateway.child.pid,
        system_info: { pid: readiness.info.pid },
      },
      input: {
        digest: inputRecord.digest,
        path: inputRecord.path,
        stat: inputRecord.stat,
      },
      limitations: LIMITATIONS,
      plugin: {
        configured_path: input.plugin.path,
        expected_tree_digest: input.plugin.digest,
        inspect,
        snapshot: plugin,
      },
      probe: {
        implementation_digest: sha256(readFileSync(SELF)),
        process: probeIdentity,
      },
      profile: preparation,
      provider: {
        errors: provider.errors,
        health_request_count: provider.health_requests,
        records: provider.records,
        request_count: provider.records.length,
        transport: "openai-completions",
      },
      recorded_at: new Date().toISOString(),
      runtime: {
        ...runtime,
        expected_version: input.runtime.expected_version,
        version_command: summarized(versionCommand),
        version_output: versionCommand.stdout.trim(),
      },
      scenario: {
        content_bytes: Buffer.byteLength(input.scenario.content),
        content_digest: sha256(Buffer.from(input.scenario.content)),
        expected_effect_status: input.scenario.expected_effect_status,
        expected_verdict: input.scenario.expected_verdict,
        id: input.scenario.id,
        proof,
        status: proof.passed ? "PASS" : "FAIL",
        target_name: input.scenario.target_name,
      },
      schema: EVIDENCE_SCHEMA,
      skill,
      turn: {
        history: { command: summarized(historyCommand), response: history },
        identifiers: {
          run_id: send.runId,
          session_id: history.sessionId ?? null,
          session_key: history.sessionKey ?? null,
          tool_call_id: toolCallId,
        },
        send: { command: summarized(sendCommand), response: send },
        target_after: targetAfter,
        target_before: targetBefore,
        wait: { command: summarized(waitCommand), response: wait },
      },
    };
  } catch (error) {
    operationError = error;
  }

  let shutdown;
  try {
    shutdown = await stopGateway(gateway);
  } catch (error) {
    operationError = operationError
      ? new Error(
          `${operationError instanceof Error ? operationError.message : String(operationError)}; Gateway cleanup failed: ${
            error instanceof Error ? error.message : String(error)
          }`,
        )
      : error;
  }
  if (operationError) throw operationError;
  expect(result !== null, "probe result was not assembled");
  expect(
    shutdown.pid === result.gateway.system_info.pid &&
      shutdown.spawn_error === null &&
      (shutdown.exit_code !== null || shutdown.signal !== null),
    "Gateway child was not exactly stopped and reaped",
  );
  result.gateway.shutdown = shutdown;
  return result;
}

function failureEvidence(error) {
  return {
    authority: AUTHORITY,
    decision: {
      edr_claim_eligible: false,
      phase3_exit_eligible: false,
      pinned_openclaw_composition_observed: false,
      public_release_eligible: false,
      run_01_eligible: false,
      run_02_eligible: false,
      status: "FAIL",
    },
    fatal_error: {
      message: error instanceof Error ? error.message : String(error),
      name: error instanceof Error ? error.name : "Error",
    },
    limitations: [...LIMITATIONS, "OPENCLAW_RUNTIME_ACTION_PROBE_DID_NOT_COMPLETE"],
    recorded_at: new Date().toISOString(),
    schema: EVIDENCE_SCHEMA,
  };
}

try {
  expect(process.argv.length === 3, `usage: ${process.argv[1]} INPUT.json`);
  const input = readInput(process.argv[2]);
  const evidence = await runProbe(input);
  process.stdout.write(`${canonicalJson(evidence)}\n`);
  process.exitCode = evidence.scenario.status === "PASS" ? 0 : 2;
} catch (error) {
  process.stdout.write(`${canonicalJson(failureEvidence(error))}\n`);
  process.exitCode = 2;
}
