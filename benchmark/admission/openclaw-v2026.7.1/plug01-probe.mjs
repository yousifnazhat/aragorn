#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  closeSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/profile/state/openclaw.json";
const STATE = "/profile/state";
const WORKSPACE = "/profile/workspace";
const HOME = "/profile/home";
const SOURCES = "/sources";
const BASELINE_SOURCE = join(SOURCES, "baseline-source");
const BLOCKED_SOURCE = join(SOURCES, "blocked-source");
const ALLOWED_SOURCE = join(SOURCES, "allowed-source");
const PLUGIN_ID = "aragorn-plug01";
const PACKAGE_NAME = "@aragorn/plug01-fixture";
const SKILL_NAME = "aragorn-plug01-skill";
const TARGET = join(STATE, "extensions", PLUGIN_ID);
const TARGET_SKILL = join(TARGET, "skills", SKILL_NAME);
const PUBLISHED_SKILL = join(STATE, "plugin-skills", SKILL_NAME);
const POLICY_LOG = join(STATE, "plug01-policy-requests.jsonl");
const SETUP_EVIDENCE = join(STATE, "plug01-setup.json");
const TEST_TOKEN = "aragorn-contained-plug01-token-v1";
const EXPECTED_VERSION = "OpenClaw 2026.7.1 (2d2ddc4)";
const EXPECTED_COMMIT = "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4";
const BLOCK_REASON = "Aragorn PLUG-01 exact blocked fixture";
const SELF = fileURLToPath(import.meta.url);
const COMMAND_OUTPUT_LIMIT = 2 * 1024 * 1024;
const RETAINED_TEXT_LIMIT = 2048;
const GATEWAY_LOG_LIMIT = 256 * 1024;
const PROFILE_ENV = {
  HOME,
  HTTP_PROXY: "http://127.0.0.1:9",
  HTTPS_PROXY: "http://127.0.0.1:9",
  NO_COLOR: "1",
  NO_PROXY: "127.0.0.1,localhost",
  OPENCLAW_CONFIG_PATH: CONFIG,
  OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
  OPENCLAW_GATEWAY_TOKEN: TEST_TOKEN,
  OPENCLAW_NO_RESPAWN: "1",
  OPENCLAW_SKIP_CHANNELS: "1",
  OPENCLAW_SKIP_PROVIDERS: "1",
  OPENCLAW_STATE_DIR: STATE,
  PATH: "/usr/local/bin:/usr/bin:/bin",
  npm_config_audit: "false",
  npm_config_fund: "false",
  npm_config_offline: "true",
};

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

function packageJson(version) {
  return `${canonicalJson({
    name: PACKAGE_NAME,
    openclaw: { extensions: ["./index.js"] },
    type: "commonjs",
    version,
  })}\n`;
}

function pluginManifest(version) {
  return `${canonicalJson({
    configSchema: {
      additionalProperties: false,
      properties: {},
      type: "object",
    },
    id: PLUGIN_ID,
    name: "Aragorn PLUG-01",
    skills: ["./skills"],
    version,
  })}\n`;
}

function pluginModule(marker) {
  return [
    '"use strict";',
    "",
    `const marker = ${JSON.stringify(marker)};`,
    "",
    "module.exports = {",
    `  id: ${JSON.stringify(PLUGIN_ID)},`,
    '  name: "Aragorn PLUG-01",',
    "  register() {",
    "    void marker;",
    "  },",
    "};",
    "",
  ].join("\n");
}

function skillDocument(marker, version) {
  return [
    "---",
    `name: ${SKILL_NAME}`,
    `description: Inert Aragorn PLUG-01 fixture ${marker}.`,
    "---",
    `# Aragorn PLUG-01 fixture ${version}`,
    "",
    "This fixture is inert and performs no actions.",
    "",
  ].join("\n");
}

function fixture(version, marker) {
  return {
    "index.js": pluginModule(marker),
    "openclaw.plugin.json": pluginManifest(version),
    "package.json": packageJson(version),
    [`skills/${SKILL_NAME}/SKILL.md`]: skillDocument(marker, version),
  };
}

const FIXTURES = {
  allowed: fixture("2.0.0", "allowed-v2"),
  baseline: fixture("1.0.0", "baseline-v1"),
  blocked: fixture("2.0.0", "blocked-v2"),
};

function configuration(enabled = false) {
  return {
    agents: {
      defaults: { skills: [SKILL_NAME], workspace: WORKSPACE },
      list: [{ id: "main", skills: [SKILL_NAME], workspace: WORKSPACE }],
    },
    plugins: {
      allow: [PLUGIN_ID],
      enabled: true,
      entries: { [PLUGIN_ID]: { enabled } },
    },
    security: {
      installPolicy: {
        enabled: true,
        exec: {
          args: ["/probe/plug01-probe.mjs", "policy"],
          command: NODE,
          maxOutputBytes: 4096,
          noOutputTimeoutMs: 5000,
          source: "exec",
          timeoutMs: 5000,
          trustedDirs: ["/probe", "/usr/local/bin"],
        },
        targets: ["skill", "plugin"],
      },
    },
    skills: {
      load: {
        allowSymlinkTargets: [],
        extraDirs: [],
        watch: true,
        watchDebounceMs: 250,
      },
    },
  };
}

function sourcePolicyRequest(sourcePath, version, mode) {
  return {
    openclawVersion: "2026.7.1",
    origin: { packageName: PACKAGE_NAME, type: "plugin-package", version },
    plugin: {
      contentType: "package",
      extensions: ["./index.js"],
      manifestId: PLUGIN_ID,
      packageName: PACKAGE_NAME,
      pluginId: PLUGIN_ID,
      version,
    },
    protocolVersion: 1,
    request: {
      kind: "plugin-dir",
      mode,
      requestedSpecifier: sourcePath,
    },
    source: {
      authority: "user",
      kind: "local-path",
      mutable: true,
      network: false,
    },
    sourcePath,
    sourcePathKind: "directory",
    targetName: PLUGIN_ID,
    targetType: "plugin",
  };
}

function installedPolicyRequest({
  mode,
  requestedSpecifier,
  sourcePath,
}) {
  const version = requestedSpecifier === BASELINE_SOURCE ? "1.0.0" : "2.0.0";
  const request = sourcePolicyRequest(requestedSpecifier, version, mode);
  request.origin = { type: "plugin-dependency-tree" };
  request.plugin = {
    contentType: "dependency-tree",
    pluginId: PLUGIN_ID,
  };
  request.sourcePath = sourcePath;
  return request;
}

function isInstallStage(path) {
  if (typeof path !== "string") {
    return false;
  }
  const stat = lstatSync(path);
  return (
    stat.isDirectory() &&
    !stat.isSymbolicLink() &&
    dirname(resolve(path)) === realpathSync(dirname(TARGET)) &&
    /^\.openclaw-install-stage-[a-zA-Z0-9_-]+$/.test(basename(path)) &&
    realpathSync(path) === resolve(path)
  );
}

function fileMapDigest(files) {
  return sha256(
    Buffer.from(
      canonicalJson(
        Object.fromEntries(
          Object.entries(files)
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([path, contents]) => [path, sha256(Buffer.from(contents))]),
        ),
      ),
      "utf8",
    ),
  );
}

function exactFixtureTree(root, files) {
  const rootStat = lstatSync(root);
  if (
    !rootStat.isDirectory() ||
    rootStat.isSymbolicLink() ||
    realpathSync(root) !== resolve(root)
  ) {
    throw new Error(`unsafe fixture root: ${root}`);
  }
  const observed = [];
  const visit = (path) => {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
      throw new Error(`unsafe fixture entry: ${path}`);
    }
    if (stat.isFile() && stat.nlink !== 1) {
      throw new Error(`linked fixture file: ${path}`);
    }
    if (path !== root) {
      observed.push({
        mode: (stat.mode & 0o777).toString(8).padStart(3, "0"),
        path: relative(root, path),
        type: stat.isDirectory() ? "directory" : "file",
      });
    }
    if (stat.isDirectory()) {
      for (const name of readdirSync(path).sort()) {
        visit(join(path, name));
      }
    }
  };
  visit(root);
  const observedFiles = observed
    .filter((entry) => entry.type === "file")
    .map((entry) => entry.path)
    .sort();
  const expectedFiles = Object.keys(files).sort();
  if (canonicalJson(observedFiles) !== canonicalJson(expectedFiles)) {
    throw new Error(`fixture file set changed: ${root}`);
  }
  const expectedDirs = [...new Set(expectedFiles.flatMap((path) => {
    const parts = path.split("/");
    return parts.slice(0, -1).map((_, index) => parts.slice(0, index + 1).join("/"));
  }))].sort();
  const observedDirs = observed
    .filter((entry) => entry.type === "directory")
    .map((entry) => entry.path)
    .sort();
  if (canonicalJson(observedDirs) !== canonicalJson(expectedDirs)) {
    throw new Error(`fixture directory set changed: ${root}`);
  }
  for (const [path, contents] of Object.entries(files)) {
    const raw = readFileSync(join(root, path));
    if (!raw.equals(Buffer.from(contents, "utf8"))) {
      throw new Error(`fixture bytes changed: ${join(root, path)}`);
    }
  }
  return {
    digest: fileMapDigest(files),
    entries: observed,
    path: root,
  };
}

function writeFixture(root, files) {
  mkdirSync(root, { recursive: true, mode: 0o755 });
  for (const [path, contents] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true, mode: 0o755 });
    writeFileSync(join(root, path), contents, { flag: "wx", mode: 0o444 });
  }
  const directories = [
    root,
    ...new Set(
      Object.keys(files).flatMap((path) => {
        const parts = path.split("/");
        return parts.slice(0, -1).map((_, index) =>
          join(root, ...parts.slice(0, index + 1)));
      }),
    ),
  ].sort((left, right) => right.length - left.length);
  for (const path of directories) {
    chmodSync(path, 0o755);
  }
}

function prepare() {
  const roots = {
    allowed: "/prepare/sources/allowed-source",
    baseline: "/prepare/sources/baseline-source",
    blocked: "/prepare/sources/blocked-source",
  };
  for (const [name, root] of Object.entries(roots)) {
    writeFixture(root, FIXTURES[name]);
  }
  chmodSync("/prepare/sources", 0o555);
  chmodSync("/prepare", 0o555);
  return {
    fixtures: Object.fromEntries(
      Object.entries(roots).map(([name, path]) => [
        name,
        { digest: fileMapDigest(FIXTURES[name]), path },
      ]),
    ),
    implementation_digest: sha256(readFileSync(SELF)),
    schema: "aragorn/openclaw-contained-plug01-preparation/v1",
  };
}

async function readBoundedPolicyInput() {
  process.stdin.setEncoding("utf8");
  const hash = createHash("sha256");
  let bytes = 0;
  let raw = "";
  let oversized = false;
  for await (const chunk of process.stdin) {
    hash.update(chunk);
    bytes += Buffer.byteLength(chunk, "utf8");
    if (!oversized && bytes <= 64 * 1024) {
      raw += chunk;
    } else {
      oversized = true;
      raw = "";
    }
  }
  return { bytes, digest: `sha256:${hash.digest("hex")}`, oversized, raw };
}

async function policy() {
  const input = await readBoundedPolicyInput();
  let request = null;
  let parseError = null;
  if (!input.oversized) {
    try {
      request = JSON.parse(input.raw);
    } catch (error) {
      parseError = error instanceof Error ? error.message : String(error);
    }
  }
  let decision = "block";
  let reason = "Aragorn PLUG-01 rejected an unexpected request";
  let route = "unrecognized";
  let source = null;
  try {
    if (
      canonicalJson(request) ===
      canonicalJson(sourcePolicyRequest(BLOCKED_SOURCE, "2.0.0", "update"))
    ) {
      route = "blocked-source";
      source = exactFixtureTree(BLOCKED_SOURCE, FIXTURES.blocked);
      reason = BLOCK_REASON;
    } else if (
      canonicalJson(request) ===
      canonicalJson(sourcePolicyRequest(BASELINE_SOURCE, "1.0.0", "install"))
    ) {
      route = "baseline-source";
      source = exactFixtureTree(BASELINE_SOURCE, FIXTURES.baseline);
      decision = "allow";
      reason = "exact baseline source and setup request";
    } else if (
      canonicalJson(request) ===
      canonicalJson(sourcePolicyRequest(ALLOWED_SOURCE, "2.0.0", "update"))
    ) {
      route = "allowed-source";
      source = exactFixtureTree(ALLOWED_SOURCE, FIXTURES.allowed);
      decision = "allow";
      reason = "exact allowed source and request";
    } else if (
      isInstallStage(request?.sourcePath) &&
      canonicalJson(request) ===
        canonicalJson(
          installedPolicyRequest({
            mode: "install",
            requestedSpecifier: BASELINE_SOURCE,
            sourcePath: request.sourcePath,
          }),
        )
    ) {
      route = "baseline-installed-dependency-tree";
      source = exactFixtureTree(request.sourcePath, FIXTURES.baseline);
      decision = "allow";
      reason = "exact staged baseline dependency tree and setup request";
    } else if (
      isInstallStage(request?.sourcePath) &&
      canonicalJson(request) ===
        canonicalJson(
          installedPolicyRequest({
            mode: "update",
            requestedSpecifier: ALLOWED_SOURCE,
            sourcePath: request.sourcePath,
          }),
        )
    ) {
      route = "allowed-installed-dependency-tree";
      source = exactFixtureTree(request.sourcePath, FIXTURES.allowed);
      decision = "allow";
      reason = "exact staged allowed dependency tree and update request";
    }
  } catch (error) {
    reason = `Aragorn PLUG-01 source validation failed: ${
      error instanceof Error ? error.message : String(error)
    }`;
  }
  const record = {
    decision,
    input_bytes: input.bytes,
    input_digest: input.digest,
    oversized: input.oversized,
    parse_error: parseError,
    protocol_version: 1,
    recorded_at: new Date().toISOString(),
    request,
    route,
    source,
  };
  appendFileSync(POLICY_LOG, `${canonicalJson(record)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  process.stdout.write(
    canonicalJson({
      decision,
      protocolVersion: 1,
      ...(decision === "block" ? { reason } : {}),
    }),
  );
}

function command(args, timeout = 30_000) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(NODE, [OPENCLAW, ...args], {
    cwd: WORKSPACE,
    encoding: "utf8",
    env: PROFILE_ENV,
    maxBuffer: COMMAND_OUTPUT_LIMIT,
    timeout,
  });
  return {
    argv: [NODE, OPENCLAW, ...args],
    completed_at: new Date().toISOString(),
    error: result.error?.message ?? null,
    exit_code: result.status,
    pid: result.pid,
    signal: result.signal,
    started_at: startedAt,
    stderr: result.stderr ?? "",
    stdout: result.stdout ?? "",
  };
}

function summarized(result) {
  const bounded = (value) =>
    value.length <= RETAINED_TEXT_LIMIT
      ? value
      : `${value.slice(0, RETAINED_TEXT_LIMIT)}[truncated]`;
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
    stderr_excerpt: bounded(result.stderr),
    stdout_bytes: Buffer.byteLength(result.stdout),
    stdout_digest: sha256(Buffer.from(result.stdout)),
    stdout_excerpt: bounded(result.stdout),
  };
}

function parseCommand(result, label) {
  if (result.exit_code !== 0) {
    throw new Error(`${label} failed: ${(result.stderr || result.stdout).trim()}`);
  }
  for (const output of [result.stdout, result.stderr]) {
    try {
      return JSON.parse(output);
    } catch {
      // OpenClaw service-control JSON may use either stream.
    }
  }
  throw new Error(`${label} did not return JSON`);
}

function gatewayCall(method, timeout = 5000) {
  return command(
    ["gateway", "call", method, "--json", "--timeout", String(timeout)],
    timeout + 5000,
  );
}

function boundedCapture(stream) {
  const hash = createHash("sha256");
  let bytes = 0;
  let retained = Buffer.alloc(0);
  stream.on("data", (chunk) => {
    const raw = Buffer.from(chunk);
    hash.update(raw);
    bytes += raw.length;
    if (retained.length < GATEWAY_LOG_LIMIT) {
      retained = Buffer.concat([
        retained,
        raw.subarray(0, GATEWAY_LOG_LIMIT - retained.length),
      ]);
    }
  });
  return {
    snapshot() {
      return {
        bytes,
        digest: `sha256:${hash.copy().digest("hex")}`,
        excerpt: retained.subarray(0, RETAINED_TEXT_LIMIT).toString("utf8"),
        retained_bytes: retained.length,
        truncated: bytes > retained.length,
      };
    },
  };
}

function startGateway() {
  const child = spawn(
    NODE,
    [
      OPENCLAW,
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
      cwd: WORKSPACE,
      env: PROFILE_ENV,
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

async function waitForGateway(gateway) {
  const deadline = Date.now() + 20_000;
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
    const call = gatewayCall("system.info");
    if (call.exit_code === 0) {
      const info = parseCommand(call, "system.info");
      if (info.pid === gateway.child.pid) {
        return { command: summarized(call), info };
      }
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
  }
  throw new Error("timed out waiting for the contained Gateway");
}

async function stopGateway(gateway) {
  let closed = null;
  if (gatewayRunning(gateway)) {
    gateway.child.kill("SIGTERM");
    closed = await Promise.race([
      gateway.closed,
      new Promise((resolvePromise) => setTimeout(() => resolvePromise(null), 5000)),
    ]);
  }
  if (gatewayRunning(gateway)) {
    gateway.child.kill("SIGKILL");
    closed = await Promise.race([
      gateway.closed,
      new Promise((_, rejectPromise) =>
        setTimeout(() => rejectPromise(new Error("Gateway did not close after SIGKILL")), 5000)),
    ]);
  }
  return {
    exit_code: closed?.exit_code ?? gateway.child.exitCode,
    pid: gateway.child.pid,
    signal: closed?.signal ?? gateway.child.signalCode,
    spawn_error: gateway.lifecycle.spawn_error,
    stderr: gateway.stderr.snapshot(),
    stdout: gateway.stdout.snapshot(),
  };
}

function findGatewayLog() {
  const dir = "/tmp/openclaw";
  const names = readdirSync(dir)
    .filter((name) => name.endsWith(".log"))
    .sort();
  if (names.length !== 1) {
    throw new Error(`expected one Gateway log, found ${names.length}`);
  }
  return join(dir, names[0]);
}

function gatewayLogSnapshot(path) {
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > GATEWAY_LOG_LIMIT * 16) {
    throw new Error("Gateway log exceeded the bounded PLUG-01 limit");
  }
  const raw = readFileSync(path);
  if (raw.includes(TEST_TOKEN)) {
    throw new Error("Gateway log contains the contained test credential");
  }
  const lines = raw.toString("utf8").split("\n");
  if (lines.at(-1) === "") {
    lines.pop();
  }
  let offset = 0;
  const records = lines.map((line) => {
    const record = { document: JSON.parse(line), offset };
    offset += Buffer.byteLength(line, "utf8") + 1;
    return record;
  });
  return { path, raw, records };
}

function matchingLogRecord(snapshot, pattern, after = -1) {
  return snapshot.records.find(
    (record) =>
      record.offset > after &&
      pattern.test(String(record.document.message ?? "")),
  );
}

function logMarker(record) {
  if (!record) {
    return null;
  }
  return {
    message: String(record.document.message ?? "").slice(0, 512),
    offset: record.offset,
    time: record.document.time ?? null,
  };
}

function gatewayLogEvidence(snapshot) {
  const selected = snapshot.records
    .filter((record) =>
      /gateway ready|config change|config hot reload|SIGUSR1|restart mode|shutdown completed/i.test(
        String(record.document.message ?? ""),
      ))
    .slice(-32)
    .map(logMarker);
  return {
    bytes: snapshot.raw.length,
    digest: sha256(snapshot.raw),
    marker_records: selected,
    path: basename(snapshot.path),
    ready_count: snapshot.records.filter(
      (record) => record.document.message === "gateway ready",
    ).length,
    record_count: snapshot.records.length,
    restart_mode_count: snapshot.records.filter((record) =>
      /^restart mode: /.test(String(record.document.message ?? "")),
    ).length,
  };
}

async function waitForLog(path, predicate, label, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let snapshot = null;
  while (Date.now() < deadline) {
    snapshot = gatewayLogSnapshot(path);
    if (predicate(snapshot)) {
      return snapshot;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
  }
  throw new Error(`${label} was not observed within ${timeoutMs}ms`);
}

function configSnapshot(expectedEnabled = null) {
  const stat = lstatSync(CONFIG);
  const raw = readFileSync(CONFIG);
  const document = JSON.parse(raw);
  const { meta, ...core } = document;
  const validMeta =
    meta === undefined ||
    (
      canonicalJson(Object.keys(meta).sort()) ===
        '["lastTouchedAt","lastTouchedVersion"]' &&
      meta.lastTouchedVersion === "2026.7.1" &&
      new Date(meta.lastTouchedAt).toISOString() === meta.lastTouchedAt
    );
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== 0o600 ||
    !validMeta ||
    (
      expectedEnabled !== null &&
      canonicalJson(core) !== canonicalJson(configuration(expectedEnabled))
    )
  ) {
    throw new Error(`configuration identity changed for enabled=${expectedEnabled}`);
  }
  return {
    core_digest: sha256(Buffer.from(canonicalJson(core), "utf8")),
    digest: sha256(raw),
    document,
    mode: (stat.mode & 0o777).toString(8).padStart(3, "0"),
    path: CONFIG,
    size: raw.length,
  };
}

function readPolicyLog() {
  const stat = lstatSync(POLICY_LOG);
  const raw = readFileSync(POLICY_LOG, "utf8");
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== 0o600
  ) {
    throw new Error("PLUG-01 policy log identity changed");
  }
  const lines = raw.split("\n");
  if (lines.pop() !== "") {
    throw new Error("PLUG-01 policy log lacks a trailing newline");
  }
  return lines.map((line) => {
    const record = JSON.parse(line);
    if (line !== canonicalJson(record)) {
      throw new Error("PLUG-01 policy record is not canonical");
    }
    return record;
  });
}

function policyLogProof(records = readPolicyLog()) {
  const raw = readFileSync(POLICY_LOG);
  return {
    count: records.length,
    digest: sha256(raw),
    path: POLICY_LOG,
    routes: records.map((record) => ({
      decision: record.decision,
      input_digest: record.input_digest,
      route: record.route,
      source_path: record.request?.sourcePath ?? null,
    })),
  };
}

function pluginInspect() {
  const call = command(["plugins", "inspect", PLUGIN_ID, "--json"]);
  const response = parseCommand(call, "plugins inspect");
  return { command: summarized(call), response };
}

function isCanonicalIsoTimestamp(value) {
  if (typeof value !== "string") {
    return false;
  }
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function exactInstallRecord(inspect, {
  enabled,
  sourcePath,
  version,
}) {
  const plugin = inspect.response?.plugin;
  const install = inspect.response?.install;
  const valid =
    plugin?.id === PLUGIN_ID &&
    plugin?.version === version &&
    plugin?.source === join(TARGET, "index.js") &&
    plugin?.status === (enabled ? "loaded" : "disabled") &&
    install?.source === "path" &&
    install?.sourcePath === sourcePath &&
    install?.installPath === TARGET &&
    install?.version === version &&
    isCanonicalIsoTimestamp(install?.installedAt);
  return {
    install: {
      install_path: install?.installPath,
      installed_at: install?.installedAt,
      source: install?.source,
      source_path: install?.sourcePath,
      version: install?.version,
    },
    plugin: {
      id: plugin?.id,
      source: plugin?.source,
      status: plugin?.status,
      version: plugin?.version,
    },
    valid,
  };
}

function skillStatus() {
  const call = gatewayCall("skills.status");
  const response = parseCommand(call, "skills.status");
  if (!Array.isArray(response.skills)) {
    throw new Error("skills.status omitted its skill array");
  }
  return {
    command: summarized(call),
    matches: response.skills
      .filter((item) => item.name === SKILL_NAME)
      .map((item) => ({
        blocked_by_agent_filter: item.blockedByAgentFilter,
        command_visible: item.commandVisible,
        disabled: item.disabled,
        eligible: item.eligible,
        file_path: item.filePath,
        model_visible: item.modelVisible,
        name: item.name,
        source: item.source,
        user_invocable: item.userInvocable,
      })),
  };
}

function publishedSkillProof(expectedPresent, fixtureName = "allowed") {
  if (!entryExists(PUBLISHED_SKILL)) {
    if (expectedPresent) {
      throw new Error("plugin skill link was not published");
    }
    return { exists: false, path: PUBLISHED_SKILL };
  }
  if (!expectedPresent) {
    throw new Error("disabled plugin published its skill link");
  }
  const stat = lstatSync(PUBLISHED_SKILL);
  const target = readlinkSync(PUBLISHED_SKILL);
  const raw = readFileSync(join(PUBLISHED_SKILL, "SKILL.md"));
  if (
    !stat.isSymbolicLink() ||
    target !== TARGET_SKILL ||
    realpathSync(PUBLISHED_SKILL) !== TARGET_SKILL
  ) {
    throw new Error("published plugin skill identity changed");
  }
  const expected = Buffer.from(
    FIXTURES[fixtureName][`skills/${SKILL_NAME}/SKILL.md`],
    "utf8",
  );
  if (!raw.equals(expected)) {
    throw new Error(`published plugin skill is not exact ${fixtureName}`);
  }
  return {
    digest: sha256(raw),
    exists: true,
    fixture: fixtureName,
    path: PUBLISHED_SKILL,
    realpath: realpathSync(PUBLISHED_SKILL),
    symlink_target: target,
  };
}

function writeGuard(filePath, directoryPath) {
  const attempts = [];
  for (const path of [filePath, join(directoryPath, ".write-probe")]) {
    try {
      const descriptor = openSync(
        path,
        path === filePath ? "r+" : "wx",
        0o600,
      );
      closeSync(descriptor);
      if (path.endsWith(".write-probe")) {
        unlinkSync(path);
      }
      attempts.push({ blocked: false, code: null, path });
    } catch (error) {
      attempts.push({
        blocked: error?.code === "EROFS" || error?.code === "EACCES",
        code: typeof error?.code === "string" ? error.code : null,
        path,
      });
    }
  }
  return {
    attempts,
    blocked: attempts.every((attempt) => attempt.blocked),
  };
}

function extensionWriteGuard() {
  return writeGuard(join(TARGET, "package.json"), dirname(TARGET));
}

function sourceWriteGuard() {
  return writeGuard(join(BASELINE_SOURCE, "package.json"), BASELINE_SOURCE);
}

function installResidueProof() {
  const root = dirname(TARGET);
  const entries = readdirSync(root).sort();
  const residue = [];
  for (const name of entries) {
    if (name === basename(TARGET)) {
      continue;
    }
    const path = join(root, name);
    const stat = lstatSync(path);
    if (
      name === ".openclaw-install-backups" &&
      stat.isDirectory() &&
      !stat.isSymbolicLink() &&
      readdirSync(path).length === 0
    ) {
      continue;
    }
    residue.push(name);
  }
  return { clean: residue.length === 0, entries, residue, root };
}

function readSetupBinding() {
  const stat = lstatSync(SETUP_EVIDENCE);
  const raw = readFileSync(SETUP_EVIDENCE);
  const evidence = JSON.parse(raw);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (stat.mode & 0o777) !== 0o600 ||
    !raw.equals(Buffer.from(`${canonicalJson(evidence)}\n`, "utf8")) ||
    evidence.schema !== "aragorn/openclaw-contained-plug01-setup-evidence/v1" ||
    evidence.setup?.status !== "PASS" ||
    evidence.decision?.status !== "NOT_TESTED" ||
    evidence.decision?.installer_work_eligible !== false ||
    evidence.adapter?.implementation_digest !== sha256(readFileSync(SELF))
  ) {
    throw new Error("PLUG-01 setup evidence identity changed");
  }
  return {
    digest: sha256(raw),
    evidence,
    path: SETUP_EVIDENCE,
  };
}

function setupBindingProjection(binding) {
  return {
    digest: binding.digest,
    path: binding.path,
    recorded_at: binding.evidence.recorded_at,
    schema: binding.evidence.schema,
    target_digest: binding.evidence.setup.target.digest,
  };
}

async function waitForSkill(gateway) {
  let lastError = null;
  let lastStatus = null;
  for (let attempt = 1; attempt <= 80; attempt += 1) {
    if (!gatewayRunning(gateway)) {
      throw new Error("Gateway exited during plugin activation");
    }
    try {
      lastStatus = skillStatus();
      lastError = null;
      if (activeSkillStatus(lastStatus)) {
        return { poll_count: attempt, status: lastStatus };
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
  }
  throw new Error(
    `plugin skill did not activate: ${lastError ?? canonicalJson(lastStatus)}`,
  );
}

function entryExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function assertContainedCredential() {
  if (process.env.OPENCLAW_GATEWAY_TOKEN !== TEST_TOKEN) {
    throw new Error("unexpected contained Gateway test credential");
  }
}

function runtimeVersion() {
  const version = command(["--version"]);
  if (version.exit_code !== 0 || version.stdout.trim() !== EXPECTED_VERSION) {
    throw new Error(`unexpected OpenClaw version: ${version.stdout.trim()}`);
  }
  return {
    commit: EXPECTED_COMMIT,
    name: "OpenClaw",
    version: "2026.7.1",
    version_command: summarized(version),
  };
}

function adapterEvidence() {
  return {
    configuration: configuration(false),
    configuration_digest: sha256(
      Buffer.from(canonicalJson(configuration(false)), "utf8"),
    ),
    implementation_digest: sha256(readFileSync(SELF)),
    name: "openclaw-contained-plug01",
  };
}

function unevaluatedDecision() {
  return {
    installer_work_eligible: false,
    status: "NOT_TESTED",
  };
}

function isRecordedInstallStage(path) {
  return (
    typeof path === "string" &&
    dirname(resolve(path)) === resolve(dirname(TARGET)) &&
    /^\.openclaw-install-stage-[a-zA-Z0-9_-]+$/.test(basename(path))
  );
}

function exactPolicySequence(records, routes, decisions) {
  return (
    canonicalJson(records.map((record) => record.route)) ===
      canonicalJson(routes) &&
    canonicalJson(records.map((record) => record.decision)) ===
      canonicalJson(decisions)
  );
}

function exactSetupPolicy(records) {
  if (
    records.length !== 2 ||
    !exactPolicySequence(
      records,
      ["baseline-source", "baseline-installed-dependency-tree"],
      ["allow", "allow"],
    )
  ) {
    return false;
  }
  const stagePath = records[1].request?.sourcePath;
  return (
    canonicalJson(records[0].request) ===
      canonicalJson(sourcePolicyRequest(BASELINE_SOURCE, "1.0.0", "install")) &&
    records[0].source?.digest === fileMapDigest(FIXTURES.baseline) &&
    records[0].source?.path === BASELINE_SOURCE &&
    isRecordedInstallStage(stagePath) &&
    canonicalJson(records[1].request) ===
      canonicalJson(
        installedPolicyRequest({
          mode: "install",
          requestedSpecifier: BASELINE_SOURCE,
          sourcePath: stagePath,
        }),
      ) &&
    records[1].source?.digest === fileMapDigest(FIXTURES.baseline) &&
    records[1].source?.path === stagePath
  );
}

function exactReplacementPolicy(records) {
  if (
    records.length !== 5 ||
    !exactPolicySequence(
      records,
      [
        "baseline-source",
        "baseline-installed-dependency-tree",
        "blocked-source",
        "allowed-source",
        "allowed-installed-dependency-tree",
      ],
      ["allow", "allow", "block", "allow", "allow"],
    ) ||
    !exactSetupPolicy(records.slice(0, 2))
  ) {
    return false;
  }
  const stagePath = records[4].request?.sourcePath;
  return (
    canonicalJson(records[2].request) ===
      canonicalJson(sourcePolicyRequest(BLOCKED_SOURCE, "2.0.0", "update")) &&
    records[2].source?.digest === fileMapDigest(FIXTURES.blocked) &&
    records[2].source?.path === BLOCKED_SOURCE &&
    canonicalJson(records[3].request) ===
      canonicalJson(sourcePolicyRequest(ALLOWED_SOURCE, "2.0.0", "update")) &&
    records[3].source?.digest === fileMapDigest(FIXTURES.allowed) &&
    records[3].source?.path === ALLOWED_SOURCE &&
    isRecordedInstallStage(stagePath) &&
    canonicalJson(records[4].request) ===
      canonicalJson(
        installedPolicyRequest({
          mode: "update",
          requestedSpecifier: ALLOWED_SOURCE,
          sourcePath: stagePath,
        }),
      ) &&
    records[4].source?.digest === fileMapDigest(FIXTURES.allowed) &&
    records[4].source?.path === stagePath
  );
}

function activeSkillStatus(status) {
  return (
    status.matches.length === 1 &&
    status.matches[0].blocked_by_agent_filter === false &&
    status.matches[0].command_visible === true &&
    status.matches[0].disabled === false &&
    status.matches[0].eligible === true &&
    status.matches[0].file_path === join(PUBLISHED_SKILL, "SKILL.md") &&
    status.matches[0].model_visible === true &&
    status.matches[0].name === SKILL_NAME &&
    status.matches[0].source === "openclaw-extra" &&
    status.matches[0].user_invocable === true
  );
}

function inactiveSkillStatus(status) {
  return status.matches.every(
    (item) =>
      item.disabled === true ||
      (item.eligible !== true && item.model_visible !== true),
  );
}

function systemInfo() {
  const call = gatewayCall("system.info");
  return {
    command: summarized(call),
    response: parseCommand(call, "system.info"),
  };
}

function logBoundary(snapshot) {
  return snapshot.raw.length - 1;
}

function noRestartEvidence(snapshot, boundary, readyCount) {
  const records = snapshot.records.filter((record) => record.offset > boundary);
  const restartRecords = records.filter((record) =>
    /^(signal SIGUSR1 received|shutdown completed cleanly |restart mode: )/.test(
      String(record.document.message ?? ""),
    ),
  );
  const readyAfter = records.filter(
    (record) => record.document.message === "gateway ready",
  );
  return {
    passed: restartRecords.length === 0 &&
      readyAfter.length === 0 &&
      gatewayLogEvidence(snapshot).ready_count === readyCount,
    ready_after: readyAfter.map(logMarker),
    restart_records: restartRecords.map(logMarker),
  };
}

function restartLifecycle(snapshot, boundary) {
  const signal = matchingLogRecord(
    snapshot,
    /^signal SIGUSR1 received$/,
    boundary,
  );
  const restarting = matchingLogRecord(
    snapshot,
    /^received SIGUSR1; restarting$/,
    signal?.offset,
  );
  const shutdown = matchingLogRecord(
    snapshot,
    /^shutdown completed cleanly /,
    restarting?.offset,
  );
  const restartMode = matchingLogRecord(
    snapshot,
    /^restart mode: in-process restart \(OPENCLAW_NO_RESPAWN\)$/,
    shutdown?.offset,
  );
  const ready = matchingLogRecord(
    snapshot,
    /^gateway ready$/,
    restartMode?.offset,
  );
  return {
    complete: Boolean(signal && restarting && shutdown && restartMode && ready),
    ready: logMarker(ready),
    restart_mode: logMarker(restartMode),
    restarting: logMarker(restarting),
    shutdown: logMarker(shutdown),
    signal: logMarker(signal),
  };
}

async function withGateway(run) {
  const gateway = startGateway();
  let value = null;
  let failure = null;
  try {
    value = await run(gateway);
  } catch (error) {
    failure = error;
  }
  const shutdown = await stopGateway(gateway);
  if (
    shutdown.stderr.bytes > GATEWAY_LOG_LIMIT * 4 ||
    shutdown.stdout.bytes > GATEWAY_LOG_LIMIT * 4
  ) {
    throw new Error("Gateway emitted excessive bounded probe logs");
  }
  let finalLog = null;
  try {
    finalLog = gatewayLogEvidence(gatewayLogSnapshot(findGatewayLog()));
  } catch (error) {
    if (failure === null) {
      throw error;
    }
  }
  if (failure !== null) {
    throw failure;
  }
  return { final_log: finalLog, shutdown, value };
}

function freshSetupProfile() {
  assertContainedCredential();
  for (const path of [
    CONFIG,
    POLICY_LOG,
    SETUP_EVIDENCE,
    TARGET,
    PUBLISHED_SKILL,
  ]) {
    if (entryExists(path)) {
      throw new Error(`contained profile was not fresh: ${path}`);
    }
  }
  for (const path of [HOME, STATE, WORKSPACE, dirname(TARGET)]) {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  const sourceGuard = sourceWriteGuard();
  if (!sourceGuard.blocked) {
    throw new Error("fixture source mount was writable");
  }
  const fixtures = {
    allowed: exactFixtureTree(ALLOWED_SOURCE, FIXTURES.allowed),
    baseline: exactFixtureTree(BASELINE_SOURCE, FIXTURES.baseline),
    blocked: exactFixtureTree(BLOCKED_SOURCE, FIXTURES.blocked),
  };
  writeFileSync(CONFIG, `${canonicalJson(configuration())}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  return {
    fixtures,
    initial_config: configSnapshot(false),
    source_write_guard: sourceGuard,
  };
}

function runSetup() {
  const prepared = freshSetupProfile();
  const runtime = runtimeVersion();
  const install = command(["plugins", "install", BASELINE_SOURCE]);
  if (install.exit_code !== 0) {
    throw new Error(`baseline plugin install failed: ${install.stderr.trim()}`);
  }
  const configAfterInstall = configSnapshot(true);
  const targetAfterInstall = exactFixtureTree(TARGET, FIXTURES.baseline);
  const inspectAfterInstall = pluginInspect();
  const installAfterInstall = exactInstallRecord(inspectAfterInstall, {
    enabled: true,
    sourcePath: BASELINE_SOURCE,
    version: "1.0.0",
  });
  const policyRecordsAfterInstall = readPolicyLog();
  if (!installAfterInstall.valid || !exactSetupPolicy(policyRecordsAfterInstall)) {
    throw new Error("baseline install identity or policy sequence changed");
  }

  const disable = command(["plugins", "disable", PLUGIN_ID]);
  if (disable.exit_code !== 0) {
    throw new Error(`baseline plugin disable failed: ${disable.stderr.trim()}`);
  }
  const configAfterDisable = configSnapshot(false);
  const inspectAfterDisable = pluginInspect();
  const installAfterDisable = exactInstallRecord(inspectAfterDisable, {
    enabled: false,
    sourcePath: BASELINE_SOURCE,
    version: "1.0.0",
  });
  const target = exactFixtureTree(TARGET, FIXTURES.baseline);
  const link = publishedSkillProof(false);
  const residue = installResidueProof();
  const finalPolicyRecords = readPolicyLog();
  if (
    !installAfterDisable.valid ||
    !exactSetupPolicy(finalPolicyRecords) ||
    !residue.clean ||
    target.digest !== targetAfterInstall.digest
  ) {
    throw new Error("baseline setup did not finish in its exact disabled state");
  }

  const evidence = {
    adapter: adapterEvidence(),
    assurance: "SELF_REPORTED_CONTAINED_RUNTIME_NOT_INDEPENDENTLY_ATTESTED",
    decision: unevaluatedDecision(),
    recorded_at: new Date().toISOString(),
    runtime,
    schema: "aragorn/openclaw-contained-plug01-setup-evidence/v1",
    setup: {
      config_after_disable: configAfterDisable,
      config_after_install: configAfterInstall,
      config_initial: prepared.initial_config,
      disable_command: summarized(disable),
      fixtures: prepared.fixtures,
      install_after_disable: installAfterDisable,
      install_after_install: installAfterInstall,
      install_command: summarized(install),
      link,
      policy: policyLogProof(finalPolicyRecords),
      residue,
      source_write_guard: prepared.source_write_guard,
      status: "PASS",
      target,
    },
  };
  writeFileSync(SETUP_EVIDENCE, `${canonicalJson(evidence)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  const binding = readSetupBinding();
  if (canonicalJson(binding.evidence) !== canonicalJson(evidence)) {
    throw new Error("persisted setup evidence changed");
  }
  return evidence;
}

function verifyConsumedSetup() {
  assertContainedCredential();
  const binding = readSetupBinding();
  const sourceGuard = sourceWriteGuard();
  const fixtures = {
    allowed: exactFixtureTree(ALLOWED_SOURCE, FIXTURES.allowed),
    baseline: exactFixtureTree(BASELINE_SOURCE, FIXTURES.baseline),
    blocked: exactFixtureTree(BLOCKED_SOURCE, FIXTURES.blocked),
  };
  const config = configSnapshot(false);
  const target = exactFixtureTree(TARGET, FIXTURES.baseline);
  const policyRecords = readPolicyLog();
  const policyProof = policyLogProof(policyRecords);
  const inspect = pluginInspect();
  const install = exactInstallRecord(inspect, {
    enabled: false,
    sourcePath: BASELINE_SOURCE,
    version: "1.0.0",
  });
  const link = publishedSkillProof(false);
  const residue = installResidueProof();
  const setup = binding.evidence.setup;
  if (
    !exactSetupPolicy(policyRecords) ||
    !install.valid ||
    !residue.clean ||
    !sourceGuard.blocked ||
    canonicalJson(fixtures) !== canonicalJson(setup.fixtures) ||
    canonicalJson(sourceGuard) !== canonicalJson(setup.source_write_guard) ||
    config.digest !== setup.config_after_disable.digest ||
    target.digest !== setup.target.digest ||
    policyProof.digest !== setup.policy.digest ||
    canonicalJson(install) !== canonicalJson(setup.install_after_disable)
  ) {
    throw new Error("consumed PLUG-01 setup state diverged from its binding");
  }
  return {
    binding: setupBindingProjection(binding),
    config,
    fixtures,
    inspect: install,
    link,
    policy: policyProof,
    policy_records: policyRecords,
    residue,
    source_write_guard: sourceGuard,
    target,
  };
}

async function runActivation() {
  const consumed = verifyConsumedSetup();
  const runtime = runtimeVersion();
  const writeGuard = extensionWriteGuard();
  if (!writeGuard.blocked) {
    throw new Error("activation extensions mount was writable");
  }

  const gatewayResult = await withGateway(async (gateway) => {
    const ready = await waitForGateway(gateway);
    const logPath = findGatewayLog();
    const statusBefore = skillStatus();
    const linkBefore = publishedSkillProof(false);
    if (!inactiveSkillStatus(statusBefore)) {
      throw new Error("disabled baseline skill was active before enable");
    }
    const targetBefore = exactFixtureTree(TARGET, FIXTURES.baseline);
    const configBefore = configSnapshot(false);
    const policyBefore = policyLogProof();
    const logBefore = gatewayLogSnapshot(logPath);
    const boundary = logBoundary(logBefore);
    const processBefore = {
      alive: gatewayRunning(gateway),
      pid: gateway.child.pid,
      system_info_pid: ready.info.pid,
    };

    const enable = command(["plugins", "enable", PLUGIN_ID]);
    if (enable.exit_code !== 0) {
      throw new Error(`plugin enable failed: ${enable.stderr.trim()}`);
    }
    const activation = await waitForSkill(gateway);
    const linkAfter = publishedSkillProof(true, "baseline");
    const targetAfter = exactFixtureTree(TARGET, FIXTURES.baseline);
    const configAfter = configSnapshot(true);
    const inspectAfter = pluginInspect();
    const installAfter = exactInstallRecord(inspectAfter, {
      enabled: true,
      sourcePath: BASELINE_SOURCE,
      version: "1.0.0",
    });
    const policyAfter = policyLogProof();
    const hotSnapshot = await waitForLog(
      logPath,
      (snapshot) =>
        Boolean(
          matchingLogRecord(
            snapshot,
            /^config hot reload applied \(.*plugins\.entries\.aragorn-plug01\.enabled/,
            boundary,
          ),
        ),
      "plugin enable hot-reload boundary",
    );
    const detected = matchingLogRecord(
      hotSnapshot,
      /^config change detected; evaluating reload \(.*plugins\.entries\.aragorn-plug01\.enabled/,
      boundary,
    );
    const applied = matchingLogRecord(
      hotSnapshot,
      /^config hot reload applied \(.*plugins\.entries\.aragorn-plug01\.enabled/,
      detected?.offset,
    );
    const noRestart = noRestartEvidence(
      hotSnapshot,
      boundary,
      gatewayLogEvidence(logBefore).ready_count,
    );
    const infoAfter = systemInfo();
    const processAfter = {
      alive: gatewayRunning(gateway),
      pid: gateway.child.pid,
      system_info_pid: infoAfter.response.pid,
    };
    if (
      !installAfter.valid ||
      !activeSkillStatus(activation.status) ||
      !detected ||
      !applied ||
      !noRestart.passed ||
      targetAfter.digest !== targetBefore.digest ||
      policyAfter.digest !== policyBefore.digest ||
      policyAfter.count !== policyBefore.count ||
      !processBefore.alive ||
      !processAfter.alive ||
      processBefore.pid !== processAfter.pid ||
      processBefore.system_info_pid !== processAfter.system_info_pid
    ) {
      throw new Error("plugin enable did not activate at the exact hot boundary");
    }
    return {
      gateway_log: gatewayLogEvidence(hotSnapshot),
      scenarios: [
        {
          evidence: {
            config_after: configAfter,
            config_before: configBefore,
            enable_command: summarized(enable),
            install_after: installAfter,
            policy_after: policyAfter,
            policy_before: policyBefore,
            process_after: processAfter,
            process_before: processBefore,
          },
          id: "ADM-02/update/plugin-enable-activation",
          status: "PASS",
        },
        {
          evidence: {
            activation,
            config_detected: logMarker(detected),
            hot_reload_applied: logMarker(applied),
            link_after: linkAfter,
            link_before: linkBefore,
            no_restart: noRestart,
            status_before: statusBefore,
            target_after: targetAfter,
            target_before: targetBefore,
          },
          id: "ADM-02/reload/plugin-skill-dir-activation",
          status: "PASS",
        },
      ],
    };
  });

  return {
    adapter: adapterEvidence(),
    assurance: "SELF_REPORTED_CONTAINED_RUNTIME_NOT_INDEPENDENTLY_ATTESTED",
    consumed_setup: consumed,
    decision: unevaluatedDecision(),
    gateway: {
      final_log: gatewayResult.final_log,
      shutdown: gatewayResult.shutdown,
    },
    gateway_log: gatewayResult.value.gateway_log,
    recorded_at: new Date().toISOString(),
    runtime,
    scenarios: gatewayResult.value.scenarios,
    schema: "aragorn/openclaw-contained-plug01-activation-evidence/v1",
    write_guard: writeGuard,
  };
}

async function runReplacement() {
  const consumed = verifyConsumedSetup();
  const runtime = runtimeVersion();
  const gatewayResult = await withGateway(async (gateway) => {
    const ready = await waitForGateway(gateway);
    const logPath = findGatewayLog();
    const statusBefore = skillStatus();
    const linkBefore = publishedSkillProof(false);
    if (!inactiveSkillStatus(statusBefore)) {
      throw new Error("disabled baseline skill was active before replacement");
    }
    const configBefore = configSnapshot(false);
    const targetBefore = exactFixtureTree(TARGET, FIXTURES.baseline);
    const inspectBefore = exactInstallRecord(pluginInspect(), {
      enabled: false,
      sourcePath: BASELINE_SOURCE,
      version: "1.0.0",
    });
    const policyBefore = policyLogProof();
    const logBeforeBlocked = gatewayLogSnapshot(logPath);
    const blockedBoundary = logBoundary(logBeforeBlocked);
    if (!inspectBefore.valid || policyBefore.count !== 2) {
      throw new Error("replacement did not begin from exact setup state");
    }

    const blocked = command([
      "plugins",
      "install",
      BLOCKED_SOURCE,
      "--force",
    ]);
    const configAfterBlocked = configSnapshot(false);
    const targetAfterBlocked = exactFixtureTree(TARGET, FIXTURES.baseline);
    const inspectAfterBlocked = exactInstallRecord(pluginInspect(), {
      enabled: false,
      sourcePath: BASELINE_SOURCE,
      version: "1.0.0",
    });
    const recordsAfterBlocked = readPolicyLog();
    const policyAfterBlocked = policyLogProof(recordsAfterBlocked);
    const residueAfterBlocked = installResidueProof();
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 600));
    const logAfterBlocked = gatewayLogSnapshot(logPath);
    const blockedNoRestart = noRestartEvidence(
      logAfterBlocked,
      blockedBoundary,
      gatewayLogEvidence(logBeforeBlocked).ready_count,
    );
    const infoAfterBlocked = systemInfo();
    const blockedPassed =
      blocked.exit_code !== 0 &&
      `${blocked.stdout}\n${blocked.stderr}`.includes(BLOCK_REASON) &&
      exactPolicySequence(
        recordsAfterBlocked,
        [
          "baseline-source",
          "baseline-installed-dependency-tree",
          "blocked-source",
        ],
        ["allow", "allow", "block"],
      ) &&
      canonicalJson(recordsAfterBlocked[2].request) ===
        canonicalJson(sourcePolicyRequest(BLOCKED_SOURCE, "2.0.0", "update")) &&
      recordsAfterBlocked[2].source?.digest ===
        fileMapDigest(FIXTURES.blocked) &&
      recordsAfterBlocked[2].source?.path === BLOCKED_SOURCE &&
      configAfterBlocked.digest === configBefore.digest &&
      targetAfterBlocked.digest === targetBefore.digest &&
      canonicalJson(targetAfterBlocked) === canonicalJson(targetBefore) &&
      canonicalJson(inspectAfterBlocked) === canonicalJson(inspectBefore) &&
      policyAfterBlocked.count === policyBefore.count + 1 &&
      residueAfterBlocked.clean &&
      blockedNoRestart.passed &&
      gatewayRunning(gateway) &&
      infoAfterBlocked.response.pid === ready.info.pid;
    if (!blockedPassed) {
      throw new Error("blocked force replacement had effects or wrong gate count");
    }

    const allowedBoundarySnapshot = gatewayLogSnapshot(logPath);
    const allowedBoundary = logBoundary(allowedBoundarySnapshot);
    const allowed = command([
      "plugins",
      "install",
      ALLOWED_SOURCE,
      "--force",
    ]);
    if (allowed.exit_code !== 0) {
      throw new Error(`allowed force replacement failed: ${allowed.stderr.trim()}`);
    }
    const configAfterAllowed = configSnapshot(true);
    const targetAfterAllowed = exactFixtureTree(TARGET, FIXTURES.allowed);
    const inspectAfterAllowed = exactInstallRecord(pluginInspect(), {
      enabled: true,
      sourcePath: ALLOWED_SOURCE,
      version: "2.0.0",
    });
    const recordsAfterAllowed = readPolicyLog();
    const policyAfterAllowed = policyLogProof(recordsAfterAllowed);
    const residueAfterAllowed = installResidueProof();
    const recordedStage = recordsAfterAllowed[4]?.request?.sourcePath;
    if (
      !inspectAfterAllowed.valid ||
      !exactReplacementPolicy(recordsAfterAllowed) ||
      entryExists(recordedStage) ||
      !residueAfterAllowed.clean
    ) {
      throw new Error("allowed force replacement identity or residue changed");
    }

    await new Promise((resolvePromise) => setTimeout(resolvePromise, 600));
    const logAfterAllowed = gatewayLogSnapshot(logPath);
    const allowedNoRestart = noRestartEvidence(
      logAfterAllowed,
      allowedBoundary,
      gatewayLogEvidence(allowedBoundarySnapshot).ready_count,
    );
    if (!allowedNoRestart.passed) {
      throw new Error("allowed force replacement restarted before authorization");
    }
    const restartBoundary = logBoundary(logAfterAllowed);
    const restartCommand = command(["gateway", "restart", "--safe", "--json"]);
    const restart = parseCommand(restartCommand, "safe plugin replacement restart");
    const emptyCounts = {
      activeTasks: 0,
      cronRuns: 0,
      embeddedRuns: 0,
      pendingReplies: 0,
      queueSize: 0,
      totalActive: 0,
    };
    if (
      restart.ok !== true ||
      restart.result !== "scheduled" ||
      restart.preflight?.safe !== true ||
      canonicalJson(restart.preflight?.counts) !== canonicalJson(emptyCounts) ||
      restart.preflight?.blockers?.length !== 0 ||
      restart.restart?.ok !== true ||
      restart.restart?.pid !== gateway.child.pid ||
      restart.restart?.signal !== "SIGUSR1" ||
      restart.restart?.reason !== "gateway.restart.safe" ||
      restart.restart?.mode !== "emit" ||
      restart.restart?.coalesced !== false
    ) {
      throw new Error("Gateway did not authorize the exact replacement restart");
    }

    const restarted = await waitForLog(
      logPath,
      (snapshot) => restartLifecycle(snapshot, restartBoundary).complete,
      "plugin replacement in-process restart lifecycle",
    );
    const lifecycle = restartLifecycle(restarted, restartBoundary);
    const readyAfter = await waitForGateway(gateway);
    const activation = await waitForSkill(gateway);
    const linkAfter = publishedSkillProof(true, "allowed");
    const finalTarget = exactFixtureTree(TARGET, FIXTURES.allowed);
    const finalConfig = configSnapshot(true);
    const finalInspect = exactInstallRecord(pluginInspect(), {
      enabled: true,
      sourcePath: ALLOWED_SOURCE,
      version: "2.0.0",
    });
    const finalPolicy = policyLogProof();
    const finalResidue = installResidueProof();
    if (
      !lifecycle.complete ||
      !activeSkillStatus(activation.status) ||
      !finalInspect.valid ||
      finalTarget.digest !== targetAfterAllowed.digest ||
      finalPolicy.digest !== policyAfterAllowed.digest ||
      !finalResidue.clean ||
      !gatewayRunning(gateway) ||
      ready.info.pid !== gateway.child.pid ||
      readyAfter.info.pid !== gateway.child.pid
    ) {
      throw new Error("replacement restart did not publish exact v2 skill state");
    }

    return {
      gateway_log: gatewayLogEvidence(restarted),
      scenarios: [
        {
          evidence: {
            blocked: {
              command: summarized(blocked),
              config_after: configAfterBlocked,
              config_before: configBefore,
              install_after: inspectAfterBlocked,
              install_before: inspectBefore,
              no_restart: blockedNoRestart,
              policy_after: policyAfterBlocked,
              policy_before: policyBefore,
              residue_after: residueAfterBlocked,
              target_after: targetAfterBlocked,
              target_before: targetBefore,
            },
            allowed: {
              command: summarized(allowed),
              config_after: configAfterAllowed,
              install_after: inspectAfterAllowed,
              no_restart_before_authorization: allowedNoRestart,
              policy_after: policyAfterAllowed,
              recorded_stage_absent: !entryExists(recordedStage),
              recorded_stage_path: recordedStage,
              residue_after: residueAfterAllowed,
              target_after: targetAfterAllowed,
            },
            post_restart: {
              activation,
              final_config: finalConfig,
              final_install: finalInspect,
              final_policy: finalPolicy,
              final_residue: finalResidue,
              final_target: finalTarget,
              lifecycle,
              link_after: linkAfter,
              link_before: linkBefore,
              restart_command: summarized(restartCommand),
              restart_response: restart,
              status_before: statusBefore,
            },
          },
          id: "ADM-02/update/plugin-force-reinstall",
          status: "PASS",
        },
      ],
    };
  });

  return {
    adapter: adapterEvidence(),
    assurance: "SELF_REPORTED_CONTAINED_RUNTIME_NOT_INDEPENDENTLY_ATTESTED",
    consumed_setup: consumed,
    decision: unevaluatedDecision(),
    gateway: {
      final_log: gatewayResult.final_log,
      shutdown: gatewayResult.shutdown,
    },
    gateway_log: gatewayResult.value.gateway_log,
    recorded_at: new Date().toISOString(),
    runtime,
    scenarios: gatewayResult.value.scenarios,
    schema: "aragorn/openclaw-contained-plug01-replacement-evidence/v1",
  };
}

function selfCheck() {
  const config = configuration();
  const sourceRequest = sourcePolicyRequest(
    ALLOWED_SOURCE,
    "2.0.0",
    "update",
  );
  const stagePath =
    "/profile/state/extensions/.openclaw-install-stage-selfcheck";
  const installedRequest = installedPolicyRequest({
    mode: "update",
    requestedSpecifier: ALLOWED_SOURCE,
    sourcePath: stagePath,
  });
  const checks = {
    agent_skill_is_explicit:
      canonicalJson(config.agents.defaults.skills) ===
        canonicalJson([SKILL_NAME]) &&
      canonicalJson(config.agents.list[0].skills) ===
        canonicalJson([SKILL_NAME]),
    canonical_round_trip:
      canonicalJson(JSON.parse(canonicalJson(config))) === canonicalJson(config),
    exact_fixture_paths:
      canonicalJson(Object.keys(FIXTURES.allowed).sort()) ===
      canonicalJson([
        "index.js",
        "openclaw.plugin.json",
        "package.json",
        `skills/${SKILL_NAME}/SKILL.md`,
      ].sort()),
    install_policy_targets:
      canonicalJson(config.security.installPolicy.targets) ===
        '["skill","plugin"]',
    installed_route_exact:
      installedRequest.origin.type === "plugin-dependency-tree" &&
      installedRequest.sourcePath === stagePath &&
      installedRequest.request.mode === "update",
    no_declared_dependencies:
      !Object.hasOwn(JSON.parse(FIXTURES.allowed["package.json"]), "dependencies") &&
      !Object.hasOwn(
        JSON.parse(FIXTURES.allowed["package.json"]),
        "optionalDependencies",
      ),
    plugin_allow_is_explicit:
      canonicalJson(config.plugins.allow) === canonicalJson([PLUGIN_ID]),
    plugin_initially_disabled:
      config.plugins.entries[PLUGIN_ID].enabled === false,
    source_route_exact:
      sourceRequest.request.kind === "plugin-dir" &&
      sourceRequest.request.mode === "update" &&
      sourceRequest.source.network === false,
    watch_is_enabled:
      config.skills.load.watch === true &&
      config.skills.load.watchDebounceMs === 250,
  };
  return {
    checks,
    fixture_digests: Object.fromEntries(
      Object.entries(FIXTURES).map(([name, files]) => [
        name,
        fileMapDigest(files),
      ]),
    ),
    implementation_digest: sha256(readFileSync(SELF)),
    modes: ["activate", "policy", "prepare", "replace", "self-check", "setup"],
    schema: "aragorn/openclaw-contained-plug01-self-check/v1",
    status: Object.values(checks).every(Boolean) ? "PASS" : "FAIL",
  };
}

async function main() {
  const mode = process.argv[2];
  if (mode === "prepare") {
    process.stdout.write(`${canonicalJson(prepare())}\n`);
    return;
  }
  if (mode === "policy") {
    await policy();
    return;
  }
  if (mode === "self-check") {
    const result = selfCheck();
    process.stdout.write(`${canonicalJson(result)}\n`);
    if (result.status !== "PASS") {
      process.exitCode = 1;
    }
    return;
  }
  if (mode === "setup") {
    process.stdout.write(`${canonicalJson(runSetup())}\n`);
    return;
  }
  if (mode === "activate") {
    process.stdout.write(`${canonicalJson(await runActivation())}\n`);
    return;
  }
  if (mode === "replace") {
    process.stdout.write(`${canonicalJson(await runReplacement())}\n`);
    return;
  }
  throw new Error(
    `unknown PLUG-01 probe mode: ${mode ?? "(missing)"}; expected setup, activate, replace, prepare, policy, or self-check`,
  );
}

main().catch((error) => {
  process.stdout.write(
    `${canonicalJson({
      error: error instanceof Error ? error.message : String(error),
      schema: "aragorn/openclaw-contained-plug01-error/v1",
      status: "ERROR",
    })}\n`,
  );
  process.exitCode = 1;
});
