"use strict";

// Private fixed-profile bridge. Both compiled callers require this exact CJS
// path, sharing Node's module cache and one client for the process lifetime.
// This is not a hostile same-process JavaScript boundary or an activation proof.
const { spawnSync } = require("node:child_process");
const { TextDecoder } = require("node:util");
const CREDENTIAL_DIRECTORY = "/run/credentials/aragorn-agent-gateway.service";
const CLIENT_PATH = "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/index.js";
const HELPER_PATH = "/usr/libexec/aragorn/aragorn-runtime-native-gateway-credentials.py";
const SOCKET_PATH = "/run/aragorn-runtime-action-worker/worker.sock";
const DIGEST = /^sha256:[0-9a-f]{64}$/;
let client;
let bootstrapFailure;
let starting = false;

function requireBinding(condition) {
  if (!condition) throw new Error("ARAGORN_NATIVE_BOOTSTRAP_REFUSED");
}

function fields(value, names) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...names].sort().join("\n");
}

function parseBinding(raw) {
  requireBinding(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= 1024);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  const value = JSON.parse(text);
  requireBinding(fields(value, ["genesis_digest", "worker_config"]));
  requireBinding(typeof value.genesis_digest === "string" && DIGEST.test(value.genesis_digest));
  const config = value.worker_config;
  requireBinding(fields(config, [
    "expectedGatewayGid", "expectedGatewayUid", "expectedWorkerUid", "workerSocketPath",
  ]));
  for (const name of ["expectedGatewayGid", "expectedGatewayUid", "expectedWorkerUid"]) {
    requireBinding(Number.isSafeInteger(config[name]) && config[name] > 0 && config[name] <= 0xffffffff);
  }
  requireBinding(config.expectedGatewayUid !== config.expectedWorkerUid && config.workerSocketPath === SOCKET_PATH);
  requireBinding(process.getuid() === config.expectedGatewayUid && process.geteuid() === config.expectedGatewayUid);
  requireBinding(process.getgid() === config.expectedGatewayGid && process.getegid() === config.expectedGatewayGid);
  requireBinding(process.getgroups().every((gid) => gid === config.expectedGatewayGid));
  // These exact ASCII strings and uint32s have the protocol's canonical JSON
  // representation. Reconstruction also rejects duplicate keys and float forms.
  const bound = {
    genesis_digest: value.genesis_digest,
    worker_config: {
      expectedGatewayGid: config.expectedGatewayGid,
      expectedGatewayUid: config.expectedGatewayUid,
      expectedWorkerUid: config.expectedWorkerUid,
      workerSocketPath: SOCKET_PATH,
    },
  };
  requireBinding(JSON.stringify(bound) === text);
  Object.freeze(bound.worker_config);
  return Object.freeze(bound);
}

function getClient() {
  if (bootstrapFailure) throw bootstrapFailure;
  if (client) return client;
  try {
    requireBinding(!starting);
    starting = true;
    requireBinding(process.platform === "linux");
    requireBinding(process.env.CREDENTIALS_DIRECTORY === CREDENTIAL_DIRECTORY);
    requireBinding(process.env.OPENCLAW_CONFIG_PATH === `${CREDENTIAL_DIRECTORY}/openclaw-config`);
    const result = spawnSync(
      "/usr/bin/python3.12",
      ["-I", "-S", "-B", HELPER_PATH],
      {
        cwd: "/", shell: false, encoding: "buffer",
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 2000, killSignal: "SIGKILL", maxBuffer: 1024,
        env: {
          CREDENTIALS_DIRECTORY: CREDENTIAL_DIRECTORY, HOME: "/nonexistent", LANG: "C", LC_ALL: "C",
          PATH: "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1", TZ: "UTC",
        },
      },
    );
    requireBinding(result && result.error === undefined && result.status === 0 && result.signal === null);
    requireBinding(Buffer.isBuffer(result.stderr) && result.stderr.length === 0);
    const bound = parseBinding(result.stdout);
    const plugin = require(CLIENT_PATH);
    requireBinding(plugin && plugin.id === "aragorn-runtime-action-worker" &&
      typeof plugin.nativeClient?.createNativeToolClient === "function");
    const candidate = plugin.nativeClient.createNativeToolClient(bound.worker_config, bound.genesis_digest);
    requireBinding(candidate && typeof candidate.execute === "function");
    client = candidate;
    return client;
  } catch {
    // No retry, raw credential bytes, helper stderr or partial binding escapes.
    bootstrapFailure = new Error("ARAGORN_NATIVE_BOOTSTRAP_REFUSED");
    throw bootstrapFailure;
  } finally {
    starting = false;
  }
}

function execute(toolName, finalParams, context, invoke, signal) {
  if (toolName !== "read" && toolName !== "aragorn_runtime_create") {
    throw new Error("ARAGORN_NATIVE_TOOL_UNSUPPORTED");
  }
  // Bootstrap is synchronous; the unchanged client snapshots final params and
  // context before its first await. Its result/native throw is not translated.
  // Only invoke is inside the client's native RETURNED/RAISED boundary.
  return getClient().execute(toolName, finalParams, context, invoke, signal);
}

module.exports = Object.freeze({ execute });
