#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  chownSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/profile/config/openclaw.json";
const STATE = "/profile/state";
const WORKSPACE = "/profile/workspace";
const HOME = "/profile/home";
const ACTIVE_ROOT = join(WORKSPACE, "skills");
const VERSION_ROOT = join(ACTIVE_ROOT, ".aragorn-versions");
const ACTIVATION_RECORD_ROOT = join(VERSION_ROOT, ".evidence");
const NAME = "aragorn-admitted";
const ACTIVE_LINK = join(ACTIVE_ROOT, NAME);
const ACTIVE_FILE = join(ACTIVE_LINK, "SKILL.md");
const SESSION_KEY = "agent:main:aragorn-broker-switch-v1";
const SESSION_STORE = join(STATE, "agents", "main", "sessions", "sessions.json");
const BASELINE_FILE = join(STATE, "broker-switch-before.json");
const POLICY_LOG = join(STATE, "broker-native-policy.jsonl");
const PROVIDER_LOG = join(STATE, "broker-provider-requests.jsonl");
const OUTPUT_FILE = "/output/broker-symlink-evidence.json";
const TEST_TOKEN = "aragorn-contained-broker-switch-token-v1";
const MOCK_KEY = "aragorn-broker-mock-local";
const MODEL = "fixture-model";
const PROVIDER = "aragorn-mock";
const EXPECTED_VERSION = "OpenClaw 2026.7.1 (2d2ddc4)";
const ASSURANCE = "SELF_REPORTED_EVIDENCE_ONLY_NOT_CONFORMANCE_AUTHORITY";
const BROKER_UID = 2000;
const RUNTIME_UID = 1000;
const MAX_PROVIDER_BODY_BYTES = 4 * 1024 * 1024;
const MAX_PROVIDER_REQUESTS = 24;
const SELF = fileURLToPath(import.meta.url);
const PINNED_SOURCE_REVIEW = {
  commit: "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
  findings: {
    active_named_symlinks_are_bounded_and_loadable: true,
    active_symlink_targets_are_watched: true,
    dot_prefixed_version_storage_is_ignored_by_discovery: true,
    root_symlink_rename_invalidates_the_workspace_snapshot: true,
  },
  files: {
    "src/skills/loading/local-loader.ts":
      "sha256:821c2490c5e4d0b00c7e09daef71038314d0e1ee34e888067bb5a3c0980d590f",
    "src/skills/loading/symlink-targets.ts":
      "sha256:6fa5124aa200ff9c18ef027ed729b3f3dd9cf2b58d86d19999cb2aa57838e670",
    "src/skills/loading/workspace.ts":
      "sha256:61720022e6f2d3b688da8ab9ee0b93eb80f12b70acec15d161c1b2116a09148a",
    "src/skills/runtime/refresh.ts":
      "sha256:24afdf4b95d910b7cedca8415b3b93430b9417d4be2737e4eb76b2eaba8df531",
  },
  status: "SOURCE_REVIEWED_RUNTIME_LIVE_PROOF_PENDING",
};

const FIXTURE_TEXT = {
  v1: [
    "---",
    `name: ${NAME}`,
    "description: Inert Aragorn broker fixture aragorn-broker-v1.",
    "---",
    "# Aragorn broker fixture v1",
    "",
    "This fixture is inert and performs no actions.",
    "",
  ].join("\n"),
  v2: [
    "---",
    `name: ${NAME}`,
    "description: Inert Aragorn broker fixture aragorn-broker-v2.",
    "---",
    "# Aragorn broker fixture v2",
    "",
    "This fixture is inert and performs no actions.",
    "",
  ].join("\n"),
};
const MARKERS = {
  v1: "aragorn-broker-v1",
  v2: "aragorn-broker-v2",
};
const FINAL_TEXT = {
  v1: "ARAGORN_BROKER_V1_OK",
  v2: "ARAGORN_BROKER_V2_OK",
};
const EXPECTATION_TOKEN = {
  v1: "ARAGORN_BROKER_EXPECT_V1",
  v2: "ARAGORN_BROKER_EXPECT_V2",
};
const PROFILE_ENV = {
  HOME,
  OPENCLAW_CONFIG_PATH: CONFIG,
  OPENCLAW_GATEWAY_TOKEN: TEST_TOKEN,
  OPENCLAW_STATE_DIR: STATE,
  PATH: "/usr/local/bin:/usr/bin:/bin",
};

function sha256(raw) {
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

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

function fixtureIdentity(version) {
  const raw = Buffer.from(FIXTURE_TEXT[version], "utf8");
  const manifest = {
    entries: [
      {
        digest: sha256(raw),
        executable: false,
        mode: "444",
        path: "SKILL.md",
        size: raw.length,
        type: "file",
      },
    ],
    schema: "aragorn/broker-symlink-fixture-tree/v1",
  };
  return {
    bytes: raw.length,
    file_digest: sha256(raw),
    manifest,
    marker: MARKERS[version],
    tree_digest: sha256(Buffer.from(canonicalJson(manifest), "ascii")),
    version,
  };
}

const FIXTURES = {
  v1: fixtureIdentity("v1"),
  v2: fixtureIdentity("v2"),
};

function configuration() {
  return {
    agents: {
      defaults: {
        model: { primary: `${PROVIDER}/${MODEL}` },
        skills: [NAME],
        workspace: WORKSPACE,
      },
      list: [{ id: "main", skills: [NAME], workspace: WORKSPACE }],
    },
    models: {
      mode: "replace",
      providers: {
        [PROVIDER]: {
          api: "openai-completions",
          apiKey: MOCK_KEY,
          baseUrl: "http://127.0.0.1:18080/v1",
          localService: {
            args: ["/probe/broker-symlink-probe.mjs", "provider"],
            command: NODE,
            healthUrl: "http://127.0.0.1:18080/v1/models",
            idleStopMs: 0,
            readyTimeoutMs: 5000,
          },
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
              cost: {
                cacheRead: 0,
                cacheWrite: 0,
                input: 0,
                output: 0,
              },
              id: MODEL,
              input: ["text"],
              maxTokens: 256,
              name: "Aragorn deterministic broker mock",
              reasoning: false,
            },
          ],
          timeoutSeconds: 10,
        },
      },
    },
    plugins: { enabled: false },
    security: {
      installPolicy: {
        enabled: true,
        exec: {
          args: ["/probe/broker-symlink-probe.mjs", "native-policy"],
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
        allowSymlinkTargets: [VERSION_ROOT],
        extraDirs: [],
        watch: true,
        watchDebounceMs: 250,
      },
    },
  };
}

function evidenceEnvelope(schema, payload, status = "PASS") {
  return {
    assurance: ASSURANCE,
    decision: {
      installer_work_eligible: false,
      status: "NOT_TESTED",
    },
    limitations: [
      "CONFORMANCE_FIXTURES_ONLY_NOT_PRODUCTION_ALLOW_LINEAGE",
      "BROKER_AND_DOCKER_CONTROL_PLANE_NOT_INDEPENDENTLY_ATTESTED",
      "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_NOT_EXTERNAL_MODEL_PROOF",
      "NO_ADM_02_ROUTE_STATUS_IS_GRANTED",
    ],
    payload,
    recorded_at: new Date().toISOString(),
    schema,
    slice_status: status,
  };
}

function mode(stat) {
  return (stat.mode & 0o777).toString(8).padStart(3, "0");
}

function requireEmptyDirectory(path) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`preparation root is not a regular directory: ${path}`);
  }
  const names = readdirSync(path);
  if (names.length !== 0) {
    throw new Error(`preparation root is not empty: ${path}`);
  }
}

function writeExclusive(path, raw, fileMode) {
  writeFileSync(path, raw, { flag: "wx", mode: fileMode });
  const handle = openSync(path, "r");
  try {
    fsyncSync(handle);
  } finally {
    closeSync(handle);
  }
}

function fsyncDirectory(path) {
  const handle = openSync(path, "r");
  try {
    fsyncSync(handle);
  } finally {
    closeSync(handle);
  }
}

function exactSkillDirectory(path, version) {
  const expected = FIXTURES[version];
  const directoryStat = lstatSync(path);
  const names = readdirSync(path).sort();
  const file = join(path, "SKILL.md");
  const fileStat = lstatSync(file);
  const raw = readFileSync(file);
  if (
    !directoryStat.isDirectory() ||
    directoryStat.isSymbolicLink() ||
    mode(directoryStat) !== "555" ||
    canonicalJson(names) !== '["SKILL.md"]' ||
    !fileStat.isFile() ||
    fileStat.isSymbolicLink() ||
    fileStat.nlink !== 1 ||
    mode(fileStat) !== "444" ||
    !raw.equals(Buffer.from(FIXTURE_TEXT[version], "utf8"))
  ) {
    throw new Error(`sealed ${version} fixture identity changed: ${path}`);
  }
  const observed = fixtureIdentity(version);
  if (
    observed.file_digest !== expected.file_digest ||
    observed.tree_digest !== expected.tree_digest
  ) {
    throw new Error(`sealed ${version} fixture digest changed`);
  }
  return {
    directory: {
      device: directoryStat.dev,
      inode: directoryStat.ino,
      mode: mode(directoryStat),
      realpath: realpathSync(path),
      type: "directory",
    },
    file: {
      device: fileStat.dev,
      digest: sha256(raw),
      inode: fileStat.ino,
      links: fileStat.nlink,
      mode: mode(fileStat),
      path: "SKILL.md",
      size: raw.length,
      type: "file",
    },
    manifest: expected.manifest,
    tree_digest: expected.tree_digest,
    version,
  };
}

function prepare() {
  const roots = {
    config: "/prepare/config",
    probe: "/prepare/probe",
    skills: "/prepare/skills",
  };
  for (const path of Object.values(roots)) {
    requireEmptyDirectory(path);
  }

  const config = configuration();
  writeExclusive(
    join(roots.config, "openclaw.json"),
    `${canonicalJson(config)}\n`,
    0o444,
  );
  writeExclusive(
    join(roots.probe, "broker-symlink-probe.mjs"),
    readFileSync(SELF),
    0o444,
  );
  const fixturesRoot = join(roots.probe, "fixtures");
  mkdirSync(fixturesRoot, { mode: 0o755 });
  for (const version of ["v1", "v2"]) {
    const fixtureRoot = join(fixturesRoot, version);
    mkdirSync(fixtureRoot, { mode: 0o755 });
    writeExclusive(
      join(fixtureRoot, "SKILL.md"),
      FIXTURE_TEXT[version],
      0o444,
    );
    chmodSync(fixtureRoot, 0o555);
  }

  chownSync(roots.skills, BROKER_UID, BROKER_UID);
  chmodSync(roots.skills, 0o755);
  chmodSync(fixturesRoot, 0o555);
  chmodSync(roots.config, 0o555);
  chmodSync(roots.probe, 0o555);
  fsyncDirectory(roots.config);
  fsyncDirectory(roots.probe);
  fsyncDirectory(roots.skills);

  return evidenceEnvelope(
    "aragorn/openclaw-broker-symlink-preparation-evidence/v1",
    {
      broker_identity: { uid: BROKER_UID },
      configuration_digest: sha256(
        Buffer.from(canonicalJson(config), "ascii"),
      ),
      fixtures: FIXTURES,
      implementation_digest: sha256(readFileSync(SELF)),
      runtime_identity: { uid: RUNTIME_UID },
      runtime_mount: {
        mode: "ro",
        path: ACTIVE_ROOT,
        type: "nested-volume-mount",
      },
      shared_skill_volume: {
        broker_mount_mode: "rw",
        mode: "755",
        owner: `${BROKER_UID}:${BROKER_UID}`,
        runtime_mount_mode: "ro",
      },
      probe_mode: "444",
      version_root: VERSION_ROOT,
    },
  );
}

function isPathInside(parent, child) {
  const path = relative(resolve(parent), resolve(child));
  return path === "" || (!path.startsWith("..") && !isAbsolute(path));
}

function decodeMountInfoPath(raw) {
  return raw.replace(/\\([0-7]{3})/g, (_match, octal) =>
    String.fromCharCode(Number.parseInt(octal, 8)),
  );
}

function mountSnapshot(expectedPath) {
  const resolvedPath = resolve(expectedPath);
  const records = readFileSync("/proc/self/mountinfo", "utf8")
    .split("\n")
    .filter(Boolean)
    .flatMap((line) => {
      const fields = line.split(" ");
      const separator = fields.indexOf("-");
      if (separator < 6 || fields.length < separator + 4) {
        return [];
      }
      const mountPoint = decodeMountInfoPath(fields[4]);
      if (resolve(mountPoint) !== resolvedPath) {
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
  if (records.length !== 1) {
    throw new Error(
      `expected exactly one nested mount at ${resolvedPath}, found ${records.length}`,
    );
  }
  return records[0];
}

function executionBoundary(role) {
  const expectedUid = role === "broker" ? BROKER_UID : RUNTIME_UID;
  const expectedMountMode = role === "broker" ? "rw" : "ro";
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  const gid = typeof process.getgid === "function" ? process.getgid() : null;
  if (uid !== expectedUid) {
    throw new Error(`${role} mode requires uid ${expectedUid}, observed ${uid}`);
  }
  const rootStat = lstatSync(ACTIVE_ROOT);
  if (
    !rootStat.isDirectory() ||
    rootStat.isSymbolicLink() ||
    rootStat.uid !== BROKER_UID ||
    rootStat.gid !== BROKER_UID
  ) {
    throw new Error("shared skill volume root ownership or type changed");
  }
  const mount = mountSnapshot(ACTIVE_ROOT);
  if (
    !mount.mount_options.includes(expectedMountMode) ||
    mount.mount_options.includes(expectedMountMode === "rw" ? "ro" : "rw")
  ) {
    throw new Error(
      `${role} skill-volume mount is not exclusively ${expectedMountMode}`,
    );
  }
  return {
    active_root: {
      device: rootStat.dev,
      gid: rootStat.gid,
      inode: rootStat.ino,
      mode: mode(rootStat),
      uid: rootStat.uid,
    },
    effective_identity: { gid, uid },
    mount,
    role,
  };
}

function finalVersionPath(version) {
  const digest = FIXTURES[version].tree_digest.slice("sha256:".length);
  return join(VERSION_ROOT, NAME, digest);
}

function relativeVersionTarget(version) {
  return relative(ACTIVE_ROOT, finalVersionPath(version));
}

function activeLinkSnapshot() {
  const stat = lstatSync(ACTIVE_LINK);
  if (!stat.isSymbolicLink()) {
    throw new Error("active skill entry is not a symbolic link");
  }
  const target = readlinkSync(ACTIVE_LINK);
  if (isAbsolute(target)) {
    throw new Error("active skill link is not relative");
  }
  const resolvedTarget = realpathSync(ACTIVE_LINK);
  if (!isPathInside(VERSION_ROOT, resolvedTarget)) {
    throw new Error("active skill link escaped the version root");
  }
  const version = Object.keys(FIXTURES).find(
    (candidate) => resolvedTarget === finalVersionPath(candidate),
  );
  if (!version) {
    throw new Error("active skill link targets an unknown version");
  }
  return {
    device: stat.dev,
    inode: stat.ino,
    resolved_target: resolvedTarget,
    target,
    tree_digest: FIXTURES[version].tree_digest,
    type: "symlink",
    version,
  };
}

function cleanupStage(path) {
  if (!existsSync(path)) {
    return;
  }
  try {
    chmodSync(path, 0o700);
  } catch {
    // Best effort after a failed, not-yet-published stage.
  }
  rmSync(path, { force: true, recursive: true });
}

function materializeVersion(version) {
  const source = join("/probe/fixtures", version);
  const sourceProof = exactSkillDirectory(source, version);
  if (!existsSync(VERSION_ROOT)) {
    mkdirSync(VERSION_ROOT, { mode: 0o755 });
    fsyncDirectory(ACTIVE_ROOT);
  }
  const versionRootStat = lstatSync(VERSION_ROOT);
  if (
    !versionRootStat.isDirectory() ||
    versionRootStat.isSymbolicLink() ||
    mode(versionRootStat) !== "755" ||
    versionRootStat.uid !== BROKER_UID ||
    versionRootStat.gid !== BROKER_UID
  ) {
    throw new Error("hidden version root ownership or type changed");
  }
  const parent = join(VERSION_ROOT, NAME);
  if (!existsSync(parent)) {
    mkdirSync(parent, { mode: 0o755 });
    fsyncDirectory(VERSION_ROOT);
  }
  const parentStat = lstatSync(parent);
  if (
    !parentStat.isDirectory() ||
    parentStat.isSymbolicLink() ||
    mode(parentStat) !== "755" ||
    parentStat.uid !== BROKER_UID ||
    parentStat.gid !== BROKER_UID
  ) {
    throw new Error("version namespace is not a writable regular directory");
  }

  const finalPath = finalVersionPath(version);
  if (existsSync(finalPath)) {
    return {
      final: exactSkillDirectory(finalPath, version),
      promoted: false,
      source: sourceProof,
    };
  }

  const stage = join(parent, `.stage-${version}-${process.pid}`);
  if (existsSync(stage)) {
    throw new Error(`version stage already exists: ${basename(stage)}`);
  }
  try {
    mkdirSync(stage, { mode: 0o700 });
    writeExclusive(
      join(stage, "SKILL.md"),
      readFileSync(join(source, "SKILL.md")),
      0o600,
    );
    chmodSync(join(stage, "SKILL.md"), 0o444);
    chmodSync(stage, 0o555);
    const staged = exactSkillDirectory(stage, version);
    fsyncDirectory(stage);
    const sameFilesystem = staged.directory.device === parentStat.dev;
    if (!sameFilesystem) {
      throw new Error("version promotion would cross filesystems");
    }
    renameSync(stage, finalPath);
    fsyncDirectory(parent);
    return {
      final: exactSkillDirectory(finalPath, version),
      promoted: true,
      promotion_same_filesystem: sameFilesystem,
      source: sourceProof,
      staged_device: staged.directory.device,
      staged_inode: staged.directory.inode,
    };
  } catch (error) {
    cleanupStage(stage);
    throw error;
  }
}

function activate(version) {
  if (!Object.hasOwn(FIXTURES, version)) {
    throw new Error(`unknown broker fixture version: ${version}`);
  }
  const boundary = executionBoundary("broker");
  const prior = existsSync(ACTIVE_LINK) ? activeLinkSnapshot() : null;
  if (
    (version === "v1" && prior !== null && prior.version !== "v1") ||
    (version === "v2" && prior?.version !== "v1")
  ) {
    throw new Error(`unexpected active version before ${version}`);
  }

  const materialized = materializeVersion(version);
  const target = relativeVersionTarget(version);
  if (
    isAbsolute(target) ||
    !target.startsWith(".aragorn-versions/") ||
    target.includes("..")
  ) {
    throw new Error("broker did not derive a bounded relative target");
  }
  const temporary = join(ACTIVE_ROOT, `.${NAME}.next-${version}-${process.pid}`);
  if (existsSync(temporary)) {
    throw new Error("temporary active link already exists");
  }
  symlinkSync(target, temporary);
  const temporaryStat = lstatSync(temporary);
  const activeRootStat = lstatSync(ACTIVE_ROOT);
  const temporaryTarget = realpathSync(temporary);
  if (
    !temporaryStat.isSymbolicLink() ||
    temporaryTarget !== finalVersionPath(version) ||
    temporaryStat.dev !== activeRootStat.dev ||
    materialized.final.directory.device !== activeRootStat.dev
  ) {
    rmSync(temporary, { force: true });
    throw new Error("temporary active link failed its atomicity boundary");
  }
  renameSync(temporary, ACTIVE_LINK);
  fsyncDirectory(ACTIVE_ROOT);
  const active = activeLinkSnapshot();
  if (
    active.version !== version ||
    active.inode !== temporaryStat.ino ||
    active.device !== temporaryStat.dev
  ) {
    throw new Error("atomic active-link rename did not publish the staged inode");
  }

  const result = evidenceEnvelope(
    "aragorn/openclaw-broker-symlink-activation-evidence/v1",
    {
      action: `activate-${version}`,
      active_after: active,
      active_before: prior,
      atomic_relative_symlink_rename: true,
      broker_boundary: boundary,
      implementation_digest: sha256(readFileSync(SELF)),
      materialized,
      native_openclaw_route_used: false,
      requested_tree_digest: FIXTURES[version].tree_digest,
      single_volume_same_filesystem: true,
      temporary_link: {
        device: temporaryStat.dev,
        inode: temporaryStat.ino,
        target,
      },
    },
  );
  if (!existsSync(ACTIVATION_RECORD_ROOT)) {
    mkdirSync(ACTIVATION_RECORD_ROOT, { mode: 0o755 });
    fsyncDirectory(VERSION_ROOT);
  }
  writeExclusive(
    join(ACTIVATION_RECORD_ROOT, `activate-${version}.json`),
    `${canonicalJson(result)}\n`,
    0o444,
  );
  fsyncDirectory(ACTIVATION_RECORD_ROOT);
  return result;
}

async function readBoundedStream(stream, maxBytes) {
  stream.setEncoding("utf8");
  const hash = createHash("sha256");
  let bytes = 0;
  let raw = "";
  let oversized = false;
  for await (const chunk of stream) {
    hash.update(chunk);
    bytes += Buffer.byteLength(chunk);
    if (!oversized && bytes <= maxBytes) {
      raw += chunk;
    } else {
      oversized = true;
      raw = "";
    }
  }
  return {
    bytes,
    digest: `sha256:${hash.digest("hex")}`,
    oversized,
    raw,
  };
}

async function nativePolicy() {
  const input = await readBoundedStream(process.stdin, 64 * 1024);
  let request_schema = null;
  if (!input.oversized) {
    try {
      request_schema = JSON.parse(input.raw)?.schema ?? null;
    } catch {
      // Malformed requests are still fail-closed.
    }
  }
  appendFileSync(
    POLICY_LOG,
    `${canonicalJson({
      decision: "block",
      input_bytes: input.bytes,
      input_digest: input.digest,
      oversized: input.oversized,
      protocol_version: 1,
      request_schema,
    })}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  process.stdout.write(
    canonicalJson({
      decision: "block",
      protocolVersion: 1,
      reason: "Native OpenClaw mutation is disabled; use the Aragorn broker",
    }),
  );
}

function flattenContent(content) {
  if (typeof content === "string") {
    return content;
  }
  if (!Array.isArray(content)) {
    return "";
  }
  return content
    .map((item) =>
      typeof item === "string"
        ? item
        : typeof item?.text === "string"
          ? item.text
          : "",
    )
    .join("");
}

function systemPrompt(body) {
  return (body.messages ?? [])
    .filter((message) => message.role === "system")
    .map((message) => flattenContent(message.content))
    .join("\n");
}

function promptMarkers(prompt) {
  return Object.fromEntries(
    Object.entries(MARKERS).map(([version, marker]) => [
      version,
      prompt.includes(marker),
    ]),
  );
}

function oneMarker(markers) {
  const present = Object.entries(markers)
    .filter(([, value]) => value === true)
    .map(([key]) => key);
  return present.length === 1 ? present[0] : null;
}

function expectedVersionFromBody(body) {
  const users = (body.messages ?? []).filter((message) => message.role === "user");
  const text = flattenContent(users.at(-1)?.content);
  return Object.keys(EXPECTATION_TOKEN).find((version) =>
    text.includes(EXPECTATION_TOKEN[version]),
  );
}

function latestToolContent(body) {
  const messages = body.messages ?? [];
  const lastUser = messages.findLastIndex((message) => message.role === "user");
  const tools = messages
    .slice(lastUser + 1)
    .filter((message) => message.role === "tool");
  return tools.length > 0 ? flattenContent(tools.at(-1).content) : null;
}

function providerResponse(version, toolContent) {
  const common = {
    created: 0,
    model: MODEL,
    object: "chat.completion.chunk",
  };
  if (toolContent === null) {
    return {
      chunks: [
        {
          ...common,
          choices: [
            {
              delta: {
                role: "assistant",
                tool_calls: [
                  {
                    function: {
                      arguments: canonicalJson({ path: ACTIVE_FILE }),
                      name: "read",
                    },
                    id: `callbrokerread${version}`,
                    index: 0,
                    type: "function",
                  },
                ],
              },
              finish_reason: "tool_calls",
              index: 0,
            },
          ],
          id: `chatcmpl-aragorn-broker-read-${version}`,
        },
      ],
      kind: "tool_call",
    };
  }
  const exact = toolContent === FIXTURE_TEXT[version];
  const text = exact ? FINAL_TEXT[version] : "ARAGORN_BROKER_CONTENT_MISMATCH";
  return {
    chunks: [
      {
        ...common,
        choices: [
          {
            delta: { content: text, role: "assistant" },
            finish_reason: null,
            index: 0,
          },
        ],
        id: `chatcmpl-aragorn-broker-final-${version}`,
      },
      {
        ...common,
        choices: [{ delta: {}, finish_reason: "stop", index: 0 }],
        id: `chatcmpl-aragorn-broker-final-${version}`,
        usage: { completion_tokens: 1, prompt_tokens: 1, total_tokens: 2 },
      },
    ],
    kind: exact ? "final" : "mismatch",
  };
}

function sendSse(res, chunks) {
  res.writeHead(200, {
    "cache-control": "no-cache",
    connection: "keep-alive",
    "content-type": "text/event-stream; charset=utf-8",
  });
  for (const chunk of chunks) {
    res.write(`data: ${canonicalJson(chunk)}\n\n`);
  }
  res.end("data: [DONE]\n\n");
}

async function provider() {
  if (existsSync(PROVIDER_LOG)) {
    throw new Error("provider request log already exists");
  }
  let sequence = 0;
  const server = createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/v1/models") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          canonicalJson({
            data: [
              { created: 0, id: MODEL, object: "model", owned_by: "aragorn" },
            ],
            object: "list",
          }),
        );
        return;
      }
      if (req.method !== "POST" || req.url !== "/v1/chat/completions") {
        res.writeHead(404).end();
        return;
      }
      const input = await readBoundedStream(req, MAX_PROVIDER_BODY_BYTES);
      if (input.oversized) {
        throw new Error("provider request exceeded 4 MiB");
      }
      const body = JSON.parse(input.raw);
      const version = expectedVersionFromBody(body);
      if (!version) {
        throw new Error("provider request omitted its fixture expectation");
      }
      const authorization = req.headers.authorization;
      if (typeof authorization !== "string") {
        throw new Error("provider request lacked authorization");
      }
      sequence += 1;
      if (sequence > MAX_PROVIDER_REQUESTS) {
        throw new Error("provider request bound exceeded");
      }
      const toolContent = latestToolContent(body);
      const response = providerResponse(version, toolContent);
      const prompt = systemPrompt(body);
      appendFileSync(
        PROVIDER_LOG,
        `${canonicalJson({
          authorization_digest: sha256(Buffer.from(authorization)),
          body_bytes: input.bytes,
          body_digest: input.digest,
          expected_version: version,
          message_count: Array.isArray(body.messages) ? body.messages.length : 0,
          model: body.model,
          prompt_bytes: Buffer.byteLength(prompt),
          prompt_digest: sha256(Buffer.from(prompt)),
          prompt_markers: promptMarkers(prompt),
          response_kind: response.kind,
          sequence,
          tool_content_digest:
            toolContent === null ? null : sha256(Buffer.from(toolContent)),
        })}\n`,
        { encoding: "utf8", mode: 0o600 },
      );
      sendSse(res, response.chunks);
    } catch (error) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(
        canonicalJson({
          error: error instanceof Error ? error.message : String(error),
        }),
      );
    }
  });
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(18080, "127.0.0.1", resolvePromise);
  });
}

function command(args, timeout = 20_000) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(NODE, [OPENCLAW, ...args], {
    cwd: WORKSPACE,
    encoding: "utf8",
    env: PROFILE_ENV,
    maxBuffer: 16 * 1024 * 1024,
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
  if (result.exit_code !== 0) {
    throw new Error(`${label} failed: ${result.stderr.trim()}`);
  }
  for (const output of [result.stdout, result.stderr]) {
    try {
      return JSON.parse(output);
    } catch {
      // Gateway service-control JSON may use either stream.
    }
  }
  throw new Error(`${label} did not return JSON`);
}

function gatewayCall(method, params = null, timeout = 5000) {
  const args = ["gateway", "call", method, "--json", "--timeout", String(timeout)];
  if (params !== null) {
    args.push("--params", canonicalJson(params));
  }
  return command(args, timeout + 5000);
}

async function waitForGateway() {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const call = gatewayCall("system.info");
    if (call.exit_code === 0) {
      const info = parseCommand(call, "system.info");
      if (info.pid === 1) {
        return { command: summarized(call), info };
      }
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
  }
  throw new Error("timed out waiting for the contained Gateway");
}

function processIdentity() {
  const raw = readFileSync("/proc/1/stat", "utf8").trim();
  const fields = raw.slice(raw.lastIndexOf(")") + 2).split(" ");
  return {
    cmdline: readFileSync("/proc/1/cmdline")
      .toString("utf8")
      .split("\0")
      .filter(Boolean),
    pid: 1,
    start_time_ticks: fields[19],
  };
}

function gatewayLog() {
  const directory = "/tmp/openclaw";
  const names = readdirSync(directory)
    .filter((name) => name.endsWith(".log"))
    .sort();
  if (names.length !== 1) {
    throw new Error(`expected one Gateway log, found ${names.length}`);
  }
  const path = join(directory, names[0]);
  const raw = readFileSync(path);
  if (raw.includes(TEST_TOKEN) || raw.includes(MOCK_KEY)) {
    throw new Error("Gateway log contains a contained test credential");
  }
  const messages = raw
    .toString("utf8")
    .split("\n")
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [JSON.parse(line).message ?? ""];
      } catch {
        return [];
      }
    });
  return {
    bytes: raw.length,
    digest: sha256(raw),
    path: basename(path),
    ready_count: messages.filter((message) => message === "gateway ready").length,
    restart_count: messages.filter((message) =>
      /SIGUSR1.*restart|restarting|restart mode:/i.test(message),
    ).length,
  };
}

function readCanonicalRecords(path) {
  if (!existsSync(path)) {
    return [];
  }
  const raw = readFileSync(path, "utf8");
  const lines = raw.split("\n");
  if (lines.pop() !== "") {
    throw new Error(`canonical record log lacks a trailing newline: ${path}`);
  }
  return lines.map((line) => {
    const parsed = JSON.parse(line);
    if (canonicalJson(parsed) !== line) {
      throw new Error(`non-canonical record in ${path}`);
    }
    return parsed;
  });
}

function resolveSnapshotPrompt(snapshot) {
  if (typeof snapshot.prompt === "string") {
    return { prompt: snapshot.prompt, storage: "inline" };
  }
  const ref = snapshot.promptRef;
  if (
    ref?.version !== 1 ||
    ref?.algorithm !== "sha256" ||
    !/^[a-f0-9]{64}$/.test(ref?.hash ?? "") ||
    !Number.isSafeInteger(ref?.bytes) ||
    ref.bytes < 0
  ) {
    throw new Error("session snapshot has no valid prompt or promptRef");
  }
  const path = join(
    dirname(SESSION_STORE),
    "skills-prompts",
    "sha256",
    ref.hash.slice(0, 2),
    `${ref.hash}.txt`,
  );
  const stat = lstatSync(path);
  const raw = readFileSync(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    raw.length !== ref.bytes ||
    sha256(raw) !== `sha256:${ref.hash}`
  ) {
    throw new Error("session prompt blob failed integrity validation");
  }
  return { prompt: raw.toString("utf8"), storage: "promptRef" };
}

function sessionSnapshot() {
  const store = JSON.parse(readFileSync(SESSION_STORE, "utf8"));
  const entry = store[SESSION_KEY];
  if (!entry || typeof entry.sessionId !== "string" || !entry.skillsSnapshot) {
    throw new Error("expected broker-switch session snapshot is missing");
  }
  const snapshot = entry.skillsSnapshot;
  const { prompt, storage } = resolveSnapshotPrompt(snapshot);
  const markers = promptMarkers(prompt);
  return {
    active_marker: oneMarker(markers),
    ended_at: entry.endedAt,
    markers,
    prompt_bytes: Buffer.byteLength(prompt),
    prompt_digest: sha256(Buffer.from(prompt)),
    prompt_storage: storage,
    run_status: entry.status,
    runtime_ms: entry.runtimeMs,
    session_id: entry.sessionId,
    skill_names: (snapshot.skills ?? []).map((item) => item.name),
    started_at: entry.startedAt,
    version: snapshot.version,
  };
}

function validSessionSnapshot(snapshot) {
  return (
    ["v1", "v2"].includes(snapshot.active_marker) &&
    typeof snapshot.session_id === "string" &&
    snapshot.run_status === "done" &&
    Number.isSafeInteger(snapshot.started_at) &&
    Number.isSafeInteger(snapshot.ended_at) &&
    snapshot.ended_at >= snapshot.started_at &&
    Number.isSafeInteger(snapshot.runtime_ms) &&
    snapshot.runtime_ms >= 0 &&
    Number.isSafeInteger(snapshot.version) &&
    snapshot.version >= 0 &&
    canonicalJson(snapshot.skill_names) === `["${NAME}"]`
  );
}

function historyProof(history, version, idempotencyKey) {
  const messages = history.messages ?? [];
  const userIndex = messages.findIndex(
    (message) => message.idempotencyKey === `${idempotencyKey}:user`,
  );
  const selected =
    userIndex >= 0 ? messages.slice(userIndex, userIndex + 4) : [];
  const [user, assistant, tool, final] = selected;
  const roles = selected.map((message) => message.role);
  const toolText = tool?.content?.find?.((item) => item.type === "text")?.text;
  const toolCall = assistant?.content?.find?.(
    (item) => item.type === "toolCall" && item.name === "read",
  );
  const finalText = final?.content?.find?.((item) => item.type === "text")?.text;
  const valid =
    canonicalJson(roles) === '["user","assistant","toolResult","assistant"]' &&
    flattenContent(user?.content).includes(EXPECTATION_TOKEN[version]) &&
    toolCall?.arguments?.path === ACTIVE_FILE &&
    tool?.toolName === "read" &&
    tool?.isError === false &&
    toolText === FIXTURE_TEXT[version] &&
    final?.provider === PROVIDER &&
    final?.model === MODEL &&
    final?.stopReason === "stop" &&
    finalText === FINAL_TEXT[version] &&
    history.sessionKey === SESSION_KEY &&
    history.sessionInfo?.key === SESSION_KEY;
  return {
    final_text: finalText ?? null,
    roles,
    tool_content_digest:
      typeof toolText === "string" ? sha256(Buffer.from(toolText)) : null,
    tool_path: toolCall?.arguments?.path ?? null,
    valid,
  };
}

function providerTurnProof(records, version) {
  if (records.length !== 2) {
    return { record_count: records.length, valid: false };
  }
  const [first, second] = records;
  const expectedDigest = FIXTURES[version].file_digest;
  const firstMarker = oneMarker(first.prompt_markers);
  const secondMarker = oneMarker(second.prompt_markers);
  const valid =
    first.expected_version === version &&
    second.expected_version === version &&
    first.model === MODEL &&
    second.model === MODEL &&
    first.response_kind === "tool_call" &&
    second.response_kind === "final" &&
    first.tool_content_digest === null &&
    second.tool_content_digest === expectedDigest &&
    ["v1", "v2"].includes(firstMarker) &&
    firstMarker === secondMarker &&
    first.authorization_digest ===
      sha256(Buffer.from(`Bearer ${MOCK_KEY}`)) &&
    second.authorization_digest === first.authorization_digest &&
    second.sequence === first.sequence + 1;
  return {
    first_sequence: first.sequence,
    prompt_marker: firstMarker,
    prompt_digest: first.prompt_digest,
    record_count: records.length,
    second_sequence: second.sequence,
    tool_content_digest: second.tool_content_digest,
    valid,
  };
}

async function chatTurn(version, attempt) {
  const providerBefore = readCanonicalRecords(PROVIDER_LOG).length;
  const idempotencyKey = `aragorn-broker-switch-${version}-${attempt}`;
  const sendCommand = gatewayCall("chat.send", {
    deliver: false,
    idempotencyKey,
    message:
      `Read the active Aragorn broker skill file, then return its fixed result. ` +
      EXPECTATION_TOKEN[version],
    sessionKey: SESSION_KEY,
    timeoutMs: 10_000,
  });
  const send = parseCommand(sendCommand, `${version} chat.send`);
  if (send.status !== "started" || typeof send.runId !== "string") {
    throw new Error(`${version} chat.send did not start`);
  }
  const waitCommand = gatewayCall(
    "agent.wait",
    { runId: send.runId, timeoutMs: 15_000 },
    17_000,
  );
  const wait = parseCommand(waitCommand, `${version} agent.wait`);
  if (wait.status !== "ok" || !Number.isSafeInteger(wait.endedAt)) {
    throw new Error(`${version} turn did not finish`);
  }
  const historyCommand = gatewayCall("chat.history", {
    limit: 100,
    sessionKey: SESSION_KEY,
  });
  const history = parseCommand(historyCommand, `${version} chat.history`);
  const records = readCanonicalRecords(PROVIDER_LOG).slice(providerBefore);
  const providerProof = providerTurnProof(records, version);
  const consumed = historyProof(history, version, idempotencyKey);
  if (!providerProof.valid || !consumed.valid) {
    throw new Error(`${version} provider or exact-byte consumption proof failed`);
  }
  return {
    consumption: consumed,
    history_command: summarized(historyCommand),
    provider: providerProof,
    send: { command: summarized(sendCommand), response: send },
    wait: { command: summarized(waitCommand), response: wait },
  };
}

function exactConfiguration() {
  const raw = readFileSync(CONFIG);
  const expected = Buffer.from(`${canonicalJson(configuration())}\n`, "utf8");
  if (!raw.equals(expected)) {
    throw new Error("broker-switch configuration changed");
  }
  return {
    bytes: raw.length,
    digest: sha256(Buffer.from(canonicalJson(configuration()), "ascii")),
  };
}

function runtimeVersion() {
  const result = command(["--version"]);
  if (result.exit_code !== 0 || result.stdout.trim() !== EXPECTED_VERSION) {
    throw new Error(`unexpected OpenClaw version: ${result.stdout.trim()}`);
  }
  return summarized(result);
}

function errorCode(error) {
  return error && typeof error === "object" && "code" in error
    ? String(error.code)
    : null;
}

function directWriteGuard(id, root) {
  const target = join(root, ".aragorn-write-probe");
  if (existsSync(target)) {
    throw new Error(`write-guard residue exists: ${target}`);
  }
  try {
    writeFileSync(target, "must-not-write\n", { flag: "wx", mode: 0o600 });
    let cleanup = true;
    try {
      rmSync(target);
    } catch {
      cleanup = false;
    }
    return {
      blocked: false,
      cleanup,
      code: null,
      id,
      operation: "direct-write",
      root,
    };
  } catch (error) {
    return {
      blocked: true,
      code: errorCode(error),
      id,
      operation: "direct-write",
      root,
    };
  }
}

function mountpointGuard(operation) {
  const moved = `${ACTIVE_ROOT}.aragorn-mount-move`;
  if (existsSync(moved)) {
    throw new Error(`mountpoint-guard residue exists: ${moved}`);
  }
  try {
    if (operation === "rename") {
      renameSync(ACTIVE_ROOT, moved);
      renameSync(moved, ACTIVE_ROOT);
    } else {
      unlinkSync(ACTIVE_ROOT);
    }
    return {
      blocked: false,
      cleanup: operation === "rename" && !existsSync(moved),
      code: null,
      operation: `${operation}-skills-mountpoint`,
      root: ACTIVE_ROOT,
    };
  } catch (error) {
    if (existsSync(moved) && !existsSync(ACTIVE_ROOT)) {
      renameSync(moved, ACTIVE_ROOT);
    }
    return {
      blocked: true,
      code: errorCode(error),
      operation: `${operation}-skills-mountpoint`,
      root: ACTIVE_ROOT,
    };
  }
}

function replacementGuard(id, root) {
  const source = join(WORKSPACE, `.aragorn-replacement-source-${id}`);
  const target = join(root, NAME);
  if (existsSync(source)) {
    throw new Error(`replacement-guard source residue exists: ${source}`);
  }
  mkdirSync(source, { mode: 0o700 });
  writeExclusive(join(source, "SKILL.md"), FIXTURE_TEXT.v2, 0o600);
  try {
    renameSync(source, target);
    let cleanup = true;
    try {
      rmSync(target, { force: true, recursive: true });
    } catch {
      cleanup = false;
    }
    return {
      blocked: false,
      cleanup,
      code: null,
      id,
      operation: "alternate-root-replacement",
      root,
      target,
    };
  } catch (error) {
    rmSync(source, { force: true, recursive: true });
    return {
      blocked: true,
      code: errorCode(error),
      id,
      operation: "alternate-root-replacement",
      root,
      target,
    };
  }
}

function writeGuards() {
  const runtimeBoundary = executionBoundary("runtime");
  const directRoots = [
    ["active-workspace-skills", ACTIVE_ROOT],
    ["active-version-directory", realpathSync(ACTIVE_LINK)],
    ["project-agents", join(WORKSPACE, ".agents")],
    ["personal-agents", join(HOME, ".agents")],
    ["managed-skills", join(STATE, "skills")],
    ["plugin-skills", join(STATE, "plugin-skills")],
    ["extensions", join(STATE, "extensions")],
    ["configuration", dirname(CONFIG)],
    ["bundled-runtime-skills", "/runtime/lib/node_modules/openclaw/skills"],
  ];
  const alternateRoots = [
    ["project-agents", join(WORKSPACE, ".agents")],
    ["personal-agents", join(HOME, ".agents")],
    ["managed-skills", join(STATE, "skills")],
    ["plugin-skills", join(STATE, "plugin-skills")],
    ["extensions", join(STATE, "extensions")],
    ["configuration", dirname(CONFIG)],
    ["bundled-runtime-skills", "/runtime/lib/node_modules/openclaw/skills"],
  ];
  const directWrites = directRoots.map(([id, root]) =>
    directWriteGuard(id, root),
  );
  const mountpoint = [
    mountpointGuard("rename"),
    mountpointGuard("unlink"),
  ];
  const replacements = alternateRoots.map(([id, root]) =>
    replacementGuard(id, root),
  );
  const directWritesPassed = directWrites.every(
    (attempt) =>
      attempt.blocked === true && ["EACCES", "EROFS"].includes(attempt.code),
  );
  const mountpointPassed =
    mountpoint[0].blocked === true &&
    mountpoint[0].code === "EBUSY" &&
    mountpoint[1].blocked === true &&
    ["EBUSY", "EISDIR", "EPERM", "EROFS"].includes(mountpoint[1].code);
  const replacementsPassed = replacements.every(
    (attempt) =>
      attempt.blocked === true &&
      ["EACCES", "EEXIST", "ENOTEMPTY", "EPERM", "EROFS", "EXDEV"].includes(
        attempt.code,
      ),
  );
  if (!directWritesPassed || !mountpointPassed || !replacementsPassed) {
    throw new Error("one or more protected roots remained writable");
  }
  return {
    all_blocked: true,
    direct_writes: directWrites,
    mountpoint,
    replacements,
    runtime_boundary: runtimeBoundary,
  };
}

function readCanonicalDocument(path) {
  const raw = readFileSync(path, "utf8");
  if (!raw.endsWith("\n")) {
    throw new Error(`canonical document lacks a trailing newline: ${path}`);
  }
  const document = JSON.parse(raw);
  if (`${canonicalJson(document)}\n` !== raw) {
    throw new Error(`document is not canonical: ${path}`);
  }
  return document;
}

async function before() {
  if (process.env.OPENCLAW_GATEWAY_TOKEN !== TEST_TOKEN) {
    throw new Error("unexpected contained Gateway test credential");
  }
  const runtimeBoundary = executionBoundary("runtime");
  if (existsSync(BASELINE_FILE) || existsSync(SESSION_STORE)) {
    throw new Error("broker-switch baseline state was not fresh");
  }
  const configurationProof = exactConfiguration();
  const link = activeLinkSnapshot();
  if (link.version !== "v1") {
    throw new Error("before slice did not start on v1");
  }
  const version = runtimeVersion();
  const gateway = await waitForGateway();
  const gatewayProcess = processIdentity();
  const log = gatewayLog();
  if (log.ready_count !== 1 || log.restart_count !== 0) {
    throw new Error("before slice lacked a clean Gateway boundary");
  }
  const turn = await chatTurn("v1", 1);
  const session = sessionSnapshot();
  if (!validSessionSnapshot(session) || session.active_marker !== "v1") {
    throw new Error("before slice did not retain one exact v1 snapshot");
  }
  const baseline = {
    configuration: configurationProof,
    gateway: {
      log,
      process: gatewayProcess,
      readiness_command: gateway.command,
      system_info: {
        arch: gateway.info.arch,
        node_version: gateway.info.nodeVersion,
        pid: gateway.info.pid,
        platform: gateway.info.platform,
        port: gateway.info.port,
      },
    },
    implementation_digest: sha256(readFileSync(SELF)),
    link,
    recorded_at: new Date().toISOString(),
    runtime_boundary: runtimeBoundary,
    runtime_version: version,
    schema: "aragorn/openclaw-broker-symlink-before-state/v1",
    session,
    turn,
  };
  writeExclusive(BASELINE_FILE, `${canonicalJson(baseline)}\n`, 0o600);
  return evidenceEnvelope(
    "aragorn/openclaw-broker-symlink-before-evidence/v1",
    baseline,
  );
}

async function after() {
  if (process.env.OPENCLAW_GATEWAY_TOKEN !== TEST_TOKEN) {
    throw new Error("unexpected contained Gateway test credential");
  }
  const runtimeBoundary = executionBoundary("runtime");
  const baseline = readCanonicalDocument(BASELINE_FILE);
  if (baseline.schema !== "aragorn/openclaw-broker-symlink-before-state/v1") {
    throw new Error("broker-switch baseline schema changed");
  }
  const configurationProof = exactConfiguration();
  const link = activeLinkSnapshot();
  if (link.version !== "v2") {
    throw new Error("after slice did not start on v2");
  }
  const versionProofs = {
    v1: exactSkillDirectory(finalVersionPath("v1"), "v1"),
    v2: exactSkillDirectory(finalVersionPath("v2"), "v2"),
  };
  const activations = {
    v1: readCanonicalDocument(
      join(ACTIVATION_RECORD_ROOT, "activate-v1.json"),
    ),
    v2: readCanonicalDocument(
      join(ACTIVATION_RECORD_ROOT, "activate-v2.json"),
    ),
  };
  const gateway = await waitForGateway();
  const gatewayProcess = processIdentity();
  const log = gatewayLog();
  if (
    canonicalJson(gatewayProcess) !==
      canonicalJson(baseline.gateway.process) ||
    canonicalJson(runtimeBoundary) !==
      canonicalJson(baseline.runtime_boundary) ||
    log.ready_count !== baseline.gateway.log.ready_count ||
    log.restart_count !== 0
  ) {
    throw new Error("Gateway restarted across the broker switch");
  }

  const observations = [];
  let selected = null;
  for (let attempt = 1; attempt <= 10 && selected === null; attempt += 1) {
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 150));
    const turn = await chatTurn("v2", attempt);
    const session = sessionSnapshot();
    if (!validSessionSnapshot(session)) {
      throw new Error("observed a missing or mixed session snapshot");
    }
    const observation = { attempt, session, turn };
    observations.push(observation);
    if (
      session.active_marker === "v2" &&
      turn.provider.prompt_marker === "v2"
    ) {
      selected = observation;
    }
  }
  if (
    selected === null ||
    selected.session.session_id !== baseline.session.session_id ||
    selected.session.version <= baseline.session.version ||
    selected.session.prompt_digest === baseline.session.prompt_digest
  ) {
    throw new Error("same-session snapshot did not advance cleanly to v2");
  }
  const observedSnapshots = [
    baseline.session,
    ...observations.map((item) => item.session),
  ];
  if (
    observedSnapshots.some(
      (snapshot) => !["v1", "v2"].includes(snapshot.active_marker),
    )
  ) {
    throw new Error("snapshot sequence contained a missing or mixed version");
  }
  const guards = writeGuards();
  const result = evidenceEnvelope(
    "aragorn/openclaw-broker-symlink-live-switch-evidence/v2",
    {
      active_after: link,
      active_before: baseline.link,
      activations,
      baseline,
      configuration: configurationProof,
      exact_old_and_new_versions_retained: true,
      gateway: {
        log_after: log,
        log_before: baseline.gateway.log,
        process_after: gatewayProcess,
        process_before: baseline.gateway.process,
        readiness_command: gateway.command,
      },
      guards,
      implementation_digest: sha256(readFileSync(SELF)),
      no_gateway_restart: true,
      observations,
      observed_snapshots_only_v1_or_v2: true,
      runtime_boundary_after: runtimeBoundary,
      runtime_boundary_before: baseline.runtime_boundary,
      runtime: {
        commit: PINNED_SOURCE_REVIEW.commit,
        name: "OpenClaw",
        source_review: PINNED_SOURCE_REVIEW,
        version: "2026.7.1",
      },
      same_session_advanced: true,
      selected_attempt: selected.attempt,
      version_proofs: versionProofs,
    },
  );
  if (existsSync(dirname(OUTPUT_FILE))) {
    writeExclusive(OUTPUT_FILE, `${canonicalJson(result)}\n`, 0o600);
  }
  return result;
}

function guardEvidence() {
  return evidenceEnvelope(
    "aragorn/openclaw-broker-symlink-write-guard-evidence/v1",
    {
      active: activeLinkSnapshot(),
      guards: writeGuards(),
      implementation_digest: sha256(readFileSync(SELF)),
    },
  );
}

function selfCheck() {
  const config = configuration();
  const relativeV1 = relativeVersionTarget("v1");
  const relativeV2 = relativeVersionTarget("v2");
  const checks = {
    agent_selects_only_fixture:
      canonicalJson(config.agents.defaults.skills) === `["${NAME}"]` &&
      canonicalJson(config.agents.list[0].skills) === `["${NAME}"]`,
    assurance_is_non_authoritative:
      ASSURANCE === "SELF_REPORTED_EVIDENCE_ONLY_NOT_CONFORMANCE_AUTHORITY",
    config_denies_native_skill_and_plugin_mutation:
      canonicalJson(config.security.installPolicy.targets) ===
      '["skill","plugin"]',
    config_disables_plugins: config.plugins.enabled === false,
    config_has_no_extra_roots:
      canonicalJson(config.skills.load.extraDirs) === "[]",
    config_trusts_only_hidden_version_root:
      canonicalJson(config.skills.load.allowSymlinkTargets) ===
      `["${VERSION_ROOT}"]`,
    execution_identities_are_distinct:
      BROKER_UID === 2000 &&
      RUNTIME_UID === 1000 &&
      BROKER_UID !== RUNTIME_UID,
    fixtures_are_distinct:
      FIXTURES.v1.file_digest !== FIXTURES.v2.file_digest &&
      FIXTURES.v1.tree_digest !== FIXTURES.v2.tree_digest,
    fixtures_are_inert: Object.values(FIXTURE_TEXT).every(
      (text) =>
        text.includes("fixture is inert") &&
        !/[`$]|https?:|exec|spawn|child_process/.test(text),
    ),
    implementation_digest_is_sha256:
      /^sha256:[a-f0-9]{64}$/.test(sha256(readFileSync(SELF))),
    pinned_source_review_is_bounded:
      PINNED_SOURCE_REVIEW.commit ===
        "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4" &&
      Object.values(PINNED_SOURCE_REVIEW.files).every((digest) =>
        /^sha256:[a-f0-9]{64}$/.test(digest),
      ) &&
      Object.values(PINNED_SOURCE_REVIEW.findings).every(Boolean),
    provider_scopes_tool_results_to_latest_user:
      latestToolContent({
        messages: [
          { content: "old", role: "tool" },
          { content: "next", role: "user" },
        ],
      }) === null &&
      latestToolContent({
        messages: [
          { content: "old", role: "tool" },
          { content: "next", role: "user" },
          { content: "new", role: "tool" },
        ],
      }) === "new",
    relative_targets_are_bounded:
      !isAbsolute(relativeV1) &&
      !isAbsolute(relativeV2) &&
      relativeV1.startsWith(".aragorn-versions/") &&
      relativeV2.startsWith(".aragorn-versions/") &&
      !relativeV1.includes("..") &&
      !relativeV2.includes(".."),
    single_volume_hidden_version_layout:
      isPathInside(ACTIVE_ROOT, VERSION_ROOT) &&
      basename(VERSION_ROOT).startsWith(".") &&
      resolve(ACTIVE_ROOT) !== resolve(VERSION_ROOT),
    tree_digests_are_sha256: Object.values(FIXTURES).every((fixture) =>
      /^sha256:[a-f0-9]{64}$/.test(fixture.tree_digest),
    ),
    watcher_is_enabled:
      config.skills.load.watch === true &&
      config.skills.load.watchDebounceMs === 250,
  };
  return {
    assurance: ASSURANCE,
    checks,
    configuration_digest: sha256(
      Buffer.from(canonicalJson(config), "ascii"),
    ),
    fixtures: FIXTURES,
    implementation_digest: sha256(readFileSync(SELF)),
    mount_contract: {
      broker: {
        mode: "rw",
        path: ACTIVE_ROOT,
        uid: BROKER_UID,
      },
      runtime: {
        mode: "ro",
        nested_mountpoint: true,
        path: ACTIVE_ROOT,
        uid: RUNTIME_UID,
      },
      shared_volume_count: 1,
    },
    modes: [
      "activate-v1",
      "activate-v2",
      "after",
      "before",
      "guards",
      "native-policy",
      "prepare",
      "provider",
      "self-check",
    ],
    pinned_source_review: PINNED_SOURCE_REVIEW,
    schema: "aragorn/openclaw-broker-symlink-self-check/v1",
    status: Object.values(checks).every(Boolean) ? "PASS" : "FAIL",
  };
}

async function main() {
  const modeName = process.argv[2];
  let result;
  switch (modeName) {
    case "self-check":
      result = selfCheck();
      break;
    case "prepare":
      result = prepare();
      break;
    case "activate-v1":
      result = activate("v1");
      break;
    case "activate-v2":
      result = activate("v2");
      break;
    case "before":
      result = await before();
      break;
    case "after":
      result = await after();
      break;
    case "guards":
      result = guardEvidence();
      break;
    case "native-policy":
      await nativePolicy();
      return;
    case "provider":
      await provider();
      return;
    default:
      throw new Error(
        `unknown broker-symlink probe mode: ${modeName ?? "(missing)"}`,
      );
  }
  process.stdout.write(`${canonicalJson(result)}\n`);
  if (result.status === "FAIL" || result.slice_status === "FAIL") {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  process.stdout.write(
    `${canonicalJson({
      assurance: ASSURANCE,
      decision: { installer_work_eligible: false, status: "FAIL" },
      error: error instanceof Error ? error.message : String(error),
      recorded_at: new Date().toISOString(),
      schema: "aragorn/openclaw-broker-symlink-error/v1",
      slice_status: "ERROR",
    })}\n`,
  );
  process.exitCode = 1;
});
