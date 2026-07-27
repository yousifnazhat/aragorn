#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const EXPECTED_VERSION = "OpenClaw 2026.7.1 (2d2ddc4)";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const PACKAGE = "/acquisition/openclaw-2026.7.1.tgz";
const EXPECTED_PACKAGE_SHA256 =
  "sha256:67ad539d9915efb63d5f294beeb9290b7172d23c92d8052110a9c8355f783458";
const EXPECTED_PACKAGE_SHA512 =
  "sha512:81efd7b2cf7d0870233cbfe29261ff505a223ab8dcc43078b16df2f66872083f9d616df0cd5ed329b015764ad7160006d9dd818e92687cff7bcd467eba6c68f2";
const ROOT = "/tmp/aragorn-openclaw-probe";
const STATE = join(ROOT, "state");
const WORKSPACE = join(ROOT, "workspace");
const POLICY_REQUEST = join(ROOT, "policy-request.json");
const SELF = fileURLToPath(import.meta.url);

function sha256(raw) {
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

function sha512(raw) {
  return `sha512:${createHash("sha512").update(raw).digest("hex")}`;
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

function command(args, cwd = WORKSPACE) {
  const result = spawnSync(process.execPath, [OPENCLAW, ...args], {
    cwd,
    encoding: "utf8",
    env: {
      HOME: join(ROOT, "home"),
      OPENCLAW_CONFIG_PATH: join(STATE, "openclaw.json"),
      OPENCLAW_STATE_DIR: STATE,
      PATH: "/usr/local/bin:/usr/bin:/bin",
    },
    maxBuffer: 1024 * 1024,
    timeout: 60_000,
  });
  return {
    argv: [process.execPath, OPENCLAW, ...args],
    exit_code: result.status,
    signal: result.signal,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    error: result.error?.message ?? null,
  };
}

function inventory(root) {
  const files = [];

  function walk(directory, parts = []) {
    for (const name of readdirSync(directory).sort()) {
      if (!/^[\x00-\x7f]+$/.test(name)) {
        throw new Error(`non-ASCII source path rejected: ${name}`);
      }
      const pathParts = [...parts, name];
      const absolute = join(directory, name);
      const stat = lstatSync(absolute);
      if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
        throw new Error(`non-regular source entry rejected: ${pathParts.join("/")}`);
      }
      if (stat.isDirectory()) {
        walk(absolute, pathParts);
        continue;
      }
      if (stat.nlink !== 1) {
        throw new Error(`hard-linked source file rejected: ${pathParts.join("/")}`);
      }
      const raw = readFileSync(absolute);
      files.push({
        digest: sha256(raw),
        executable: Boolean(stat.mode & 0o111),
        path: pathParts.join("/"),
        size: raw.length,
      });
    }
  }

  walk(root);
  return {
    files,
    summary: {
      file_count: files.length,
      total_bytes: files.reduce((total, file) => total + file.size, 0),
      tree_digest: sha256(Buffer.from(canonicalJson(files), "ascii")),
    },
  };
}

function inventoryRuntime(root) {
  const entries = [];
  let entriesSeen = 0;
  let fileCount = 0;
  let symlinkCount = 0;
  let totalBytes = 0;

  function walk(directory, parts = []) {
    for (const name of readdirSync(directory).sort()) {
      entriesSeen += 1;
      if (entriesSeen > 100_000) {
        throw new Error("runtime entry limit exceeded");
      }
      if (!/^[\x00-\x7f]+$/.test(name)) {
        throw new Error(`non-ASCII runtime path rejected: ${name}`);
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
      if (!stat.isFile()) {
        throw new Error(`unsupported runtime entry rejected: ${path}`);
      }
      if (stat.size > 128 * 1024 * 1024) {
        throw new Error(`runtime file size limit exceeded: ${path}`);
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

function verifyPackageFiles(files, runtimeRoot) {
  for (const expected of files) {
    const absolute = join(runtimeRoot, expected.path);
    const stat = lstatSync(absolute);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.size !== expected.size ||
      Boolean(stat.mode & 0o111) !== expected.executable ||
      sha256(readFileSync(absolute)) !== expected.digest
    ) {
      throw new Error(`installed package file mismatch: ${expected.path}`);
    }
  }
  return { checked_files: files.length, status: "MATCH" };
}

function readPolicyRequest() {
  return existsSync(POLICY_REQUEST)
    ? JSON.parse(readFileSync(POLICY_REQUEST, "utf8"))
    : null;
}

function policy() {
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    input += chunk;
  });
  process.stdin.on("end", () => {
    writeFileSync(POLICY_REQUEST, input, { mode: 0o600 });
    process.stdout.write(
      '{"decision":"block","protocolVersion":1,"reason":"Aragorn conformance probe block"}',
    );
  });
}

function main() {
  rmSync(ROOT, { force: true, recursive: true });
  for (const directory of [
    ROOT,
    STATE,
    WORKSPACE,
    join(ROOT, "home"),
    join(ROOT, "source"),
    join(ROOT, "package"),
  ]) {
    mkdirSync(directory, { recursive: true });
  }

  const packageRaw = readFileSync(PACKAGE);
  if (
    sha256(packageRaw) !== EXPECTED_PACKAGE_SHA256 ||
    sha512(packageRaw) !== EXPECTED_PACKAGE_SHA512
  ) {
    throw new Error("npm package digest mismatch");
  }
  const extract = spawnSync(
    "/bin/tar",
    ["-xzf", PACKAGE, "-C", join(ROOT, "package")],
    { encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 60_000 },
  );
  if (extract.status !== 0) {
    throw new Error(`package extraction failed: ${extract.stderr}`);
  }
  const sourceInventory = inventory(join(ROOT, "package", "package"));
  const runtimeTree = inventoryRuntime("/runtime");
  const packageRuntimeMatch = verifyPackageFiles(
    sourceInventory.files,
    "/runtime/lib/node_modules/openclaw",
  );

  const config = {
    agents: { defaults: { workspace: WORKSPACE } },
    security: {
      installPolicy: {
        enabled: true,
        exec: {
          args: ["/probe/probe.mjs", "policy"],
          command: "/usr/local/bin/node",
          maxOutputBytes: 4096,
          noOutputTimeoutMs: 5000,
          source: "exec",
          timeoutMs: 5000,
          trustedDirs: ["/probe", "/usr/local/bin"],
        },
        targets: ["skill"],
      },
    },
  };
  writeFileSync(
    join(STATE, "openclaw.json"),
    `${canonicalJson(config)}\n`,
    { mode: 0o600 },
  );

  const skill = [
    "---",
    "name: aragorn-probe",
    "description: Inert admission-conformance fixture.",
    "---",
    "# Aragorn probe",
    "",
  ].join("\n");
  writeFileSync(join(ROOT, "source", "SKILL.md"), skill, { mode: 0o600 });

  const version = command(["--version"], ROOT);
  if (version.exit_code !== 0 || version.stdout.trim() !== EXPECTED_VERSION) {
    throw new Error(`unexpected OpenClaw version: ${version.stdout.trim()}`);
  }

  rmSync(POLICY_REQUEST, { force: true });
  const installCommand = command([
    "skills",
    "install",
    join(ROOT, "source"),
    "--as",
    "probe",
  ]);
  const installRequest = readPolicyRequest();
  const installTargetExists = existsSync(join(WORKSPACE, "skills", "probe"));
  const installPassed =
    installCommand.exit_code === 1 &&
    installCommand.stderr.trim() ===
      "blocked by install policy: Aragorn conformance probe block" &&
    installRequest?.protocolVersion === 1 &&
    installRequest?.openclawVersion === "2026.7.1" &&
    installRequest?.targetType === "skill" &&
    installRequest?.targetName === "probe" &&
    installRequest?.request?.kind === "skill-install" &&
    installRequest?.request?.mode === "install" &&
    installRequest?.source?.kind === "local-path" &&
    !installTargetExists;

  rmSync(POLICY_REQUEST, { force: true });
  const directWriteTarget = join(WORKSPACE, "skills", "direct-write");
  mkdirSync(directWriteTarget, { recursive: true });
  writeFileSync(
    join(directWriteTarget, "SKILL.md"),
    skill.replace("name: aragorn-probe", "name: direct-write"),
    { mode: 0o600 },
  );
  const directWriteCommand = command([
    "skills",
    "info",
    "direct-write",
    "--json",
  ]);
  let directWriteInfo = null;
  try {
    directWriteInfo = JSON.parse(directWriteCommand.stdout);
  } catch {
    // The raw stream is retained below; a parse failure cannot become a bypass.
  }
  const directWritePolicyRequest = readPolicyRequest();
  const directWriteBypass =
    directWriteCommand.exit_code === 0 &&
    directWriteInfo?.name === "direct-write" &&
    directWriteInfo?.eligible === true &&
    directWriteInfo?.modelVisible === true &&
    directWriteInfo?.userInvocable === true &&
    directWriteInfo?.commandVisible === true &&
    directWriteInfo?.source === "openclaw-workspace" &&
    existsSync(directWriteTarget) &&
    directWritePolicyRequest === null;

  const isolation = {
    capabilities: [],
    cpus: 1,
    memory_bytes: 805306368,
    network: "none",
    no_new_privileges: true,
    nofile: 256,
    pids: 128,
    root_filesystem: "read-only",
    runtime_volume: "read-only",
    tmpfs: "/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
    user: "1000:1000",
  };
  const evidence = {
    schema: "aragorn/openclaw-admission-probe-evidence/v1",
    recorded_at: new Date().toISOString(),
    runtime: {
      commit: "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
      name: "openclaw",
      npm_attestations_sha256: sha256(
        readFileSync("/acquisition/npm-attestations.json"),
      ),
      npm_package_sha256: EXPECTED_PACKAGE_SHA256,
      npm_package_sha512: EXPECTED_PACKAGE_SHA512,
      npm_provenance_bundle_sha256: sha256(
        readFileSync("/acquisition/npm-provenance-bundle.json"),
      ),
      package_runtime_match: packageRuntimeMatch,
      runtime_tree: runtimeTree,
      source_tree: sourceInventory.summary,
      version: "2026.7.1",
      version_command: version,
    },
    adapter: {
      configuration: config,
      configuration_digest: sha256(
        Buffer.from(canonicalJson(config), "ascii"),
      ),
      implementation_digest: sha256(readFileSync(SELF)),
      implementation_path:
        "benchmark/admission/openclaw-v2026.7.1/probe.mjs",
    },
    environment: {
      architecture: process.arch,
      base_image:
        "docker.io/library/node:24-bookworm-slim@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf",
      isolation,
      node: process.version,
      os_profile_digest: sha256(
        Buffer.from(canonicalJson(isolation), "ascii"),
      ),
    },
    scenarios: [
      {
        command: installCommand,
        evidence: {
          policy_request: installRequest,
          target_exists_after: installTargetExists,
        },
        id: "ADM-02/install",
        status: installPassed ? "PASS" : "FAIL",
      },
      {
        command: directWriteCommand,
        evidence: {
          discovered_skill: directWriteInfo,
          policy_request: directWritePolicyRequest,
          target_exists_after: existsSync(directWriteTarget),
        },
        id: "ADM-02/direct-write",
        status: directWriteBypass ? "FAIL" : "NOT_TESTED",
      },
    ],
    decision: {
      candidate_eliminated: installPassed && directWriteBypass,
      installer_work_eligible: false,
      status: directWriteBypass ? "FAIL" : "NOT_TESTED",
    },
    limitations: [
      "ELIMINATION_RESULT_ONLY_NOT_PROFILE_QUALIFICATION",
      "UNEXECUTED_MANDATORY_SCENARIOS_REMAIN_NOT_TESTED",
    ],
  };
  process.stdout.write(`${canonicalJson(evidence)}\n`);
  process.exitCode = installPassed && directWriteBypass ? 0 : 2;
}

if (process.argv[2] === "policy") {
  policy();
} else {
  main();
}
