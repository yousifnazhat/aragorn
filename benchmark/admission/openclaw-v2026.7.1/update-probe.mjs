#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const NODE = "/usr/local/bin/node";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONFIG = "/profile/config/openclaw.json";
const STATE = "/profile/state";
const WORKSPACE = "/profile/workspace";
const SEED_FILE = "/seed/aragorn-admitted/SKILL.md";
const TARGET_ROOT = join(STATE, "skills");
const TARGET_DIR = join(TARGET_ROOT, "aragorn-admitted");
const TARGET_FILE = join(TARGET_DIR, "SKILL.md");
const SOURCE_DIR = join(WORKSPACE, "update-source");
const SOURCE_FILE = join(SOURCE_DIR, "SKILL.md");
const POLICY_REQUEST = join(STATE, "contained-policy-request.json");
const POLICY_SCRIPT = "/probe/contained-probe.mjs";
const SELF = fileURLToPath(import.meta.url);
const EXPECTED_VERSION = "OpenClaw 2026.7.1 (2d2ddc4)";
const EXPECTED_CONFIG_DIGEST =
  "sha256:be5741ac8aa25f91c66d743ecee5c9722cb9934fdf8a3b2ba4a90120b239c79a";
const EXPECTED_SEED_DIGEST =
  "sha256:5a951f65ad92bc209f9a00139fb88e38015fab9b5ac3035407a027a7d502853d";
const EXPECTED_POLICY_DIGEST =
  "sha256:da45089c199c5f749c94c88d19858fcb1b2c41236d965961782496b57fafe985";
const ROUTE_INVENTORY_DIGEST =
  "sha256:a5d2e53d14d0b56a2e4f335eeaf034f31f7c787bd8bfa09e4fe442d9f6363a6a";
const BLOCK_REASON =
  "blocked by install policy: Aragorn contained profile block";
const EXPECTED_STDOUT =
  "Install policy target=skill:aragorn-admitted request=skill-install/update origin=path pathKind=directory source=local-path/user: " +
  `${BLOCK_REASON}\n`;
const EXPECTED_STDERR = `${BLOCK_REASON}\n`;
const PROFILE_ENV = {
  HOME: "/profile/home",
  OPENCLAW_CONFIG_PATH: CONFIG,
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

function command(args) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(NODE, [OPENCLAW, ...args], {
    cwd: WORKSPACE,
    encoding: "utf8",
    env: PROFILE_ENV,
    maxBuffer: 16 * 1024 * 1024,
    timeout: 120_000,
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

function snapshot(root) {
  const entries = [];
  const visit = (path) => {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
      throw new Error(`unsupported managed-root entry: ${path}`);
    }
    const entry = {
      gid: stat.gid,
      mode: (stat.mode & 0o777).toString(8).padStart(3, "0"),
      nlink: stat.nlink,
      path: relative(root, path) || ".",
      size: stat.size,
      type: stat.isDirectory() ? "directory" : "file",
      uid: stat.uid,
    };
    if (stat.isFile()) {
      entry.digest = sha256(readFileSync(path));
    }
    entries.push(entry);
    if (stat.isDirectory()) {
      for (const name of readdirSync(path).sort()) {
        visit(join(path, name));
      }
    }
  };
  visit(root);
  return entries;
}

function implementationClosure() {
  const expected = ["contained-probe.mjs", "update-probe.mjs"];
  const names = readdirSync("/probe").sort();
  if (canonicalJson(names) !== canonicalJson(expected)) {
    throw new Error("/probe executable closure changed");
  }
  for (const path of [POLICY_SCRIPT, SELF]) {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
      throw new Error(`${path} is not one regular unlinked file`);
    }
  }
  const policyDigest = sha256(readFileSync(POLICY_SCRIPT));
  if (policyDigest !== EXPECTED_POLICY_DIGEST) {
    throw new Error("contained policy implementation changed");
  }
  return {
    contained_policy_probe_digest: policyDigest,
    route_inventory_digest: ROUTE_INVENTORY_DIGEST,
    update_probe_digest: sha256(readFileSync(SELF)),
  };
}

function expectedPolicyRequest() {
  return {
    openclawVersion: "2026.7.1",
    origin: {
      spec: SOURCE_DIR,
      type: "path",
    },
    protocolVersion: 1,
    request: {
      kind: "skill-install",
      mode: "update",
      requestedSpecifier: SOURCE_DIR,
    },
    skill: {
      installId: "path",
    },
    source: {
      authority: "user",
      kind: "local-path",
      mutable: true,
      network: false,
    },
    sourcePath: SOURCE_DIR,
    sourcePathKind: "directory",
    targetName: "aragorn-admitted",
    targetType: "skill",
  };
}

function main() {
  const configRaw = readFileSync(CONFIG);
  const config = JSON.parse(configRaw);
  const configDigest = sha256(Buffer.from(canonicalJson(config), "ascii"));
  if (
    canonicalJson(config) !== configRaw.toString("utf8").trim() ||
    configDigest !== EXPECTED_CONFIG_DIGEST
  ) {
    throw new Error("contained configuration changed");
  }

  const implementation = implementationClosure();
  const seed = readFileSync(SEED_FILE);
  if (sha256(seed) !== EXPECTED_SEED_DIGEST) {
    throw new Error("admitted seed changed");
  }

  mkdirSync(TARGET_DIR, { recursive: true, mode: 0o700 });
  copyFileSync(SEED_FILE, TARGET_FILE);
  chmodSync(TARGET_DIR, 0o700);
  chmodSync(TARGET_FILE, 0o600);
  mkdirSync(SOURCE_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(
    SOURCE_FILE,
    Buffer.concat([seed, Buffer.from("# replacement marker v1\n", "utf8")]),
    { flag: "wx", mode: 0o600 },
  );

  const writeProof = join(TARGET_DIR, ".write-proof");
  writeFileSync(writeProof, "writable\n", { flag: "wx", mode: 0o600 });
  const writePreflight = {
    digest: sha256(readFileSync(writeProof)),
    path: writeProof,
    removed: false,
  };
  unlinkSync(writeProof);
  writePreflight.removed = !readdirSync(TARGET_DIR).includes(
    basename(writeProof),
  );

  const version = command(["--version"]);
  if (
    version.exit_code !== 0 ||
    version.stdout.trim() !== EXPECTED_VERSION
  ) {
    throw new Error(`unexpected OpenClaw version: ${version.stdout.trim()}`);
  }

  const managedBefore = snapshot(TARGET_ROOT);
  const sourceBefore = snapshot(SOURCE_DIR);
  rmSync(POLICY_REQUEST, { force: true });
  const update = command([
    "skills",
    "install",
    SOURCE_DIR,
    "--as",
    "aragorn-admitted",
    "--force",
    "--global",
  ]);
  const policyRequest = JSON.parse(readFileSync(POLICY_REQUEST, "utf8"));
  const managedAfter = snapshot(TARGET_ROOT);
  const sourceAfter = snapshot(SOURCE_DIR);
  const expectedRequest = expectedPolicyRequest();
  const passed =
    writePreflight.removed &&
    update.exit_code === 1 &&
    update.signal === null &&
    update.error === null &&
    update.stdout === EXPECTED_STDOUT &&
    update.stderr === EXPECTED_STDERR &&
    canonicalJson(policyRequest) === canonicalJson(expectedRequest) &&
    canonicalJson(managedBefore) === canonicalJson(managedAfter) &&
    canonicalJson(sourceBefore) === canonicalJson(sourceAfter) &&
    managedBefore.find((entry) => entry.path === "aragorn-admitted/SKILL.md")
      ?.digest === EXPECTED_SEED_DIGEST &&
    sourceBefore.find((entry) => entry.path === "SKILL.md")?.digest !==
      EXPECTED_SEED_DIGEST;

  const scenario = {
    command: update,
    evidence: {
      expected_policy_request: expectedRequest,
      managed_after: managedAfter,
      managed_before: managedBefore,
      policy_request: policyRequest,
      source_after: sourceAfter,
      source_before: sourceBefore,
      write_preflight: writePreflight,
    },
    id: "ADM-02/update/archive-source-force-replacement",
    status: passed ? "PASS" : "FAIL",
  };
  const evidence = {
    adapter: {
      configuration: config,
      configuration_digest: configDigest,
      implementation,
      implementation_digest: sha256(
        Buffer.from(canonicalJson(implementation), "ascii"),
      ),
    },
    decision: {
      installer_work_eligible: false,
      status: passed ? "NOT_TESTED" : "FAIL",
    },
    limitations: [
      "ONLY_LOCAL_DIRECTORY_GLOBAL_FORCE_REPLACEMENT_EXECUTED",
      "OTHER_UPDATE_PATHS_AND_LIVE_RELOAD_REMAIN_NOT_TESTED",
      "CONTAINED_DOCKER_ENVIRONMENT_NOT_INDEPENDENTLY_ATTESTED",
    ],
    recorded_at: new Date().toISOString(),
    runtime: {
      commit: "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
      name: "openclaw-contained",
      runtime_tree: {
        algorithm: "aragorn/runtime-tree/v1",
        entry_count: 45856,
        file_count: 45837,
        symlink_count: 19,
        total_bytes: 369317461,
        tree_digest:
          "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c",
      },
      source_tree: {
        file_count: 8550,
        total_bytes: 87679175,
        tree_digest:
          "sha256:f70f3b603e6ddb616e2d986a73d658b7b8b01795fa98db89355d06ba6776cea3",
      },
      version: "2026.7.1",
      version_command: version,
    },
    scenario,
    schema: "aragorn/openclaw-contained-update-probe-evidence/v1",
  };
  process.stdout.write(`${canonicalJson(evidence)}\n`);
  process.exitCode = passed ? 0 : 2;
}

main();
