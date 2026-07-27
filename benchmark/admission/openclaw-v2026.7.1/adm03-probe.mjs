#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const CONTAINED_PROBE = "/probe/contained-probe.mjs";
const CONTAINED_EVIDENCE = "/tmp/contained-profile.json";
const POLICY_SCRIPT = CONTAINED_PROBE;
const CONFIG = "/profile/config/openclaw.json";
const STATE = "/profile/state";
const WORKSPACE = "/profile/workspace";
const HOME = "/profile/home";
const POLICY_REQUEST = join(STATE, "contained-policy-request.json");
const NODE = "/usr/local/bin/node";
const SELF = fileURLToPath(import.meta.url);
const PROFILE_ENV = {
  HOME,
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

function run(script, args, cwd = WORKSPACE) {
  const result = spawnSync(NODE, [script, ...args], {
    cwd,
    encoding: "utf8",
    env: PROFILE_ENV,
    maxBuffer: 16 * 1024 * 1024,
    timeout: 120_000,
  });
  return {
    argv: [NODE, script, ...args],
    exit_code: result.status,
    signal: result.signal,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    error: result.error?.message ?? null,
  };
}

function command(args) {
  return run(OPENCLAW, args);
}

function summarizedCommand(result) {
  const { stdout, ...summary } = result;
  const raw = Buffer.from(stdout, "utf8");
  return {
    ...summary,
    stdout_bytes: raw.length,
    stdout_digest: sha256(raw),
  };
}

function attempt(subject, operation, action) {
  try {
    action();
    return { blocked: false, operation, subject };
  } catch (error) {
    return {
      blocked: true,
      code: error?.code ?? null,
      operation,
      subject,
    };
  }
}

function targetAbsent(name) {
  return (
    !existsSync(join(WORKSPACE, "skills", name)) &&
    !existsSync(join(STATE, "skills", name))
  );
}

function main() {
  const containedRaw = readFileSync(CONTAINED_EVIDENCE);
  const contained = JSON.parse(containedRaw);
  if (
    contained.schema !==
      "aragorn/openclaw-contained-profile-probe-evidence/v1" ||
    contained.decision?.status !== "NOT_TESTED" ||
    !containedRaw.equals(
      Buffer.from(`${canonicalJson(contained)}\n`, "ascii"),
    )
  ) {
    throw new Error("contained profile replay identity changed");
  }

  const configRaw = readFileSync(CONFIG);
  const policyRaw = readFileSync(POLICY_SCRIPT);
  if (
    sha256(
      Buffer.from(canonicalJson(JSON.parse(configRaw)), "ascii"),
    ) !== contained.adapter.configuration_digest ||
    sha256(policyRaw) !==
      contained.adapter.implementation.contained_probe_digest
  ) {
    throw new Error("committed policy or configuration bytes changed");
  }

  rmSync(POLICY_REQUEST, { force: true, recursive: true });
  mkdirSync(POLICY_REQUEST, { mode: 0o700 });
  const failureName = "adm03-policy-failure";
  const failureCommand = command([
    "skills",
    "install",
    join(STATE, "skills", "aragorn-admitted"),
    "--as",
    failureName,
    "--agent",
    "main",
  ]);
  const failurePassed =
    failureCommand.exit_code === 1 &&
    failureCommand.stderr.includes(
      "install policy failed closed: policy command exited with code 1",
    ) &&
    targetAbsent(failureName);
  rmSync(POLICY_REQUEST, { force: true, recursive: true });

  const configReplacement = join(WORKSPACE, "config-replacement.json");
  const policyReplacement = join(WORKSPACE, "policy-replacement.mjs");
  writeFileSync(configReplacement, configRaw, { mode: 0o600 });
  writeFileSync(policyReplacement, policyRaw, { mode: 0o600 });
  const attempts = [
    attempt("config", "overwrite", () => writeFileSync(CONFIG, configRaw)),
    attempt("config", "chmod", () => chmodSync(CONFIG, 0o600)),
    attempt("config", "remove", () => rmSync(CONFIG)),
    attempt("config", "replace-by-rename", () =>
      renameSync(configReplacement, CONFIG),
    ),
    attempt("config", "create-symlink", () =>
      symlinkSync(configReplacement, join(dirname(CONFIG), "replacement")),
    ),
    attempt("config", "retarget-mount", () =>
      renameSync(dirname(CONFIG), `${dirname(CONFIG)}-retargeted`),
    ),
    attempt("policy-script", "overwrite", () =>
      writeFileSync(POLICY_SCRIPT, policyRaw),
    ),
    attempt("policy-script", "chmod", () => chmodSync(POLICY_SCRIPT, 0o600)),
    attempt("policy-script", "remove", () => rmSync(POLICY_SCRIPT)),
    attempt("policy-script", "replace-by-rename", () =>
      renameSync(policyReplacement, POLICY_SCRIPT),
    ),
    attempt("policy-script", "create-symlink", () =>
      symlinkSync(policyReplacement, join(dirname(POLICY_SCRIPT), "replacement")),
    ),
    attempt("policy-script", "retarget-mount", () =>
      renameSync(dirname(POLICY_SCRIPT), `${dirname(POLICY_SCRIPT)}-retargeted`),
    ),
    attempt("policy-command", "chmod", () => chmodSync(NODE, 0o700)),
    attempt("policy-command", "retarget-parent", () =>
      renameSync(dirname(NODE), `${dirname(NODE)}-retargeted`),
    ),
  ];
  const unchanged =
    sha256(readFileSync(CONFIG)) === sha256(configRaw) &&
    sha256(readFileSync(POLICY_SCRIPT)) === sha256(policyRaw);

  const tamperingName = "adm03-policy-tampering";
  const tamperingCommand = command([
    "skills",
    "install",
    join(STATE, "skills", "aragorn-admitted"),
    "--as",
    tamperingName,
    "--agent",
    "main",
  ]);
  const policyRequest = existsSync(POLICY_REQUEST)
    ? JSON.parse(readFileSync(POLICY_REQUEST, "utf8"))
    : null;
  const tamperingPassed =
    attempts.every((item) => item.blocked) &&
    unchanged &&
    tamperingCommand.exit_code === 1 &&
    tamperingCommand.stderr.includes(
      "blocked by install policy: Aragorn contained profile block",
    ) &&
    policyRequest?.protocolVersion === 1 &&
    policyRequest?.targetType === "skill" &&
    policyRequest?.request?.kind === "skill-install" &&
    targetAbsent(tamperingName);

  const scenarios = [
    {
      command: summarizedCommand(failureCommand),
      evidence: {
        policy_request_path_was_directory: true,
        target_absent: targetAbsent(failureName),
      },
      id: "ADM-03/policy-failure",
      status: failurePassed ? "PASS" : "FAIL",
    },
    {
      command: summarizedCommand(tamperingCommand),
      evidence: {
        attempts,
        config_digest_after: sha256(readFileSync(CONFIG)),
        config_digest_before: sha256(configRaw),
        policy_request: policyRequest,
        policy_script_digest_after: sha256(readFileSync(POLICY_SCRIPT)),
        policy_script_digest_before: sha256(policyRaw),
        target_absent: targetAbsent(tamperingName),
      },
      id: "ADM-03/policy-tampering",
      status: tamperingPassed ? "PASS" : "FAIL",
    },
  ];
  const implementation = {
    adm03_probe_digest: sha256(readFileSync(SELF)),
    baseline_probe_digest:
      contained.adapter.implementation.baseline_probe_digest,
    contained_probe_digest:
      contained.adapter.implementation.contained_probe_digest,
  };
  const failed =
    contained.scenarios.some((scenario) => scenario.status === "FAIL") ||
    scenarios.some((scenario) => scenario.status === "FAIL");
  const evidence = {
    adapter: {
      configuration: contained.adapter.configuration,
      configuration_digest: contained.adapter.configuration_digest,
      implementation,
      implementation_digest: sha256(
        Buffer.from(canonicalJson(implementation), "ascii"),
      ),
    },
    contained_profile: {
      digest: sha256(containedRaw),
      evidence: contained,
    },
    decision: {
      installer_work_eligible: false,
      status: failed ? "FAIL" : "NOT_TESTED",
    },
    limitations: [
      "DET_01_ADM_01_UPDATE_RELOAD_AND_RESTART_REMAIN_NOT_TESTED",
      "DOCKER_HOST_ROOT_AND_CROSS_HOST_TAMPERING_NOT_TESTED",
      "TAMPER_RESISTANCE_SCOPED_TO_UNPRIVILEGED_CONTAINER_UID_1000",
    ],
    recorded_at: new Date().toISOString(),
    runtime: contained.runtime,
    scenarios,
    schema: "aragorn/openclaw-contained-adm03-probe-evidence/v1",
  };
  process.stdout.write(`${canonicalJson(evidence)}\n`);
  process.exitCode = failed ? 2 : 0;
}

main();
