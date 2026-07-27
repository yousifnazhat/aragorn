#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const EXPECTED_VERSION = "OpenClaw 2026.7.1 (2d2ddc4)";
const OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs";
const BASELINE_PROBE = "/probe/probe.mjs";
const CONFIG = "/profile/config/openclaw.json";
const STATE = "/profile/state";
const WORKSPACE = "/profile/workspace";
const HOME = "/profile/home";
const ADMITTED_NAME = "aragorn-admitted";
const ADMITTED_FILE = join(STATE, "skills", ADMITTED_NAME, "SKILL.md");
const POLICY_REQUEST = join(STATE, "contained-policy-request.json");
const PRIOR_EVIDENCE_DIGEST =
  "sha256:c26c1a99f271c632254fb2865b8295714ac09a2dbba4a6cb29820939dde666a0";
const PRIOR_EVIDENCE_PATH =
  "benchmark/evidence/openclaw-v2026.7.1-admission-probe-2026-07-27.json";
const SELF = fileURLToPath(import.meta.url);
const PROFILE_ENV = {
  HOME,
  OPENCLAW_CONFIG_PATH: CONFIG,
  OPENCLAW_STATE_DIR: STATE,
  PATH: "/usr/local/bin:/usr/bin:/bin",
};
const SKILL = [
  "---",
  `name: ${ADMITTED_NAME}`,
  "description: Inert contained-profile fixture.",
  "---",
  "# Aragorn admitted fixture",
  "",
].join("\n");

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
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd,
    encoding: "utf8",
    env: PROFILE_ENV,
    maxBuffer: 16 * 1024 * 1024,
    timeout: 120_000,
  });
  return {
    argv: [process.execPath, script, ...args],
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

function parseCommand(result, label) {
  if (result.exit_code !== 0) {
    throw new Error(`${label} failed: ${result.stderr.trim()}`);
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`${label} did not return JSON`);
  }
}

function configuration() {
  const agent = {
    id: "main",
    skills: [ADMITTED_NAME],
    workspace: WORKSPACE,
  };
  return {
    agents: {
      defaults: {
        skills: [ADMITTED_NAME],
        workspace: WORKSPACE,
      },
      list: [agent],
    },
    plugins: { enabled: false },
    security: {
      installPolicy: {
        enabled: true,
        exec: {
          args: ["/probe/contained-probe.mjs", "policy"],
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
    skills: {
      load: {
        allowSymlinkTargets: [],
        extraDirs: [],
        watch: false,
      },
    },
  };
}

function prepare() {
  const config = configuration();
  const paths = {
    admitted: "/prepare/admitted",
    config: "/prepare/config",
    guard: "/prepare/guard",
  };
  for (const path of Object.values(paths)) {
    mkdirSync(path, { recursive: true });
  }
  mkdirSync(join(paths.admitted, ADMITTED_NAME), { recursive: true });
  mkdirSync(join(paths.guard, "skills"), { recursive: true });
  writeFileSync(
    join(paths.config, "openclaw.json"),
    `${canonicalJson(config)}\n`,
    { flag: "wx", mode: 0o444 },
  );
  writeFileSync(
    join(paths.admitted, ADMITTED_NAME, "SKILL.md"),
    SKILL,
    { flag: "wx", mode: 0o444 },
  );
  for (const path of [
    join(paths.admitted, ADMITTED_NAME),
    join(paths.guard, "skills"),
    ...Object.values(paths),
  ]) {
    chmodSync(path, 0o555);
  }
  process.stdout.write(
    `${canonicalJson({
      admitted_digest: sha256(Buffer.from(SKILL, "utf8")),
      config_digest: sha256(
        Buffer.from(canonicalJson(config), "ascii"),
      ),
      implementation_digest: sha256(readFileSync(SELF)),
      schema: "aragorn/openclaw-contained-profile-preparation/v1",
    })}\n`,
  );
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
      '{"decision":"block","protocolVersion":1,"reason":"Aragorn contained profile block"}',
    );
  });
}

function retainedBaseline() {
  const result = run(BASELINE_PROBE, [], "/tmp");
  if (result.exit_code !== 0) {
    throw new Error(`baseline probe failed: ${result.stderr.trim()}`);
  }
  const evidence = JSON.parse(result.stdout);
  if (
    evidence.schema !== "aragorn/openclaw-admission-probe-evidence/v1" ||
    evidence.decision?.status !== "FAIL" ||
    evidence.runtime?.version_command?.stdout?.trim() !== EXPECTED_VERSION
  ) {
    throw new Error("baseline probe identity or elimination result changed");
  }
  const retainedEvidence = {
    adapter: evidence.adapter,
    decision: evidence.decision,
    environment: evidence.environment,
    recorded_at: evidence.recorded_at,
    runtime: evidence.runtime,
    scenario_statuses: evidence.scenarios.map((scenario) => ({
      id: scenario.id,
      status: scenario.status,
    })),
    schema: evidence.schema,
  };
  return {
    command: summarizedCommand(result),
    digest: sha256(Buffer.from(result.stdout, "utf8")),
    evidence: retainedEvidence,
    prior_retained_evidence: {
      digest: PRIOR_EVIDENCE_DIGEST,
      path: PRIOR_EVIDENCE_PATH,
    },
  };
}

function makeSkill(directory, name) {
  mkdirSync(directory, { recursive: true });
  writeFileSync(
    join(directory, "SKILL.md"),
    SKILL.replace(`name: ${ADMITTED_NAME}`, `name: ${name}`),
    { mode: 0o600 },
  );
}

function attempt(id, operation, action) {
  try {
    action();
    return { blocked: false, id, operation };
  } catch (error) {
    return {
      blocked: true,
      code: error?.code ?? null,
      id,
      operation,
    };
  }
}

function profileSkill(info) {
  return {
    baseDir: info?.baseDir,
    blockedByAgentFilter: info?.blockedByAgentFilter,
    commandVisible: info?.commandVisible,
    eligible: info?.eligible,
    filePath: info?.filePath,
    modelVisible: info?.modelVisible,
    name: info?.name,
    source: info?.source,
    userInvocable: info?.userInvocable,
  };
}

function main() {
  const baseline = retainedBaseline();
  const configRaw = readFileSync(CONFIG);
  const config = JSON.parse(configRaw);
  if (canonicalJson(config) !== configRaw.toString("utf8").trim()) {
    throw new Error("contained configuration is not canonical");
  }

  const managedRoot = dirname(dirname(ADMITTED_FILE));
  if (
    readdirSync(managedRoot).join("\0") !== ADMITTED_NAME ||
    readdirSync(dirname(ADMITTED_FILE)).join("\0") !== "SKILL.md"
  ) {
    throw new Error("admitted root contains undeclared entries");
  }
  const admittedStat = lstatSync(ADMITTED_FILE);
  if (
    !admittedStat.isFile() ||
    admittedStat.isSymbolicLink() ||
    admittedStat.nlink !== 1
  ) {
    throw new Error("admitted skill is not one regular unlinked file");
  }
  const admittedRaw = readFileSync(ADMITTED_FILE);

  const version = command(["--version"]);
  if (version.exit_code !== 0 || version.stdout.trim() !== EXPECTED_VERSION) {
    throw new Error(`unexpected OpenClaw version: ${version.stdout.trim()}`);
  }
  const initialInfoCommand = command([
    "skills",
    "info",
    ADMITTED_NAME,
    "--json",
  ]);
  const initialInfo = parseCommand(initialInfoCommand, "initial admitted skill");
  const initialProfile = profileSkill(initialInfo);

  for (const path of [
    join(WORKSPACE, "ordinary.txt"),
    join(STATE, "ordinary.txt"),
    join(HOME, "ordinary.txt"),
  ]) {
    writeFileSync(path, "mutable profile state\n", { mode: 0o600 });
  }
  makeSkill(join(WORKSPACE, "not-a-discovery-root"), "outside-root");
  makeSkill("/tmp/not-a-discovery-root", "tmp-outside-root");

  const roots = [
    {
      discovery: join(WORKSPACE, "skills"),
      id: "workspace",
      mount: join(WORKSPACE, "skills"),
    },
    {
      discovery: join(WORKSPACE, ".agents", "skills"),
      id: "project-agents",
      mount: join(WORKSPACE, ".agents"),
    },
    {
      discovery: join(HOME, ".agents", "skills"),
      id: "personal-agents",
      mount: join(HOME, ".agents"),
    },
    {
      discovery: join(STATE, "skills"),
      id: "managed",
      mount: join(STATE, "skills"),
    },
    {
      discovery: join(STATE, "plugin-skills"),
      id: "plugin",
      mount: join(STATE, "plugin-skills"),
    },
    {
      discovery: "/runtime/lib/node_modules/openclaw/skills",
      id: "bundled",
      mount: "/runtime",
    },
  ].map((root) => ({
    ...root,
    discovery_realpath: realpathSync(root.discovery),
    mount_realpath: realpathSync(root.mount),
  }));

  const attempts = [];
  for (const root of roots) {
    const createName = `direct-${root.id}`;
    attempts.push(
      attempt(root.id, "create", () => {
        makeSkill(join(root.discovery, createName), createName);
      }),
    );

    const renameName = `rename-${root.id}`;
    const renameSource = join(WORKSPACE, `.rename-source-${root.id}`);
    makeSkill(renameSource, renameName);
    attempts.push(
      attempt(root.id, "rename-into-root", () => {
        renameSync(renameSource, join(root.discovery, renameName));
      }),
    );

    attempts.push(
      attempt(root.id, "symlink-into-root", () => {
        symlinkSync(
          join(WORKSPACE, "not-a-discovery-root"),
          join(root.discovery, `symlink-${root.id}`),
        );
      }),
    );

    if (root.mount !== "/runtime") {
      attempts.push(
        attempt(root.id, "retarget-mount", () => {
          renameSync(root.mount, `${root.mount}-retargeted`);
        }),
      );
    }
  }
  attempts.push(
    attempt("managed", "overwrite-admitted", () => {
      writeFileSync(ADMITTED_FILE, "changed\n");
    }),
  );

  makeSkill(join(WORKSPACE, "install-source"), "install-source");
  rmSync(POLICY_REQUEST, { force: true });
  const installCommand = command([
    "skills",
    "install",
    join(WORKSPACE, "install-source"),
    "--as",
    "install-probe",
  ]);
  const policyRequest = existsSync(POLICY_REQUEST)
    ? JSON.parse(readFileSync(POLICY_REQUEST, "utf8"))
    : null;
  const installPassed =
    installCommand.exit_code === 1 &&
    policyRequest?.protocolVersion === 1 &&
    policyRequest?.targetType === "skill" &&
    policyRequest?.request?.kind === "skill-install" &&
    !existsSync(join(WORKSPACE, "skills", "install-probe")) &&
    !existsSync(join(STATE, "skills", "install-probe"));

  const listCommand = command(["skills", "list", "--json"]);
  const list = parseCommand(listCommand, "contained skill list");
  const observedSkills = list.skills.map((skill) => ({
    blockedByAgentFilter: skill.blockedByAgentFilter,
    blockedByAllowlist: skill.blockedByAllowlist,
    commandVisible: skill.commandVisible,
    eligible: skill.eligible,
    modelVisible: skill.modelVisible,
    name: skill.name,
    source: skill.source,
  }));
  const effectiveSkills = observedSkills.filter(
    (skill) =>
      skill.blockedByAgentFilter !== true &&
      skill.blockedByAllowlist !== true &&
      (skill.eligible === true ||
        skill.modelVisible === true ||
        skill.commandVisible === true),
  );
  const injectedNames = new Set([
    "outside-root",
    "tmp-outside-root",
    "install-probe",
    ...roots.flatMap((root) => [
      `direct-${root.id}`,
      `rename-${root.id}`,
      `symlink-${root.id}`,
    ]),
  ]);
  const discoveredInjected = list.skills
    .filter((skill) => injectedNames.has(skill.name))
    .map((skill) => skill.name)
    .sort();

  const finalInfoCommand = command([
    "skills",
    "info",
    ADMITTED_NAME,
    "--json",
  ]);
  const finalInfo = parseCommand(finalInfoCommand, "restarted admitted skill");
  const finalProfile = profileSkill(finalInfo);
  const expectedProfile = {
    baseDir: dirname(ADMITTED_FILE),
    blockedByAgentFilter: false,
    commandVisible: true,
    eligible: true,
    filePath: ADMITTED_FILE,
    modelVisible: true,
    name: ADMITTED_NAME,
    source: "openclaw-managed",
    userInvocable: true,
  };

  const createPassed = attempts
    .filter((item) => ["create", "overwrite-admitted"].includes(item.operation))
    .every((item) => item.blocked);
  const renamePassed = attempts
    .filter((item) =>
      ["rename-into-root", "retarget-mount"].includes(item.operation),
    )
    .every((item) => item.blocked);
  const symlinkPassed = attempts
    .filter((item) => item.operation === "symlink-into-root")
    .every((item) => item.blocked);
  const exactBytesPassed =
    admittedRaw.equals(Buffer.from(SKILL, "utf8")) &&
    canonicalJson(initialProfile) === canonicalJson(expectedProfile) &&
    canonicalJson(finalProfile) === canonicalJson(expectedProfile) &&
    effectiveSkills.length === 1 &&
    effectiveSkills[0]?.name === ADMITTED_NAME;
  const autoDiscoveryPassed =
    discoveredInjected.length === 0 && effectiveSkills.length === 1;
  const restartPassed =
    canonicalJson(initialProfile) === canonicalJson(finalProfile);
  const createAttempts = attempts.filter((item) =>
    ["create", "overwrite-admitted"].includes(item.operation),
  );
  const renameAttempts = attempts.filter((item) =>
    ["rename-into-root", "retarget-mount"].includes(item.operation),
  );
  const symlinkAttempts = attempts.filter(
    (item) => item.operation === "symlink-into-root",
  );

  const scenarios = [
    {
      evidence: {
        admitted_digest: sha256(admittedRaw),
        effective_skills: effectiveSkills,
        final: finalProfile,
        initial: initialProfile,
      },
      id: "ADM-01/exact-admitted-bytes",
      status: exactBytesPassed ? "PASS" : "FAIL",
    },
    {
      command: installCommand,
      evidence: { policy_request: policyRequest },
      id: "ADM-02/install",
      status: installPassed ? "PASS" : "FAIL",
    },
    {
      evidence: { attempts: createAttempts },
      id: "ADM-02/direct-write",
      status: createPassed ? "PASS" : "FAIL",
    },
    {
      evidence: { attempts: renameAttempts },
      id: "ADM-02/rename",
      status: renamePassed ? "PASS" : "FAIL",
    },
    {
      evidence: { attempts: symlinkAttempts },
      id: "ADM-02/symlink",
      status: symlinkPassed ? "PASS" : "FAIL",
    },
    {
      command: summarizedCommand(listCommand),
      evidence: {
        discovered_injected: discoveredInjected,
        observed_skills: observedSkills,
      },
      id: "ADM-02/auto-discovery",
      status: autoDiscoveryPassed ? "PASS" : "FAIL",
    },
    {
      command: summarizedCommand(finalInfoCommand),
      evidence: { final: finalProfile, initial: initialProfile },
      id: "ADM-02/restart",
      status: restartPassed ? "PASS" : "FAIL",
    },
  ];
  const failed = scenarios.some((scenario) => scenario.status === "FAIL");
  const implementation = {
    baseline_probe_digest: sha256(readFileSync(BASELINE_PROBE)),
    contained_probe_digest: sha256(readFileSync(SELF)),
  };
  const evidence = {
    adapter: {
      configuration: config,
      configuration_digest: sha256(
        Buffer.from(canonicalJson(config), "ascii"),
      ),
      implementation,
      implementation_digest: sha256(
        Buffer.from(canonicalJson(implementation), "ascii"),
      ),
    },
    baseline,
    decision: {
      installer_work_eligible: false,
      status: failed ? "FAIL" : "NOT_TESTED",
    },
    limitations: [
      "OS_MEDIATED_PROFILE_NOT_NATIVE_OPENCLAW_REFERENCE_MONITOR",
      "DET_01_UPDATE_RELOAD_AND_ADM_03_REMAIN_NOT_TESTED",
      "EFFECTIVE_CONTAINER_INSPECTION_ADDED_BY_EVALUATOR",
    ],
    profile: {
      admitted: {
        digest: sha256(admittedRaw),
        path: ADMITTED_FILE,
      },
      config_digest: sha256(Buffer.from(canonicalJson(config), "ascii")),
      protected_roots: roots,
    },
    recorded_at: new Date().toISOString(),
    runtime: {
      commit: baseline.evidence.runtime.commit,
      name: "openclaw-contained",
      runtime_tree: baseline.evidence.runtime.runtime_tree,
      source_tree: baseline.evidence.runtime.source_tree,
      version: baseline.evidence.runtime.version,
      version_command: version,
    },
    scenarios,
    schema: "aragorn/openclaw-contained-profile-probe-evidence/v1",
  };
  process.stdout.write(`${canonicalJson(evidence)}\n`);
  process.exitCode = failed ? 2 : 0;
}

switch (process.argv[2]) {
  case "policy":
    policy();
    break;
  case "prepare":
    prepare();
    break;
  default:
    main();
}
