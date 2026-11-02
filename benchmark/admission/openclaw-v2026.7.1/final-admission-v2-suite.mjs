#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalJson,
  runtimeTree,
} from "./protected-observation-v1.mjs";

const SELF = fileURLToPath(import.meta.url);
const SELF_ROOT = resolve(SELF, "..");
const OBSERVATION_HELPER = join(SELF_ROOT, "protected-observation-v1.mjs");
const REQUIRED_ENV = Object.freeze([
  "ARAGORN_CONFIG_PATH",
  "ARAGORN_PROBE_ROOT",
  "ARAGORN_PROFILE_PATH",
  "ARAGORN_RUNTIME_LOCK_PATH",
  "ARAGORN_RUNTIME_ROOT",
  "ARAGORN_RUN_NONCE",
  "ARAGORN_SKILL_PATH",
]);
const ROUTE_IDS = Object.freeze([
  "ADM-02/update/archive-source-force-replacement",
  "ADM-02/update/clawhub-tracked-replacement",
  "ADM-02/update/config-entry-activation",
  "ADM-02/update/core-updater-plugin-replacement",
  "ADM-02/update/curator-restore-activation",
  "ADM-02/update/plugin-enable-activation",
  "ADM-02/update/plugin-force-reinstall",
  "ADM-02/update/plugin-package-skill-replacement",
  "ADM-02/update/workshop-proposal-apply",
  "ADM-02/reload/chat-session-snapshot-consumer",
  "ADM-02/reload/config-invalidation",
  "ADM-02/reload/cron-rescan",
  "ADM-02/reload/filesystem-watch-invalidation",
  "ADM-02/reload/fresh-session-reset",
  "ADM-02/reload/manual-plugin-invalidation",
  "ADM-02/reload/missing-prompt-blob-rebuild",
  "ADM-02/reload/plugin-skill-dir-activation",
  "ADM-02/reload/remote-eligibility-invalidation",
  "ADM-02/reload/sandbox-per-run-rescan",
  "ADM-02/reload/session-snapshot-consumer",
  "ADM-02/reload/workshop-invalidation",
]);
const PROPERTY_IDS = Object.freeze([
  "DET-01",
  "ADM-01/exact-admitted-bytes",
]);
const CATEGORY_IDS = Object.freeze([
  "ADM-02/install",
  "ADM-02/update",
  "ADM-02/direct-write",
  "ADM-02/rename",
  "ADM-02/symlink",
  "ADM-02/auto-discovery",
  "ADM-02/reload",
  "ADM-02/restart",
]);
const ADM03_IDS = Object.freeze([
  "ADM-03/policy-failure",
  "ADM-03/policy-tampering",
]);
const MAIN_PROBES = Object.freeze([
  "broker-symlink-probe.mjs",
  "config-activation-probe.mjs",
  "contained-probe.mjs",
  "live-reload-probe.mjs",
  "model-activation-probe.mjs",
  "plug01-probe.mjs",
  "pre-effect-write-probe.mjs",
  "probe.mjs",
  "protected-archive-replacement-probe.mjs",
  "protected-config-activation-probe.mjs",
  "protected-cron-rescan-probe.mjs",
  "protected-curator-restore-denial-probe.mjs",
  "protected-prompt-rebuild-probe.mjs",
  "protected-route-probe.mjs",
  "protected-session-snapshot-fixed-probe.mjs",
  "protected-session-snapshot-probe.mjs",
  "restart-probe.mjs",
  "update-probe.mjs",
  "workshop-bypass-probe.mjs",
]);
const ADM03_PROBES = Object.freeze(["adm03-probe.mjs"]);
const STATUS = new Set(["FAIL", "NOT_TESTED", "OBSERVED"]);
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REASON = /^[A-Z][A-Z0-9_]{2,127}$/;
const BOUND_EVIDENCE_SCHEMA =
  "aragorn/openclaw-final-admission-v2-bound-evidence/v1";
const EXPECTED = Object.freeze({
  configuration: {
    canonical_digest:
      "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e",
    digest:
      "sha256:d145feb4e935e6f86c7e2bfdeefcaec5fa4ebf8f044ffa472bd7589b03bf4fe8",
  },
  observation_helper_digest:
    "sha256:44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b",
  profile: {
    canonical_digest:
      "sha256:a20ab2dd6572ada5fac086bc818495a6e6079f55f6fcbae397687c7b19eac59e",
    digest:
      "sha256:615928c74bb467ed1422aa19c0ca3266fec21e6a9b195ff32e7e2fae86f966fc",
  },
  runtime: {
    entrypoint_digest:
      "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188",
    source_commit: "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
    tree_digest:
      "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154",
  },
  runtime_lock: {
    canonical_digest:
      "sha256:95f6088dfe227e27e136c7a1fb79688e0afa0ea3ac543137d7089d0a79f2eff9",
    digest:
      "sha256:4832dc99c016bd8c0f6d97133dbb7d3681d4ad18c1c225c94f10a51d6df839c1",
  },
  skill: {
    bytes: 140,
    digest:
      "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa",
  },
});
const ELIGIBILITY = Object.freeze({
  admission_profile_eligible: false,
  aggregate_admission_eligible: false,
  edr_eligible: false,
  installer_work_eligible: false,
  phase3_exit_eligible: false,
  release_eligible: false,
  run_01_eligible: false,
  run_02_eligible: false,
  run_eligible: false,
});

function sha256(raw) {
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

function fail(message) {
  throw new Error(message);
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(`${label} keys changed`);
  }
  return value;
}

function exactArray(actual, expected, label) {
  if (!Array.isArray(actual) || canonicalJson(actual) !== canonicalJson(expected)) {
    fail(`${label} changed`);
  }
}

function regularFile(path, label, maxBytes = 32 * 1024 * 1024) {
  if (!isAbsolute(path)) {
    fail(`${label} path must be absolute`);
  }
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    fail(`${label} must be one regular non-symlink file`);
  }
  if (metadata.size < 1 || metadata.size > maxBytes) {
    fail(`${label} byte size is outside the accepted bound`);
  }
  const raw = readFileSync(path);
  return { digest: sha256(raw), path: realpathSync(path), raw };
}

function directory(path, label) {
  if (!isAbsolute(path)) {
    fail(`${label} path must be absolute`);
  }
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail(`${label} must be a non-symlink directory`);
  }
  return realpathSync(path);
}

function jsonSource(path, label, expected) {
  const source = regularFile(path, label);
  let document;
  try {
    document = JSON.parse(source.raw.toString("utf8"));
  } catch (error) {
    fail(`${label} is not JSON: ${error.message}`);
  }
  const canonical = Buffer.from(canonicalJson(document), "utf8");
  if (!source.raw.equals(Buffer.concat([canonical, Buffer.from("\n")]))) {
    fail(`${label} is not canonical JSON plus LF`);
  }
  const identity = {
    canonical_digest: sha256(canonical),
    digest: source.digest,
  };
  if (canonicalJson(identity) !== canonicalJson(expected)) {
    fail(`${label} identity changed`);
  }
  return { document, identity, source };
}

function environment() {
  const actual = Object.keys(process.env)
    .filter((key) => key.startsWith("ARAGORN_"))
    .sort();
  exactArray(actual, REQUIRED_ENV, "ARAGORN environment");
  for (const key of REQUIRED_ENV) {
    if (typeof process.env[key] !== "string" || process.env[key].length === 0) {
      fail(`${key} is required`);
    }
  }
  if (!/^[0-9a-f]{64}$/.test(process.env.ARAGORN_RUN_NONCE)) {
    fail("ARAGORN_RUN_NONCE must be exactly 32 random bytes in lowercase hex");
  }
  return Object.fromEntries(REQUIRED_ENV.map((key) => [key, process.env[key]]));
}

function pluginBinding(lock) {
  const plugin = lock.deployment_bindings?.aragorn_plugin;
  exactKeys(plugin, ["files", "id", "source"], "runtime lock plugin");
  exactKeys(plugin.source, ["commit", "commit_signature", "tree"], "plugin source");
  if (plugin.id !== "aragorn-runtime-action-worker") {
    fail("runtime lock plugin id changed");
  }
  if (!Array.isArray(plugin.files) || plugin.files.length !== 3) {
    fail("runtime lock plugin files changed");
  }
  const files = plugin.files.map((file, index) => {
    exactKeys(file, ["digest", "path"], `plugin files[${index}]`);
    if (!DIGEST.test(file.digest) || typeof file.path !== "string") {
      fail(`plugin files[${index}] is invalid`);
    }
    const installed = regularFile(file.path, `installed plugin file ${index}`);
    if (installed.digest !== file.digest) {
      fail(`installed plugin file ${index} identity changed`);
    }
    return { digest: file.digest, path: file.path };
  });
  return {
    files,
    id: plugin.id,
    source_commit: plugin.source.commit,
    source_tree: plugin.source.tree,
  };
}

function sourceBindings(env) {
  const configuration = jsonSource(
    env.ARAGORN_CONFIG_PATH,
    "configuration",
    EXPECTED.configuration,
  );
  const profile = jsonSource(
    env.ARAGORN_PROFILE_PATH,
    "profile",
    EXPECTED.profile,
  );
  const runtimeLock = jsonSource(
    env.ARAGORN_RUNTIME_LOCK_PATH,
    "runtime lock",
    EXPECTED.runtime_lock,
  );
  const skill = regularFile(env.ARAGORN_SKILL_PATH, "skill", 4096);
  if (skill.digest !== EXPECTED.skill.digest || skill.raw.length !== EXPECTED.skill.bytes) {
    fail("skill identity changed");
  }
  const runtimeRoot = directory(env.ARAGORN_RUNTIME_ROOT, "runtime root");
  const probeRoot = directory(env.ARAGORN_PROBE_ROOT, "probe root");
  const lock = runtimeLock.document;
  const installed = lock.installed_runtime;
  const lockedRoot = installed?.root;
  const lockedEntrypoint = installed?.openclaw_path;
  if (
    typeof lockedRoot !== "string" ||
    typeof lockedEntrypoint !== "string" ||
    !isAbsolute(lockedRoot) ||
    !isAbsolute(lockedEntrypoint)
  ) {
    fail("runtime lock installed runtime paths are invalid");
  }
  const relativeEntrypoint = relative(lockedRoot, lockedEntrypoint);
  if (
    relativeEntrypoint.length === 0 ||
    relativeEntrypoint === ".." ||
    relativeEntrypoint.startsWith(`..${sep}`) ||
    isAbsolute(relativeEntrypoint)
  ) {
    fail("runtime lock entrypoint escapes its runtime root");
  }
  const entrypoint = regularFile(
    join(runtimeRoot, relativeEntrypoint),
    "runtime entrypoint",
    256 * 1024 * 1024,
  );
  const observationHelper = regularFile(
    OBSERVATION_HELPER,
    "protected observation helper",
  );
  if (
    entrypoint.digest !== EXPECTED.runtime.entrypoint_digest ||
    observationHelper.digest !== EXPECTED.observation_helper_digest ||
    installed.openclaw_digest !== EXPECTED.runtime.entrypoint_digest ||
    installed.runtime_tree?.tree_digest !== EXPECTED.runtime.tree_digest ||
    lock.source?.commit !== EXPECTED.runtime.source_commit ||
    profile.document.runtime?.commit !== EXPECTED.runtime.source_commit ||
    lock.deployment_bindings?.configuration?.digest !== configuration.identity.digest ||
    lock.deployment_bindings?.configuration?.canonical_digest !==
      configuration.identity.canonical_digest ||
    lock.deployment_bindings?.skill_source?.digest !== skill.digest ||
    configuration.document.skills?.allowBundled?.length !== 1 ||
    configuration.document.skills.allowBundled[0] !== "template-skill" ||
    configuration.document.skills?.activation?.sources?.length !== 1 ||
    configuration.document.skills.activation.sources[0]?.sha256 !==
      skill.digest.slice("sha256:".length)
  ) {
    fail("V2 runtime, configuration, profile, lock, or skill binding changed");
  }
  exactArray(
    profile.document.routes?.map((route) => route.id),
    ROUTE_IDS,
    "profile route ids",
  );
  if (profile.document.routes.some((route) => route.outcome !== "NOT_TESTED")) {
    fail("source V2 profile unexpectedly promotes a route");
  }
  return {
    bindings: {
      configuration: configuration.identity,
      plugin: pluginBinding(lock),
      profile: profile.identity,
      runtime: EXPECTED.runtime,
      runtime_lock: runtimeLock.identity,
      skill: { digest: skill.digest },
      suite: {
        digest: sha256(readFileSync(SELF)),
        observation_helper_digest: observationHelper.digest,
      },
    },
    paths: {
      probe_root: probeRoot,
      runtime_root: runtimeRoot,
    },
  };
}

function verifyRuntime(runtimeRoot) {
  const observed = runtimeTree(runtimeRoot);
  if (canonicalJson(observed) !== canonicalJson({
    algorithm: "aragorn/runtime-tree/v1",
    entry_count: 45860,
    file_count: 45841,
    symlink_count: 19,
    total_bytes: 369443243,
    tree_digest: EXPECTED.runtime.tree_digest,
  })) {
    fail("installed runtime tree changed");
  }
  return { root: runtimeRoot, tree: observed };
}

function probeInventory(names) {
  return names.map((name) => {
    if (name.includes("/") || name.includes("\\")) {
      fail("probe module name is invalid");
    }
    const source = regularFile(join(SELF_ROOT, name), `probe module ${name}`);
    return { digest: source.digest, name };
  });
}

function manifest(env, source) {
  return {
    assurance: "BOUND_INPUT_CONTRACT_ONLY_NOT_CONFORMANCE_AUTHORITY",
    bindings: source.bindings,
    contract: {
      adm03: {
        allowed_probe_modules: probeInventory(ADM03_PROBES),
        filename: "adm03-input.json",
        scenario_ids: ADM03_IDS,
        schema: "aragorn/openclaw-final-admission-v2-adm03-input/v1",
      },
      bound_evidence_schema: BOUND_EVIDENCE_SCHEMA,
      environment: REQUIRED_ENV,
      main: {
        allowed_probe_modules: probeInventory(MAIN_PROBES),
        category_ids: CATEGORY_IDS,
        filename: "main-input.json",
        property_ids: PROPERTY_IDS,
        route_ids: ROUTE_IDS,
        schema: "aragorn/openclaw-final-admission-v2-main-input/v1",
      },
      row_statuses: [...STATUS].sort(),
    },
    decision: { ...ELIGIBILITY, status: "NOT_TESTED" },
    limitations: [
      "MANIFEST_IS_AN_INPUT_CONTRACT_NOT_RUNTIME_EVIDENCE",
      "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
    ],
    mode: "manifest",
    run_nonce: env.ARAGORN_RUN_NONCE,
    schema: "aragorn/openclaw-final-admission-v2-manifest/v1",
  };
}

function safeEvidencePath(root, relativePath, label) {
  if (
    typeof relativePath !== "string" ||
    !relativePath.startsWith("artifacts/") ||
    isAbsolute(relativePath) ||
    relativePath.includes("\\") ||
    relativePath.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    fail(`${label} path is invalid`);
  }
  const path = join(root, relativePath);
  const source = regularFile(path, label);
  const contained = relative(root, source.path);
  if (contained === ".." || contained.startsWith(`..${sep}`) || isAbsolute(contained)) {
    fail(`${label} escapes probe root`);
  }
  return source;
}

function rejectEligibility(value, label = "observation") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectEligibility(item, `${label}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") {
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    if (key.endsWith("_eligible") && item !== false) {
      fail(`${label} contains promoted eligibility`);
    }
    rejectEligibility(item, `${label}.${key}`);
  }
}

function evidenceArtifacts(input, mode, root, bindings, allowedProbes) {
  if (!Array.isArray(input.artifacts) || input.artifacts.length > 128) {
    fail(`${mode} artifacts must be a bounded array`);
  }
  const byDigest = new Map();
  const paths = new Set();
  for (const [index, record] of input.artifacts.entries()) {
    exactKeys(record, ["digest", "path", "schema"], `${mode} artifacts[${index}]`);
    if (
      !DIGEST.test(record.digest) ||
      record.schema !== BOUND_EVIDENCE_SCHEMA ||
      paths.has(record.path) ||
      byDigest.has(record.digest)
    ) {
      fail(`${mode} artifacts[${index}] is invalid or duplicated`);
    }
    const source = safeEvidencePath(root, record.path, `${mode} artifact ${record.path}`);
    if (source.digest !== record.digest) {
      fail(`${mode} artifact digest changed: ${record.path}`);
    }
    let document;
    try {
      document = JSON.parse(source.raw.toString("utf8"));
    } catch (error) {
      fail(`${mode} artifact is not JSON: ${error.message}`);
    }
    if (!source.raw.equals(Buffer.from(`${canonicalJson(document)}\n`, "utf8"))) {
      fail(`${mode} artifact is not canonical JSON plus LF: ${record.path}`);
    }
    exactKeys(
      document,
      [
        "bindings",
        "mode",
        "observation",
        "probe_digest",
        "probe_module",
        "run_nonce",
        "schema",
      ],
      `${mode} bound evidence`,
    );
    if (
      document.schema !== BOUND_EVIDENCE_SCHEMA ||
      document.mode !== mode ||
      document.run_nonce !== input.run_nonce ||
      canonicalJson(document.bindings) !== canonicalJson(bindings) ||
      !allowedProbes.includes(document.probe_module)
    ) {
      fail(`${mode} artifact is unbound: ${record.path}`);
    }
    const probe = regularFile(
      join(SELF_ROOT, document.probe_module),
      `${mode} artifact probe module`,
    );
    if (document.probe_digest !== probe.digest) {
      fail(`${mode} artifact probe digest changed: ${record.path}`);
    }
    if (!document.observation || typeof document.observation !== "object") {
      fail(`${mode} artifact observation must be an object`);
    }
    if (
      "run_nonce" in document.observation &&
      document.observation.run_nonce !== input.run_nonce
    ) {
      fail(`${mode} artifact observation nonce changed: ${record.path}`);
    }
    rejectEligibility(document.observation);
    paths.add(record.path);
    byDigest.set(record.digest, {
      digest: record.digest,
      observation: document.observation,
      path: record.path,
      probe_digest: document.probe_digest,
      probe_module: document.probe_module,
      schema: document.schema,
    });
  }
  return byDigest;
}

function rows(value, expectedIds, label, artifacts) {
  if (!Array.isArray(value) || value.length !== expectedIds.length) {
    fail(`${label} must contain exactly ${expectedIds.length} rows`);
  }
  const seenRefs = new Set();
  const normalized = value.map((row, index) => {
    exactKeys(
      row,
      ["evidence_refs", "id", "reason_codes", "status"],
      `${label}[${index}]`,
    );
    if (row.id !== expectedIds[index] || !STATUS.has(row.status)) {
      fail(`${label}[${index}] identity or status changed`);
    }
    if (
      !Array.isArray(row.reason_codes) ||
      new Set(row.reason_codes).size !== row.reason_codes.length ||
      row.reason_codes.some((reason) => typeof reason !== "string" || !REASON.test(reason))
    ) {
      fail(`${label}[${index}] reason codes are invalid`);
    }
    if (
      !Array.isArray(row.evidence_refs) ||
      new Set(row.evidence_refs).size !== row.evidence_refs.length ||
      row.evidence_refs.some((digest) => !DIGEST.test(digest) || !artifacts.has(digest))
    ) {
      fail(`${label}[${index}] evidence references are invalid`);
    }
    if (
      (row.status === "NOT_TESTED" &&
        (row.reason_codes.length === 0 || row.evidence_refs.length !== 0)) ||
      (row.status !== "NOT_TESTED" && row.evidence_refs.length === 0)
    ) {
      fail(`${label}[${index}] status is not supported by its evidence`);
    }
    row.evidence_refs.forEach((digest) => seenRefs.add(digest));
    return {
      evidence_refs: [...row.evidence_refs],
      id: row.id,
      reason_codes: [...row.reason_codes],
      status: row.status,
    };
  });
  return { normalized, seenRefs };
}

function inputFile(source, mode) {
  const filename = mode === "main" ? "main-input.json" : "adm03-input.json";
  const path = join(source.paths.probe_root, filename);
  const input = jsonSourceUnpinned(path, `${mode} input`);
  return { filename, ...input };
}

function jsonSourceUnpinned(path, label) {
  const source = regularFile(path, label);
  let document;
  try {
    document = JSON.parse(source.raw.toString("utf8"));
  } catch (error) {
    fail(`${label} is not JSON: ${error.message}`);
  }
  if (!source.raw.equals(Buffer.from(`${canonicalJson(document)}\n`, "utf8"))) {
    fail(`${label} is not canonical JSON plus LF`);
  }
  return { document, source };
}

function counts(groups) {
  const output = { FAIL: 0, NOT_TESTED: 0, OBSERVED: 0 };
  for (const group of groups) {
    group.forEach((row) => {
      output[row.status] += 1;
    });
  }
  return output;
}

function aggregateMain(env, source) {
  const input = inputFile(source, "main");
  const document = input.document;
  exactKeys(
    document,
    [
      "artifacts",
      "bindings",
      "formal_categories",
      "mode",
      "properties",
      "routes",
      "run_nonce",
      "schema",
    ],
    "main input",
  );
  if (
    document.schema !== "aragorn/openclaw-final-admission-v2-main-input/v1" ||
    document.mode !== "main" ||
    document.run_nonce !== env.ARAGORN_RUN_NONCE ||
    canonicalJson(document.bindings) !== canonicalJson(source.bindings)
  ) {
    fail("main input is unbound");
  }
  const artifacts = evidenceArtifacts(
    document,
    "main",
    source.paths.probe_root,
    source.bindings,
    MAIN_PROBES,
  );
  const properties = rows(document.properties, PROPERTY_IDS, "properties", artifacts);
  const categories = rows(
    document.formal_categories,
    CATEGORY_IDS,
    "formal categories",
    artifacts,
  );
  const routes = rows(document.routes, ROUTE_IDS, "routes", artifacts);
  const used = new Set([
    ...properties.seenRefs,
    ...categories.seenRefs,
    ...routes.seenRefs,
  ]);
  if (used.size !== artifacts.size) {
    fail("main input contains unreferenced evidence");
  }
  const outcomeCounts = counts([
    properties.normalized,
    categories.normalized,
    routes.normalized,
  ]);
  const runtime = verifyRuntime(source.paths.runtime_root);
  return {
    assurance: "BOUND_RAW_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY",
    bindings: source.bindings,
    decision: {
      ...ELIGIBILITY,
      outcome_counts: outcomeCounts,
      status: outcomeCounts.FAIL > 0 ? "FAIL" : "NOT_TESTED",
    },
    evidence: [...artifacts.values()],
    formal_categories: categories.normalized,
    input: {
      digest: input.source.digest,
      path: input.filename,
      schema: document.schema,
    },
    limitations: [
      "OBSERVED_IS_NOT_PASS",
      "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
      "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
    ],
    mode: "main",
    properties: properties.normalized,
    routes: routes.normalized,
    run_nonce: env.ARAGORN_RUN_NONCE,
    runtime_verification: runtime,
    schema: "aragorn/openclaw-final-admission-v2-main-observation/v1",
  };
}

function aggregateAdm03(env, source) {
  const input = inputFile(source, "adm03");
  const document = input.document;
  exactKeys(
    document,
    ["artifacts", "bindings", "mode", "run_nonce", "scenarios", "schema"],
    "adm03 input",
  );
  if (
    document.schema !== "aragorn/openclaw-final-admission-v2-adm03-input/v1" ||
    document.mode !== "adm03" ||
    document.run_nonce !== env.ARAGORN_RUN_NONCE ||
    canonicalJson(document.bindings) !== canonicalJson(source.bindings)
  ) {
    fail("adm03 input is unbound");
  }
  const artifacts = evidenceArtifacts(
    document,
    "adm03",
    source.paths.probe_root,
    source.bindings,
    ADM03_PROBES,
  );
  const scenarios = rows(document.scenarios, ADM03_IDS, "adm03 scenarios", artifacts);
  if (scenarios.seenRefs.size !== artifacts.size) {
    fail("adm03 input contains unreferenced evidence");
  }
  const outcomeCounts = counts([scenarios.normalized]);
  const runtime = verifyRuntime(source.paths.runtime_root);
  return {
    assurance: "ISOLATED_BOUND_RAW_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY",
    bindings: source.bindings,
    decision: {
      ...ELIGIBILITY,
      outcome_counts: outcomeCounts,
      status: outcomeCounts.FAIL > 0 ? "FAIL" : "NOT_TESTED",
    },
    evidence: [...artifacts.values()],
    input: {
      digest: input.source.digest,
      path: input.filename,
      schema: document.schema,
    },
    limitations: [
      "OBSERVED_IS_NOT_PASS",
      "ADM_03_SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
      "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
    ],
    mode: "adm03",
    run_nonce: env.ARAGORN_RUN_NONCE,
    runtime_verification: runtime,
    scenarios: scenarios.normalized,
    schema: "aragorn/openclaw-final-admission-v2-adm03-observation/v1",
  };
}

function emit(document) {
  process.stdout.write(`${canonicalJson(document)}\n`);
}

function errorRecord(error, mode) {
  return {
    assurance: "FAIL_CLOSED_NO_CONFORMANCE_AUTHORITY",
    decision: { ...ELIGIBILITY, status: "FAIL_CLOSED" },
    fatal_error: {
      message: error instanceof Error ? error.message : String(error),
      name: error instanceof Error ? error.name : "Error",
    },
    mode,
    schema: "aragorn/openclaw-final-admission-v2-suite-error/v1",
  };
}

let mode = process.argv[2] ?? null;
try {
  if (process.argv.length !== 3 || !["adm03", "main", "manifest"].includes(mode)) {
    fail("usage: final-admission-v2-suite.mjs manifest|main|adm03");
  }
  const env = environment();
  const source = sourceBindings(env);
  if (mode === "manifest") {
    emit(manifest(env, source));
  } else if (mode === "main") {
    emit(aggregateMain(env, source));
  } else {
    emit(aggregateAdm03(env, source));
  }
} catch (error) {
  emit(errorRecord(error, mode));
  process.exitCode = 2;
}
