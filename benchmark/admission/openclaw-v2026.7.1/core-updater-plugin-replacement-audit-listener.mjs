import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const DIST = "/runtime/lib/node_modules/openclaw/dist";
const JOURNAL =
  "/var/lib/aragorn-agent-gateway/state/core-updater-policy-audit.jsonl";
const PLUGIN_ID = "aragorn-runtime-action-worker";

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

if (canonicalJson({ omitted: undefined, retained: true }) !== '{"retained":true}') {
  throw new Error("audit canonical JSON invariant failed");
}

function sha256(raw) {
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

function locateTrustedDiagnosticModule() {
  const matches = [];
  for (const name of readdirSync(DIST).sort()) {
    if (!/^diagnostic-events-[A-Za-z0-9_-]+\.js$/.test(name)) {
      continue;
    }
    const path = join(DIST, name);
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > 2 * 1024 * 1024) {
      continue;
    }
    const raw = readFileSync(path);
    const source = raw.toString("utf8");
    if (
      !source.includes("function onTrustedInternalDiagnosticEvent(listener)") ||
      !source.includes("state.trustedListeners.add(listener)")
    ) {
      continue;
    }
    const aliases = [
      ...source.matchAll(
        /onTrustedInternalDiagnosticEvent as ([A-Za-z_$][A-Za-z0-9_$]*)/g,
      ),
    ].map((match) => match[1]);
    if (aliases.length !== 1) {
      throw new Error("trusted diagnostic export shape changed");
    }
    matches.push({
      alias: aliases[0],
      bytes: raw.length,
      digest: sha256(raw),
      path,
    });
  }
  if (matches.length !== 1) {
    throw new Error("trusted diagnostic module is not an exact singleton");
  }
  return matches[0];
}

if (process.env.ARAGORN_CORE_UPDATER_AUDIT_PATH !== JOURNAL) {
  throw new Error("core-updater audit journal path changed");
}

const diagnosticModule = locateTrustedDiagnosticModule();
const imported = await import(pathToFileURL(diagnosticModule.path).href);
const subscribe = imported[diagnosticModule.alias];
if (typeof subscribe !== "function") {
  throw new Error("trusted diagnostic subscription is not callable");
}

subscribe((event, metadata) => {
  if (
    event?.type !== "security.event" ||
    event?.category !== "plugin" ||
    event?.action !== "plugin.audit.failed" ||
    event?.target?.name !== PLUGIN_ID
  ) {
    return;
  }
  if (canonicalJson(metadata) !== canonicalJson({ trusted: true })) {
    throw new Error("plugin audit event lacks exact trusted diagnostic metadata");
  }
  writeFileSync(
    JOURNAL,
    `${canonicalJson({ diagnostic_module: diagnosticModule, event, metadata })}\n`,
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );
});
