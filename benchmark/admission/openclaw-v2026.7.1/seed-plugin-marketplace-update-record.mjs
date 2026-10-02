// Fresh owned fixture bootstrap only; not an install or policy override.
import fs from "node:fs";
import { createHash } from "node:crypto";

const state = "/var/lib/aragorn-agent-gateway/state";
const id = "aragorn-plugin-skill-replacement-fixture";
const input = "/route-input/plugin-package-skill-replacement";
const modulePath = "/runtime/lib/node_modules/openclaw/dist/installed-plugin-index-records-NrU3hnwq.js";
const readerPath = "/runtime/lib/node_modules/openclaw/dist/installed-plugin-index-record-reader-CrcykudU.js";
const sha = (raw) => createHash("sha256").update(raw).digest("hex");
const record = {
  source: "marketplace",
  marketplaceSource: input + "/marketplace.json",
  marketplacePlugin: id,
  installPath: state + "/extensions/" + id,
  version: "1.0.0",
};
const stable = (value) => JSON.stringify(value, Object.keys(value).sort());

try {
  if (process.argv.length !== 2 || process.getuid() !== 992 || process.getgid() !== 992 ||
      JSON.stringify(process.getgroups()) !== "[992]" || process.env.OPENCLAW_STATE_DIR !== state ||
      fs.realpathSync(modulePath) !== modulePath ||
      sha(fs.readFileSync(modulePath)) !== "5500445dcd66876952758eec91019a3c4dcc4a852498f956022828f0f867d21f") {
    throw new Error("identity");
  }
  const raw = fs.readFileSync(0);
  if (raw.length > 65536) throw new Error("input");
  const config = JSON.parse(raw);
  if (config.plugins?.allow?.includes(id) || config.plugins?.entries?.[id] || config.plugins?.installs) {
    throw new Error("fixture config");
  }
  const { t: read } = await import(readerPath);
  const { s: write } = await import(modulePath);
  const before = await read({ stateDir: state });
  if (Object.keys(before).length !== 0) throw new Error("not fresh");
  await write({ [id]: record }, { stateDir: state, config,
    workspaceDir: "/var/lib/aragorn-agent-gateway/workspace" });
  // Writer clears the reader cache through the store refresh.
  const after = await read({ stateDir: state });
  if (Object.keys(after).length !== 1 || stable(after[id]) !== stable(record)) throw new Error("readback");
  process.stdout.write("ARAGORN_OWNED_MARKETPLACE_RECORD_SEEDED\n");
} catch {
  process.stderr.write("ARAGORN_MARKETPLACE_SEED_REFUSED\n");
  process.exitCode = 126;
}
