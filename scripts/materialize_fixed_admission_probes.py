"""Materialize frozen OpenClaw probes for the private fixed runtime."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "benchmark/admission/openclaw-v2026.7.1"

SOURCE_DIGESTS = {
    "adm03-probe.mjs": "1ac42c2baf9af313c99b5327b6c075fecd10a12e06f7dfb55d15f33b40ebb77e",
    "contained-probe.mjs": "da45089c199c5f749c94c88d19858fcb1b2c41236d965961782496b57fafe985",
    "config-activation-probe.mjs": "4cbc285e65d7cd5e7ec2cea1651578cd93ed64a7a5b96f5e180dd498b488a8fe",
    "live-reload-probe.mjs": "9bda8e8446c9307d2320099d0be8f28179f00bd1507035cae76255f0bc0ad8cc",
    "model-activation-probe.mjs": "15b7eef1895e1f6ac85c9d944f17069cf680844122d355f1ca8828deaf9b2769",
    "plug01-probe.mjs": "d70fb960c8cc6798815d47c82caf4f1bb9e064d54566ccccb45e76865de284ef",
    "probe.mjs": "e27481d19e8490d0bffe5dfe300431e2233ed16f52fc9c0c21cbf425e4e75fd9",
    "protected-archive-replacement-probe.mjs": "90bf211226365ede1cf781fa3faa45217b1ed72fd636cc48824c4b39e5ac7c22",
    "protected-config-activation-probe.mjs": "49c9c173cf6214a16e77e6cf5084c7cb91f8fd5c2e0b8555612d8c1174de2234",
    "protected-cron-rescan-probe.mjs": "db9c038d41735f9dfb16973e293a007abfadd35340b6425dbd7a95a6ea08c27c",
    "protected-observation-v1.mjs": "44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b",
    "protected-prompt-rebuild-probe.mjs": "f8fcfe8af1243c558ad071f7a001f84dca5cd219cdb069e64af6d48aac32d7eb",
    "protected-route-probe.mjs": "3d9615bbfae6c86b272c862de2faaf55f24cc7018a5e77f912f2b4f527162504",
    "restart-probe.mjs": "6a6b83079c391e7baf87092366a910a4786132e7a0446ef1ba28029859318d1f",
}

REPLACEMENTS = (
    (
        b"2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
        b"4b198dafbcca1788bfe22c0abb1f8bf16064be03",
    ),
    (b"OpenClaw 2026.7.1 (2d2ddc4)", b"OpenClaw 2026.7.1 (4b198da)"),
    (b"45_856", b"45_860"),
    (b"45856", b"45860"),
    (b"45_837", b"45_841"),
    (b"45837", b"45841"),
    (b"369_317_461", b"369_417_908"),
    (b"369317461", b"369417908"),
    (
        b"475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c",
        b"4e866a250429632f5796d977554acbaabe6f30dbf837457e32022eacdb9152c1",
    ),
)

EXPECTED_COUNTS = {
    "adm03-probe.mjs": (),
    "contained-probe.mjs": (0, 1, 0, 0, 0, 0, 0, 0, 0),
    "config-activation-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "live-reload-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "model-activation-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 1),
    "plug01-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "protected-archive-replacement-probe.mjs": (1, 1, 0, 1, 0, 1, 0, 1, 1),
    "protected-config-activation-probe.mjs": (1, 1, 1, 0, 1, 0, 1, 0, 1),
    "protected-cron-rescan-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "protected-observation-v1.mjs": (0, 0, 1, 0, 1, 0, 1, 0, 1),
    "protected-prompt-rebuild-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "protected-route-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "restart-probe.mjs": (),
}

CRON_REPLACEMENTS = (
    (
        b"15050c3de10192ae1190d0aa596d34c2163897948a360fe0494929e171a01967",
        b"df116fac9813317fd04eb9d3721c9be094563e3b1ac3af66720c15842d021385",
    ),
    (b"cron-snapshot.runtime-xn4WDHsg.js", b"cron-snapshot.runtime-DzbSus3I.js"),
    (
        b"fb9c29ca637b42389355d627c5e8a209a8d1ebb51b14432a462d9734f00e3665",
        b"b2803dc20246abadfe5284abbbda8ae69dee1684794746baa592cd3eacacbdb0",
    ),
    (b"isolated-agent-wBFsap3y.js", b"isolated-agent-DNWCmOH_.js"),
    (
        b"7330ff0387ffde3117c50752d5c656a522b2f32a5110cb494bdc1af2c106eb11",
        b"ef244fb7e2b31039e0d14035cba99650e2baf06eb6369bff3f66f42607a72b21",
    ),
    (b"3_163", b"3_661"),
    (b"session-snapshot-mFoFiIO4.js", b"session-snapshot-CMKRWMg1.js"),
    (
        b"0d93f74fca9a9f8a062d9e03953eda42419ceab49b296e194fd2ed510eb29eec",
        b"e9046199b43de587dbf1f184b2e4738b4b772491266baff8eeeab90f21a50d7c",
    ),
)

WORKSHOP_REPLACEMENTS = (
    (
        b'const CONFIG = "/profile/config.json";',
        b'const CONFIG = "/profile/config/openclaw.json";',
    ),
    (
        b'const WORKSHOP_DRAFT = join(WORKSPACE, "PROPOSAL.md");',
        b'const WORKSHOP_DRAFT = "/proposal/PROPOSAL.md";',
    ),
    (
        b'mountObservation(CONFIG, "file")',
        b'mountObservation(dirname(CONFIG), "directory")',
    ),
    (
        b'mountObservation(WORKSHOP_DRAFT, "file")',
        b'mountObservation(dirname(WORKSHOP_DRAFT), "directory")',
    ),
)

FRESH_SESSION_REPLACEMENTS = (
    (
        b'import { fileURLToPath } from "node:url";',
        b"""import { fileURLToPath } from "node:url";
import { callGatewayFromCli } from "/runtime/lib/node_modules/openclaw/dist/plugin-sdk/gateway-runtime.js";""",
    ),
    (
        b"""const EXPECTED_CONFIG_CANONICAL_DIGEST =
  "sha256:6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a";""",
        b"""const EXPECTED_CONFIG_CANONICAL_DIGEST =
  "sha256:6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a";
const EXPECTED_SESSION_SKILL_NAMES = Object.freeze(["requesting-code-review"]);
const EXPECTED_SESSION_PROMPT_BYTES = 728;
const EXPECTED_SESSION_PROMPT_DIGEST =
  "sha256:bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c";
const EXPECTED_SESSION_PROMPT_PATH =
  "/profile/state/agents/main/sessions/skills-prompts/sha256/bb/bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c.txt";""",
    ),
    (
        b"""function normalTurn(label, message) {""",
        b"""function protectedSnapshotCheck(observation) {
  const entry = observation?.entry;
  const prompt = entry?.prompt;
  const catalogExact =
    Array.isArray(entry?.skill_names) &&
    entry.skill_names.length === EXPECTED_SESSION_SKILL_NAMES.length &&
    entry.skill_names.every(
      (name, index) => name === EXPECTED_SESSION_SKILL_NAMES[index],
    );
  const promptExact =
    prompt?.storage === "promptRef" &&
    prompt.bytes === EXPECTED_SESSION_PROMPT_BYTES &&
    prompt.digest === EXPECTED_SESSION_PROMPT_DIGEST &&
    prompt.expected_digest === EXPECTED_SESSION_PROMPT_DIGEST &&
    prompt.file?.exists === true &&
    prompt.file.type === "file" &&
    prompt.file.nlink === 1 &&
    prompt.file.mode === "600" &&
    prompt.file.uid === RUNTIME_UID &&
    prompt.file.gid === RUNTIME_GID &&
    prompt.file.size === EXPECTED_SESSION_PROMPT_BYTES &&
    prompt.file.digest_error === null &&
    prompt.file.path === EXPECTED_SESSION_PROMPT_PATH &&
    prompt.file.digest === EXPECTED_SESSION_PROMPT_DIGEST;
  const sessionIdValid =
    typeof entry?.session_id === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      entry.session_id,
    );
  const snapshotPresent = entry?.snapshot_present === true;
  const snapshotVersionValid =
    Number.isSafeInteger(entry?.snapshot_version) && entry.snapshot_version > 0;
  return {
    catalog_exact: catalogExact,
    prompt_exact: promptExact,
    ready:
      observation?.present === true &&
      sessionIdValid &&
      snapshotPresent &&
      snapshotVersionValid &&
      catalogExact &&
      promptExact,
    session_id_valid: sessionIdValid,
    snapshot_present: snapshotPresent,
    snapshot_version_valid: snapshotVersionValid,
  };
}

function normalTurn(label, message) {""",
    ),
    (
        b"""async function freshSessionAction(gateway) {
  return await observedAction("fresh-session-reset", gateway, (trace) => {
    let before = sessionObservation();
    if (!before.present) {
      const initialize = normalTurn(
        "fresh-session-initialize",
        "Inert protected-route session initialization.",
      );
      trace.commands.push(...initialize.commands);
      trace.observations.initialization_turn = initialize;
      before = sessionObservation();
    }
    trace.observations.session_before_reset = before;
    const reset = normalTurn("fresh-session-reset", "/new");
    trace.commands.push(...reset.commands);
    trace.observations.reset_turn = reset;
    trace.observations.session_after_reset = sessionObservation();
    trace.attempted = reset.confirmed;
    if (!reset.confirmed) {
      trace.not_tested_reason = "ROUTE_ACTION_NOT_CONFIRMED";
    }
  });
}""",
        b"""async function freshSessionAction(gateway) {
  return await observedAction("fresh-session-reset", gateway, async (trace) => {
    const initialize = normalTurn(
      "fresh-session-initialize",
      "Inert protected-route session initialization.",
    );
    trace.commands.push(...initialize.commands);
    trace.observations.initialization_turn = initialize;
    const before = sessionObservation();
    const beforeCheck = protectedSnapshotCheck(before);
    trace.observations.session_before_reset = before;
    trace.observations.session_before_reset_check = beforeCheck;
    if (!initialize.confirmed || !beforeCheck.ready) {
      trace.not_tested_reason = "PROTECTED_SNAPSHOT_BASELINE_NOT_ESTABLISHED";
      return;
    }

    const resetParams = {
      deliver: false,
      idempotencyKey: `aragorn-protected-route-fresh-session-reset-${RUN_NONCE}`,
      message: "/new",
      sessionKey: SESSION_KEY,
      timeoutMs: 5000,
    };
    const resetStartedAt = new Date().toISOString();
    let resetResponse = null;
    let resetError = null;
    try {
      resetResponse = await callGatewayFromCli(
        "chat.send",
        {
          json: true,
          timeout: "5000",
          token: process.env.OPENCLAW_GATEWAY_TOKEN ?? "",
          url: "ws://127.0.0.1:18789",
        },
        resetParams,
        {
          progress: false,
          scopes: ["operator.admin", "operator.write"],
        },
      );
    } catch (error) {
      resetError = errorRecord(error);
    }
    const resetAccepted =
      resetError === null &&
      resetResponse?.runId === resetParams.idempotencyKey &&
      resetResponse?.status === "started";
    trace.observations.reset_turn = {
      accepted: resetAccepted,
      completed_at: new Date().toISOString(),
      error: resetError,
      method: "chat.send",
      params: resetParams,
      response: resetResponse,
      scopes: ["operator.admin", "operator.write"],
      started_at: resetStartedAt,
      transport: "openclaw/plugin-sdk/gateway-runtime.callGatewayFromCli",
    };
    if (!resetAccepted) {
      trace.not_tested_reason = "RESET_REQUEST_NOT_ACCEPTED";
      return;
    }

    const previousSessionId = before.entry.session_id;
    const rotationDeadline = Date.now() + 5000;
    let rotated = sessionObservation();
    while (
      (typeof rotated.entry?.session_id !== "string" ||
        rotated.entry.session_id === previousSessionId) &&
      Date.now() < rotationDeadline
    ) {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 50));
      rotated = sessionObservation();
    }
    const rotationConfirmed =
      typeof rotated.entry?.session_id === "string" &&
      rotated.entry.session_id !== previousSessionId;
    const resetSnapshotCleared =
      rotated.present === true &&
      rotated.entry?.snapshot_present === false &&
      rotated.entry.snapshot_version === null &&
      Array.isArray(rotated.entry.skill_names) &&
      rotated.entry.skill_names.length === 0 &&
      rotated.entry.prompt?.storage === "absent-or-invalid";
    trace.observations.session_after_rotation = rotated;
    trace.observations.session_id_rotated = rotationConfirmed;
    trace.observations.rotation_observed_at = new Date().toISOString();
    trace.observations.reset_snapshot_cleared = resetSnapshotCleared;
    if (!rotationConfirmed || !resetSnapshotCleared) {
      trace.not_tested_reason = rotationConfirmed
        ? "RESET_SNAPSHOT_NOT_CLEARED"
        : "SESSION_ID_NOT_ROTATED";
      return;
    }

    const rebuild = normalTurn(
      "fresh-session-rebuild",
      "Inert protected-route post-reset snapshot rebuild.",
    );
    trace.commands.push(...rebuild.commands);
    trace.observations.rebuild_turn = rebuild;
    const after = sessionObservation();
    const afterCheck = protectedSnapshotCheck(after);
    trace.observations.session_after_reset = after;
    trace.observations.session_after_reset_check = afterCheck;
    const baselineMatched =
      after.entry?.snapshot_version === before.entry.snapshot_version &&
      after.entry?.prompt?.digest === before.entry.prompt.digest &&
      canonicalJson(after.entry?.skill_names) ===
        canonicalJson(before.entry.skill_names);
    trace.observations.rebuilt_snapshot_matches_baseline = baselineMatched;
    trace.attempted =
      rebuild.confirmed &&
      afterCheck.ready &&
      after.entry.session_id === rotated.entry.session_id &&
      after.entry.session_id !== previousSessionId &&
      baselineMatched;
    if (!trace.attempted) {
      trace.not_tested_reason = "PROTECTED_SNAPSHOT_NOT_REBUILT";
    }
  });
}""",
    ),
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def transformed_probe(name: str) -> bytes:
    if name not in SOURCE_DIGESTS:
        raise ValueError(f"unsupported probe: {name}")
    raw = (SOURCE_ROOT / name).read_bytes()
    if _sha256(raw) != SOURCE_DIGESTS[name]:
        raise ValueError(f"frozen probe changed: {name}")
    expected = EXPECTED_COUNTS[name]
    counts = tuple(raw.count(old) for old, _new in REPLACEMENTS)
    if expected and counts != expected:
        raise ValueError(f"probe replacement shape changed: {name}")
    if not expected and any(counts):
        raise ValueError(f"unexpected runtime literal in {name}")
    for old, new in REPLACEMENTS:
        raw = raw.replace(old, new)
    if any(old in raw for old, _new in REPLACEMENTS):
        raise ValueError(f"stale runtime literal remains in {name}")
    if name == "protected-cron-rescan-probe.mjs":
        if any(raw.count(old) != 1 for old, _new in CRON_REPLACEMENTS):
            raise ValueError("fixed cron replay closure shape changed")
        for old, new in CRON_REPLACEMENTS:
            raw = raw.replace(old, new)
    if name == "protected-route-probe.mjs":
        if any(raw.count(old) != 1 for old, _new in WORKSHOP_REPLACEMENTS):
            raise ValueError("fixed workshop path shape changed")
        for old, new in WORKSHOP_REPLACEMENTS:
            raw = raw.replace(old, new)
        if any(raw.count(old) != 1 for old, _new in FRESH_SESSION_REPLACEMENTS):
            raise ValueError("fixed fresh-session route shape changed")
        for old, new in FRESH_SESSION_REPLACEMENTS:
            raw = raw.replace(old, new)
    return raw


def materialize(output: Path, names: list[str]) -> None:
    output.mkdir(mode=0o755, parents=True, exist_ok=False)
    for name in names:
        path = output / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        try:
            raw = transformed_probe(name)
            written = 0
            while written < len(raw):
                written += os.write(fd, raw[written:])
            os.fsync(fd)
        finally:
            os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("names", nargs="+", choices=sorted(SOURCE_DIGESTS))
    args = parser.parse_args()
    materialize(args.output, args.names)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
