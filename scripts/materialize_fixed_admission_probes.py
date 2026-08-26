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

RESTORE_AUTHORITY_CONFIG_REPLACEMENTS = (
    (
        b"4b198dafbcca1788bfe22c0abb1f8bf16064be03",
        b"805a4b152b0cee271ee78ad5608c15a4f8d1624b",
    ),
    (b"OpenClaw 2026.7.1 (4b198da)", b"OpenClaw 2026.7.1 (805a4b1)"),
    (b"45_860", b"45_859"),
    (b"45_841", b"45_840"),
    (b"369_417_908", b"369_418_625"),
    (
        b"4e866a250429632f5796d977554acbaabe6f30dbf837457e32022eacdb9152c1",
        b"6448edb21fd2a27dd3cf2b740e0d0dfc3a395e2ccae446853867a95485d54e74",
    ),
    (
        b"ec2b2022ed27f62840583d31264826c88514a04e7e7cc94d78820b021d6288b6",
        b"701da2485f2844603c13b40c56876984de5ff9cdc22927f1a5bcd218ba369751",
    ),
    (
        b"6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a",
        b"417fc06b87a539654433451aff12509ca7dca28003c9f2cedc91bcc611eba16e",
    ),
)

RESTORE_AUTHORITY_ARCHIVE_REPLACEMENTS = (
    (b"45860", b"45859"),
    (b"45841", b"45840"),
    (b"369417908", b"369418625"),
)

RESTORE_AUTHORITY_CRON_REPLACEMENTS = (
    (b"result.runAtMs === runEpoch", b"runEpoch <= result.runAtMs"),
    (
        b"0e3346d4397db7675073c7f80599aa312a1819b0f5a6480a8ba194b296c78144",
        b"ad9cde2c065d5d4d69f465193007a435c0cd0b378d253329238dd36fdc70f849",
    ),
    (b"cron-BoFeDMVi.js", b"cron-DOr4RFbn.js"),
    (
        b"df116fac9813317fd04eb9d3721c9be094563e3b1ac3af66720c15842d021385",
        b"f76a2799c0e012a39fd12c5ce4245c92f0afa74fd30a1cddec506af092733a60",
    ),
    (
        b"b2803dc20246abadfe5284abbbda8ae69dee1684794746baa592cd3eacacbdb0",
        b"661385d87db47117e9e49e41b01fcfe07aacea32326de09f6764c2568bc2620d",
    ),
    (b"cron-snapshot.runtime-DzbSus3I.js", b"cron-snapshot.runtime-DrQirS_k.js"),
    (
        b"ef244fb7e2b31039e0d14035cba99650e2baf06eb6369bff3f66f42607a72b21",
        b"0b7aa925514a2c44babb98dedfd11de28733fbd853b361716860adca340923d7",
    ),
    (b"isolated-agent-DNWCmOH_.js", b"isolated-agent-2U26aOeI.js"),
    (
        b"59a2138c9906cffe26e67ad662d1a35d835c10d8d8742a2cb928fc529df81e3b",
        b"edd138bac24f7fbc0e08013e1be9e4962f12d530ef5462efa0a1d82d4b475784",
    ),
    (b"session-B4NuLEbl.js", b"session-CagbPApz.js"),
    (
        b"e9046199b43de587dbf1f184b2e4738b4b772491266baff8eeeab90f21a50d7c",
        b"d8a1bd6c3ee26b981e5cfe6e7756a91263fd40c4727e1bdb0e69171b8458cb28",
    ),
    (b"session-snapshot-CMKRWMg1.js", b"session-snapshot-8MgHKMdq.js"),
    (
        b"ee73b5621ff0fa5d198cb39a54eb6fa332d1f96897e4151538415eef7a72846c",
        b"f4e73f5c7a111fe2ed4d953c54f96ff9e9e4ad2ba962cf7f00afd141c8d125c2",
    ),
    (b"workspace-BKXau6p-.js", b"workspace-CKU1tzCf.js"),
)

RESTORE_AUTHORITY_PROBE_COUNTS = {
    "protected-archive-replacement-probe.mjs": (1, 1, 0, 0, 0, 1, 1, 1),
    "protected-config-activation-probe.mjs": (1,) * 8,
    "protected-cron-rescan-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0),
    "protected-observation-v1.mjs": (0, 0, 1, 1, 1, 1, 1, 1),
    "protected-prompt-rebuild-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0),
    "protected-route-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 1),
}

RESTORE_AUTHORITY_SELECTIONS = frozenset(
    {
        frozenset({"protected-archive-replacement-probe.mjs"}),
        frozenset({"protected-config-activation-probe.mjs"}),
        frozenset({"protected-route-probe.mjs"}),
        frozenset(
            {
                "protected-cron-rescan-probe.mjs",
                "protected-observation-v1.mjs",
            }
        ),
        frozenset(
            {
                "protected-observation-v1.mjs",
                "protected-prompt-rebuild-probe.mjs",
            }
        ),
    }
)

FINAL_COMBINED_SOURCE_DIGESTS = {
    **{name: SOURCE_DIGESTS[name] for name in RESTORE_AUTHORITY_PROBE_COUNTS},
    "protected-curator-restore-denial-probe.mjs": (
        "ecc2649b40cc9e6106181a12a31b12999a596d634f7a1ee9cc658adc70c9192a"
    ),
    "protected-session-snapshot-fixed-probe.mjs": (
        "1efe13c3beb3ac2ff6fc1293aa64875c95424f1576a10b12943f0b875af223e2"
    ),
}

FINAL_COMBINED_SELECTIONS = frozenset(
    {
        frozenset({"protected-archive-replacement-probe.mjs"}),
        frozenset({"protected-config-activation-probe.mjs"}),
        frozenset({"protected-route-probe.mjs"}),
        frozenset(
            {
                "protected-curator-restore-denial-probe.mjs",
                "protected-observation-v1.mjs",
            }
        ),
        frozenset(
            {
                "protected-observation-v1.mjs",
                "protected-session-snapshot-fixed-probe.mjs",
            }
        ),
        frozenset(
            {
                "protected-observation-v1.mjs",
                "protected-prompt-rebuild-probe.mjs",
            }
        ),
        frozenset(
            {
                "protected-cron-rescan-probe.mjs",
                "protected-observation-v1.mjs",
            }
        ),
    }
)

FINAL_COMBINED_V2_SOURCE_DIGESTS = {
    **FINAL_COMBINED_SOURCE_DIGESTS,
    "protected-cron-rescan-probe.mjs": (
        "3733b27d34e692271b0ac7c93956017d55b318fef1dcabc27e3478531c0e47b3"
    ),
}
FINAL_COMBINED_V2_SELECTIONS = FINAL_COMBINED_SELECTIONS

FINAL_COMBINED_V2_CONFIG_REPLACEMENTS = (
    (
        b"ae9d44f2c347a8b10a689d55c435ed0106a2a7aec40e0c6ceaefd0ea99d2564d",
        b"b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e",
    ),
    (
        b"configuration.file?.size === 1811",
        b"configuration.file?.size === 1880",
    ),
    (b"file.size === 1811", b"file.size === 1880"),
)

FINAL_COMBINED_V2_CONFIG_COUNTS = {
    "protected-archive-replacement-probe.mjs": (3, 1, 0),
    "protected-config-activation-probe.mjs": (3, 1, 0),
    "protected-cron-rescan-probe.mjs": (0, 0, 0),
    "protected-curator-restore-denial-probe.mjs": (3, 1, 1),
    "protected-observation-v1.mjs": (3, 1, 0),
    "protected-prompt-rebuild-probe.mjs": (0, 0, 0),
    "protected-route-probe.mjs": (2, 1, 0),
    "protected-session-snapshot-fixed-probe.mjs": (0, 0, 0),
}

FINAL_COMBINED_COMMIT_REPLACEMENTS = (
    (
        b"805a4b152b0cee271ee78ad5608c15a4f8d1624b",
        b"7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
    ),
    (b"OpenClaw 2026.7.1 (805a4b1)", b"OpenClaw 2026.7.1 (7fa98d8)"),
)

FINAL_COMBINED_CONFIG_REPLACEMENTS = (
    (
        b"701da2485f2844603c13b40c56876984de5ff9cdc22927f1a5bcd218ba369751",
        b"ae9d44f2c347a8b10a689d55c435ed0106a2a7aec40e0c6ceaefd0ea99d2564d",
    ),
    (
        b"417fc06b87a539654433451aff12509ca7dca28003c9f2cedc91bcc611eba16e",
        b"ae9d44f2c347a8b10a689d55c435ed0106a2a7aec40e0c6ceaefd0ea99d2564d",
    ),
)

FINAL_COMBINED_RUNTIME_REPLACEMENTS = (
    (b"45_859", b"45_860"),
    (b"45859", b"45860"),
    (b"45_840", b"45_841"),
    (b"45840", b"45841"),
    (b"369_418_625", b"369_443_243"),
    (b"369418625", b"369443243"),
    (
        b"6448edb21fd2a27dd3cf2b740e0d0dfc3a395e2ccae446853867a95485d54e74",
        b"5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154",
    ),
)

FINAL_COMBINED_TARGET_REPLACEMENTS = (
    (
        b'const TARGET_NAME = "requesting-code-review";',
        b'const TARGET_NAME = "template-skill";',
    ),
    (
        b"const TARGET = `/profile/workspace/skills/${TARGET_NAME}`;",
        b'const TARGET = "/opt/aragorn/runtime-profile/template-skill";',
    ),
    (
        b"sha256:1a13f195721f8fa75974bd4918a25b30e8406ff6d423cd0e3306c391b8fee07a",
        b"sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa",
    ),
    (
        b"sha256:c3e201e18e2fa35a56d4cae3a0ed481072f4ed77db18e6d568b266068cbe96c3",
        b"sha256:38625b40892cc1f5b3cac1dcc6cd0116f8b7f21900a5baa7eeeded0ed2e87ed1",
    ),
    (b"tree.root.gid === 982", b"tree.root.gid === 0"),
    (b'tree.root.mode === "750"', b'tree.root.mode === "555"'),
    (b"skill.gid === 982", b"skill.gid === 0"),
    (b'skill.mode === "440"', b'skill.mode === "444"'),
    (b'skill?.source === "openclaw-workspace"', b'skill?.source === "openclaw-extra"'),
)

FINAL_COMBINED_PROMPT_OLD = b"""

The following skills provide specialized instructions for specific tasks.
Use the read tool to load a skill's file when the task matches its description.
If a skill's <version> differs from a previous turn, re-read its SKILL.md before using it.
When a skill file references a relative path, resolve it against the skill directory (parent of SKILL.md / dirname of the path) and use that absolute path in tool commands.

<available_skills>
  <skill>
    <name>requesting-code-review</name>
    <description>Inert protected archive replacement target v1.</description>
    <location>/profile/workspace/skills/requesting-code-review/SKILL.md</location>
    <version>sha256:1a13f195721f8fa7</version>
  </skill>
</available_skills>"""

FINAL_COMBINED_PROMPT_NEW = b"""

The following skills provide specialized instructions for specific tasks.
Use the read tool to load a skill's file when the task matches its description.
If a skill's <version> differs from a previous turn, re-read its SKILL.md before using it.
When a skill file references a relative path, resolve it against the skill directory (parent of SKILL.md / dirname of the path) and use that absolute path in tool commands.

<available_skills>
  <skill>
    <name>template-skill</name>
    <description>Replace with description of the skill and when Claude should use it.</description>
    <location>/opt/aragorn/runtime-profile/template-skill/SKILL.md</location>
    <version>sha256:eb685d91de039ed8</version>
  </skill>
</available_skills>"""

FINAL_COMBINED_CRON_REPLACEMENTS = (
    (
        b"ad9cde2c065d5d4d69f465193007a435c0cd0b378d253329238dd36fdc70f849",
        b"5b4687614137ecc59ff375c47679ba641eca20d73b20cf75e0ae6bee0afbb533",
    ),
    (b"cron-DOr4RFbn.js", b"cron-qc-KsHeU.js"),
    (
        b"f76a2799c0e012a39fd12c5ce4245c92f0afa74fd30a1cddec506af092733a60",
        b"b44d93ef82f61910088810c5f26f819ef5f3b23c3d1986223781149805d86ab6",
    ),
    (
        b"661385d87db47117e9e49e41b01fcfe07aacea32326de09f6764c2568bc2620d",
        b"bdc0ebba0d83ef830af7542f70c8436decc9809195f1fd6e114e11f8e6220768",
    ),
    (b"cron-snapshot.runtime-DrQirS_k.js", b"cron-snapshot.runtime-DOWu3ZvS.js"),
    (
        b"0b7aa925514a2c44babb98dedfd11de28733fbd853b361716860adca340923d7",
        b"111dbe5add64d796453660fe8b5f8f8fa830716d87ecc902d2b11a0489e36610",
    ),
    (b"isolated-agent-2U26aOeI.js", b"isolated-agent-knotypz1.js"),
    (
        b"edd138bac24f7fbc0e08013e1be9e4962f12d530ef5462efa0a1d82d4b475784",
        b"11800a76db678e445aebb1e3193ba089c7ae8da94d3628ba4252ff5afc09cc4e",
    ),
    (b"session-CagbPApz.js", b"session-DhY9vRaC.js"),
    (b"3_661", b"3_877"),
    (
        b"d8a1bd6c3ee26b981e5cfe6e7756a91263fd40c4727e1bdb0e69171b8458cb28",
        b"5ac3cf77479e9573b5326f81c5ddc7ad4e21017b6f34d3bf2612d67dc8b9f50d",
    ),
    (b"session-snapshot-8MgHKMdq.js", b"session-snapshot-C3iM3syv.js"),
    (b"47_738", b"55_215"),
    (
        b"f4e73f5c7a111fe2ed4d953c54f96ff9e9e4ad2ba962cf7f00afd141c8d125c2",
        b"9a573db609deb917613f3e85437236a5997883daa299a52f2652891b7ec43b1b",
    ),
    (b"workspace-CKU1tzCf.js", b"workspace-DvqxsRU0.js"),
)

FINAL_COMBINED_CRON_DISCOVERY_REPLACEMENTS = (
    (
        b"""function discovery() {
  const native = command([
    "skills",
    "info",
    TARGET_NAME,
    "--agent",
    "main",
    "--json",
  ]);
  return { command: native, response: parsedCommand(native) };
}

""",
        b"",
    ),
    (
        b"""function exactDiscovery(value) {
  const skill = value.response.value;
  return (
    value.command.exit_code === 0 &&
    cleanCommand(value.command) &&
    value.response.parsed &&
    skill?.name === TARGET_NAME &&
    skill?.skillKey === TARGET_NAME &&
    skill?.baseDir === TARGET &&
    skill?.filePath === `${TARGET}/SKILL.md` &&
    skill?.source === "openclaw-extra" &&
    skill?.description ===
      "Replace with description of the skill and when Claude should use it." &&
    skill?.disabled === false &&
    skill?.eligible === true &&
    skill?.modelVisible === true
  );
}

""",
        b"",
    ),
    (b"    discovery_before: skillDiscovery,\n", b""),
    (
        b"    commands: [version, system.command, skillDiscovery.command],",
        b"    commands: [version, system.command],",
    ),
    (b"    exactDiscovery(item.discovery_before) &&\n", b""),
    (
        b"    commands: [skillDiscovery.command, system.command],",
        b"    commands: [system.command],",
    ),
    (b"      discovery_after: skillDiscovery,\n", b""),
    (b"    exactDiscovery(last.discovery_after) &&\n", b""),
)

FINAL_COMBINED_V2_CRON_DISCOVERY_REPLACEMENTS = (
    *FINAL_COMBINED_CRON_DISCOVERY_REPLACEMENTS[:3],
    (
        b"  const commands = [version, system.command, skillDiscovery.command];",
        b"  const commands = [version, system.command];",
    ),
    *FINAL_COMBINED_CRON_DISCOVERY_REPLACEMENTS[4:],
)

FINAL_COMBINED_CURATOR_REPLACEMENTS = (
    (
        b"b0cb989a0543181aa737cc5ca37c10bf3f21b010a76cb742aefd1b5b4cef8db8",
        b"d88d92cfd6829a4d5204709f3ded852d8d1b0c71c94714a8e42dce8302aa7b79",
    ),
    (b"skills-cli-B0D3yE3o.js", b"skills-cli-CNPwjJpH.js"),
    (
        b"5baa73a9a2ef36d65243ac9068ada55f2bfc5e25041ccf2bae6635aede89bdfa",
        b"196ac4211309e82af77db50230eb3d83eb5d7a9a100bdbc50ab70018ee21868a",
    ),
    (b"skills-BY50TjFr.js", b"skills-wlxjcAuQ.js"),
    (b"59_911", b"61_198"),
    (
        b"a90be5b2226ad12935be90094b01c8544c5641f7cf7df175e6f962ca402d8309",
        b"42b8547c53a366ee333527117dcc12400398ec6267c84d351cbfee813ea3d95e",
    ),
    (b"zod-schema-Cvjp91Cd.js", b"zod-schema-HPCU20Az.js"),
)

FINAL_COMBINED_SNAPSHOT_REPLACEMENTS = (
    (
        b"4b198dafbcca1788bfe22c0abb1f8bf16064be03",
        b"7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
    ),
    (b"OpenClaw 2026.7.1 (4b198da)", b"OpenClaw 2026.7.1 (7fa98d8)"),
    (b"369_417_908", b"369_443_243"),
    (
        b"4e866a250429632f5796d977554acbaabe6f30dbf837457e32022eacdb9152c1",
        b"5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154",
    ),
    (b"agent-command-DowjS4rA.js", b"agent-command-DTQcyNEV.js"),
    (
        b"1ad8a7b0b8d9cc7defbaad1c4e9a8b413d462627f1c81e29ec99ea0a31bc03d6",
        b"940878576c7383f1e1ca99a5257a121bb6ddc8637f599a587e50a229cf185f03",
    ),
    (b"attempt-execution-BYfuRexC.js", b"attempt-execution-D1Tem6Ut.js"),
    (
        b"0e51074290fe09589add2de7f7bb5e9fe76e0de90f2139111969b287e554a4ef",
        b"6e71434cf0fcb84eabcafdf8ad24f489d47f2ce25144e79d9681ba35a37aceec",
    ),
    (b"218_413", b"220_322"),
    (b"embedded-agent-Dkb05T-e.js", b"embedded-agent-UzpuyD8i.js"),
    (
        b"e240ee9ddb20a783630903606ed82ba068fd2e697d34a64a07241a4abc466d38",
        b"fa4ffb66d910e52e376addc614d6e02926ac89e5d83eb96624bf77d2b93ce681",
    ),
    (b"673_468", b"673_592"),
    (b"selection-weQvCGzP.js", b"selection-CqQ5E0T1.js"),
    (
        b"c5165cec26aed90a576dc6b3b02749d5412a65d3a57d92a3b1855a087f2a2ec8",
        b"e44ca619f4d12fda4962076adba16474e994ac02dbcfbadcb75c81d23b21edde",
    ),
    (b"session-snapshot-Bm-DN9wl.js", b"session-snapshot-CUCETeUr.js"),
    (
        b"3405a1d019fcbb854d4f84fa00624c714fb8c82bacfbe984fc5ccc8c24e89dff",
        b"5c33aa0c9e0b38b264e87962dce0b80470e4f6963e7d5d0b37c9d876213db459",
    ),
    (b"3_661", b"3_877"),
    (b"session-snapshot-CMKRWMg1.js", b"session-snapshot-C3iM3syv.js"),
    (
        b"e9046199b43de587dbf1f184b2e4738b4b772491266baff8eeeab90f21a50d7c",
        b"5ac3cf77479e9573b5326f81c5ddc7ad4e21017b6f34d3bf2612d67dc8b9f50d",
    ),
    (b"47_738", b"55_215"),
    (b"workspace-BKXau6p-.js", b"workspace-DvqxsRU0.js"),
    (
        b"ee73b5621ff0fa5d198cb39a54eb6fa332d1f96897e4151538415eef7a72846c",
        b"9a573db609deb917613f3e85437236a5997883daa299a52f2652891b7ec43b1b",
    ),
    (b"system-prompt-config-BeuaroSf.js", b"system-prompt-config-C1imAkur.js"),
    (
        b"ae0182fdf7377187493f033111bfdf2c15fd02971eed5517ebdaa4c3334f7f66",
        b"fba952469e9941a14733b2505964244e6efd24f0a4962e60e1d6e63761a6dc27",
    ),
    (b"store-CRMOBYMq.js", b"store-Bn4xSDrE.js"),
    (
        b"2a55293b9f9fb75dd62d73365cac05212b60c650650135f967ca0e192e0ec46f",
        b"b64871b386445e6bb5300bed786e3c4eb3ba7d28f0eb469b3b4dfe786d90ac96",
    ),
)

FINAL_COMBINED_SNAPSHOT_DISCOVERY_REPLACEMENTS = (
    (
        b"""function discovery() {
  const native = command([
    "skills",
    "info",
    TARGET_NAME,
    "--agent",
    "main",
    "--json",
  ]);
  return { command: native, response: parsedCommand(native) };
}

""",
        b"",
    ),
    (
        b"""function exactDiscovery(value) {
  const skill = value.response.value;
  return (
    value.command.exit_code === 0 &&
    cleanCommand(value.command) &&
    value.response.parsed &&
    skill?.name === TARGET_NAME &&
    skill?.skillKey === TARGET_NAME &&
    skill?.baseDir === TARGET &&
    skill?.filePath === `${TARGET}/SKILL.md` &&
    skill?.source === "openclaw-extra" &&
    skill?.disabled === false &&
    skill?.eligible === true &&
    skill?.modelVisible === true
  );
}

""",
        b"",
    ),
    (b"  const discoveryAfter = discovery();\n", b""),
    (
        b"    commands: [discoveryAfter.command, systemAfter.command],",
        b"    commands: [systemAfter.command],",
    ),
    (b"      discovery_after: discoveryAfter,\n", b""),
    (b"  const discoveryBefore = discovery();\n", b""),
    (b"    exactDiscovery(discoveryBefore) &&\n", b""),
    (b"    discovery_before: discoveryBefore,\n", b""),
    (
        b"    result.commands = [version, systemBefore.command, discoveryBefore.command];",
        b"    result.commands = [version, systemBefore.command];",
    ),
)

FINAL_COMBINED_SNAPSHOT_TERMINAL_REPLACEMENTS = (
    (
        b"""function exactInitialSnapshot(value) {
  const metadata = value.snapshot.metadata;
  return (
    value.present === true &&
    value.entry.run_status === "failed" &&
    Number.isSafeInteger(value.entry.started_at) &&
    Number.isSafeInteger(value.entry.ended_at) &&
    Math.abs(value.entry.ended_at - value.entry.started_at) <= 1 &&
    value.entry.runtime_ms === 0 &&""",
        b"""function exactInitialSnapshot(value, turn) {
  const metadata = value.snapshot.metadata;
  const waitValue = turn?.wait?.response?.value;
  const sendStartedAt = Date.parse(turn?.send?.command?.started_at ?? "");
  const waitCompletedAt = Date.parse(
    turn?.wait?.command?.completed_at ?? "",
  );
  const terminalMatchesSession =
    (waitValue?.status === "ok" &&
      waitValue?.error == null &&
      value.entry.run_status === "failed") ||
    (waitValue?.status === "error" &&
      waitValue?.error ===
        "\\u26a0\\ufe0f Agent failed before reply: LLM request failed: network connection error.\\nLogs: openclaw logs --follow" &&
      value.entry.run_status === "timeout");
  return (
    value.present === true &&
    terminalMatchesSession &&
    Number.isSafeInteger(value.entry.started_at) &&
    value.entry.started_at >= 0 &&
    Number.isSafeInteger(value.entry.ended_at) &&
    value.entry.started_at <= value.entry.ended_at &&
    Number.isSafeInteger(value.entry.updated_at) &&
    value.entry.ended_at <= value.entry.updated_at &&
    Number.isSafeInteger(value.entry.runtime_ms) &&
    value.entry.runtime_ms ===
      value.entry.ended_at - value.entry.started_at &&
    Number.isSafeInteger(waitValue?.endedAt) &&
    Number.isSafeInteger(sendStartedAt) &&
    Number.isSafeInteger(waitCompletedAt) &&
    sendStartedAt <= value.entry.started_at &&
    value.entry.ended_at <= waitValue.endedAt &&
    waitValue.endedAt <= waitCompletedAt &&
    value.entry.updated_at <= waitCompletedAt &&""",
    ),
    (
        b"""  const sendResponse = parsedCommand(send);
  if (
    send.exit_code !== 0 ||
    !cleanCommand(send) ||
    sendResponse.value?.runId !== runId ||
    sendResponse.value?.status !== "started"
  ) {""",
        b"""  const sendResponse = parsedCommand(send);
  if (
    send.exit_code !== 0 ||
    !cleanCommand(send) ||
    !sendResponse.parsed ||
    sendResponse.value?.runId !== runId ||
    sendResponse.value?.status !== "started"
  ) {""",
    ),
    (
        b"""  const waitResponse = parsedCommand(wait);
  if (
    wait.exit_code !== 0 ||
    !cleanCommand(wait) ||
    waitResponse.value?.runId !== runId ||
    waitResponse.value?.status !== "ok" ||
    !Number.isSafeInteger(waitResponse.value?.endedAt)
  ) {""",
        b"""  const waitResponse = parsedCommand(wait);
  const terminalStatus = waitResponse.value?.status ?? null;
  const terminalOk =
    terminalStatus === "ok" &&
    Number.isSafeInteger(waitResponse.value?.endedAt) &&
    waitResponse.value.endedAt > 0 &&
    waitResponse.value?.error == null;
  const terminalNetworkError =
    terminalStatus === "error" &&
    Number.isSafeInteger(waitResponse.value?.endedAt) &&
    waitResponse.value.endedAt > 0 &&
    waitResponse.value?.error ===
      "\\u26a0\\ufe0f Agent failed before reply: LLM request failed: network connection error.\\nLogs: openclaw logs --follow";
  if (
    wait.exit_code !== 0 ||
    !cleanCommand(wait) ||
    !waitResponse.parsed ||
    waitResponse.value?.runId !== runId ||
    (!terminalOk && !terminalNetworkError)
  ) {""",
    ),
    (
        b"function exactRecoveredSnapshot(initial, final, attackerRef) {",
        b"function exactRecoveredSnapshot(initial, final, attackerRef, turn) {",
    ),
    (
        b"    exactInitialSnapshot(final) &&",
        b"    exactInitialSnapshot(final, turn) &&",
    ),
    (
        b"  if (!exactInitialSnapshot(initialSnapshot)) {",
        b"  if (!exactInitialSnapshot(initialSnapshot, initialTurn)) {",
    ),
    (
        b"""      mutation.blob.prompt_ref,
    ) &&""",
        b"""      mutation.blob.prompt_ref,
      injectedTurn,
    ) &&""",
    ),
)

FINAL_COMBINED_SNAPSHOT_REPLAY_REPLACEMENTS = ((b"      entries: [],\n", b""),)
FINAL_COMBINED_SNAPSHOT_PROMPT_REPLACEMENTS = (
    (b"initialSnapshot.prompt.exact_text.trim()", b"initialSnapshot.prompt.exact_text"),
)

FINAL_COMBINED_PROMPT_DISCOVERY_REPLACEMENTS = (
    *FINAL_COMBINED_SNAPSHOT_DISCOVERY_REPLACEMENTS[:2],
    (b"  const discoveryBefore = discovery();\n", b""),
    (b"    exactDiscovery(discoveryBefore) &&\n", b""),
    (b"    discovery_before: discoveryBefore,\n", b""),
    (
        b"      commands: [version, systemBefore.command, discoveryBefore.command],",
        b"      commands: [version, systemBefore.command],",
    ),
    (b"  const discoveryAfter = discovery();\n", b""),
    (b"      discoveryBefore.command,\n", b""),
    (b"      discoveryAfter.command,\n", b""),
    (b"      discovery_after: discoveryAfter,\n", b""),
)

FINAL_COMBINED_PROMPT_TERMINAL_REPLACEMENTS = (
    (
        b"      started_at: entry.startedAt,\n",
        b"      started_at: entry.startedAt,\n      updated_at: entry.updatedAt,\n",
    ),
    FINAL_COMBINED_SNAPSHOT_TERMINAL_REPLACEMENTS[1],
    FINAL_COMBINED_SNAPSHOT_TERMINAL_REPLACEMENTS[2],
    (
        b"""function exactSnapshot(value) {
  return (
    value.entry.run_status === "failed" &&
    Number.isSafeInteger(value.entry.started_at) &&
    value.entry.ended_at === value.entry.started_at &&
    value.entry.runtime_ms === 0 &&""",
        b"""function exactSnapshot(value, turn) {
  const waitValue = turn?.wait?.response?.value;
  const sendStartedAt = Date.parse(turn?.send?.command?.started_at ?? "");
  const waitCompletedAt = Date.parse(
    turn?.wait?.command?.completed_at ?? "",
  );
  const terminalMatchesSession =
    (waitValue?.status === "ok" &&
      waitValue?.error == null &&
      value.entry.run_status === "failed") ||
    (waitValue?.status === "error" &&
      waitValue?.error ===
        "\\u26a0\\ufe0f Agent failed before reply: LLM request failed: network connection error.\\nLogs: openclaw logs --follow" &&
      value.entry.run_status === "timeout");
  return (
    terminalMatchesSession &&
    Number.isSafeInteger(value.entry.started_at) &&
    value.entry.started_at >= 0 &&
    Number.isSafeInteger(value.entry.ended_at) &&
    value.entry.started_at <= value.entry.ended_at &&
    Number.isSafeInteger(value.entry.updated_at) &&
    value.entry.ended_at <= value.entry.updated_at &&
    Number.isSafeInteger(value.entry.runtime_ms) &&
    value.entry.runtime_ms ===
      value.entry.ended_at - value.entry.started_at &&
    Number.isSafeInteger(waitValue?.endedAt) &&
    Number.isSafeInteger(sendStartedAt) &&
    Number.isSafeInteger(waitCompletedAt) &&
    sendStartedAt <= value.entry.started_at &&
    value.entry.ended_at <= waitValue.endedAt &&
    waitValue.endedAt <= waitCompletedAt &&
    value.entry.updated_at <= waitCompletedAt &&""",
    ),
    (
        b"  if (!exactSnapshot(initialSnapshot)) {",
        b"  if (!exactSnapshot(initialSnapshot, initialTurn)) {",
    ),
    (
        b"    !exactSnapshot(rebuiltSnapshot) ||",
        b"    !exactSnapshot(rebuiltSnapshot, rebuildTurn) ||",
    ),
)

FINAL_COMBINED_NORMAL_TURN_OLD = b"""function normalTurn(label, message) {
  const send = gatewayCall("chat.send", {
    deliver: false,
    idempotencyKey: `aragorn-protected-route-${label}-${RUN_NONCE}`,
    message,
    sessionKey: SESSION_KEY,
    timeoutMs: 5000,
  });
  const parsedSend = parsedCommand(send);
  const runId = parsedSend.value?.runId;
  let wait = null;
  let parsedWait = { parsed: false, value: null };
  if (typeof runId === "string" && runId.length > 0) {
    wait = gatewayCall(
      "agent.wait",
      { runId, timeoutMs: 10_000 },
      12_000,
    );
    parsedWait = parsedCommand(wait);
  }
  const confirmed =
    send.exit_code === 0 &&
    send.error === null &&
    send.signal === null &&
    typeof runId === "string" &&
    runId.length > 0 &&
    wait?.exit_code === 0 &&
    wait.error === null &&
    wait.signal === null &&
    parsedWait.parsed &&
    parsedWait.value?.runId === runId &&
    parsedWait.value?.status === "ok";
  return {
    commands: wait === null ? [send] : [send, wait],
    confirmed,
    send: { command: send, response: parsedSend },
    wait: { command: wait, response: parsedWait },
  };
}"""

FINAL_COMBINED_NORMAL_TURN_NEW = b"""function normalTurn(label, message) {
  const expectedRunId = `aragorn-protected-route-${label}-${RUN_NONCE}`;
  const send = gatewayCall("chat.send", {
    deliver: false,
    idempotencyKey: expectedRunId,
    message,
    sessionKey: SESSION_KEY,
    timeoutMs: 5000,
  });
  const parsedSend = parsedCommand(send);
  const runId = parsedSend.value?.runId;
  let wait = null;
  let parsedWait = { parsed: false, value: null };
  if (typeof runId === "string" && runId.length > 0) {
    wait = gatewayCall(
      "agent.wait",
      { runId, timeoutMs: 10_000 },
      12_000,
    );
    parsedWait = parsedCommand(wait);
  }
  const terminalStatus = parsedWait.value?.status ?? null;
  const terminalOk =
    terminalStatus === "ok" &&
    Number.isSafeInteger(parsedWait.value?.endedAt) &&
    parsedWait.value.endedAt > 0 &&
    parsedWait.value?.error == null;
  const terminalNetworkError =
    terminalStatus === "error" &&
    Number.isSafeInteger(parsedWait.value?.endedAt) &&
    parsedWait.value.endedAt > 0 &&
    typeof parsedWait.value?.error === "string" &&
    parsedWait.value.error ===
      "\\u26a0\\ufe0f Agent failed before reply: LLM request failed: network connection error.\\nLogs: openclaw logs --follow";
  const transportCompleted =
    send.exit_code === 0 &&
    send.error === null &&
    send.signal === null &&
    parsedSend.parsed &&
    typeof runId === "string" &&
    runId.length > 0 &&
    runId === expectedRunId &&
    parsedSend.value?.status === "started" &&
    wait?.exit_code === 0 &&
    wait.error === null &&
    wait.signal === null &&
    parsedWait.parsed &&
    parsedWait.value?.runId === runId &&
    (terminalOk || terminalNetworkError);
  return {
    commands: wait === null ? [send] : [send, wait],
    confirmed: transportCompleted,
    send: { command: send, response: parsedSend },
    wait: { command: wait, response: parsedWait },
  };
}"""

FINAL_COMBINED_SESSION_CONSUMER_OLD = b"""async function sessionConsumerAction(gateway) {
  return await observedAction(
    "session-snapshot-consumer",
    gateway,
    (trace) => {
      trace.observations.session_before = sessionObservation();
      const turn = normalTurn(
        "snapshot-consumer",
        "Inert protected-route snapshot consumer observation.",
      );
      trace.commands.push(...turn.commands);
      trace.observations.turn = turn;
      trace.observations.session_after = sessionObservation();
      trace.attempted = turn.confirmed;
      if (!turn.confirmed) {
        trace.not_tested_reason = "ROUTE_ACTION_NOT_CONFIRMED";
      }
    },
  );
}"""

FINAL_COMBINED_SESSION_CONSUMER_NEW = b"""async function sessionConsumerAction(gateway) {
  return await observedAction(
    "session-snapshot-consumer",
    gateway,
    (trace) => {
      const before = sessionObservation();
      trace.observations.session_before = before;
      const turn = normalTurn(
        "snapshot-consumer",
        "Inert protected-route snapshot consumer observation.",
      );
      trace.commands.push(...turn.commands);
      trace.observations.turn = turn;
      const after = sessionObservation();
      const afterCheck = protectedSnapshotCheck(after);
      const store = after.file;
      const storeExact =
        store?.exists === true &&
        store.type === "file" &&
        store.nlink === 1 &&
        store.mode === "600" &&
        store.uid === RUNTIME_UID &&
        store.gid === RUNTIME_GID &&
        Number.isSafeInteger(store.device) &&
        store.device > 0 &&
        Number.isSafeInteger(store.inode) &&
        store.inode > 0 &&
        Number.isSafeInteger(store.size) &&
        store.size > 0 &&
        store.size <= CONTROL_LIMIT &&
        store.digest_error === null &&
        store.path === SESSION_STORE &&
        /^sha256:[0-9a-f]{64}$/.test(store.digest ?? "");
      const beforeAbsent =
        before.present === false &&
        before.entry === null &&
        !Object.hasOwn(before, "error") &&
        before.file?.path === SESSION_STORE;
      trace.observations.session_after = after;
      trace.observations.session_after_check = afterCheck;
      trace.observations.session_store_exact = storeExact;
      trace.attempted =
        beforeAbsent && turn.confirmed && afterCheck.ready && storeExact;
      if (!trace.attempted) {
        trace.not_tested_reason = "EXACT_PROTECTED_SNAPSHOT_NOT_CREATED";
      }
    },
  );
}"""

FINAL_COMBINED_PROFILE_REPLACEMENTS = (
    (
        b"/profile/config/openclaw.json",
        b"/run/credentials/aragorn-agent-gateway.service/openclaw-config",
    ),
    (
        b"/profile/config",
        b"/run/credentials/aragorn-agent-gateway.service",
    ),
    (b"/profile/state", b"/var/lib/aragorn-agent-gateway/state"),
    (b"/profile/home", b"/var/lib/aragorn-agent-gateway/home"),
    (b"/profile/workspace", b"/var/lib/aragorn-agent-gateway/workspace"),
)

FINAL_COMBINED_PROFILE_COUNTS = {
    "protected-archive-replacement-probe.mjs": (1, 1, 4, 2, 3),
    "protected-config-activation-probe.mjs": (1, 1, 4, 2, 3),
    "protected-cron-rescan-probe.mjs": (0, 2, 1, 0, 0),
    "protected-curator-restore-denial-probe.mjs": (0, 3, 1, 0, 0),
    "protected-observation-v1.mjs": (1, 1, 4, 2, 3),
    "protected-prompt-rebuild-probe.mjs": (0, 2, 1, 0, 0),
    "protected-route-probe.mjs": (1, 0, 5, 2, 3),
    "protected-session-snapshot-fixed-probe.mjs": (0, 2, 1, 0, 4),
}

FINAL_COMBINED_WRITABLE_BOUNDARY_HELPER = b"""
function writableRoots(rootPaths) {
  return Object.fromEntries(
    Object.entries(rootPaths).map(([name, path]) => {
      const observation = pathObservation(path);
      let writable = false;
      try {
        accessSync(path, constants.W_OK);
        writable = true;
      } catch {
        // The exact writable-root predicate below remains false.
      }
      const ready =
        observation.exists === true &&
        observation.type === "directory" &&
        observation.uid === 992 &&
        observation.gid === 992 &&
        (Number.parseInt(observation.mode, 8) & 0o200) !== 0 &&
        writable;
      return [name, { observation, ready, writable }];
    }),
  );
}

function exactExternalSingleton(configuration) {
  let document = null;
  try {
    document = JSON.parse(readFileSync(CONFIG, "utf8"));
  } catch {
    // The exact singleton predicate below remains false.
  }
  const activation = document?.skills?.activation;
  return (
    configuration?.ready === true &&
    configuration.file?.uid === 992 &&
    configuration.file?.gid === 0 &&
    configuration.file?.mode === "400" &&
    configuration.file?.nlink === 1 &&
    configuration.file?.size === 1811 &&
    configuration.file?.digest ===
      "sha256:ae9d44f2c347a8b10a689d55c435ed0106a2a7aec40e0c6ceaefd0ea99d2564d" &&
    activation?.authority === "external" &&
    canonicalJson(activation.sources) ===
      '[{"filePath":"/opt/aragorn/runtime-profile/template-skill/SKILL.md","name":"template-skill","sha256":"eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"}]' &&
    canonicalJson(document?.skills?.load) ===
      '{"allowSymlinkTargets":[],"extraDirs":["/opt/aragorn/runtime-profile/template-skill"],"watch":false}' &&
    document?.skills?.workshop?.restoreAuthority === "external" &&
    canonicalJson(document?.agents?.defaults?.skills) === '["template-skill"]' &&
    canonicalJson(document?.agents?.list?.[0]?.skills) === '["template-skill"]'
  );
}
"""

FINAL_COMBINED_WRITABLE_BOUNDARY_REPLACEMENTS = (
    (
        b"""  const roots = Object.fromEntries(
    Object.entries(PROTECTED_ROOTS).map(([name, path]) => [
      name,
      mountObservation(path),
    ]),
  );""",
        b"  const roots = writableRoots(PROTECTED_ROOTS);",
    ),
    (
        b"Object.values(roots).every((entry) => entry.ready)",
        (
            b"exactExternalSingleton(configuration) &&\n"
            b"      Object.values(roots).every((entry) => entry.ready)"
        ),
    ),
)

FINAL_COMBINED_GATEWAY_PROCESS_REPLACEMENTS = (
    (
        b"function gatewayProcessObservation() {\n  try {",
        b"""function gatewayProcessObservation() {
  const rawPid = process.env.ARAGORN_GATEWAY_PID ?? "";
  if (!/^[1-9][0-9]*$/.test(rawPid)) {
    return {
      error: errorRecord(
        new Error("ARAGORN_GATEWAY_PID must be a positive decimal PID"),
      ),
      pid: null,
    };
  }
  const pid = Number.parseInt(rawPid, 10);
  if (!Number.isSafeInteger(pid)) {
    return {
      error: errorRecord(new Error("ARAGORN_GATEWAY_PID exceeds safe integer range")),
      pid: null,
    };
  }
  const procRoot = `/proc/${rawPid}`;
  try {""",
    ),
    (
        b'readFileSync("/proc/1/cmdline", "utf8")',
        b'readFileSync(`${procRoot}/cmdline`, "utf8")',
    ),
    (
        b'readFileSync("/proc/1/stat", "utf8")',
        b'readFileSync(`${procRoot}/stat`, "utf8")',
    ),
    (b"      pid: 1,", b"      pid,"),
)

FINAL_COMBINED_GATEWAY_STATUS_REPLACEMENT = (
    b'readFileSync("/proc/1/status", "utf8")',
    b'readFileSync(`${procRoot}/status`, "utf8")',
)

FINAL_COMBINED_SYSTEM_PID_REPLACEMENTS = {
    "protected-archive-replacement-probe.mjs": (
        (
            b"systemResponse.value?.pid === 1",
            b"systemResponse.value?.pid === processObservation.pid",
        ),
    ),
    "protected-config-activation-probe.mjs": (
        (
            b"systemResponseBefore.value?.pid === 1",
            b"systemResponseBefore.value?.pid === processBefore.pid",
        ),
    ),
    "protected-cron-rescan-probe.mjs": (
        (
            b"item.system_info_before.response.value?.pid === 1",
            b"item.system_info_before.response.value?.pid ===\n      item.gateway_process_before.pid",
        ),
        (
            b"last.system_info_after.response.value?.pid === 1",
            b"last.system_info_after.response.value?.pid ===\n      last.gateway_process_after.pid",
        ),
    ),
    "protected-curator-restore-denial-probe.mjs": (
        (
            b"observation.response.value?.pid === 1",
            b"observation.response.value?.pid === gateway.pid",
        ),
    ),
    "protected-observation-v1.mjs": (),
    "protected-prompt-rebuild-probe.mjs": (
        (
            b"systemBefore.response.value?.pid === 1",
            b"systemBefore.response.value?.pid === gatewayBefore.pid",
        ),
    ),
    "protected-route-probe.mjs": (
        (b"info.pid === 1", b"info.pid === processObservation.pid"),
    ),
    "protected-session-snapshot-fixed-probe.mjs": (
        (
            b"systemBefore.response.value?.pid === 1",
            b"systemBefore.response.value?.pid === gatewayBefore.pid",
        ),
    ),
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def transformed_probe(
    name: str, *, source_raw: bytes | None = None, source_digest: str | None = None
) -> bytes:
    if name not in SOURCE_DIGESTS:
        raise ValueError(f"unsupported probe: {name}")
    raw = (SOURCE_ROOT / name).read_bytes() if source_raw is None else source_raw
    expected_digest = SOURCE_DIGESTS[name] if source_digest is None else source_digest
    if _sha256(raw) != expected_digest:
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


def transformed_restore_authority_probe(
    name: str, *, source_raw: bytes | None = None, source_digest: str | None = None
) -> bytes:
    expected = RESTORE_AUTHORITY_PROBE_COUNTS.get(name)
    if expected is None:
        raise ValueError(f"unsupported restore-authority probe: {name}")
    raw = transformed_probe(name, source_raw=source_raw, source_digest=source_digest)
    counts = tuple(
        raw.count(old) for old, _new in RESTORE_AUTHORITY_CONFIG_REPLACEMENTS
    )
    if counts != expected:
        raise ValueError("restore-authority probe shape changed")
    for old, new in RESTORE_AUTHORITY_CONFIG_REPLACEMENTS:
        raw = raw.replace(old, new)
    if name == "protected-archive-replacement-probe.mjs":
        if any(
            raw.count(old) != 1 for old, _new in RESTORE_AUTHORITY_ARCHIVE_REPLACEMENTS
        ):
            raise ValueError("restore-authority archive probe shape changed")
        for old, new in RESTORE_AUTHORITY_ARCHIVE_REPLACEMENTS:
            raw = raw.replace(old, new)
    if name == "protected-cron-rescan-probe.mjs":
        if any(
            raw.count(old) != 1 for old, _new in RESTORE_AUTHORITY_CRON_REPLACEMENTS
        ):
            raise ValueError("restore-authority cron probe shape changed")
        for old, new in RESTORE_AUTHORITY_CRON_REPLACEMENTS:
            raw = raw.replace(old, new)
        if any(old in raw for old, _new in RESTORE_AUTHORITY_CRON_REPLACEMENTS):
            raise ValueError("stale restore-authority cron literal remains")
    return raw


def _replace_once(raw: bytes, replacements: tuple[tuple[bytes, bytes], ...]) -> bytes:
    for old, new in replacements:
        if raw.count(old) != 1:
            raise ValueError("final-combined probe shape changed")
        raw = raw.replace(old, new)
    return raw


def _replace_counted(
    raw: bytes, replacements: tuple[tuple[bytes, bytes], ...], counts: tuple[int, ...]
) -> bytes:
    if len(replacements) != len(counts):
        raise ValueError("final-combined replacement count shape changed")
    for (old, new), expected in zip(replacements, counts):
        if raw.count(old) != expected:
            raise ValueError("final-combined probe shape changed")
        raw = raw.replace(old, new)
    return raw


def transformed_final_combined_probe(
    name: str, *, source_raw: bytes | None = None, source_digest: str | None = None
) -> bytes:
    expected_digest = (
        FINAL_COMBINED_SOURCE_DIGESTS.get(name)
        if source_digest is None
        else source_digest
    )
    if expected_digest is None:
        raise ValueError(f"unsupported final-combined probe: {name}")
    if name in RESTORE_AUTHORITY_PROBE_COUNTS:
        raw = transformed_restore_authority_probe(
            name, source_raw=source_raw, source_digest=source_digest
        )
    else:
        raw = (SOURCE_ROOT / name).read_bytes() if source_raw is None else source_raw
        if _sha256(raw) != expected_digest:
            raise ValueError(f"frozen probe changed: {name}")

    commit_names = {
        "protected-archive-replacement-probe.mjs",
        "protected-config-activation-probe.mjs",
        "protected-cron-rescan-probe.mjs",
        "protected-curator-restore-denial-probe.mjs",
        "protected-prompt-rebuild-probe.mjs",
        "protected-route-probe.mjs",
    }
    config_names = {
        "protected-archive-replacement-probe.mjs",
        "protected-config-activation-probe.mjs",
        "protected-curator-restore-denial-probe.mjs",
        "protected-observation-v1.mjs",
    }
    runtime_underscore_names = {
        "protected-config-activation-probe.mjs",
        "protected-curator-restore-denial-probe.mjs",
        "protected-observation-v1.mjs",
    }
    target_names = {
        "protected-archive-replacement-probe.mjs",
        "protected-config-activation-probe.mjs",
        "protected-cron-rescan-probe.mjs",
        "protected-curator-restore-denial-probe.mjs",
        "protected-prompt-rebuild-probe.mjs",
        "protected-session-snapshot-fixed-probe.mjs",
    }

    if name in commit_names:
        raw = _replace_once(raw, FINAL_COMBINED_COMMIT_REPLACEMENTS)
    if name in config_names:
        raw = _replace_once(raw, FINAL_COMBINED_CONFIG_REPLACEMENTS)
    elif name == "protected-route-probe.mjs":
        raw = _replace_once(raw, (FINAL_COMBINED_CONFIG_REPLACEMENTS[1],))
    if name in runtime_underscore_names:
        raw = _replace_once(
            raw,
            (
                FINAL_COMBINED_RUNTIME_REPLACEMENTS[0],
                FINAL_COMBINED_RUNTIME_REPLACEMENTS[2],
                FINAL_COMBINED_RUNTIME_REPLACEMENTS[4],
                FINAL_COMBINED_RUNTIME_REPLACEMENTS[6],
            ),
        )
    elif name == "protected-archive-replacement-probe.mjs":
        raw = _replace_once(
            raw,
            (
                FINAL_COMBINED_RUNTIME_REPLACEMENTS[1],
                FINAL_COMBINED_RUNTIME_REPLACEMENTS[3],
                FINAL_COMBINED_RUNTIME_REPLACEMENTS[5],
                FINAL_COMBINED_RUNTIME_REPLACEMENTS[6],
            ),
        )

    if name in target_names:
        raw = _replace_once(
            raw,
            (
                FINAL_COMBINED_TARGET_REPLACEMENTS[0],
                FINAL_COMBINED_TARGET_REPLACEMENTS[2],
            ),
        )
        if name != "protected-archive-replacement-probe.mjs":
            raw = _replace_once(raw, (FINAL_COMBINED_TARGET_REPLACEMENTS[3],))
        if name in {
            "protected-archive-replacement-probe.mjs",
            "protected-cron-rescan-probe.mjs",
            "protected-prompt-rebuild-probe.mjs",
            "protected-session-snapshot-fixed-probe.mjs",
        }:
            raw = _replace_once(raw, (FINAL_COMBINED_TARGET_REPLACEMENTS[1],))
        else:
            raw = _replace_once(
                raw,
                (
                    (
                        b'const TARGET = join(WORKSPACE, "skills", TARGET_NAME);',
                        b'const TARGET = "/opt/aragorn/runtime-profile/template-skill";',
                    ),
                ),
            )
        if name != "protected-archive-replacement-probe.mjs":
            raw = _replace_once(raw, FINAL_COMBINED_TARGET_REPLACEMENTS[4:8])
        if name not in {
            "protected-archive-replacement-probe.mjs",
            "protected-config-activation-probe.mjs",
        }:
            raw = _replace_once(raw, (FINAL_COMBINED_TARGET_REPLACEMENTS[8],))

    if name in {
        "protected-archive-replacement-probe.mjs",
        "protected-config-activation-probe.mjs",
        "protected-curator-restore-denial-probe.mjs",
        "protected-observation-v1.mjs",
    }:
        raw = _replace_once(
            raw,
            (
                (b"effectiveIdentity.uid === 1000", b"effectiveIdentity.uid === 992"),
                (b"effectiveIdentity.gid === 1000", b"effectiveIdentity.gid === 992"),
                (
                    b"effectiveIdentity.groups.includes(982)",
                    b"effectiveIdentity.groups.includes(992)",
                ),
            ),
        )

    if name == "protected-archive-replacement-probe.mjs":
        raw = _replace_once(
            raw,
            (
                (
                    b'root.gid === 982 &&\n    root.mode === "750"',
                    (
                        b"root.gid === (expectedDigest === EXPECTED_TARGET_DIGEST ? 0 : 992) &&\n"
                        b'    root.mode === (expectedDigest === EXPECTED_TARGET_DIGEST ? "555" : "750")'
                    ),
                ),
                (
                    b'skill.gid === 982 &&\n    skill.mode === "440"',
                    (
                        b"skill.gid === (expectedDigest === EXPECTED_TARGET_DIGEST ? 0 : 992) &&\n"
                        b'    skill.mode === (expectedDigest === EXPECTED_TARGET_DIGEST ? "444" : "440")'
                    ),
                ),
                (
                    b'discoveredValue?.source === "openclaw-workspace"',
                    b'discoveredValue?.source === "openclaw-extra"',
                ),
                (
                    b'const CONTROL_ROOT = "/profile/control";',
                    b'const CONTROL_ROOT = "/tmp/aragorn-final-archive-control";',
                ),
            ),
        )
    elif name == "protected-config-activation-probe.mjs":
        raw = _replace_once(
            raw,
            (
                (
                    b'description: "Inert protected archive replacement target v1."',
                    b'description: "Replace with description of the skill and when Claude should use it."',
                ),
                (b'source: "openclaw-workspace"', b'source: "openclaw-extra"'),
            ),
        )
    elif name == "protected-curator-restore-denial-probe.mjs":
        raw = _replace_once(
            raw,
            (
                (b"file.uid === 0", b"file.uid === 992"),
                (b"file.gid === 982", b"file.gid === 0"),
                (b'file.mode === "440"', b'file.mode === "400"'),
                (b"file.size === 359", b"file.size === 1811"),
                (
                    b"document?.plugins?.enabled === false",
                    b"document?.plugins?.enabled === true",
                ),
                *FINAL_COMBINED_CURATOR_REPLACEMENTS,
            ),
        )
    elif name in {
        "protected-cron-rescan-probe.mjs",
        "protected-prompt-rebuild-probe.mjs",
        "protected-session-snapshot-fixed-probe.mjs",
    }:
        raw = _replace_once(
            raw, ((FINAL_COMBINED_PROMPT_OLD, FINAL_COMBINED_PROMPT_NEW),)
        )

    if name == "protected-cron-rescan-probe.mjs":
        raw = _replace_once(
            raw,
            (
                (
                    b"sha256:bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c",
                    b"sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501",
                ),
                (
                    b'"Inert protected archive replacement target v1."',
                    b'"Replace with description of the skill and when Claude should use it."',
                ),
                (
                    (
                        b'      message: "Inert protected cron rescan observation.",\n'
                        b"      timeoutSeconds: 5,"
                    ),
                    (
                        b'      message: "Inert protected cron rescan observation.",\n'
                        b'      model: "openai/gpt-5.5",\n'
                        b"      timeoutSeconds: 5,"
                    ),
                ),
                *FINAL_COMBINED_CRON_REPLACEMENTS,
            ),
        )
        raw = _replace_once(
            raw,
            FINAL_COMBINED_CRON_DISCOVERY_REPLACEMENTS
            if source_digest is None
            else FINAL_COMBINED_V2_CRON_DISCOVERY_REPLACEMENTS,
        )
        raw = _replace_counted(
            raw,
            ((b"  const skillDiscovery = discovery();\n", b""),),
            (2,),
        )
        raw = _replace_counted(raw, ((b"728", b"737"),), (4,))
        if b"discovery" in raw or b'    "skills",\n    "info",' in raw:
            raise ValueError("stale final-combined cron discovery remains")
    elif name == "protected-prompt-rebuild-probe.mjs":
        raw = _replace_once(raw, FINAL_COMBINED_PROMPT_DISCOVERY_REPLACEMENTS)
        raw = _replace_once(raw, FINAL_COMBINED_PROMPT_TERMINAL_REPLACEMENTS)
        if b"discovery" in raw or b'    "skills",\n    "info",' in raw:
            raise ValueError("stale final-combined prompt discovery remains")
    elif name == "protected-session-snapshot-fixed-probe.mjs":
        raw = _replace_once(raw, FINAL_COMBINED_SNAPSHOT_REPLACEMENTS)
        raw = _replace_once(raw, FINAL_COMBINED_SNAPSHOT_DISCOVERY_REPLACEMENTS)
        raw = _replace_once(raw, FINAL_COMBINED_SNAPSHOT_TERMINAL_REPLACEMENTS)
        raw = _replace_once(raw, FINAL_COMBINED_SNAPSHOT_REPLAY_REPLACEMENTS)
        raw = _replace_once(raw, FINAL_COMBINED_SNAPSHOT_PROMPT_REPLACEMENTS)
        raw = _replace_counted(
            raw,
            ((b"      discoveryBefore.command,\n", b""),),
            (2,),
        )
        if b"discovery" in raw or b'    "skills",\n    "info",' in raw:
            raise ValueError("stale final-combined snapshot discovery remains")
    elif name == "protected-route-probe.mjs":
        raw = _replace_once(
            raw,
            (
                (b"const RUNTIME_UID = 1000;", b"const RUNTIME_UID = 992;"),
                (b"const RUNTIME_GID = 1000;", b"const RUNTIME_GID = 992;"),
                (
                    b'Object.freeze(["requesting-code-review"])',
                    b'Object.freeze(["template-skill"])',
                ),
                (
                    b"EXPECTED_SESSION_PROMPT_BYTES = 728",
                    b"EXPECTED_SESSION_PROMPT_BYTES = 737",
                ),
                (
                    b"sha256:bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c",
                    b"sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501",
                ),
                (
                    b"/profile/state/agents/main/sessions/skills-prompts/sha256/bb/bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c.txt",
                    b"/profile/state/agents/main/sessions/skills-prompts/sha256/60/60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501.txt",
                ),
            ),
        )
        raw = _replace_once(
            raw,
            (
                (FINAL_COMBINED_NORMAL_TURN_OLD, FINAL_COMBINED_NORMAL_TURN_NEW),
                (
                    FINAL_COMBINED_SESSION_CONSUMER_OLD,
                    FINAL_COMBINED_SESSION_CONSUMER_NEW,
                ),
            ),
        )

    boundary_names = {
        "protected-archive-replacement-probe.mjs",
        "protected-config-activation-probe.mjs",
        "protected-curator-restore-denial-probe.mjs",
        "protected-observation-v1.mjs",
        "protected-route-probe.mjs",
    }
    if name in boundary_names:
        if name == "protected-curator-restore-denial-probe.mjs":
            raw = _replace_once(
                raw,
                (
                    (
                        b'import { readFileSync } from "node:fs";',
                        b'import { accessSync, constants, readFileSync } from "node:fs";',
                    ),
                    (
                        b"const SELF = fileURLToPath(import.meta.url);",
                        FINAL_COMBINED_WRITABLE_BOUNDARY_HELPER
                        + b"\nconst SELF = fileURLToPath(import.meta.url);",
                    ),
                ),
            )
        elif name != "protected-curator-restore-denial-probe.mjs":
            raw = _replace_once(
                raw,
                ((b"import {\n", b"import {\n  accessSync,\n  constants,\n"),),
            )
        if name == "protected-route-probe.mjs":
            helper = FINAL_COMBINED_WRITABLE_BOUNDARY_HELPER.replace(
                b"PROTECTED_ROOTS", b"PROTECTED_DISCOVERY_ROOTS"
            )
            raw = _replace_once(
                raw,
                (
                    (
                        b"const PROTECTED_DISCOVERY_ROOTS = Object.freeze({",
                        helper + b"\nconst PROTECTED_DISCOVERY_ROOTS = Object.freeze({",
                    ),
                ),
            )
        elif name != "protected-curator-restore-denial-probe.mjs":
            marker = b"const PROTECTED_ROOTS = Object.freeze({"
            replacement = (
                FINAL_COMBINED_WRITABLE_BOUNDARY_HELPER
                + b"\nconst PROTECTED_ROOTS = Object.freeze({"
            )
            if name == "protected-observation-v1.mjs":
                marker = b"export const PROTECTED_ROOTS = Object.freeze({"
                replacement = (
                    FINAL_COMBINED_WRITABLE_BOUNDARY_HELPER
                    + b"\nexport const PROTECTED_ROOTS = Object.freeze({"
                )
            raw = _replace_once(
                raw,
                ((marker, replacement),),
            )
        boundary_replacements = FINAL_COMBINED_WRITABLE_BOUNDARY_REPLACEMENTS
        if name == "protected-route-probe.mjs":
            boundary_replacements = (
                (
                    boundary_replacements[0][0].replace(
                        b"PROTECTED_ROOTS", b"PROTECTED_DISCOVERY_ROOTS"
                    ),
                    boundary_replacements[0][1].replace(
                        b"PROTECTED_ROOTS", b"PROTECTED_DISCOVERY_ROOTS"
                    ),
                ),
                boundary_replacements[1],
            )
        raw = _replace_once(raw, boundary_replacements)
        if name != "protected-route-probe.mjs":
            raw = _replace_once(
                raw,
                ((b'mountObservation("/probe")', b'mountObservation("/route-input")'),),
            )

    process_names = {
        "protected-archive-replacement-probe.mjs",
        "protected-config-activation-probe.mjs",
        "protected-observation-v1.mjs",
        "protected-route-probe.mjs",
    }
    if name in process_names:
        raw = _replace_once(raw, FINAL_COMBINED_GATEWAY_PROCESS_REPLACEMENTS)
        if name in {
            "protected-config-activation-probe.mjs",
            "protected-observation-v1.mjs",
        }:
            raw = _replace_once(raw, (FINAL_COMBINED_GATEWAY_STATUS_REPLACEMENT,))

    raw = _replace_once(raw, FINAL_COMBINED_SYSTEM_PID_REPLACEMENTS[name])

    if name in {
        "protected-cron-rescan-probe.mjs",
        "protected-curator-restore-denial-probe.mjs",
        "protected-prompt-rebuild-probe.mjs",
        "protected-session-snapshot-fixed-probe.mjs",
    }:
        raw = _replace_once(
            raw,
            ((b'=== "openclaw.json"', b'=== "openclaw-config"'),),
        )

    if name == "protected-route-probe.mjs":
        raw = _replace_counted(
            raw,
            (
                (
                    b"gateway.boundary.roots.workspace_skills.explicit",
                    b"gateway.boundary.roots.workspace_skills.ready",
                ),
                (
                    b"gateway.boundary.roots.workspace_skills.read_only",
                    b"gateway.boundary.roots.workspace_skills.writable",
                ),
                (
                    b"WORKSPACE_SKILLS_EXPLICIT_RO_MOUNT_REQUIRED",
                    b"WORKSPACE_SKILLS_WRITABLE_BOUNDARY_REQUIRED",
                ),
            ),
            (4, 4, 2),
        )

    raw = _replace_counted(
        raw,
        FINAL_COMBINED_PROFILE_REPLACEMENTS,
        FINAL_COMBINED_PROFILE_COUNTS[name],
    )
    if any(old in raw for old, _new in FINAL_COMBINED_PROFILE_REPLACEMENTS):
        raise ValueError("stale final-combined profile path remains")

    return raw


def transformed_final_combined_v2_probe(name: str) -> bytes:
    expected_digest = FINAL_COMBINED_V2_SOURCE_DIGESTS.get(name)
    if expected_digest is None:
        raise ValueError(f"unsupported final-combined-v2 probe: {name}")
    source_raw = None
    source_digest = None
    if name == "protected-cron-rescan-probe.mjs":
        source_raw = (SOURCE_ROOT / "protected-cron-rescan-v2-probe.mjs").read_bytes()
        source_digest = expected_digest
    raw = transformed_final_combined_probe(
        name, source_raw=source_raw, source_digest=source_digest
    )
    raw = _replace_counted(
        raw,
        FINAL_COMBINED_V2_CONFIG_REPLACEMENTS,
        FINAL_COMBINED_V2_CONFIG_COUNTS[name],
    )
    if any(old in raw for old, _new in FINAL_COMBINED_V2_CONFIG_REPLACEMENTS):
        raise ValueError("stale final-combined-v2 configuration binding remains")
    return raw


def materialize(
    output: Path,
    names: list[str],
    *,
    restore_authority: bool = False,
    final_combined: bool = False,
    final_combined_v2: bool = False,
) -> None:
    if sum((restore_authority, final_combined, final_combined_v2)) > 1:
        raise ValueError("probe materialization modes are mutually exclusive")
    if restore_authority and (
        len(names) != len(set(names))
        or frozenset(names) not in RESTORE_AUTHORITY_SELECTIONS
    ):
        raise ValueError("unsupported restore-authority probe selection")
    if final_combined and (
        len(names) != len(set(names))
        or frozenset(names) not in FINAL_COMBINED_SELECTIONS
    ):
        raise ValueError("unsupported final-combined probe selection")
    if final_combined_v2 and (
        len(names) != len(set(names))
        or frozenset(names) not in FINAL_COMBINED_V2_SELECTIONS
    ):
        raise ValueError("unsupported final-combined-v2 probe selection")
    if (
        not restore_authority
        and not final_combined
        and not final_combined_v2
        and any(name not in SOURCE_DIGESTS for name in names)
    ):
        raise ValueError("unsupported probe selection")
    output.mkdir(mode=0o755, parents=True, exist_ok=False)
    for name in names:
        path = output / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        try:
            raw = (
                transformed_final_combined_v2_probe(name)
                if final_combined_v2
                else (
                    transformed_final_combined_probe(name)
                    if final_combined
                    else (
                        transformed_restore_authority_probe(name)
                        if restore_authority
                        else transformed_probe(name)
                    )
                )
            )
            written = 0
            while written < len(raw):
                written += os.write(fd, raw[written:])
            os.fsync(fd)
        finally:
            os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--restore-authority", action="store_true")
    modes.add_argument("--final-combined", action="store_true")
    modes.add_argument("--final-combined-v2", action="store_true")
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "names",
        nargs="+",
        choices=sorted(
            SOURCE_DIGESTS.keys()
            | FINAL_COMBINED_SOURCE_DIGESTS.keys()
            | FINAL_COMBINED_V2_SOURCE_DIGESTS.keys()
        ),
    )
    args = parser.parse_args()
    materialize(
        args.output,
        args.names,
        restore_authority=args.restore_authority,
        final_combined=args.final_combined,
        final_combined_v2=args.final_combined_v2,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
