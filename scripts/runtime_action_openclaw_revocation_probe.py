#!/usr/bin/env python3
"""Derive and run the bounded P3.3d OpenClaw live-revocation probe."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/lib/aragorn")

from aragorn.oci_worker_protocol import canonical_digest, canonical_json  # noqa: E402


_PYTHON_SOURCE = Path("/src/scripts/runtime_action_openclaw_systemd_probe.py")
_MJS_SOURCE = Path(
    "/src/benchmark/runtime-action-openclaw-systemd/openclaw-probe.mjs"
)
_PYTHON_DERIVED = Path("/run/aragorn-p3-3d-probe.py")
_MJS_DERIVED = Path("/run/aragorn-p3-3d-openclaw-probe.mjs")
_HARNESS = Path("/run/aragorn-harness.json")
_BASE_EVIDENCE_DIGEST = (
    "sha256:5ac0a675ac9e123eca28069693a9de118cff13745cc46e16f18d4c6980deb78f"
)
_BASE_EVIDENCE_RAW_DIGEST = (
    "sha256:023103ddc4189da4275e4123b720e9f600d514f17734a62f1b2130e54b30488e"
)
_BASE_IMAGE_ID = (
    "sha256:7e2f3812883d952c931abb30f2ed7dc1d0c0e89cc4ef43c1bdf683d5f9323e1c"
)


class ProbeError(RuntimeError):
    """The P3.3d derivation or live capture violated its pinned contract."""


def _snapshot_function() -> str:
    return '''

def _revocation_snapshot(target: Path) -> dict[str, Any]:
    return {
        "protected_entries": sorted(item.name for item in _PROTECTED.iterdir()),
        "staging_entries": sorted(item.name for item in _STAGING.iterdir()),
        "target": {"path": str(target), "lexists": os.path.lexists(target)},
        "controls": _controls(),
    }
'''


def _python_sync_functions() -> str:
    return '''

_REVOCATION_SYNC = Path("/run/aragorn-p3-3d-revocation-sync")


def _prepare_revocation_sync(identities: dict[str, int]) -> dict[str, Path]:
    _REVOCATION_SYNC.mkdir(mode=0o755)
    os.chown(_REVOCATION_SYNC, 0, 0)
    ready = _REVOCATION_SYNC / "ready"
    published = _REVOCATION_SYNC / "published"
    for path, mode, uid, gid in (
        (ready, 0o600, identities["runtime_uid"], identities["runtime_gid"]),
        (published, 0o644, 0, 0),
    ):
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        try:
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
    return {"published": published, "ready": ready}


def _write_sync(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("synchronization write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_synchronized_revocation(
    synchronization: dict[str, Path],
    identities: dict[str, int],
    target: Path,
) -> dict[str, Any]:
    before = _revocation_snapshot(target)
    publication = _run_python_as(
        identities["broker_uid"],
        identities["runtime_gid"],
        [identities["sensor_gid"]],
        ["publish-status", "revoked"],
    )
    after = _revocation_snapshot(target)
    _write_sync(synchronization["published"], b"published\\n")
    return {
        "after_publication": after,
        "before_publication": before,
        "publication": publication,
    }
'''


def _mjs_sync_function() -> str:
    return '''

async function synchronizeRevocation(input) {
  if (input.scenario.id !== "revoked") return;
  const root = "/run/aragorn-p3-3d-revocation-sync";
  const ready = join(root, "ready");
  const published = join(root, "published");
  writeFileSync(ready, "ready\\n", { encoding: "utf8", flag: "r+" });
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (readFileSync(published, "utf8") === "published\\n") return;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
  }
  throw new Error("timed out waiting for synchronized revocation publication");
}
'''


def _after_revocation() -> str:
    return '''        controls_after_revoked = _controls()
        snapshot_after_denial = _revocation_snapshot(
            _PROTECTED / payloads["revoked"][0]
        )
        deployment_after_revocation = {
            "units": {
                "broker": systemd_probe._unit(_BROKER_UNIT),
                "sensor": systemd_probe._unit(_SENSOR_UNIT),
            },
            "processes": {
                "broker": systemd_probe._process(broker_pid),
                "sensor": systemd_probe._process(sensor_pid),
            },
            "sockets": {
                "backend": systemd_probe._metadata(_BACKEND),
                "frontend": systemd_probe._metadata(_FRONTEND),
            },
        }
'''


def _revocation_checks() -> str:
    return '''        revocation_checks = {
            "publisher_health": published_revocation["health"]["status"] == "healthy",
            "published_digest": published_revocation["revocations"]["skill_digests"]
            == [_SKILL_DIGEST],
            "published_generation": published_revocation["revocations"]["generation"]
            == snapshot_before_revocation["controls"]["revocations"]["document"]["generation"] + 1,
            "published_snapshot": snapshot_after_publication["controls"]["revocations"]["document"]
            == published_revocation["revocations"],
            "filesystem_unchanged": all(
                snapshot["protected_entries"] == [payloads["allow"][0]]
                and snapshot["staging_entries"] == []
                and snapshot["target"]
                == {
                    "path": str(_PROTECTED / payloads["revoked"][0]),
                    "lexists": False,
                }
                for snapshot in (
                    snapshot_before_revocation,
                    snapshot_after_publication,
                    snapshot_after_denial,
                )
            ),
            "blocked": revoked_result["verdict"] == "BLOCK",
            "no_effect": revoked_result["effect_status"] == "NOT_PERFORMED",
            "sole_reason": revoked_result["reason_codes"]
            == ["ACTIVE_SKILL_REVOKED"]
            and revoked_result["decision"]["reason_codes"]
            == ["ACTIVE_SKILL_REVOKED"],
            "decision_generation": revoked_result["decision"]["revocation_generation"]
            == revoked_result["decision"]["minimum_revocation_generation"]
            == published_revocation["revocations"]["generation"],
            "decision_snapshot": revoked_result["decision"]["revocation_snapshot_digest"]
            == canonical_digest(published_revocation["revocations"]),
            "floor_advanced": revoked_state["minimum_revocation_generation"]
            == controls_after_revoked["revocations"]["document"]["generation"]
            == published_revocation["revocations"]["generation"],
            "control_snapshot_stable": controls_after_revoked["revocations"]["document"]
            == published_revocation["revocations"],
            "mediator_healthy": controls_after_revoked["health"]["document"]["status"]
            == "healthy",
            "units_stable": deployment_after_revocation["units"] == deployment["units"],
            "processes_stable": deployment_after_revocation["processes"]
            == deployment["processes"],
            "sockets_stable": deployment_after_revocation["sockets"]
            == deployment["sockets"],
        }
        _expect(
            all(revocation_checks.values()),
            "live active-skill revocation transition changed: "
            + ",".join(name for name, passed in revocation_checks.items() if not passed),
        )
'''


def _python_transformations() -> list[tuple[str, str, int, str]]:
    return [
        ("P3.3c", "P3.3d", 9, "milestone label"),
        ("p3.3c", "p3.3d", 2, "profile label"),
        ("p3-3c", "p3-3d", 5, "fixture identifiers"),
        ("p33c", "p33d", 2, "image and token identifiers"),
        ("unhealthy", "revoked", 33, "scenario identifier"),
        (
            '"status": status,',
            '"status": "healthy",',
            1,
            "keep mediator healthy",
        ),
        (
            '"generation": current_revocations["generation"] + 1,',
            '"generation": current_revocations["generation"] + 1,\n'
            '            "skill_digests": [_SKILL_DIGEST] if status == "revoked" else [],',
            1,
            "publish the active digest",
        ),
        (
            "    if control_status is not None:",
            '    if control_status == "healthy":',
            2,
            "reserve revoked publication for synchronized boundary",
        ),
        (
            "\n\ndef _run_openclaw(\n",
            _python_sync_functions() + "\ndef _run_openclaw(\n",
            1,
            "add bounded revocation handshake",
        ),
        (
            "    started_at = datetime.now(timezone.utc).isoformat().replace(\"+00:00\", \"Z\")\n"
            "    refreshes = []",
            '    synchronization = (\n'
            '        _prepare_revocation_sync(identities)\n'
            '        if scenario_id == "revoked"\n'
            '        else None\n'
            '    )\n'
            '    transition = None\n'
            '    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")\n'
            '    refreshes = []',
            1,
            "prepare one-use synchronization files",
        ),
        (
            "            except subprocess.TimeoutExpired:\n"
            "                if time.monotonic() >= deadline:",
            '            except subprocess.TimeoutExpired:\n'
            '                if (\n'
            '                    synchronization is not None\n'
            '                    and transition is None\n'
            '                    and synchronization["ready"].read_text() == "ready\\n"\n'
            '                ):\n'
            '                    transition = _publish_synchronized_revocation(\n'
            '                        synchronization,\n'
            '                        identities,\n'
            '                        _PROTECTED / config["scenario"]["target_name"],\n'
            '                    )\n'
            '                if time.monotonic() >= deadline:',
            1,
            "publish only after OpenClaw preflight",
        ),
        (
            "    completed_at = datetime.now(timezone.utc).isoformat().replace(\"+00:00\", \"Z\")",
            '    if synchronization is not None:\n'
            '        _expect(transition is not None, "revocation synchronization was not reached")\n'
            '    completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")',
            1,
            "require completed synchronization",
        ),
        (
            '    return {\n        "config": config,',
            '    result = {\n        "config": config,',
            1,
            "retain private transition until collection",
        ),
        (
            '        "evidence": document,\n    }\n\n\ndef _controls',
            '        "evidence": document,\n'
            '    }\n'
            '    if transition is not None:\n'
            '        result["_revocation_transition"] = transition\n'
            '    return result\n\n\n'
            'def _controls',
            1,
            "return synchronized transition",
        ),
        (
            'revoked["control_refreshes"]\n'
            '            and revoked["control_refreshes"][-1]["health"]["status"]\n'
            '            == "revoked"\n'
            '            and revoked_pair',
            'not revoked["control_refreshes"]\n'
            '            and published_revocation["health"]["status"] == "healthy"\n'
            '            and revoked_pair',
            1,
            "require one authoritative publication",
        ),
        (
            "aragorn/runtime-action-openclaw-systemd-composition-evidence/v1",
            "aragorn/runtime-action-openclaw-revocation-composition-evidence/v1",
            1,
            "version evidence schema",
        ),
        (
            "BOUNDED_PINNED_OPENCLAW_SYSTEMD_COMPOSITION_ONLY_NOT_RUN_OR_EDR_AUTHORITY",
            "BOUNDED_PINNED_OPENCLAW_LIVE_REVOCATION_ONLY_NOT_RUN_OR_EDR_AUTHORITY",
            1,
            "bound authority",
        ),
        (
            '"pinned_openclaw_composition_observed": True,',
            '"pinned_openclaw_composition_observed": True,\n'
            '                "live_active_skill_revocation_observed": True,',
            1,
            "record bounded revocation observation",
        ),
        (
            "P3_3C_OBSERVED",
            "P3_3D_OBSERVED",
            1,
            "version bounded status",
        ),
        (
            '"ACTIVE_SKILL_DIGEST_IS_DEPLOYMENT_PIN_NOT_CAUSAL_ATTRIBUTION",',
            '"ACTIVE_SKILL_DIGEST_IS_DEPLOYMENT_PIN_NOT_CAUSAL_ATTRIBUTION",\n'
            '    "REVOCATION_PUBLICATION_IS_EVALUATOR_OPERATED_NOT_AUTHENTICATED_INGRESS",',
            1,
            "retain ingress limitation",
        ),
        (
            "aragorn/runtime-action-openclaw-systemd-harness/v1",
            "aragorn/runtime-action-openclaw-revocation-harness/v1",
            1,
            "version harness schema",
        ),
        (
            "runtime_action_openclaw_systemd_probe.py",
            "runtime_action_openclaw_revocation_probe.py",
            1,
            "bind derivation driver",
        ),
        (
            "capture_runtime_action_openclaw_systemd.sh",
            "capture_runtime_action_openclaw_revocation.sh",
            1,
            "bind capture recipe",
        ),
        (
            "runtime-action-openclaw-systemd/Dockerfile",
            "runtime-action-openclaw-revocation/Dockerfile",
            1,
            "bind child Dockerfile",
        ),
        (
            "/src/benchmark/runtime-action-openclaw-systemd/openclaw-probe.mjs",
            str(_MJS_DERIVED),
            1,
            "use derived OpenClaw probe",
        ),
        (
            'sys.path.insert(0, str(Path(__file__).resolve().parent))',
            'sys.path.insert(0, "/src/scripts")',
            1,
            "reuse installed systemd helpers",
        ),
        (
            "\n\ndef _collect() -> dict[str, Any]:",
            _snapshot_function() + "\ndef _collect() -> dict[str, Any]:",
            1,
            "add filesystem/control snapshots",
        ),
        (
            '            "revoked", policy, plugin_digest, identities, "revoked"\n'
            "        )",
            '            "revoked", policy, plugin_digest, identities, "revoked"\n'
            '        )\n'
            '        synchronized = revoked.pop("_revocation_transition")\n'
            '        snapshot_before_revocation = synchronized["before_publication"]\n'
            '        published_revocation = synchronized["publication"]\n'
            '        snapshot_after_publication = synchronized["after_publication"]',
            1,
            "extract synchronized publication",
        ),
        (
            "        controls_after_revoked = _controls()\n",
            _after_revocation(),
            1,
            "capture post-denial stability",
        ),
        (
            "        _expect(\n"
            "            not revoked[\"control_refreshes\"]",
            _revocation_checks()
            + "        _expect(\n"
            "            not revoked[\"control_refreshes\"]",
            1,
            "assert the revocation transition",
        ),
        (
            '            "deployment": deployment,',
            '            "deployment": deployment,\n'
            '            "deployment_after_revocation": deployment_after_revocation,',
            1,
            "retain service stability",
        ),
        (
            '            "peer_trace": {"broker": broker_trace, "sensor": sensor_trace},',
            '            "peer_trace": {"broker": broker_trace, "sensor": sensor_trace},\n'
            '            "revocation_transition": {\n'
            '                "before_publication": snapshot_before_revocation,\n'
            '                "publication": published_revocation,\n'
            '                "after_publication": snapshot_after_publication,\n'
            '                "after_denial": snapshot_after_denial,\n'
            '            },',
            1,
            "retain causal transition",
        ),
    ]


def _mjs_transformations() -> list[tuple[str, str, int, str]]:
    return [
        ("p33c", "p33d", 2, "probe identifiers"),
        (
            "P3_3C_OBSERVED",
            "P3_3D_OBSERVED",
            1,
            "version nested bounded status",
        ),
        (
            "MEDIATOR_UNHEALTHY",
            "ACTIVE_SKILL_REVOKED",
            1,
            "exact blocked reason",
        ),
        (
            "\n\nfunction providerResponse(sequence, input, toolCallId, finalText) {",
            _mjs_sync_function()
            + "\nfunction providerResponse(sequence, input, toolCallId, finalText) {",
            1,
            "add pre-tool revocation synchronization",
        ),
        (
            "    try {\n      sendCommand = await gatewayCall(runCommand, \"chat.send\", {",
            '    try {\n'
            '      await synchronizeRevocation(input);\n'
            '      sendCommand = await gatewayCall(runCommand, "chat.send", {',
            1,
            "pause after preflight before tool request",
        ),
    ]


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _write_all(descriptor: int, raw: bytes) -> None:
    remaining = memoryview(raw)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("evidence write made no progress")
        remaining = remaining[written:]


def _derive(
    source: Path,
    destination: Path,
    expected_digest: str,
    transformations: list[tuple[str, str, int, str]],
) -> dict[str, Any]:
    raw = source.read_bytes()
    if _digest(raw) != expected_digest:
        raise ProbeError(f"pinned derivation source changed: {source}")
    records = []
    for old, new, count, purpose in transformations:
        old_raw = old.encode()
        observed = raw.count(old_raw)
        if observed != count:
            raise ProbeError(
                f"derivation match count changed for {purpose}: {observed} != {count}"
            )
        raw = raw.replace(old_raw, new.encode())
        records.append(
            {
                "count": count,
                "old_digest": _digest(old_raw),
                "new_digest": _digest(new.encode()),
                "purpose": purpose,
            }
        )
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o444,
    )
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "source_path": str(source),
        "source_digest": expected_digest,
        "derived_path": str(destination),
        "derived_digest": _digest(raw),
        "derived_bytes": len(raw),
        "transformations": records,
        "transformations_digest": canonical_digest(records),
    }


def _file(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    metadata = path.stat(follow_symlinks=False)
    return {
        "path": str(path),
        "digest": _digest(raw),
        "bytes": len(raw),
        "mode": f"{metadata.st_mode & 0o7777:04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def _publish(path: Path, document: dict[str, Any]) -> None:
    raw = canonical_json(document) + b"\n"
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _collect() -> dict[str, Any]:
    harness = json.loads(_HARNESS.read_bytes())
    retained = harness.get("retained_p3c")
    if not (
        harness.get("schema")
        == "aragorn/runtime-action-openclaw-revocation-harness/v1"
        and harness.get("parent_image_id") == _BASE_IMAGE_ID
        and isinstance(retained, dict)
        and retained.get("canonical_digest") == _BASE_EVIDENCE_DIGEST
        and retained.get("raw_digest") == _BASE_EVIDENCE_RAW_DIGEST
    ):
        raise ProbeError("P3.3c lineage harness changed")
    python_derivation = _derive(
        _PYTHON_SOURCE,
        _PYTHON_DERIVED,
        "sha256:29480b57ea2ffd74dfd3df6cc32473f2d35a947715e58c92697b1b968d95a85e",
        _python_transformations(),
    )
    mjs_derivation = _derive(
        _MJS_SOURCE,
        _MJS_DERIVED,
        "sha256:d8c65f78ae9a619de6dc257bf0fa89d1dce9c739d09ec9335df9f58927a63c2f",
        _mjs_transformations(),
    )
    derived_output = Path("/run/aragorn-p3-3d-derived-evidence.json")
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(_PYTHON_DERIVED),
            "--output",
            str(derived_output),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise ProbeError(
            "derived probe failed: "
            + completed.stderr.decode(errors="replace")[-4000:]
        )
    document = json.loads(derived_output.read_bytes())
    if canonical_json(document) + b"\n" != derived_output.read_bytes():
        raise ProbeError("derived probe output is not canonical JSON")
    document["lineage"] = {
        "retained_p3c": retained,
        "parent_image_id": _BASE_IMAGE_ID,
        "derivations": [python_derivation, mjs_derivation],
    }
    document["collector"]["derivation_driver"] = _file(Path(__file__).resolve())
    return document


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2 or arguments[0] != "--output":
        print("usage: runtime_action_openclaw_revocation_probe.py --output PATH", file=sys.stderr)
        return 64
    _publish(Path(arguments[1]), _collect())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
