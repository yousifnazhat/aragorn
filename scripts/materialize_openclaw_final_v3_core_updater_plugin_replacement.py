#!/usr/bin/env python3
"""Materialize the dedicated V3 core-updater replacement capture bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import runpy
from pathlib import Path
from typing import Any


class CoreUpdaterMaterializationError(ValueError):
    """The pinned core-updater capture bundle changed."""


_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_REBINDER = _ROOT / "scripts/materialize_openclaw_final_v3_rebound_probes.py"
_REBINDER_BYTES = 7_691
_REBINDER_DIGEST = (
    "sha256:8321a6c423b03c283d175185de6886ca12aaa08c244f81b67be3a73a47279a1c"
)
_CASE_ID = "ADM-02/update/core-updater-plugin-replacement"
_PROBE = "protected-core-updater-plugin-replacement-v3-probe.mjs"
_DELEGATED_PROBE = "protected-route-action-probe.mjs"
_SCHEMA = "aragorn/openclaw-final-v3-core-updater-plugin-replacement-bundle/v1"
_AUTHORITY = (
    "PINNED_CORE_UPDATER_REPLACEMENT_CAPTURE_BUNDLE_ONLY_"
    "NOT_EXECUTION_QUALIFICATION_ADMISSION_OR_UPDATE_AUTHORITY"
)
_SOURCES = {
    _PROBE: (
        _ADMISSION / _PROBE,
        26_844,
        "sha256:7348d0ee886ccdbb315a950a8793d2cd654c39019b52849b40bcd43cc9ba5ee3",
        "probe",
    ),
    "core-updater-plugin-replacement-audit-listener.mjs": (
        _ADMISSION / "core-updater-plugin-replacement-audit-listener.mjs",
        2_947,
        "sha256:66da837cb9c1f54ce66ccf5f3c2012021715bf6848005f545102d18155976545",
        "probe-dependency",
    ),
    "candidate-source/index.js": (
        _ADMISSION / "core-updater-plugin-replacement-index.js",
        154,
        "sha256:67ecfc8f10e39dcc60ec880a587fadeacdb0040b1911ef93a995575f2aa5bbf2",
        "fixture",
    ),
    "candidate-source/openclaw.plugin.json": (
        _ADMISSION / "core-updater-plugin-replacement-openclaw.plugin.json",
        698,
        "sha256:a9d62834481462f8f474fe16bab4fb3d466942d9fc2602c618592897bf427d82",
        "fixture",
    ),
    "candidate-source/package.json": (
        _ADMISSION / "core-updater-plugin-replacement-package.json",
        134,
        "sha256:86f83ebce70efcb741663859444a059de21eb8906fbe45dc220aed6c94eb5803",
        "fixture",
    ),
}
_REBIND_DELEGATED_BYTES = 44_825
_REBIND_DELEGATED_DIGEST = (
    "sha256:4687054e9d7ea264c6772de4e0560fafb195ebbbfc7397333297abd6cc4347ff"
)
_DELEGATED_BYTES = 45_093
_DELEGATED_DIGEST = (
    "sha256:18f17a79ba6c72b247857d9213abc1093f699a2000e4d8c4f5192b719e905132"
)
_AUDIT_ENV_REPLACEMENTS = (
    (
        (
            b'    NO_PROXY: "127.0.0.1,localhost",\n'
            b"    OPENCLAW_CONFIG_PATH: CONFIG,"
        ),
        (
            b'    NO_PROXY: "127.0.0.1,localhost",\n'
            b"    ARAGORN_CORE_UPDATER_AUDIT_PATH:\n"
            b'      "/profile/state/core-updater-policy-audit.jsonl",\n'
            b"    NODE_OPTIONS:\n"
            b'      "--import=/route-input/core-updater-plugin-replacement/'
            b'core-updater-plugin-replacement-audit-listener.mjs",\n'
            b"    OPENCLAW_CONFIG_PATH:\n"
            b'      "/profile/state/core-updater-openclaw.json",'
        ),
    ),
)


def materialize_openclaw_final_v3_core_updater_plugin_replacement(
    output: Path,
) -> dict[str, Any]:
    """Write one exact read-only preflight, action probe, and candidate source."""

    if not isinstance(output, Path) or output.exists() or output.is_symlink():
        raise CoreUpdaterMaterializationError("output must be a new Path")

    materialized: list[tuple[str, bytes, str, str]] = []
    for name, (source, bytes_, digest, role) in _SOURCES.items():
        raw = _verified_file(source, bytes_, digest)
        materialized.append((name, raw, digest, role))
    delegated = _materialize_delegated_probe()
    materialized.insert(
        1, (_DELEGATED_PROBE, delegated, _DELEGATED_DIGEST, "probe-dependency")
    )

    output.mkdir(mode=0o755)
    candidate = output / "candidate-source"
    candidate.mkdir(mode=0o755)
    files = []
    for name, raw, digest, role in materialized:
        path = output / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o444)
        try:
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise CoreUpdaterMaterializationError(
                        "bundle write made no progress"
                    )
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, 0o444, follow_symlinks=False)
        files.append(
            {"bytes": len(raw), "digest": digest, "name": name, "role": role}
        )
    os.chmod(candidate, 0o555, follow_symlinks=False)
    os.chmod(output, 0o555, follow_symlinks=False)
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "case_id": _CASE_ID,
        "files": files,
        "source_relationship": {
            "action_probe": "exact-final-v3-rebound-protected-route-probe",
            "candidate_git_commit": "222d0c39429841044b95549407422873ec106a54",
            "candidate_git_tree": "fc3f1336c488b32d3b668f637ec4bdc6ccf56213",
            "preflight": "dedicated-pinned-installed-plugin-index-writer",
        },
    }


def _materialize_delegated_probe() -> bytes:
    namespace = _verified_rebinder()
    base = namespace.get("_verified_v2_materializer")
    replacements = namespace.get("_REPLACEMENTS")
    bundles = namespace.get("_BUNDLES")
    if not callable(base) or not isinstance(replacements, tuple) or not isinstance(
        bundles, dict
    ):
        raise CoreUpdaterMaterializationError("V3 rebound materializer API changed")
    transform = base().get("transformed_final_combined_v2_probe")
    if not callable(transform):
        raise CoreUpdaterMaterializationError("fixed V2 materializer entry changed")
    raw = transform("protected-route-probe.mjs", workshop=False)
    expected = bundles.get(_CASE_ID, {}).get("protected-route-probe.mjs")
    if type(raw) is not bytes or expected != (
        (2, 1, 0),
        _REBIND_DELEGATED_BYTES,
        _REBIND_DELEGATED_DIGEST,
    ):
        raise CoreUpdaterMaterializationError("delegated rebound contract changed")
    counts = tuple(raw.count(old) for old, _new in replacements)
    if counts != expected[0]:
        raise CoreUpdaterMaterializationError("delegated replacement shape changed")
    for old, new in replacements:
        raw = raw.replace(old, new)
    for old, new in _AUDIT_ENV_REPLACEMENTS:
        if raw.count(old) != 1:
            raise CoreUpdaterMaterializationError(
                "delegated audit environment shape changed"
            )
        raw = raw.replace(old, new)
    if len(raw) != _DELEGATED_BYTES or _digest(raw) != _DELEGATED_DIGEST:
        raise CoreUpdaterMaterializationError("delegated probe bytes changed")
    return raw


def _verified_rebinder() -> dict[str, Any]:
    _verified_file(_REBINDER, _REBINDER_BYTES, _REBINDER_DIGEST)
    try:
        return runpy.run_path(str(_REBINDER))
    except (OSError, TypeError, ValueError) as exc:
        raise CoreUpdaterMaterializationError(
            f"V3 rebound materializer failed: {exc}"
        ) from exc


def _verified_file(path: Path, bytes_: int, digest: str) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CoreUpdaterMaterializationError(f"cannot read pinned source: {path}") from exc
    if len(raw) != bytes_ or _digest(raw) != digest:
        raise CoreUpdaterMaterializationError(f"pinned source changed: {path}")
    return raw


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = materialize_openclaw_final_v3_core_updater_plugin_replacement(
        args.output
    )
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
