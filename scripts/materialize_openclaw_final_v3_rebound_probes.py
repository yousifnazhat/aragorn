"""Materialize exact V3 probe bundles for the six rebound-only campaign cases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import runpy
from pathlib import Path
from typing import Any


class V3RebindError(ValueError):
    """The fixed V3 rebind input or output changed."""


_ROOT = Path(__file__).resolve().parents[1]
_V2_MATERIALIZER = _ROOT / "scripts/materialize_fixed_admission_probes.py"
_V2_MATERIALIZER_BYTES = 87_912
_V2_MATERIALIZER_DIGEST = (
    "sha256:0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec"
)
_SCHEMA = "aragorn/openclaw-final-admission-v3-rebound-probe-bundle/v1"
_AUTHORITY = "PINNED_V3_PROBE_BUNDLE_ONLY_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY"
_REPLACEMENTS = (
    (
        b"sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e",
        b"sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c",
    ),
    (
        b"configuration.file?.size === 1880",
        b"configuration.file?.size === 2159",
    ),
    (b"file.size === 1880", b"file.size === 2159"),
)
_BUNDLES = {
    "ADM-02/update/archive-source-force-replacement": {
        "protected-archive-replacement-probe.mjs": (
            (3, 1, 0),
            25_498,
            "sha256:c89af8975bcdc8963659b39b354fc8b754d4805f7249a1cc766458cdad891328",
        ),
    },
    "ADM-02/update/core-updater-plugin-replacement": {
        "protected-route-probe.mjs": (
            (2, 1, 0),
            44_825,
            "sha256:4687054e9d7ea264c6772de4e0560fafb195ebbbfc7397333297abd6cc4347ff",
        ),
    },
    "ADM-02/update/curator-restore-activation": {
        "protected-curator-restore-denial-probe.mjs": (
            (3, 1, 1),
            26_571,
            "sha256:fd3fa9ec7dce5b626eb1243c3391279093d08555e7c81f67d1b4549160fca089",
        ),
        "protected-observation-v1.mjs": (
            (3, 1, 0),
            16_324,
            "sha256:672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        ),
    },
    "ADM-02/reload/cron-rescan": {
        "protected-cron-rescan-probe.mjs": (
            (0, 0, 0),
            35_318,
            "sha256:94d3b47162fd1bdc97028f44115ef54acfe8b7a296210a47a8a24a71771bb2d0",
        ),
        "protected-observation-v1.mjs": (
            (3, 1, 0),
            16_324,
            "sha256:672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        ),
    },
    "ADM-02/reload/missing-prompt-blob-rebuild": {
        "protected-prompt-rebuild-probe.mjs": (
            (0, 0, 0),
            16_464,
            "sha256:9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7",
        ),
        "protected-observation-v1.mjs": (
            (3, 1, 0),
            16_324,
            "sha256:672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        ),
    },
    "ADM-02/reload/session-snapshot-consumer": {
        "protected-session-snapshot-fixed-probe.mjs": (
            (0, 0, 0),
            42_266,
            "sha256:9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11",
        ),
        "protected-observation-v1.mjs": (
            (3, 1, 0),
            16_324,
            "sha256:672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        ),
    },
}


def materialize_openclaw_final_v3_rebound_case(
    case_id: object, output: Path
) -> dict[str, Any]:
    """Write one exact, read-only rebound bundle into a new directory."""

    if type(case_id) is not str or case_id not in _BUNDLES:
        raise V3RebindError("case id is not an exact V3 rebound registry member")
    if not isinstance(output, Path) or output.exists() or output.is_symlink():
        raise V3RebindError("output must be a new Path")

    namespace = _verified_v2_materializer()
    transform = namespace.get("transformed_final_combined_v2_probe")
    if not callable(transform):
        raise V3RebindError("fixed V2 materializer entry changed")

    materialized = []
    for name, (counts, expected_bytes, expected_digest) in _BUNDLES[case_id].items():
        raw = transform(name, workshop=False)
        if type(raw) is not bytes:
            raise V3RebindError(f"V2 materializer returned non-bytes for {name}")
        observed_counts = tuple(raw.count(old) for old, _new in _REPLACEMENTS)
        if observed_counts != counts:
            raise V3RebindError(f"V3 replacement shape changed for {name}")
        for old, new in _REPLACEMENTS:
            raw = raw.replace(old, new)
        if len(raw) != expected_bytes or _digest(raw) != expected_digest:
            raise V3RebindError(f"V3 rebound bytes changed for {name}")
        materialized.append((name, raw, expected_digest))

    output.mkdir(mode=0o755)
    files = []
    for name, raw, digest in materialized:
        path = output / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o444)
        try:
            written = 0
            while written < len(raw):
                written += os.write(fd, raw[written:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(path, 0o444, follow_symlinks=False)
        files.append({"bytes": len(raw), "digest": digest, "name": name})
    os.chmod(output, 0o555, follow_symlinks=False)
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "case_id": case_id,
        "files": files,
    }


def _verified_v2_materializer() -> dict[str, Any]:
    raw = _V2_MATERIALIZER.read_bytes()
    if len(raw) != _V2_MATERIALIZER_BYTES or _digest(raw) != _V2_MATERIALIZER_DIGEST:
        raise V3RebindError("fixed V2 materializer bytes changed")
    return runpy.run_path(str(_V2_MATERIALIZER))


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id", choices=tuple(_BUNDLES))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = materialize_openclaw_final_v3_rebound_case(args.case_id, args.output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
