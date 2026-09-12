"""Render a pinned producer source overlay, not a standalone protected release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_SCHEMA = "aragorn/protected-install-quarantine-producer-overlay/v1"
_AUTHORITY = "PINNED_PRODUCER_SOURCE_OVERLAY_ONLY_NOT_RELEASE_OR_INSTALLATION_AUTHORITY"
_BASE = "benchmark/admission/openclaw-v2026.7.1/"
_IMPORT = (
    b"from aragorn.protected_install import (\n"
    b"    _ACTIVE_RUNTIME_AUTHORITY,\n"
    b"    _ACTIVE_RUNTIME_RECORD,\n"
    b"    _ACTIVE_RUNTIME_SCHEMA,\n"
    b"    ProtectedInstallTransactionError,\n"
    b"    _materialize_verified_manifest,\n"
    b"    _publish_protected_install_transaction,\n"
    b")"
)
_SUCCESSOR_IMPORT = (
    _IMPORT.replace(b"    _publish_protected_install_transaction,\n", b"")
    + b"\nfrom aragorn.protected_install_v2 import (\n"
    + b"    _publish_protected_install_transaction,\n)\n"
    + b"from aragorn.protected_install_namespace_v2 import protected_root_entries"
)
_REPLACEMENTS = (
    (_IMPORT, _SUCCESSOR_IMPORT, 1),
    (
        b"sorted(child.name for child in path.iterdir())",
        b"protected_root_entries(path, expected_uid)",
        3,
    ),
)
# Source and output identities are independent, reviewed constants.
_PRODUCERS = {
    _BASE + "protected-install-broker.py": (
        80_661,
        "sha256:29c393807458f1f92266a9657522ebc982c674a8124e18731e2c84561248b20c",
        80_768,
        "sha256:56245b4faf260439de3a3f1bbd3d33b75a851bc22177106882a2e3802ee1c637",
    ),
    _BASE + "protected-install-broker-recursive-v3.py": (
        95_777,
        "sha256:ea09f919760f73d5d3e3b1a0dca635eabc1db0bef4ba6ac19ec15d81278f2c70",
        95_884,
        "sha256:d9d447f6612e43052d568efac24e0eba0a342562c516653b538321b60e638a4d",
    ),
}
_DEPENDENCIES = {
    "src/aragorn/protected_install_namespace_v2.py": (
        3_723,
        "sha256:b5b99000549c48da2eaadca697c823326166cc4ee2e4f4ca45beb858d1177a88",
    ),
    "src/aragorn/protected_install_v2.py": (
        6_408,
        "sha256:9c16335cc10459a9ed0b75cb21615a8ea52de84fd46e57d786b9165ad483ab52",
    ),
    "src/aragorn/protected_skill_quarantine.py": (
        6_920,
        "sha256:fa1297bc05345c85e518be8ac397e35d289c8b1dc30dc4aa4002154af8aeddd0",
    ),
}


class ProducerOverlayError(ValueError):
    """A pinned source, transformation, dependency, or output is unavailable."""


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_pinned(
    name: str, size: int, digest: str, *, root: Path | None = None
) -> bytes:
    path = (_ROOT if root is None else root) / name
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != size
        ):
            raise ProducerOverlayError(f"pinned input metadata changed: {name}")
        chunks = []
        remaining = size + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if (
            len(raw) != size
            or _digest(raw) != digest
            or _identity(os.fstat(fd)) != _identity(before)
            or _identity(path.lstat()) != _identity(before)
        ):
            raise ProducerOverlayError(f"pinned input bytes changed: {name}")
        return raw
    finally:
        os.close(fd)


def _transform(raw: bytes) -> bytes:
    for old, new, expected_count in _REPLACEMENTS:
        if raw.count(old) != expected_count:
            raise ProducerOverlayError("producer replacement shape changed")
        raw = raw.replace(old, new)
    return raw


def _verified_inputs() -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    dependencies = []
    for name, (size, digest) in _DEPENDENCIES.items():
        _read_pinned(name, size, digest)
        dependencies.append({"name": name, "bytes": size, "digest": digest})
    rendered = {}
    for name, (size, digest, output_size, output_digest) in _PRODUCERS.items():
        raw = _transform(_read_pinned(name, size, digest))
        if len(raw) != output_size or _digest(raw) != output_digest:
            raise ProducerOverlayError(f"rendered producer bytes changed: {name}")
        rendered[name] = raw
    return rendered, dependencies


def materialize_protected_install_quarantine_producers(output: Path) -> dict[str, Any]:
    """Write only two producer sources into a new, read-only relative-path tree.

    The missing full src package and dependency lock are intentional. In-process
    tests may use the current checkout; this overlay cannot be launched as a
    standalone release. Every source and direct new dependency is verified before
    creating output. A write failure may leave an incomplete output directory;
    it never returns a manifest claiming successful materialization.
    """

    try:
        if not isinstance(output, Path) or output.exists() or output.is_symlink():
            raise ProducerOverlayError("output must be a new Path")
        rendered, dependencies = _verified_inputs()
        output.mkdir(mode=0o755)
        directories = [output]
        parent = output
        for part in ("benchmark", "admission", "openclaw-v2026.7.1"):
            parent = parent / part
            parent.mkdir(mode=0o755)
            directories.append(parent)
        files = []
        for name, raw in rendered.items():
            fd = os.open(
                output / name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o444,
            )
            try:
                written = 0
                while written < len(raw):
                    count = os.write(fd, raw[written:])
                    if count <= 0:
                        raise ProducerOverlayError("overlay write made no progress")
                    written += count
                os.fchmod(fd, 0o444)
                os.fsync(fd)
            finally:
                os.close(fd)
            source_size, source_digest, _, output_digest = _PRODUCERS[name]
            _read_pinned(name, len(raw), output_digest, root=output)
            files.append(
                {
                    "name": name,
                    "bytes": len(raw),
                    "digest": output_digest,
                    "source_bytes": source_size,
                    "source_digest": source_digest,
                }
            )
        for directory in reversed(directories):
            directory.chmod(0o555, follow_symlinks=False)
        return {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "files": files,
            "required_checkout_dependencies_not_included": dependencies,
            "standalone_executable": False,
            "production_activation_eligible": False,
            "runtime_startup_enforcement": False,
            "missing_release_inputs": [
                "complete src/aragorn package and its whole-package analyzer identity",
                "requirements-worker.lock",
                "protected release, launcher, and deployment identity bindings",
            ],
        }
    except (OSError, TypeError, ValueError) as exc:
        raise ProducerOverlayError(
            f"cannot materialize producer overlay: {exc}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = materialize_protected_install_quarantine_producers(args.output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
