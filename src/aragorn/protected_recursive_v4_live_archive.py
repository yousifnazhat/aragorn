"""Strict offline replay of the retained request-v4 protected-install capture."""

from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import json
import sys
import tarfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import RLock
from typing import Any
from unittest.mock import patch

from .artifact_closure import canonical_json, load_verified_retained_manifest
from .cas import CAS
from .github_recursive_live_archive import (
    GitHubRecursiveLiveArchiveError,
    _verify_cas_inventory,
    _verify_decision,
    _verify_handoff,
    _verify_receipt,
)
from .protected_install_transition_replay import (
    _File,
    _pinned_bytes,
    _safe_name,
    _sha256,
)
from .protected_recursive_v3_live_archive import (
    _REQUEST_DIGEST_FIELDS,
    _REQUEST_FIELDS,
    _REQUEST_TTL_SECONDS,
    _Archive,
    _cas_document,
    _decision_record,
    _digest,
    _document,
    _gateway_tree_digest,
    _hex,
    _journal,
    _json_document,
    _package_tree_digest,
    _positive,
    _positive_integer,
    _positive_result,
    _systemd_boundary,
    _walk,
)

ARCHIVE_DIGEST = (
    "sha256:08bb32c12e159fede3618bcdeecff5e56c8630e9681d70fe7922f4654cb1b6d8"
)
ARCHIVE_NAME = "phase1-protected-recursive-v4-live-0307946e55d9-2026-07-29.tar.xz"
ARCHIVE_PATH = f"benchmark/evidence/{ARCHIVE_NAME}"
AUTHORITY = "OFFLINE_LIVE_PATH_REPLAY_ONLY_NOT_INSTALLER_OR_RUNTIME_AUTHORITY"

_ROOT = "phase1-protected-recursive-v4-live-0307946e55d9"
_CASES = ("install", "update", "release-error")
_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
_EXPECTED_INVENTORY = {
    "members": 2_859,
    "regular_files": 2_532,
    "directories": 326,
    "symlinks": 1,
    "payload_bytes": 37_590_194,
}
_CAPTURE_LIMITATIONS = [
    "EXACT_RETAINED_VM_PATH_ONLY",
    "OPERATOR_CAPTURE_NOT_INDEPENDENT_ATTESTATION",
    "NO_INSTALLER_AUTHORITY",
    "NO_RUNTIME_CONFORMANCE_QUALIFICATION",
    "BYTE_IDENTICAL_UPDATE_ONLY",
    "RELEASE_RUNTIME_CONSUMER_UNPROVEN",
]
_CAPTURE_TIME_REPLAY_MODULES = (
    "__init__",
    "acquire",
    "admission_artifact_graph",
    "admission_decision",
    "analyze",
    "analyzer_receipt",
    "artifact_closure",
    "benchmark",
    "benchmark_authenticated_handoff_v2",
    "benchmark_handoff_v2",
    "benchmark_protocol_v2",
    "benchmark_semantic_closure_v2",
    "benchmark_worker_measurement",
    "cas",
    "decision_receipt",
    "docker_identity",
    "github_acquire",
    "github_expand",
    "github_expansion_proof",
    "github_gateway",
    "github_gateway_live_evidence",
    "github_git_protocol",
    "github_quarantine_receipt",
    "github_recursive_artifact_graph",
    "github_recursive_artifact_graph_v4",
    "github_recursive_artifact_graph_v5",
    "github_recursive_artifact_graph_v6",
    "github_recursive_gateway",
    "github_recursive_live_archive",
    "github_release_asset",
    "github_source_proof",
    "installed_tree_replay",
    "label_blind_prepare",
    "manifest_diff",
    "materialization",
    "oci_runtime",
    "oci_worker_protocol",
    "phase0_candidate",
    "policy",
    "protected_install",
    "protected_install_context",
    "protected_install_transition_replay",
    "protected_recursive_v3_live_archive",
    "protected_transition_live_archive",
    "vendor_reports",
    "zip_inventory",
)
# These modules evolved after capture; historical replay imports their retained
# bytes while every other dependency remains byte-identical in the live package.
_CAPTURED_REPLAY_OVERRIDES = {
    "benchmark": "sha256:354486f4558107f95ca8e7c12315dec5c8028657c0e5401a62d70bcbdef19736",
    "benchmark_handoff_v2": "sha256:eda3a06378a828bfe707b5c1e85483b3c1d89c5e4ac642614e8f1ebaaf8fe70e",
    "github_gateway": "sha256:21e3a74cb0927d1a160b089797cc169e1d1bfc8c68b7a2b5005904ee7aabe07c",
    "github_quarantine_receipt": "sha256:170f873cf49d8585f9b37d15c13ea823ac27c1e9d6eb966a2a6996abfc73efc1",
    "oci_runtime": "sha256:9c9ed5819ceeda4d5734da23d100b7a8058643fbea81ee742fcbba868b8dface",
    "protected_install": "sha256:885feeb23d2a29f65e51799ed5ec022c47db7f41c97f9c887af1183552cfa402",
}
# ponytail: global replay lock; pass dependencies explicitly if throughput matters.
_HISTORICAL_REPLAY_LOCK = RLock()


class ProtectedRecursiveV4LiveArchiveError(ValueError):
    """The retained request-v4 live archive is malformed or inconsistent."""


@dataclass(frozen=True, slots=True)
class _HistoricalReplay:
    gateway: Any
    recursive_gateway: Any
    quarantine_receipt: Any
    recursive_graph_v6: Any


def verify_protected_recursive_v4_live_archive(
    archive_path: str | Path,
) -> dict[str, Any]:
    """Replay the exact retained systemd path without granting runtime authority."""

    try:
        raw = _pinned_bytes(
            archive_path,
            ARCHIVE_DIGEST,
            "request-v4 protected-install live archive",
            _MAX_ARCHIVE_BYTES,
        )
        if (
            len(raw) < 18
            or raw[:8] != b"\xfd7zXZ\x00\x00\x04"
            or raw[-4:] != b"\x00\x04YZ"
        ):
            raise ProtectedRecursiveV4LiveArchiveError(
                "archive XZ stream is not normalized"
            )
        with TemporaryDirectory(prefix="aragorn-protected-recursive-v4-") as temporary:
            archive = _load(raw, Path(temporary))
            with _historical_replay(archive, Path(temporary)) as historical:
                capture = _document(archive, "capture.json")
                _capture_boundary(capture, historical)
                runtime = _runtime(archive, capture)
                journals = _journals(archive)

                install = _positive_v4(
                    archive,
                    capture,
                    journals["install"]["broker"]["message"],
                    "install",
                    journals["install"]["broker"]["timestamp"],
                    historical=historical,
                )
                update = _positive_v4(
                    archive,
                    capture,
                    journals["update"]["broker"]["message"],
                    "update",
                    journals["update"]["broker"]["timestamp"],
                    historical=historical,
                    previous=install,
                )
                _final_publication(archive, install, update)
                release_error = _release_error(
                    archive,
                    capture,
                    journals["release-error"]["broker"]["message"],
                    journals["release-error"]["coordinator"]["message"],
                    journals["release-error"]["broker"]["timestamp"],
                    historical=historical,
                    reference_request=install["service_request_v4"],
                )
                for label, cas in archive.cases.items():
                    _verify_cas_inventory(
                        CAS(cas.root, read_only=True),
                        archive.blobs[label],
                    )

        return {
            "schema": "aragorn/protected-recursive-v4-live-qualification/v1",
            "authority": AUTHORITY,
            "archive": {
                "path": ARCHIVE_PATH,
                "digest": ARCHIVE_DIGEST,
                "bytes": len(raw),
                **archive.inventory,
            },
            "provenance": capture["provenance"],
            "runtime": runtime,
            "install": _result(install),
            "update": _result(update),
            "release_error": release_error,
            "qualification": {
                "live_protected_path_qualified": True,
                "automatic_release_pin_custody_qualified": True,
                "runtime_conformance_qualified": False,
                "installer_work_eligible": False,
                "phase1_complete": False,
                "public_release_eligible": False,
            },
            "limitations": _CAPTURE_LIMITATIONS,
            "status": "PASS",
        }
    except ProtectedRecursiveV4LiveArchiveError:
        raise
    except Exception as exc:
        raise ProtectedRecursiveV4LiveArchiveError(
            f"cannot verify request-v4 protected-install live archive: {exc}"
        ) from exc


def _load(raw: bytes, temporary: Path) -> _Archive:
    files: dict[str, _File] = {}
    directories: dict[str, int] = {}
    symlinks: dict[str, tuple[int, str]] = {}
    blobs: dict[str, dict[str, bytes]] = {label: {} for label in _CASES}
    counts = {
        "members": 0,
        "regular_files": 0,
        "directories": 0,
        "symlinks": 0,
        "payload_bytes": 0,
    }
    previous = ""
    try:
        with tarfile.open(fileobj=BytesIO(raw), mode="r|xz") as source:
            for member in source:
                if counts["members"] >= _EXPECTED_INVENTORY["members"]:
                    raise ProtectedRecursiveV4LiveArchiveError(
                        "archive member count exceeds its limit"
                    )
                counts["members"] += 1
                name = _safe_name(member)
                if name <= previous:
                    raise ProtectedRecursiveV4LiveArchiveError(
                        "archive members are repeated or not name-sorted"
                    )
                previous = name
                if (
                    member.uid
                    or member.gid
                    or member.uname
                    or member.gname
                    or member.mtime
                    or member.pax_headers
                    or getattr(member, "sparse", None)
                    or member.devmajor
                    or member.devminor
                    or member.mode & ~0o777
                ):
                    raise ProtectedRecursiveV4LiveArchiveError(
                        f"archive metadata is not normalized: {name}"
                    )
                relative = _relative(name)
                if member.isdir():
                    if member.size or member.linkname:
                        raise ProtectedRecursiveV4LiveArchiveError(
                            f"archive directory metadata changed: {name}"
                        )
                    directories[relative] = member.mode
                    counts["directories"] += 1
                    continue
                if member.issym():
                    if (
                        relative != "protected/positive/aragorn-admitted"
                        or member.mode != 0o777
                        or member.size
                        or member.linkname.startswith("/")
                        or ".." in Path(member.linkname).parts
                    ):
                        raise ProtectedRecursiveV4LiveArchiveError(
                            "archive symlink changed"
                        )
                    symlinks[relative] = (member.mode, member.linkname)
                    counts["symlinks"] += 1
                    continue
                if not member.isfile() or member.linkname:
                    raise ProtectedRecursiveV4LiveArchiveError(
                        f"archive contains a hard link or special member: {name}"
                    )
                if member.size > _MAX_MEMBER_BYTES:
                    raise ProtectedRecursiveV4LiveArchiveError(
                        f"archive member exceeds its byte limit: {name}"
                    )
                stream = source.extractfile(member)
                content = b"" if stream is None else stream.read(member.size + 1)
                if len(content) != member.size:
                    raise ProtectedRecursiveV4LiveArchiveError(
                        f"archive member size changed: {name}"
                    )
                counts["payload_bytes"] += len(content)
                if counts["payload_bytes"] > _MAX_PAYLOAD_BYTES:
                    raise ProtectedRecursiveV4LiveArchiveError(
                        "archive payload exceeds its byte limit"
                    )
                identity = _cas_identity(relative)
                if identity is not None:
                    label, digest = identity
                    if (
                        member.mode != 0o444
                        or _sha256(content) != digest
                        or digest in blobs[label]
                    ):
                        raise ProtectedRecursiveV4LiveArchiveError(
                            f"archive CAS identity changed: {name}"
                        )
                    blobs[label][digest] = content
                files[relative] = _File(content, member.mode)
                counts["regular_files"] += 1
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ProtectedRecursiveV4LiveArchiveError(
            f"archive stream is invalid: {exc}"
        ) from exc

    required = {
        "capture.json",
        "protected/coordinator-state.json",
        "runtime/release.json",
        "runtime/revocations.json",
        "runtime/launcher.py",
        "runtime/coordinator.py",
        "runtime/host-facts.txt",
        "runtime/mounts.json",
        "runtime/systemd-show.txt",
        "runtime/systemd/protected-install.service",
        "runtime/systemd/coordinator.service",
        "runtime/systemd/coordinator.path",
    }
    for label in _CASES:
        required |= {
            f"requests/{label}.json",
            f"evidence/{label}-intent.json",
            f"evidence/{label}-journal.json",
            f"evidence/{label}-coordinator-journal.json",
            f"evidence/{label}-status.json",
        }
    required.add("evidence/release-error-protected-state.json")
    names = (set(files) | set(directories) | set(symlinks)) - {"."}
    if (
        counts != _EXPECTED_INVENTORY
        or not required.issubset(files)
        or any(not blobs[label] for label in _CASES)
        or {name.split("/", 1)[0] for name in names}
        != {"capture.json", "cas", "evidence", "protected", "requests", "runtime"}
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            "archive inventory or required evidence changed"
        )
    cases: dict[str, CAS] = {}
    for label, inventory in blobs.items():
        writable = CAS(temporary / label)
        for digest, content in inventory.items():
            writable.put_expected(
                BytesIO(content),
                expected_digest=digest,
                max_bytes=len(content),
            )
        cases[label] = writable
    return _Archive(files, directories, symlinks, cases, blobs, counts)


@contextmanager
def _historical_replay(
    archive: _Archive, temporary: Path
) -> Iterator[_HistoricalReplay]:
    with _HISTORICAL_REPLAY_LOCK:
        yield from _historical_replay_unlocked(archive, temporary)


def _historical_replay_unlocked(
    archive: _Archive, temporary: Path
) -> Iterator[_HistoricalReplay]:
    _verify_local_replay_closure(archive)
    package_root = temporary / "capture-source" / "aragorn"
    package_root.mkdir(parents=True, mode=0o700)
    prefix = "runtime/package/src/aragorn/"
    for module in _CAPTURE_TIME_REPLAY_MODULES:
        item = archive.files[f"{prefix}{module}.py"]
        target = package_root / f"{module}.py"
        target.write_bytes(item.raw)
        target.chmod(0o400)
    initializer = package_root / "__init__.py"
    package_name = f"_aragorn_phase1_v4_{id(archive):x}"
    spec = importlib.util.spec_from_file_location(
        package_name,
        initializer,
        submodule_search_locations=[str(package_root)],
    )
    if spec is None or spec.loader is None:
        raise ProtectedRecursiveV4LiveArchiveError(
            "cannot create capture-time replay package"
        )
    package = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = package
    try:
        try:
            spec.loader.exec_module(package)
            artifact_closure = importlib.import_module(
                f"{package_name}.artifact_closure"
            )
            captured_cas = importlib.import_module(f"{package_name}.cas")
            recursive_live = importlib.import_module(
                f"{package_name}.github_recursive_live_archive"
            )
            transition_replay = importlib.import_module(
                f"{package_name}.protected_install_transition_replay"
            )
            recursive_v3 = importlib.import_module(
                f"{package_name}.protected_recursive_v3_live_archive"
            )
            replay = _HistoricalReplay(
                gateway=importlib.import_module(f"{package_name}.github_gateway"),
                recursive_gateway=importlib.import_module(
                    f"{package_name}.github_recursive_gateway"
                ),
                quarantine_receipt=importlib.import_module(
                    f"{package_name}.github_quarantine_receipt"
                ),
                recursive_graph_v6=importlib.import_module(
                    f"{package_name}.github_recursive_artifact_graph_v6"
                ),
            )
        except Exception as exc:
            raise ProtectedRecursiveV4LiveArchiveError(
                f"cannot load capture-time replay package: {exc}"
            ) from exc
        bindings = {
            "canonical_json": artifact_closure.canonical_json,
            "load_verified_retained_manifest": (
                artifact_closure.load_verified_retained_manifest
            ),
            "CAS": captured_cas.CAS,
            "GitHubRecursiveLiveArchiveError": (
                recursive_live.GitHubRecursiveLiveArchiveError
            ),
            "_verify_cas_inventory": recursive_live._verify_cas_inventory,
            "_verify_decision": recursive_live._verify_decision,
            "_verify_handoff": recursive_live._verify_handoff,
            "_verify_receipt": recursive_live._verify_receipt,
            "_File": transition_replay._File,
            "_pinned_bytes": transition_replay._pinned_bytes,
            "_safe_name": transition_replay._safe_name,
            "_sha256": transition_replay._sha256,
            **{
                name: getattr(recursive_v3, name)
                for name in (
                    "_REQUEST_DIGEST_FIELDS",
                    "_REQUEST_FIELDS",
                    "_REQUEST_TTL_SECONDS",
                    "_Archive",
                    "_cas_document",
                    "_decision_record",
                    "_digest",
                    "_document",
                    "_gateway_tree_digest",
                    "_hex",
                    "_journal",
                    "_json_document",
                    "_package_tree_digest",
                    "_positive",
                    "_positive_integer",
                    "_positive_result",
                    "_walk",
                )
            },
        }
        with patch.multiple(sys.modules[__name__], **bindings):
            yield replay
    finally:
        for name in tuple(sys.modules):
            if name == package_name or name.startswith(package_name + "."):
                sys.modules.pop(name, None)
        importlib.invalidate_caches()


def _relative(name: str) -> str:
    if name == _ROOT:
        return "."
    prefix = _ROOT + "/"
    if not name.startswith(prefix):
        raise ProtectedRecursiveV4LiveArchiveError(
            "archive does not have the release-owned root"
        )
    return name.removeprefix(prefix)


def _cas_identity(name: str) -> tuple[str, str] | None:
    if not name.startswith("cas/"):
        return None
    parts = name.split("/")
    roots = (
        {f"cas/{label}" for label in _CASES}
        | {f"cas/{label}/blobs" for label in _CASES}
        | {f"cas/{label}/blobs/sha256" for label in _CASES}
    )
    if (
        len(parts) != 6
        or parts[1] not in _CASES
        or parts[2:4] != ["blobs", "sha256"]
        or len(parts[4]) != 2
        or len(parts[5]) != 62
        or any(character not in "0123456789abcdef" for character in parts[4] + parts[5])
    ):
        if name not in roots:
            raise ProtectedRecursiveV4LiveArchiveError(
                f"archive CAS path is invalid: {name}"
            )
        return None
    return parts[1], "sha256:" + parts[4] + parts[5]


def _capture_boundary(
    capture: dict[str, Any], historical: _HistoricalReplay
) -> None:
    if (
        set(capture)
        != {
            "schema",
            "authority",
            "assurance",
            "captured_on",
            "epochs",
            "limitations",
            "provenance",
            "runtime",
        }
        or capture["schema"] != "aragorn/protected-recursive-v4-live-capture/v1"
        or capture["authority"]
        != "LIVE_COMPOSED_EVIDENCE_ONLY_NOT_INSTALLER_OR_RUNTIME_AUTHORITY"
        or capture["assurance"]
        != {
            "capture": "OPERATOR_RETAINED_NOT_INDEPENDENTLY_ATTESTED",
            "pin_custody": (
                "AUTOMATIC_INDEPENDENT_SOURCE_PREFLIGHT_REPLAYED_DOWNSTREAM"
            ),
            "systemd_path": "LIVE_REQUEST_V4_TRANSIENT_SERVICE_REPLAYABLE_OFFLINE",
        }
        or capture["captured_on"] != "2026-07-29"
        or capture["limitations"] != _CAPTURE_LIMITATIONS
    ):
        raise ProtectedRecursiveV4LiveArchiveError("capture boundary changed")
    if capture["provenance"] != {
        "aragorn_commit": "0307946e55d9cd9423a5184741dfcde773c974c3",
        "aragorn_tree": "6f90e008be133e122f8f350e571549eb6ad4b7ee",
        "commit_signature": {
            "fingerprint": ("SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk"),
            "signer": "yousif.snazhat@gmail.com",
            "status": "GOOD_SSH_SIGNATURE",
        },
        "host": "lima-aragorn-phase1-recursive-v4-20260729a",
        "package_archive_raw_digest": (
            "sha256:288dfcf515f481a6d9e67f83e1cd3f04df2d3f7c59d3b950824ceb14ab94f65f"
        ),
    }:
        raise ProtectedRecursiveV4LiveArchiveError("capture provenance changed")
    epochs = capture["epochs"]
    if set(epochs) != set(_CASES):
        raise ProtectedRecursiveV4LiveArchiveError("capture epochs changed")
    for label in _CASES:
        epoch = epochs[label]
        if (
            set(epoch)
            != {
                "cas",
                "coordinator_journal",
                "credential",
                "intent",
                "journal",
                "outcome",
                "request",
                "status",
            }
            or epoch["cas"] != f"cas/{label}"
            or epoch["coordinator_journal"]
            != f"evidence/{label}-coordinator-journal.json"
            or epoch["credential"] != f"requests/{label}.json"
            or epoch["intent"] != f"evidence/{label}-intent.json"
            or epoch["journal"] != f"evidence/{label}-journal.json"
            or epoch["status"] != f"evidence/{label}-status.json"
            or epoch["outcome"] != ("ERROR" if label == "release-error" else "PASS")
            or epoch["request"]
            != historical.gateway.build_gateway_request(
                epoch["request"].get("owner"),
                epoch["request"].get("repository"),
                epoch["request"].get("commit"),
                epoch["request"].get("skill_path"),
            )
        ):
            raise ProtectedRecursiveV4LiveArchiveError(f"capture {label} epoch changed")


def _runtime(archive: _Archive, capture: dict[str, Any]) -> dict[str, Any]:
    runtime = capture["runtime"]
    if set(runtime) != {
        "release_identity_digest",
        "package_tree_digest",
        "package_file_count",
        "broker_digest",
        "launcher_digest",
        "coordinator_digest",
        "python_digest",
        "analyzer_verifier_digest",
        "candidate_implementation_digest",
        "gateway_package_tree_digest",
    }:
        raise ProtectedRecursiveV4LiveArchiveError("capture runtime fields changed")
    release_file = archive.files["runtime/release.json"]
    release = _document(archive, "runtime/release.json")
    broker_path = "runtime/package/" + release.get("broker", {}).get("path", "")
    package_files = [
        name for name in archive.files if name.startswith("runtime/package/")
    ]
    if (
        release
        != {
            "schema": "aragorn/protected-broker-launch-identity/v1",
            "broker": {
                "digest": runtime["broker_digest"],
                "path": (
                    "benchmark/admission/openclaw-v2026.7.1/"
                    "protected-install-broker-recursive-v3.py"
                ),
            },
            "launcher": {
                "digest": runtime["launcher_digest"],
                "path": ("/usr/libexec/aragorn/aragorn-protected-install-launcher.py"),
            },
            "package": {
                "root": "/opt/aragorn-broker-0307946e55d9",
                "tree_digest": runtime["package_tree_digest"],
            },
            "python": {
                "digest": runtime["python_digest"],
                "path": "/usr/bin/python3.14",
            },
        }
        or _sha256(release_file.raw) != runtime["release_identity_digest"]
        or _package_tree_digest(archive, "runtime/package")
        != runtime["package_tree_digest"]
        or _gateway_tree_digest(archive, "runtime/package/src")
        != runtime["gateway_package_tree_digest"]
        or len(package_files) != runtime["package_file_count"] != 75
        or _sha256(archive.files[broker_path].raw) != runtime["broker_digest"]
        or _sha256(archive.files["runtime/launcher.py"].raw)
        != runtime["launcher_digest"]
        or _sha256(archive.files["runtime/coordinator.py"].raw)
        != runtime["coordinator_digest"]
        or _sha256(archive.files["runtime/package/src/aragorn/analyzer_receipt.py"].raw)
        != runtime["analyzer_verifier_digest"]
        or _candidate_tree_digest(archive) != runtime["candidate_implementation_digest"]
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            "captured release or implementation measurement changed"
        )
    _verify_local_replay_closure(archive)
    for label in ("install", "update"):
        python = archive.cases[label].read(
            runtime["python_digest"],
            max_bytes=8 * 1024 * 1024,
        )
        if _sha256(python) != runtime["python_digest"]:
            raise ProtectedRecursiveV4LiveArchiveError(
                "captured Python executable changed"
            )
    if _document(archive, "runtime/revocations.json") != {
        "schema": "aragorn/protected-install-revocations/v1",
        "context_ids": [],
    }:
        raise ProtectedRecursiveV4LiveArchiveError("revocation snapshot changed")
    facts = archive.files["runtime/host-facts.txt"].raw.decode("utf-8")
    if not all(
        value in facts
        for value in (
            "Linux lima-aragorn-phase1-recursive-v4-20260729a ",
            'PRETTY_NAME="Ubuntu 26.04 LTS"',
            "Python 3.14.4",
            "systemd 259 ",
            "uid=999(aragorn-fetch)",
            "uid=983(aragorn-analyze)",
        )
    ):
        raise ProtectedRecursiveV4LiveArchiveError("captured host facts changed")
    mounts = _json_document(
        archive.files["runtime/mounts.json"].raw,
        "runtime mounts",
    )
    mounted = [
        value
        for value in _walk(mounts)
        if isinstance(value, dict) and {"target", "source", "fstype"}.issubset(value)
    ]
    host_share_types = {
        "9p",
        "virtiofs",
        "fuse.sshfs",
        "fuse.lima",
        "prl_fs",
        "vboxsf",
    }
    gateway = [
        value for value in mounted if value["target"] == "/var/lib/aragorn-gateway"
    ]
    if (
        any(
            str(value["target"]).startswith("/Users/")
            or value["fstype"] in host_share_types
            for value in mounted
        )
        or len(gateway) != 1
        or gateway[0]["source"] != "tmpfs"
        or gateway[0]["fstype"] != "tmpfs"
        or not {"rw", "nosuid", "nodev", "noexec", "mode=700"}.issubset(
            set(str(gateway[0].get("options", "")).split(","))
        )
    ):
        raise ProtectedRecursiveV4LiveArchiveError("captured mount boundary changed")
    return {
        **runtime,
        "host": capture["provenance"]["host"],
        "platform": "linux",
        "host_share_mount_present": False,
        "gateway_transfer_mount": "tmpfs:nosuid,nodev,noexec",
        "systemd": _systemd_boundary(archive),
    }


def _candidate_tree_digest(archive: _Archive) -> str:
    prefix = "runtime/package/src/aragorn/"
    files = sorted(
        (
            name.removeprefix(prefix),
            item.raw,
        )
        for name, item in archive.files.items()
        if name.startswith(prefix) and name.endswith(".py")
    )
    if not files:
        raise ProtectedRecursiveV4LiveArchiveError(
            "captured candidate source closure is empty"
        )
    digest = hashlib.sha256(b"aragorn-python-source-and-lock-closure/v1\0")
    for relative, content in files:
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    lock_name = b"requirements-worker.lock"
    lock = archive.files["runtime/package/requirements-worker.lock"].raw
    digest.update(len(lock_name).to_bytes(4, "big"))
    digest.update(lock_name)
    digest.update(len(lock).to_bytes(8, "big"))
    digest.update(lock)
    return "sha256:" + digest.hexdigest()


def _verify_local_replay_closure(archive: _Archive) -> None:
    source_root = Path(__file__).parent
    for module in _CAPTURE_TIME_REPLAY_MODULES:
        retained = archive.files.get(f"runtime/package/src/aragorn/{module}.py")
        expected_override = _CAPTURED_REPLAY_OVERRIDES.get(module)
        if retained is None or (
            expected_override is not None
            and _sha256(retained.raw) != expected_override
        ) or (
            expected_override is None
            and retained.raw != (source_root / f"{module}.py").read_bytes()
        ):
            raise ProtectedRecursiveV4LiveArchiveError(
                f"local replay dependency differs from capture: {module}.py"
            )


def _journals(archive: _Archive) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for label in _CASES:
        broker = _journal(
            archive,
            f"evidence/{label}-journal.json",
            "aragorn-protected-install.service",
        )
        coordinator = _journal(
            archive,
            f"evidence/{label}-coordinator-journal.json",
            "aragorn-protected-install-coordinator-evidence.service",
        )
        status = _document(archive, f"evidence/{label}-status.json")
        expected_failure = label == "release-error"
        if (
            set(status)
            != {
                "broker_invocation_id",
                "broker_result",
                "broker_status",
                "coordinator_invocation_id",
                "coordinator_result",
                "coordinator_status",
                "request_watcher_invocation_id",
            }
            or status["broker_invocation_id"] != broker["invocation"]
            or status["coordinator_invocation_id"] != coordinator["invocation"]
            or status["broker_result"]
            != ("exit-code" if expected_failure else "success")
            or status["broker_status"] != (1 if expected_failure else 0)
            or status["coordinator_result"]
            != ("exit-code" if expected_failure else "success")
            or status["coordinator_status"] != (4 if expected_failure else 0)
            or not _hex(status["request_watcher_invocation_id"], 32)
            or broker["timestamp"] > coordinator["timestamp"]
        ):
            raise ProtectedRecursiveV4LiveArchiveError(
                f"{label} live journal or status changed"
            )
        result[label] = {"broker": broker, "coordinator": coordinator}
    ordered = [
        result["release-error"]["broker"],
        result["release-error"]["coordinator"],
        result["install"]["broker"],
        result["install"]["coordinator"],
        result["update"]["broker"],
        result["update"]["coordinator"],
    ]
    if (
        len({item["boot"] for item in ordered}) != 1
        or len({item["invocation"] for item in ordered}) != len(ordered)
        or [item["timestamp"] for item in ordered]
        != sorted(item["timestamp"] for item in ordered)
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            "journal boot, invocation, or time lineage changed"
        )
    return result


def _request_v4(
    archive: _Archive,
    evidence: dict[str, Any],
    label: str,
    journal_timestamp: int,
    *,
    historical: _HistoricalReplay,
    previous: dict[str, Any] | None = None,
    reference_request: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    item = archive.files[f"requests/{label}.json"]
    request = _document(archive, f"requests/{label}.json")
    recursive = request.get("recursive")
    if (
        item.mode != 0o400
        or request.get("schema") != "aragorn/protected-install-broker-request/v4"
        or set(request) != _REQUEST_FIELDS
        or any(not _digest(request[field]) for field in _REQUEST_DIGEST_FIELDS)
        or not isinstance(recursive, dict)
        or set(recursive)
        != {
            "root_manifest_digest",
            "expansion_digest",
            "expansion_proof_digest",
            "release_asset_result_digests",
            "release_pin_set_digest",
        }
        or any(
            not _digest(recursive[field])
            for field in (
                "root_manifest_digest",
                "expansion_digest",
                "release_pin_set_digest",
            )
        )
        or (
            recursive["expansion_proof_digest"] is not None
            and not _digest(recursive["expansion_proof_digest"])
        )
        or not isinstance(recursive["release_asset_result_digests"], list)
        or recursive["release_asset_result_digests"]
        != sorted(set(recursive["release_asset_result_digests"]))
        or any(
            not _digest(value) for value in recursive["release_asset_result_digests"]
        )
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            f"{label} request-v4 schema or recursive binding changed"
        )
    source_request = request["source_request"]
    if source_request != historical.gateway.build_gateway_request(
        source_request.get("owner"),
        source_request.get("repository"),
        source_request.get("commit"),
        source_request.get("skill_path"),
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            f"{label} source request is not canonical"
        )
    authority = evidence.get("request_authority")
    credential = authority.get("credential") if isinstance(authority, dict) else None
    request_digest = _sha256(item.raw)
    if (
        not isinstance(credential, dict)
        or set(authority)
        != {"authority", "request_digest", "request_schema", "credential"}
        or set(credential)
        != {
            "path",
            "ctime_ns",
            "device",
            "gid",
            "inode",
            "links",
            "mode",
            "mtime_ns",
            "size",
            "uid",
        }
        or authority["authority"] != "PROTECTED_CANONICAL_REQUEST_CREDENTIAL"
        or authority["request_digest"] != request_digest
        or authority["request_schema"] != request["schema"]
        or credential["path"]
        != "/run/credentials/aragorn-protected-install.service/install-request"
        or credential["uid"] != 0
        or credential["gid"] != 0
        or credential["links"] != 1
        or credential["mode"] != 0o400
        or credential["size"] != len(item.raw)
        or not _positive_integer(credential["device"])
        or not _positive_integer(credential["inode"])
        or not _positive_integer(credential["ctime_ns"])
        or credential["mtime_ns"] != credential["ctime_ns"]
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            f"{label} request credential evidence changed"
        )
    credential_second = credential["ctime_ns"] // 1_000_000_000
    claim_now = (
        evidence.get("claim", {})
        .get("fresh", {})
        .get("claim_now_unix", journal_timestamp // 1_000_000)
    )
    if (
        request["expires_at_unix"] != credential_second + _REQUEST_TTL_SECONDS
        or isinstance(claim_now, bool)
        or not isinstance(claim_now, int)
        or not credential_second <= claim_now <= credential_second + 5
        or claim_now >= request["expires_at_unix"]
        or not credential_second
        <= journal_timestamp // 1_000_000
        <= credential_second + 5
    ):
        raise ProtectedRecursiveV4LiveArchiveError(f"{label} request freshness changed")
    if previous is None:
        expected_active = None
        expected_diff = None
        operation = "install"
    else:
        source = previous["evidence_v4"]["source"]
        expected_active = {
            "context_id": previous["context_id"],
            "manifest_digest": previous["manifest_digest"],
            "source_request": previous["request"],
            "quarantine_receipt_digest": source["quarantine_receipt_digest"],
            "gateway_profile_digest": source["gateway_profile_digest"],
            "recursive": source["recursive"],
        }
        expected_diff = evidence["transition"]["manifest_diff"]["digest"]
        operation = "update"
    if reference_request is None:
        analyzer = evidence["analyzer"]
        analyzer_pins = {
            "expected_analyzer_implementation_digest": analyzer[
                "implementation_digest"
            ],
            "expected_analyzer_executable_digest": analyzer["executable_digest"],
            "expected_analyzer_configuration_digest": analyzer["configuration_digest"],
            "expected_analyzer_verifier_digest": analyzer[
                "verifier_implementation_digest"
            ],
        }
        target_runtime = evidence["context"]["target_runtime_digest"]
        runtime_conformance = evidence["context"]["runtime_conformance_digest"]
        context_id = evidence["context"]["context_id"]
    else:
        analyzer_pins = {
            field: reference_request[field]
            for field in (
                "expected_analyzer_implementation_digest",
                "expected_analyzer_executable_digest",
                "expected_analyzer_configuration_digest",
                "expected_analyzer_verifier_digest",
            )
        }
        target_runtime = reference_request["target_runtime_digest"]
        runtime_conformance = reference_request["runtime_conformance_digest"]
        context_id = request["context_id"]
    expected = {
        "schema": "aragorn/protected-install-broker-request/v4",
        "expires_at_unix": credential_second + _REQUEST_TTL_SECONDS,
        "operation": operation,
        "expected_active": expected_active,
        "expected_manifest_diff_digest": expected_diff,
        "target_runtime_digest": target_runtime,
        "runtime_conformance_digest": runtime_conformance,
        "manifest_digest": evidence["source"]["manifest_digest"],
        "quarantine_receipt_digest": evidence["source"]["quarantine_receipt_digest"],
        "gateway_profile_digest": evidence["source"]["gateway_profile_digest"],
        "context_id": context_id,
        "source_request": evidence["source"]["request"],
        "recursive": evidence["source"]["recursive"],
        "expected_producer_implementation_digest": evidence[
            "producer_implementation_digest"
        ],
        **analyzer_pins,
        "expected_policy_digest": evidence["decision"]["policy_digest"],
        "expected_artifact_graph_verifier_digest": evidence["source"][
            "artifact_graph_verifier_implementation_digest"
        ],
    }
    if request != expected:
        raise ProtectedRecursiveV4LiveArchiveError(
            f"{label} canonical request-v4 does not replay"
        )
    cas = CAS(archive.cases[label].root, read_only=True)
    pin_set = historical.recursive_gateway.verify_retained_release_pin_set(
        cas,
        recursive["release_pin_set_digest"],
        expected_request=source_request,
        expected_manifest_digest=evidence["source"]["manifest_digest"],
        expected_source_proof_digest=evidence["source"]["source_proof_digest"],
        expected_recursive=recursive,
    )
    return request, request_digest, pin_set


def _positive_v4(
    archive: _Archive,
    capture: dict[str, Any],
    evidence: dict[str, Any],
    label: str,
    journal_timestamp: int,
    *,
    historical: _HistoricalReplay,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    request, request_digest, pin_set = _request_v4(
        archive,
        evidence,
        label,
        journal_timestamp,
        historical=historical,
        previous=previous,
    )
    if pin_set["release_asset_pins"]:
        raise ProtectedRecursiveV4LiveArchiveError(
            f"{label} empty release-pin mapping changed"
        )
    adapted_archive, adapted_capture, adapted_evidence = _adapt_positive(
        archive,
        capture,
        evidence,
        label,
    )
    adapted_previous = None if previous is None else previous["adapted"]
    replay = _positive(
        adapted_archive,
        adapted_capture,
        adapted_evidence,
        label,
        journal_timestamp=journal_timestamp,
        previous=adapted_previous,
    )
    replay.update(
        {
            "adapted": replay.copy(),
            "evidence_v4": evidence,
            "service_request_v4": request,
            "request_digest_v4": request_digest,
            "release_pin_set_digest": request["recursive"]["release_pin_set_digest"],
            "release_pin_count": 0,
        }
    )
    _coordinator_success(
        archive,
        label,
        request_digest,
        evidence,
    )
    return replay


def _adapt_positive(
    archive: _Archive,
    capture: dict[str, Any],
    evidence: dict[str, Any],
    label: str,
) -> tuple[_Archive, dict[str, Any], dict[str, Any]]:
    adapted_evidence = copy.deepcopy(evidence)
    adapted_evidence["source"]["recursive"].pop("release_pin_set_digest")
    previous_source = adapted_evidence.get("transition", {}).get("previous_source")
    if isinstance(previous_source, dict):
        previous_source["recursive"].pop("release_pin_set_digest")
    adapted_request = copy.deepcopy(_document(archive, f"requests/{label}.json"))
    adapted_request["schema"] = "aragorn/protected-install-broker-request/v3"
    adapted_request["recursive"].pop("release_pin_set_digest")
    expected_active = adapted_request.get("expected_active")
    if isinstance(expected_active, dict):
        expected_active["recursive"].pop("release_pin_set_digest")
    raw = canonical_json(adapted_request)
    authority = adapted_evidence["request_authority"]
    authority["request_digest"] = _sha256(raw)
    authority["request_schema"] = adapted_request["schema"]
    authority["credential"]["size"] = len(raw)
    files = dict(archive.files)
    files[f"requests/{label}.json"] = _File(raw, 0o400)
    blobs = {key: dict(value) for key, value in archive.blobs.items()}
    blobs[label].pop(evidence["source"]["recursive"]["release_pin_set_digest"])
    adapted_archive = replace(archive, files=files, blobs=blobs)
    adapted_capture = copy.deepcopy(capture)
    adapted_capture["runtime"]["recursive_v3_verifier_digest"] = capture["runtime"][
        "candidate_implementation_digest"
    ]
    return adapted_archive, adapted_capture, adapted_evidence


def _coordinator_success(
    archive: _Archive,
    label: str,
    request_digest: str,
    evidence: dict[str, Any],
) -> None:
    coordinator = _journal(
        archive,
        f"evidence/{label}-coordinator-journal.json",
        "aragorn-protected-install-coordinator-evidence.service",
    )["message"]
    source = evidence["source"]
    if coordinator != {
        "schema": "aragorn/protected-install-coordinator-result/v1",
        "assurance": "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "status": "COMPLETED_NOT_INSTALLER_AUTHORITY",
        "operation": label,
        "source_request": source["request"],
        "manifest_digest": source["manifest_digest"],
        "quarantine_receipt_digest": source["quarantine_receipt_digest"],
        "gateway_profile_digest": source["gateway_profile_digest"],
        "context_id": evidence["context"]["context_id"],
        "service_request_digest": request_digest,
        "quarantine_authority": "QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY",
        "runtime_conformance_qualified": False,
        "installer_work_eligible": False,
    }:
        raise ProtectedRecursiveV4LiveArchiveError(
            f"{label} coordinator result changed"
        )


def _release_error(
    archive: _Archive,
    capture: dict[str, Any],
    evidence: dict[str, Any],
    coordinator: dict[str, Any],
    journal_timestamp: int,
    *,
    historical: _HistoricalReplay,
    reference_request: dict[str, Any],
) -> dict[str, Any]:
    if (
        evidence.get("schema")
        != "aragorn/openclaw-github-protected-install-broker-evidence/v1"
        or evidence.get("assurance")
        != (
            "LIVE_GITHUB_CUSTODY_TO_PROTECTED_INSTALL_EVIDENCE_ONLY_"
            "NOT_INSTALLER_AUTHORITY"
        )
        or evidence.get("mode") != "github-live"
        or evidence.get("slice_status") != "ERROR"
        or evidence.get("producer_implementation_digest")
        != capture["runtime"]["broker_digest"]
        or evidence.get("analyzer") != {"run_receipt_digests": []}
        or evidence.get("decision", {}).get("verdict") != "ERROR"
        or evidence.get("error")
        != {
            "type": "INCOMPLETE_ARTIFACT_GRAPH",
            "message": (
                "GitHub artifact closure is incomplete; protected install is blocked"
            ),
        }
        or {"context", "transaction", "claim", "active"} & set(evidence)
        or evidence.get("verified_sequence")
        != [
            "quarantine-custody",
            "recursive-github-markdown/v3-closure",
            "decision-v3-error-replay",
        ]
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            "release-bearing broker did not fail closed"
        )
    request, request_digest, pin_set = _request_v4(
        archive,
        evidence,
        "release-error",
        journal_timestamp,
        historical=historical,
        reference_request=reference_request,
    )
    if len(pin_set["release_asset_pins"]) != 1:
        raise ProtectedRecursiveV4LiveArchiveError("release-bearing pin set changed")
    cas = archive.cases["release-error"]
    source = evidence["source"]
    recursive = source["recursive"]
    root_manifest = load_verified_retained_manifest(
        cas, recursive["root_manifest_digest"]
    )
    receipt_result = {
        "manifest_digest": source["manifest_digest"],
        "graph_digest": source["artifact_graph_digest"],
        "root_manifest_digest": recursive["root_manifest_digest"],
        "expansion_digest": recursive["expansion_digest"],
        "expansion_proof_digest": recursive["expansion_proof_digest"],
        "quarantine_receipt_digest": source["quarantine_receipt_digest"],
        "gateway_profile_digest": source["gateway_profile_digest"],
        "source_proof_digest": source["source_proof_digest"],
    }
    receipt_document = _cas_document(
        cas, source["quarantine_receipt_digest"], "quarantine receipt"
    )
    receipt_result["root_handoff_manifest_digest"] = receipt_document[
        "handoff_manifest_digest"
    ]
    stub = {
        "provenance": {
            "gateway_runtime": {
                "package_tree_digest": capture["runtime"][
                    "gateway_package_tree_digest"
                ],
                "python_executable_digest": capture["runtime"]["python_digest"],
            },
            "graph_verifier": {
                "implementation_digest": source[
                    "artifact_graph_verifier_implementation_digest"
                ]
            },
        }
    }
    receipt = _verify_receipt(
        cas,
        stub,
        source["request"],
        root_manifest,
        receipt_result,
    )
    historical.quarantine_receipt._receipt_id(receipt["receipt_id"])
    if (
        historical.quarantine_receipt._request_for_manifest(
            receipt["request"],
            root_manifest,
        )
        != source["request"]
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            "offline receipt request-to-manifest binding changed"
        )

    def offline_receipt(
        observed_cas: CAS,
        observed_digest: str,
        *,
        expected_manifest_digest: str,
        expected_gateway_profile_digest: str,
    ) -> dict[str, Any]:
        if (
            observed_cas is not cas
            or observed_digest != source["quarantine_receipt_digest"]
            or expected_manifest_digest != recursive["root_manifest_digest"]
            or expected_gateway_profile_digest != source["gateway_profile_digest"]
        ):
            raise ProtectedRecursiveV4LiveArchiveError(
                "offline v6 receipt replay binding changed"
            )
        return receipt

    with patch.object(
        historical.recursive_graph_v6.legacy,
        "verify_github_quarantine_receipt",
        side_effect=offline_receipt,
    ):
        graph = (
            historical.recursive_graph_v6.verify_recursive_github_artifact_graph(
                cas,
                source["artifact_graph_digest"],
                expected_manifest_digest=source["manifest_digest"],
                expected_quarantine_receipt_digest=(
                    source["quarantine_receipt_digest"]
                ),
                expected_gateway_profile_digest=source["gateway_profile_digest"],
                expected_verifier_digest=source[
                    "artifact_graph_verifier_implementation_digest"
                ],
                expected_release_asset_result_digests=tuple(
                    recursive["release_asset_result_digests"]
                ),
            )
        )
    _verify_v6_graph_binding(graph, source, recursive)
    expected_source = {
        "request": source["request"],
        "manifest_digest": source["manifest_digest"],
        "tree_digest": graph["tree_digest"],
        "source_proof_digest": receipt["source_proof_digest"],
        "source_closure_digest": receipt["source_closure_digest"],
        "quarantine_receipt_digest": source["quarantine_receipt_digest"],
        "gateway_profile_digest": source["gateway_profile_digest"],
        "containment_profile": receipt["containment_profile"],
        "gateway": receipt["gateway"],
        "quarantine_protected_cas": receipt["protected_cas"],
        "artifact_graph_digest": source["artifact_graph_digest"],
        "artifact_graph_profile": graph["profile"],
        "artifact_graph_verifier_implementation_digest": graph["verifier"][
            "implementation_digest"
        ],
        "artifact_count": len(graph["artifacts"]),
        "closure": graph["closure"],
        "recursive": recursive,
    }
    if source != expected_source:
        raise ProtectedRecursiveV4LiveArchiveError(
            "release-bearing source evidence does not replay"
        )
    decision_record = _decision_record(cas, evidence, capture, [])
    decision = _verify_decision(cas, decision_record, graph, receipt_result)
    closure_blobs = dict(archive.blobs["release-error"])
    closure_blobs.pop(recursive["release_pin_set_digest"])
    closure_blobs.pop(pin_set["handoff_manifest_digest"])
    closure_blobs.pop(graph["runtime_candidate_manifest_digest"])
    closure_blobs.pop(graph["analysis_manifest_digest"])
    _verify_release_handoff(
        cas,
        closure_blobs,
        receipt_result,
        source["manifest_digest"],
        decision_record,
    )
    unresolved = graph["closure"]["unresolved"]
    if (
        graph["schema"] != "aragorn/admission-artifact-graph/v6"
        or graph["profile"] != "recursive-github-markdown/v3"
        or graph["closure"]["status"] != "incomplete"
        or not any(
            value.startswith("GITHUB_RELEASE_ASSET_RUNTIME_CONSUMER_UNPROVEN:")
            for value in unresolved
        )
        or decision["verdict"] != "ERROR"
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            "release-bearing graph did not remain non-ALLOW"
        )
    source_request = source["request"]
    if _document(archive, "evidence/release-error-intent.json") != {
        "schema": "aragorn/protected-install-intent/v1",
        "operation": "install",
        **{
            field: source_request[field]
            for field in ("owner", "repository", "commit", "skill_path")
        },
    }:
        raise ProtectedRecursiveV4LiveArchiveError("release-bearing intent changed")
    protected = _document(archive, "evidence/release-error-protected-state.json")
    if (
        protected
        != {
            "assurance": ("OPERATOR_RECORDED_LIVE_STATE_NOT_INDEPENDENT_ATTESTATION"),
            "before_entries": [],
            "after_entries": [],
            "coordinator_state_before": False,
            "coordinator_state_after": False,
        }
        or archive.directories.get("protected/release-error") != 0o700
        or any(
            name.startswith("protected/release-error/")
            for name in archive.files | archive.directories | archive.symlinks
        )
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            "release-bearing failure changed protected state"
        )
    _verify_release_coordinator(coordinator)
    return {
        "request": source_request,
        "request_digest": request_digest,
        "request_expires_at_unix": request["expires_at_unix"],
        "manifest_digest": source["manifest_digest"],
        "graph_digest": source["artifact_graph_digest"],
        "graph_schema": graph["schema"],
        "closure_status": graph["closure"]["status"],
        "unresolved_required": graph["coverage"]["unresolved_required"],
        "release_pin_set_digest": recursive["release_pin_set_digest"],
        "release_pin_count": len(pin_set["release_asset_pins"]),
        "release_asset_result_digests": recursive["release_asset_result_digests"],
        "analyzer_run_receipts": 0,
        "decision_digest": evidence["decision"]["digest"],
        "verdict": decision["verdict"],
        "error_type": evidence["error"]["type"],
        "recorded_protected_state_unchanged": True,
        "published": False,
    }


def _verify_v6_graph_binding(
    graph: dict[str, Any],
    source: dict[str, Any],
    recursive: dict[str, Any],
) -> None:
    if (
        graph.get("root_manifest_digest") != source["manifest_digest"]
        or graph.get("root_github_manifest_digest") != recursive["root_manifest_digest"]
        or graph.get("source_proof_digest") != source["source_proof_digest"]
        or graph.get("quarantine_receipt_digest") != source["quarantine_receipt_digest"]
        or graph.get("gateway_profile_digest") != source["gateway_profile_digest"]
        or graph.get("expansion_digest") != recursive["expansion_digest"]
        or graph.get("expansion_proof_digest") != recursive["expansion_proof_digest"]
        or graph.get("verifier", {}).get("implementation_digest")
        != source["artifact_graph_verifier_implementation_digest"]
    ):
        raise ProtectedRecursiveV4LiveArchiveError("v6 graph recursive binding changed")


def _verify_release_coordinator(coordinator: dict[str, Any]) -> None:
    if coordinator != {
        "schema": "aragorn/protected-install-coordinator-result/v1",
        "assurance": "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "status": "ERROR",
        "error": {
            "type": "ProtectedInstallCoordinatorError",
            "message": (
                "protected install service failed: Job for "
                "aragorn-protected-install.service failed because the control "
                'process exited with error code.\nSee "systemctl status '
                'aragorn-protected-install.service" and "journalctl -xeu '
                'aragorn-protected-install.service" for details.'
            ),
        },
        "runtime_conformance_qualified": False,
        "installer_work_eligible": False,
    }:
        raise ProtectedRecursiveV4LiveArchiveError(
            "release-bearing coordinator result changed"
        )


def _verify_release_handoff(
    cas: CAS,
    blobs: dict[str, bytes],
    result: dict[str, Any],
    root_digest: str,
    decision_record: dict[str, Any],
) -> None:
    matches: list[str] = []
    for digest, raw in blobs.items():
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, ValueError):
            continue
        if (
            isinstance(document, dict)
            and document.get("schema") == "aragorn/benchmark-cas-handoff/v1"
            and document.get("root_digest") == root_digest
        ):
            try:
                _verify_handoff(
                    cas,
                    blobs,
                    {**result, "handoff_manifest_digest": digest},
                    decision_record=decision_record,
                )
            except (GitHubRecursiveLiveArchiveError, KeyError):
                continue
            matches.append(digest)
    if len(matches) != 1:
        raise ProtectedRecursiveV4LiveArchiveError(
            "release expanded handoff selection changed"
        )


def _final_publication(
    archive: _Archive,
    install: dict[str, Any],
    update: dict[str, Any],
) -> None:
    source = update["evidence_v4"]["source"]
    state = _document(archive, "protected/coordinator-state.json")
    expected = {
        "schema": "aragorn/protected-install-coordinator-state/v3",
        "assurance": "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "expected_active": {
            "context_id": update["context_id"],
            "manifest_digest": update["manifest_digest"],
            "source_request": update["request"],
            "quarantine_receipt_digest": source["quarantine_receipt_digest"],
            "gateway_profile_digest": source["gateway_profile_digest"],
            "recursive": source["recursive"],
        },
        "tree_digest": update["graph"]["tree_digest"],
        "version_path": update["version_path"],
        "service_request_digest": update["request_digest_v4"],
    }
    link = archive.symlinks.get("protected/positive/aragorn-admitted")
    claims = [
        "protected/positive/.aragorn-install-claims/" + item["context_id"][7:] + ".json"
        for item in (install, update)
    ]
    if (
        state != expected
        or link != (0o777, update["version_path"])
        or any(
            archive.files[path].mode != 0o400
            or _document(archive, path) != item["evidence_v4"]["transaction"]
            for path, item in zip(claims, (install, update), strict=True)
        )
    ):
        raise ProtectedRecursiveV4LiveArchiveError(
            "state-v3 predecessor linkage or publication changed"
        )


def _result(value: dict[str, Any]) -> dict[str, Any]:
    result = _positive_result(value)
    result["request_digest"] = value["request_digest_v4"]
    result["release_pin_set_digest"] = value["release_pin_set_digest"]
    result["release_pin_count"] = value["release_pin_count"]
    return result
