"""Strict replay of the retained recursive protected-install bake-off."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from . import github_recursive_artifact_graph_v4
from .artifact_closure import canonical_json, load_verified_retained_manifest
from .cas import CAS
from .github_gateway import build_gateway_request
from .github_recursive_live_archive import (
    _verify_cas_inventory,
    _verify_decision,
    _verify_graph,
    _verify_handoff,
    _verify_receipt,
)
from .github_release_asset import verify_github_release_asset_result
from .installed_tree_replay import ArchivedTreeMember, verify_installed_tree_members
from .manifest_diff import diff_verified_manifests_between
from .oci_worker_protocol import canonical_digest
from .protected_install import _transaction_record, _version_path
from .protected_install_context import VerifiedInstallContextV2
from .protected_install_transition_replay import (
    _File,
    _canonical_document,
    _evidence_decision,
    _pinned_bytes,
    _safe_name,
    _sha256,
)
from .protected_transition_live_archive import _broker_boundary

ARCHIVE_DIGEST = (
    "sha256:278e4990a1bbd01a5a726859fd30ab7fa46ab5622dcef5b484cf30f0ddd12601"
)
ARCHIVE_NAME = (
    "phase1-protected-recursive-v3-live-dac34f2-2026-07-29.tar.gz"
)
ARCHIVE_PATH = f"benchmark/evidence/{ARCHIVE_NAME}"
AUTHORITY = "OFFLINE_LIVE_PATH_REPLAY_ONLY_NOT_INSTALLER_OR_RUNTIME_AUTHORITY"

_ROOT = "phase1-protected-recursive-v3-live-dac34f2"
_MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
_EXPECTED_INVENTORY = {
    "members": 241,
    "regular_files": 155,
    "directories": 85,
    "symlinks": 1,
    "payload_bytes": 22_993_498,
}
_CASES = ("install", "update", "release-error")
_REQUEST_TTL_SECONDS = 15 * 60
_REQUEST_DIGEST_FIELDS = {
    "target_runtime_digest",
    "runtime_conformance_digest",
    "manifest_digest",
    "quarantine_receipt_digest",
    "gateway_profile_digest",
    "context_id",
    "expected_producer_implementation_digest",
    "expected_analyzer_implementation_digest",
    "expected_analyzer_executable_digest",
    "expected_analyzer_configuration_digest",
    "expected_policy_digest",
    "expected_analyzer_verifier_digest",
    "expected_artifact_graph_verifier_digest",
}
_REQUEST_FIELDS = {
    "schema",
    "expires_at_unix",
    "operation",
    "expected_active",
    "expected_manifest_diff_digest",
    "source_request",
    "recursive",
    *_REQUEST_DIGEST_FIELDS,
}
_CAPTURE_LIMITATIONS = [
    "NO_INSTALLER_AUTHORITY",
    "NO_RUNTIME_CONFORMANCE_QUALIFICATION",
    "OPERATOR_CAPTURE_NOT_INDEPENDENT_ATTESTATION",
    "RELEASE_ASSET_RETAINED_BUT_NOT_ANALYZED",
    "ARCHIVE_INVENTORY_AND_EXTRACTION_UNSUPPORTED",
    "BYTE_IDENTICAL_UPDATE_ONLY",
    "RELEASE_ERROR_PROTECTED_STATE_OPERATOR_RECORDED",
]


class ProtectedRecursiveV3LiveArchiveError(ValueError):
    """The retained composed-path archive is malformed or inconsistent."""


@dataclass(slots=True)
class _Archive:
    files: dict[str, _File]
    directories: dict[str, int]
    symlinks: dict[str, tuple[int, str]]
    cases: dict[str, CAS]
    blobs: dict[str, dict[str, bytes]]
    inventory: dict[str, int]


def verify_protected_recursive_v3_live_archive(
    archive_path: str | Path,
) -> dict[str, Any]:
    """Derive the exact live-path qualification from one release-pinned archive."""

    try:
        raw = _pinned_bytes(
            archive_path,
            ARCHIVE_DIGEST,
            "recursive protected-install live archive",
            _MAX_ARCHIVE_BYTES,
        )
        if (
            len(raw) < 10
            or raw[:4] != b"\x1f\x8b\x08\x00"
            or raw[4:8] != b"\0\0\0\0"
        ):
            raise ProtectedRecursiveV3LiveArchiveError(
                "archive gzip header is not normalized"
            )

        with TemporaryDirectory(prefix="aragorn-protected-recursive-v3-") as temporary:
            archive = _load(raw, Path(temporary))
            capture = _document(archive, "capture.json")
            _capture_boundary(capture)
            runtime = _runtime(archive, capture)
            wrappers = {
                label: _journal(
                    archive,
                    f"evidence/{label}-journal.json",
                    "aragorn-protected-install.service",
                )
                for label in ("install", "update", "release-error")
            }
            coordinator_wrapper = _journal(
                archive,
                "evidence/release-error-coordinator-journal.json",
                "aragorn-protected-install-coordinator-evidence.service",
            )
            _journal_lineage(wrappers, coordinator_wrapper)

            install = _positive(
                archive,
                capture,
                wrappers["install"]["message"],
                "install",
                journal_timestamp=wrappers["install"]["timestamp"],
            )
            update = _positive(
                archive,
                capture,
                wrappers["update"]["message"],
                "update",
                journal_timestamp=wrappers["update"]["timestamp"],
                previous=install,
            )
            _final_publication(archive, install, update)
            release_error = _release_error(
                archive,
                capture,
                wrappers["release-error"]["message"],
                coordinator_wrapper["message"],
                journal_timestamp=wrappers["release-error"]["timestamp"],
                reference_request=install["service_request"],
            )
            for label, cas in archive.cases.items():
                _verify_cas_inventory(
                    CAS(cas.root, read_only=True),
                    archive.blobs[label],
                )

        return {
            "schema": "aragorn/protected-recursive-v3-live-qualification/v1",
            "authority": AUTHORITY,
            "archive": {
                "path": ARCHIVE_PATH,
                "digest": ARCHIVE_DIGEST,
                "bytes": len(raw),
                **archive.inventory,
            },
            "provenance": capture["provenance"],
            "runtime": runtime,
            "install": _positive_result(install),
            "update": _positive_result(update),
            "release_error": release_error,
            "qualification": {
                "live_protected_path_qualified": True,
                "runtime_conformance_qualified": False,
                "installer_work_eligible": False,
                "phase1_complete": False,
                "public_release_eligible": False,
            },
            "limitations": [
                "EXACT_RETAINED_VM_PATH_ONLY",
                "OPERATOR_CAPTURE_NOT_INDEPENDENT_ATTESTATION",
                "RECORDED_LIVE_CUSTODY_NOT_REATTESTED_OFFLINE",
                "RELEASE_ASSET_BYTES_RETAINED_BUT_NOT_ANALYZED",
                "BYTE_IDENTICAL_UPDATE_ONLY",
                "RELEASE_ERROR_PROTECTED_STATE_OPERATOR_RECORDED",
                "COORDINATOR_EVIDENCE_SERVICE_NOT_FULLY_ISOLATED",
                "SYSTEMD_PROVISIONING_UNITS_NOT_RETAINED",
                "NO_RUNTIME_CONFORMANCE_QUALIFICATION",
                "NO_INSTALLER_AUTHORITY",
            ],
            "status": "PASS",
        }
    except ProtectedRecursiveV3LiveArchiveError:
        raise
    except Exception as exc:
        raise ProtectedRecursiveV3LiveArchiveError(
            f"cannot verify recursive protected-install live archive: {exc}"
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
        with tarfile.open(fileobj=BytesIO(raw), mode="r|gz") as source:
            for member in source:
                counts["members"] += 1
                name = _safe_name(member)
                if name <= previous:
                    raise ProtectedRecursiveV3LiveArchiveError(
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
                    raise ProtectedRecursiveV3LiveArchiveError(
                        f"archive metadata is not normalized: {name}"
                    )
                relative = _relative(name)
                if member.isdir():
                    if member.size or member.linkname:
                        raise ProtectedRecursiveV3LiveArchiveError(
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
                        or member.linkname
                        != (
                            ".aragorn-versions/aragorn-admitted/"
                            "d6e9ae8752d6cf7844d497e19b28ff199cd8baa5d6e4cf84"
                            "c82ea8e38ca0886f-166c7061869e00807924dae2c5cdac1939"
                            "efc9f9cf8faf4db1855e23c237e8fe"
                        )
                    ):
                        raise ProtectedRecursiveV3LiveArchiveError(
                            "archive symlink changed"
                        )
                    symlinks[relative] = (member.mode, member.linkname)
                    counts["symlinks"] += 1
                    continue
                if not member.isfile() or member.linkname:
                    raise ProtectedRecursiveV3LiveArchiveError(
                        f"archive contains a hard link or special member: {name}"
                    )
                if member.size > _MAX_MEMBER_BYTES:
                    raise ProtectedRecursiveV3LiveArchiveError(
                        f"archive member exceeds its byte limit: {name}"
                    )
                stream = source.extractfile(member)
                content = b"" if stream is None else stream.read(member.size + 1)
                if len(content) != member.size:
                    raise ProtectedRecursiveV3LiveArchiveError(
                        f"archive member size changed: {name}"
                    )
                counts["payload_bytes"] += len(content)
                if counts["payload_bytes"] > _MAX_PAYLOAD_BYTES:
                    raise ProtectedRecursiveV3LiveArchiveError(
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
                        raise ProtectedRecursiveV3LiveArchiveError(
                            f"archive CAS identity changed: {name}"
                        )
                    blobs[label][digest] = content
                files[relative] = _File(content, member.mode)
                counts["regular_files"] += 1
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ProtectedRecursiveV3LiveArchiveError(
            f"archive stream is invalid: {exc}"
        ) from exc

    if counts != _EXPECTED_INVENTORY:
        raise ProtectedRecursiveV3LiveArchiveError("archive inventory changed")
    required = {
        "capture.json",
        "evidence/install-journal.json",
        "evidence/update-journal.json",
        "evidence/release-error-journal.json",
        "evidence/release-error-coordinator-journal.json",
        "evidence/release-error-intent.json",
        "evidence/release-error-protected-state.json",
        "protected/coordinator-state.json",
        "runtime/release.json",
        "runtime/release-asset-pins.json",
        "runtime/revocations.json",
        "runtime/launcher.py",
        "runtime/coordinator.py",
        "runtime/host-facts.txt",
        "runtime/mounts.json",
        "runtime/systemd-show.txt",
        "runtime/systemd/protected-install.service",
        "runtime/systemd/coordinator.service",
        "runtime/systemd/coordinator.path",
        "requests/install.json",
        "requests/update.json",
        "requests/release-error.json",
    }
    if not required.issubset(files) or any(not blobs[label] for label in _CASES):
        raise ProtectedRecursiveV3LiveArchiveError(
            "archive omits required evidence"
        )
    names = (set(files) | set(directories) | set(symlinks)) - {"."}
    if set(part.split("/", 1)[0] for part in names) != {
        "capture.json",
        "cas",
        "evidence",
        "protected",
        "requests",
        "runtime",
    }:
        raise ProtectedRecursiveV3LiveArchiveError(
            "archive contains an unexpected top-level member"
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


def _relative(name: str) -> str:
    if name == _ROOT:
        return "."
    prefix = _ROOT + "/"
    if not name.startswith(prefix):
        raise ProtectedRecursiveV3LiveArchiveError(
            "archive does not have the release-owned root"
        )
    return name.removeprefix(prefix)


def _cas_identity(name: str) -> tuple[str, str] | None:
    if not name.startswith("cas/"):
        return None
    parts = name.split("/")
    if (
        len(parts) != 6
        or parts[1] not in _CASES
        or parts[2:4] != ["blobs", "sha256"]
        or len(parts[4]) != 2
        or len(parts[5]) != 62
        or any(character not in "0123456789abcdef" for character in parts[4] + parts[5])
    ):
        if name not in {
            f"cas/{label}" for label in _CASES
        } | {
            f"cas/{label}/blobs" for label in _CASES
        } | {
            f"cas/{label}/blobs/sha256" for label in _CASES
        }:
            raise ProtectedRecursiveV3LiveArchiveError(
                f"archive CAS path is invalid: {name}"
            )
        return None
    return parts[1], "sha256:" + parts[4] + parts[5]


def _capture_boundary(capture: dict[str, Any]) -> None:
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
        or capture["schema"] != "aragorn/protected-recursive-v3-live-capture/v1"
        or capture["authority"]
        != "LIVE_COMPOSED_EVIDENCE_ONLY_NOT_INSTALLER_OR_RUNTIME_AUTHORITY"
        or capture["assurance"]
        != {
            "capture": "OPERATOR_RETAINED_NOT_INDEPENDENTLY_ATTESTED",
            "install_update": "LIVE_SYSTEMD_COMPOSITION_REPLAYABLE_OFFLINE",
            "release_error": (
                "LIVE_PINNED_RELEASE_BEARING_ERROR_REPLAYABLE_OFFLINE"
            ),
        }
        or capture["captured_on"] != "2026-07-29"
        or capture["limitations"] != _CAPTURE_LIMITATIONS
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "capture boundary changed"
        )
    provenance = capture["provenance"]
    if provenance != {
        "aragorn_commit": "dac34f22e67a673378237038958160a0c3e51d24",
        "commit_signer_fingerprint": (
            "SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk"
        ),
        "host": "lima-aragorn-phase1-recursive-v3-20260729a",
        "positive_raw_archive_digest": (
            "sha256:5c32dfb75e2b85192172f8048a411dcd5fc118e6cfb0201c0"
            "ffbe729fa798b1c"
        ),
        "release_error_raw_archive_digest": (
            "sha256:852de40f0106f785cd3d9bbd37ef01f0d36b595c5eab30e647"
            "da0b514aafba9e"
        ),
    }:
        raise ProtectedRecursiveV3LiveArchiveError(
            "capture provenance changed"
        )
    epochs = capture["epochs"]
    if set(epochs) != {"install", "update", "release_error"}:
        raise ProtectedRecursiveV3LiveArchiveError("capture epochs changed")
    for label, archive_label, outcome in (
        ("install", "install", "ALLOW"),
        ("update", "update", "ALLOW"),
        ("release_error", "release-error", "ERROR"),
    ):
        epoch = epochs[label]
        required = {"cas", "journal", "credential", "request", "outcome"}
        if label == "release_error":
            required |= {"coordinator_journal", "intent", "protected_state"}
        if (
            set(epoch) != required
            or epoch["cas"] != f"cas/{archive_label}"
            or epoch["journal"] != f"evidence/{archive_label}-journal.json"
            or epoch["credential"] != f"requests/{archive_label}.json"
            or epoch["outcome"] != outcome
            or epoch["request"]
            != build_gateway_request(
                epoch["request"].get("owner"),
                epoch["request"].get("repository"),
                epoch["request"].get("commit"),
                epoch["request"].get("skill_path"),
            )
        ):
            raise ProtectedRecursiveV3LiveArchiveError(
                f"capture {label} epoch changed"
            )
        if label == "release_error" and (
            epoch["coordinator_journal"]
            != "evidence/release-error-coordinator-journal.json"
            or epoch["intent"] != "evidence/release-error-intent.json"
            or epoch["protected_state"]
            != "evidence/release-error-protected-state.json"
        ):
            raise ProtectedRecursiveV3LiveArchiveError(
                "capture release_error evidence pointers changed"
            )


def _runtime(archive: _Archive, capture: dict[str, Any]) -> dict[str, Any]:
    runtime = capture["runtime"]
    if set(runtime) != {
        "release_identity_digest",
        "package_tree_digest",
        "broker_digest",
        "launcher_digest",
        "coordinator_digest",
        "python_digest",
        "analyzer_verifier_digest",
        "recursive_v3_verifier_digest",
        "recursive_v4_verifier_digest",
        "gateway_package_tree_digest",
    }:
        raise ProtectedRecursiveV3LiveArchiveError(
            "capture runtime fields changed"
        )
    release_file = archive.files["runtime/release.json"]
    release = _canonical_document(release_file.raw, "release identity")
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
                "path": (
                    "/usr/libexec/aragorn/"
                    "aragorn-protected-install-launcher.py"
                ),
            },
            "package": {
                "root": "/opt/aragorn-broker-dac34f22e67a",
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
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "captured release or package measurement changed"
        )
    measured = {
        "broker_digest": _sha256(
            archive.files[
                "runtime/package/" + release["broker"]["path"]
            ].raw
        ),
        "launcher_digest": _sha256(archive.files["runtime/launcher.py"].raw),
        "coordinator_digest": _sha256(archive.files["runtime/coordinator.py"].raw),
        "recursive_v3_verifier_digest": _sha256(
            archive.files[
                "runtime/package/src/aragorn/"
                "github_recursive_artifact_graph.py"
            ].raw
        ),
        "recursive_v4_verifier_digest": _sha256(
            archive.files[
                "runtime/package/src/aragorn/"
                "github_recursive_artifact_graph_v4.py"
            ].raw
        ),
        "analyzer_verifier_digest": _sha256(
            archive.files[
                "runtime/package/src/aragorn/analyzer_receipt.py"
            ].raw
        ),
    }
    if any(runtime[field] != digest for field, digest in measured.items()):
        raise ProtectedRecursiveV3LiveArchiveError(
            "captured implementation measurement changed"
        )
    for label in ("install", "update"):
        python = archive.cases[label].read(
            runtime["python_digest"],
            max_bytes=8 * 1024 * 1024,
        )
        if _sha256(python) != runtime["python_digest"]:
            raise ProtectedRecursiveV3LiveArchiveError(
                "captured Python executable changed"
            )
    repo = Path(__file__).resolve().parents[2]
    for field, path in (
        (
            "recursive_v3_verifier_digest",
            "src/aragorn/github_recursive_artifact_graph.py",
        ),
        (
            "recursive_v4_verifier_digest",
            "src/aragorn/github_recursive_artifact_graph_v4.py",
        ),
        ("analyzer_verifier_digest", "src/aragorn/analyzer_receipt.py"),
    ):
        if _sha256((repo / path).read_bytes()) != runtime[field]:
            raise ProtectedRecursiveV3LiveArchiveError(
                f"local replay implementation differs from capture: {path}"
            )
    if _document(archive, "runtime/revocations.json") != {
        "schema": "aragorn/protected-install-revocations/v1",
        "context_ids": [],
    }:
        raise ProtectedRecursiveV3LiveArchiveError(
            "revocation snapshot changed"
        )
    facts = archive.files["runtime/host-facts.txt"].raw.decode("utf-8")
    if not all(
        value in facts
        for value in (
            "Linux lima-aragorn-phase1-recursive-v3-20260729a ",
            'PRETTY_NAME="Ubuntu 26.04 LTS"',
            "Python 3.14.4",
            "systemd 259 ",
            "uid=999(aragorn-fetch)",
            "uid=983(aragorn-analyze)",
        )
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "captured host facts changed"
        )
    mounts = _json_document(archive.files["runtime/mounts.json"].raw, "mounts")
    mounted_filesystems = [
        value
        for value in _walk(mounts)
        if isinstance(value, dict)
        and {"target", "source", "fstype"}.issubset(value)
    ]
    host_share_types = {
        "9p",
        "virtiofs",
        "fuse.sshfs",
        "fuse.lima",
        "prl_fs",
        "vboxsf",
    }
    if any(
        str(value["target"]).startswith("/Users/")
        or value["fstype"] in host_share_types
        for value in mounted_filesystems
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "capture unexpectedly exposes a host-share mount"
        )
    gateway_mounts = [
        value
        for value in _walk(mounts)
        if isinstance(value, dict)
        and value.get("target") == "/var/lib/aragorn-gateway"
    ]
    expected_options = {
        "rw",
        "nosuid",
        "nodev",
        "noexec",
        "relatime",
        "size=524288k",
        "nr_inodes=25000",
        "mode=700",
        "uid=999",
        "gid=987",
        "inode64",
    }
    if (
        len(gateway_mounts) != 1
        or gateway_mounts[0].get("source") != "tmpfs"
        or gateway_mounts[0].get("fstype") != "tmpfs"
        or set(str(gateway_mounts[0].get("options", "")).split(","))
        != expected_options
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "captured gateway transfer mount changed"
        )
    systemd = _systemd_boundary(archive)
    return {
        **runtime,
        "host": capture["provenance"]["host"],
        "platform": "linux",
        "host_share_mount_present": False,
        "gateway_transfer_mount": "tmpfs:nosuid,nodev,noexec",
        "systemd": systemd,
    }


def _systemd_boundary(archive: _Archive) -> dict[str, Any]:
    repo = Path(__file__).resolve().parents[2]
    static_units = {
        "runtime/systemd/protected-install.service": (
            "packaging/systemd/aragorn-protected-install.service"
        ),
        "runtime/systemd/coordinator.service": (
            "packaging/systemd/"
            "aragorn-protected-install-coordinator-evidence.service"
        ),
        "runtime/systemd/coordinator.path": (
            "packaging/systemd/"
            "aragorn-protected-install-coordinator-evidence.path"
        ),
    }
    for retained, source in static_units.items():
        item = archive.files[retained]
        if item.mode != 0o644 or item.raw != (repo / source).read_bytes():
            raise ProtectedRecursiveV3LiveArchiveError(
                f"captured systemd unit differs from release source: {retained}"
            )

    units = _systemd_show(archive.files["runtime/systemd-show.txt"].raw)
    install_name = "aragorn-protected-install.service"
    coordinator_name = (
        "aragorn-protected-install-coordinator-evidence.service"
    )
    path_name = "aragorn-protected-install-coordinator-evidence.path"
    if set(units) != {install_name, coordinator_name, path_name}:
        raise ProtectedRecursiveV3LiveArchiveError(
            "captured effective systemd unit set changed"
        )
    for name, values in units.items():
        _systemd_values(
            values,
            {
                "Id": name,
                "Names": name,
                "LoadState": "loaded",
                "FragmentPath": f"/etc/systemd/system/{name}",
                "NeedDaemonReload": "no",
                "Transient": "no",
            },
            name,
        )

    install = units[install_name]
    _systemd_values(
        install,
        {
            "UnitFileState": "static",
            "Type": "oneshot",
            "User": "root",
            "Group": "root",
            "Restart": "no",
            "KillMode": "control-group",
            "Result": "success",
            "NoNewPrivileges": "yes",
            "PrivateNetwork": "yes",
            "SocketBindDeny": "any",
            "ProtectSystem": "strict",
            "PrivateMounts": "yes",
            "PrivateTmp": "yes",
            "PrivateDevices": "yes",
            "PrivateIPC": "yes",
            "ProtectHome": "yes",
            "ProtectProc": "invisible",
            "ProcSubset": "pid",
            "RemoveIPC": "yes",
            "RestrictNamespaces": "yes",
            "RestrictRealtime": "yes",
            "RestrictSUIDSGID": "yes",
            "LockPersonality": "yes",
            "MemoryDenyWriteExecute": "yes",
            "KeyringMode": "private",
            "ReadWritePaths": (
                "/var/lib/aragorn-quarantine "
                "/var/lib/aragorn-protected/skills"
            ),
            "InaccessiblePaths": (
                "/run/aragorn-protected-install/request.json"
            ),
            "Environment": (
                "HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/bin:/bin "
                "PYTHONDONTWRITEBYTECODE=1 TZ=UTC"
            ),
            "UMask": "0077",
            "TasksMax": "8",
            "MemoryMax": "1073741824",
            "MemorySwapMax": "0",
            "LimitNOFILE": "128",
            "TimeoutStartUSec": "5min",
            "StandardInput": "null",
            "StandardOutput": "journal",
            "StandardError": "journal",
        },
        install_name,
    )
    _systemd_sets(
        install,
        {
            "CapabilityBoundingSet": {"cap_setgid", "cap_setuid"},
            "AmbientCapabilities": {"cap_setgid", "cap_setuid"},
            "IPAddressDeny": {"0.0.0.0/0", "::/0"},
            "RestrictAddressFamilies": {"AF_UNIX"},
            "RequiresMountsFor": {
                "/",
                "/var/lib/aragorn-quarantine",
                "/var/lib/aragorn-protected/skills",
            },
        },
        install_name,
    )
    install_argv = (
        "/usr/bin/python3.14 -I -S -B "
        "/usr/libexec/aragorn/aragorn-protected-install-launcher.py -- "
        "--github-live --service-request "
        "/run/credentials/aragorn-protected-install.service/install-request "
        "--analyzer-user aragorn-analyze --analyzer-group aragorn-analyze "
        "--cas-root /var/lib/aragorn-quarantine --protected-root "
        "/var/lib/aragorn-protected/skills --expected-broker-uid 0 "
        "--revocation-file /etc/aragorn/protected-install-revocations.json"
    )
    _systemd_exec(install, install_argv, install_name)
    if not {
        "socket",
        "connect",
        "bind",
        "mount",
        "reboot",
        "swapoff",
        "swapon",
    }.issubset(set(install["SystemCallFilter"].removeprefix("~").split())):
        raise ProtectedRecursiveV3LiveArchiveError(
            "protected install system-call isolation changed"
        )

    coordinator = units[coordinator_name]
    _systemd_values(
        coordinator,
        {
            "UnitFileState": "static",
            "Type": "oneshot",
            "User": "root",
            "Group": "root",
            "RefuseManualStart": "yes",
            "CanStart": "no",
            "Restart": "no",
            "Result": "success",
            "NoNewPrivileges": "yes",
            "PrivateNetwork": "no",
            "ProtectSystem": "no",
            "ProtectHome": "no",
            "PrivateMounts": "no",
            "PrivateTmp": "no",
            "PrivateDevices": "no",
            "PrivateIPC": "no",
            "RestrictNamespaces": "yes",
            "RestrictRealtime": "yes",
            "RestrictSUIDSGID": "yes",
            "LockPersonality": "yes",
            "MemoryDenyWriteExecute": "yes",
            "KeyringMode": "private",
            "Environment": (
                "HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/bin:/bin "
                "PYTHONDONTWRITEBYTECODE=1 TZ=UTC "
                "ARAGORN_DROP_HOST_INSPECTION_CAPABILITY=1"
            ),
            "TasksMax": "16",
            "MemoryMax": "2147483648",
            "MemorySwapMax": "0",
            "LimitNOFILE": "256",
            "TimeoutStartUSec": "10min",
        },
        coordinator_name,
    )
    _systemd_sets(
        coordinator,
        {
            "CapabilityBoundingSet": {
                "cap_dac_override",
                "cap_sys_ptrace",
            },
            "AmbientCapabilities": {
                "cap_dac_override",
                "cap_sys_ptrace",
            },
            "IPAddressDeny": {"0.0.0.0/0", "::/0"},
            "IPAddressAllow": {"127.0.0.0/8", "::1/128"},
            "RestrictAddressFamilies": {"AF_UNIX", "AF_INET", "AF_INET6"},
            "RequiresMountsFor": {
                "/",
                "/var/lib/aragorn-gateway",
                "/var/lib/aragorn-quarantine",
                "/var/lib/aragorn-protected/skills",
            },
        },
        coordinator_name,
    )
    _systemd_exec(
        coordinator,
        (
            "/usr/bin/python3.14 -I -S -B "
            "/usr/libexec/aragorn/"
            "aragorn-protected-install-coordinator.py"
        ),
        coordinator_name,
    )
    if not {
        "mount",
        "reboot",
        "process_vm_readv",
        "process_vm_writev",
        "ipc",
    }.issubset(set(coordinator["SystemCallFilter"].removeprefix("~").split())):
        raise ProtectedRecursiveV3LiveArchiveError(
            "coordinator system-call boundary changed"
        )

    path = units[path_name]
    _systemd_values(
        path,
        {
            "UnitFileState": "enabled",
            "ActiveState": "active",
            "SubState": "waiting",
            "ConditionResult": "yes",
            "Result": "success",
            "Unit": coordinator_name,
            "Triggers": coordinator_name,
            "Paths": (
                "/run/aragorn-protected-install/intent.json (PathChanged)"
            ),
        },
        path_name,
    )
    return {
        "static_units_verified": len(static_units),
        "effective_units_verified": len(units),
        "protected_install_network": "private",
        "coordinator_network": "loopback-only",
        "provisioning_units_retained": False,
    }


def _systemd_show(raw: bytes) -> dict[str, dict[str, str]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ProtectedRecursiveV3LiveArchiveError(
            f"captured systemd properties are not UTF-8: {exc}"
        ) from exc
    result: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in lines:
        if not line:
            current = None
            continue
        if "=" not in line:
            raise ProtectedRecursiveV3LiveArchiveError(
                "captured systemd property is malformed"
            )
        key, value = line.split("=", 1)
        if key == "Id":
            if value in result:
                raise ProtectedRecursiveV3LiveArchiveError(
                    "captured systemd unit is repeated"
                )
            current = {}
            result[value] = current
        if current is None or key in current:
            raise ProtectedRecursiveV3LiveArchiveError(
                "captured systemd property is repeated or unscoped"
            )
        current[key] = value
    return result


def _systemd_values(
    observed: dict[str, str],
    expected: dict[str, str],
    unit: str,
) -> None:
    if any(observed.get(key) != value for key, value in expected.items()):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"captured effective systemd properties changed: {unit}"
        )


def _systemd_sets(
    observed: dict[str, str],
    expected: dict[str, set[str]],
    unit: str,
) -> None:
    if any(
        set(observed.get(key, "").split()) != value
        for key, value in expected.items()
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"captured effective systemd set changed: {unit}"
        )


def _systemd_exec(
    observed: dict[str, str],
    argv: str,
    unit: str,
) -> None:
    command_properties = {
        "ExecCondition",
        "ExecConditionEx",
        "ExecStartPre",
        "ExecStartPreEx",
        "ExecStartPost",
        "ExecStartPostEx",
        "ExecReload",
        "ExecReloadEx",
        "ExecStop",
        "ExecStopEx",
        "ExecStopPost",
        "ExecStopPostEx",
    }
    if observed.get("DropInPaths", "") or any(
        observed.get(key, "") for key in command_properties
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"captured effective systemd command surface changed: {unit}"
        )
    prefix = re.escape(
        f"{{ path=/usr/bin/python3.14 ; argv[]={argv} ; "
    )
    suffix = (
        r" ; start_time=\[[^;\]\r\n]*\]"
        r" ; stop_time=\[[^;\]\r\n]*\]"
        r" ; pid=[0-9]+"
        r" ; code=(?:\(null\)|exited)"
        r" ; status=[0-9]+(?:/[0-9]+)? \}"
    )
    patterns = {
        "ExecStart": prefix + r"ignore_errors=no" + suffix,
        "ExecStartEx": prefix + r"flags=" + suffix,
    }
    if any(
        re.fullmatch(pattern, observed.get(key, "")) is None
        for key, pattern in patterns.items()
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"captured effective systemd command changed: {unit}"
        )


def _positive(
    archive: _Archive,
    capture: dict[str, Any],
    evidence: dict[str, Any],
    label: str,
    *,
    journal_timestamp: int,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized = _broker_boundary(evidence, label)
    if (
        evidence["source"]["request"] != capture["epochs"][label]["request"]
        or evidence["producer_implementation_digest"]
        != capture["runtime"]["broker_digest"]
        or evidence["analyzer"]["executable_digest"]
        != capture["runtime"]["python_digest"]
        or evidence["analyzer"]["verifier_implementation_digest"]
        != capture["runtime"]["analyzer_verifier_digest"]
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} source request changed"
        )
    request, request_digest = _request_v3(
        archive,
        evidence,
        label,
        journal_timestamp=journal_timestamp,
        previous=previous,
    )
    cas = archive.cases[label]
    graph, result, receipt = _source(cas, capture, evidence, graph_version=3)
    analyzer = evidence["analyzer"]
    pseudo_request = {
        "expected_analyzer_implementation_digest": analyzer[
            "implementation_digest"
        ],
        "expected_analyzer_configuration_digest": analyzer[
            "configuration_digest"
        ],
        "expected_analyzer_executable_digest": analyzer["executable_digest"],
        "expected_analyzer_verifier_digest": analyzer[
            "verifier_implementation_digest"
        ],
        "expected_policy_digest": evidence["decision"]["policy_digest"],
    }
    _evidence_decision(cas, pseudo_request, normalized, graph)
    decision_record = _decision_record(
        cas,
        evidence,
        capture,
        [analyzer["run_receipt_digest"]],
    )
    closure_blobs = dict(archive.blobs[label])
    if previous is not None:
        try:
            closure_blobs.pop(evidence["transition"]["manifest_diff"]["digest"])
        except KeyError as exc:
            raise ProtectedRecursiveV3LiveArchiveError(
                "update CAS omits its manifest diff"
            ) from exc
    _verify_handoff(
        cas,
        closure_blobs,
        {
            **result,
            "handoff_manifest_digest": _handoff_digest(
                cas,
                archive.blobs[label],
                evidence["source"]["manifest_digest"],
            ),
        },
        decision_record=decision_record,
    )

    context = evidence["context"]
    transaction = evidence["transaction"]
    expected_active = (
        None
        if previous is None
        else {
            "context_id": previous["context_id"],
            "manifest_digest": previous["manifest_digest"],
        }
    )
    version_path = _version_path(
        "aragorn-admitted",
        context["context_id"],
        evidence["source"]["manifest_digest"],
    )
    context_document = {
        "schema": "aragorn/protected-install-context/v2",
        "authority": "BROKER_CONTEXT_ONLY_NOT_INSTALLER_AUTHORITY",
        "context_id": request["context_id"],
        "status": "active",
        "expires_at_unix": request["expires_at_unix"],
        "operation": request["operation"],
        "expected_active": expected_active,
        "decision_digest": evidence["decision"]["digest"],
        "manifest_digest": request["manifest_digest"],
        "artifact_graph_digest": evidence["source"]["artifact_graph_digest"],
        "policy_digest": request["expected_policy_digest"],
        "analyzer_run_receipt_digests": [analyzer["run_receipt_digest"]],
        "analyzer_verifier_digest": request[
            "expected_analyzer_verifier_digest"
        ],
        "artifact_graph_verifier_digest": request[
            "expected_artifact_graph_verifier_digest"
        ],
        "quarantine_receipt_digest": request[
            "quarantine_receipt_digest"
        ],
        "gateway_profile_digest": request["gateway_profile_digest"],
        "target_runtime_digest": request["target_runtime_digest"],
        "runtime_conformance_digest": request[
            "runtime_conformance_digest"
        ],
        "destination": context["destination"],
    }
    verified_context = VerifiedInstallContextV2(
        context_digest=canonical_digest(context_document),
        context_id=request["context_id"],
        decision_digest=evidence["decision"]["digest"],
        manifest_digest=request["manifest_digest"],
        target_runtime_digest=request["target_runtime_digest"],
        runtime_conformance_digest=request["runtime_conformance_digest"],
        root_device=context["destination"]["root_device"],
        root_inode=context["destination"]["root_inode"],
        target_name=context["destination"]["target_name"],
        expires_at_unix=request["expires_at_unix"],
        operation=request["operation"],
        expected_active_context_id=(
            None if expected_active is None else expected_active["context_id"]
        ),
        expected_active_manifest_digest=(
            None
            if expected_active is None
            else expected_active["manifest_digest"]
        ),
    )
    if (
        context_document["context_id"] != context["context_id"]
        or context_document["operation"] != label
        or canonical_digest(context_document) != context["digest"]
        or context["expected_active"] != expected_active
        or context["context_id"] != transaction["context_id"]
        or context["digest"] != transaction["context_digest"]
        or context["destination"] != transaction["destination"]
        or transaction["operation"] != label
        or transaction["expected_active"] != expected_active
        or transaction["manifest_digest"] != evidence["source"]["manifest_digest"]
        or transaction["tree_digest"] != graph["tree_digest"]
        or transaction["version_path"] != version_path
        or transaction
        != _transaction_record(
            verified_context,
            tree_digest=graph["tree_digest"],
            version_path=version_path,
        )
        or evidence["active"]
        != {"link_target": version_path, "tree_digest": graph["tree_digest"]}
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} context or transaction changed"
        )
    _claim(archive, evidence, label)
    installed = _installed(archive, cas, evidence)

    if previous is None:
        if evidence["transition"] != {
            "operation": "install",
            "expected_active": None,
            "manifest_diff": None,
        }:
            raise ProtectedRecursiveV3LiveArchiveError(
                "install transition changed"
            )
        changed_paths: list[str] | None = None
    else:
        diff = diff_verified_manifests_between(
            previous["cas"],
            previous["manifest_digest"],
            cas,
            evidence["source"]["manifest_digest"],
        )
        transition = evidence["transition"]
        expected_previous = {
            "request": previous["evidence"]["source"]["request"],
            "manifest_digest": previous["manifest_digest"],
            "quarantine_receipt_digest": previous["evidence"]["source"][
                "quarantine_receipt_digest"
            ],
            "gateway_profile_digest": previous["evidence"]["source"][
                "gateway_profile_digest"
            ],
            "source_closure_digest": previous["evidence"]["source"][
                "source_closure_digest"
            ],
            "recursive": previous["evidence"]["source"]["recursive"],
        }
        if (
            transition["operation"] != "update"
            or transition["expected_active"] != expected_active
            or transition["previous_source"] != expected_previous
            or transition["manifest_diff"]["document"] != diff
            or transition["manifest_diff"]["digest"] != canonical_digest(diff)
            or _cas_document(
                cas,
                transition["manifest_diff"]["digest"],
                "manifest diff",
            )
            != diff
        ):
            raise ProtectedRecursiveV3LiveArchiveError(
                "update predecessor or manifest diff changed"
            )
        changed_paths = diff["changed_paths"]
    return {
        "cas": cas,
        "evidence": evidence,
        "request": evidence["source"]["request"],
        "context_id": context["context_id"],
        "manifest_digest": evidence["source"]["manifest_digest"],
        "graph": graph,
        "receipt": receipt,
        "installed": installed,
        "version_path": version_path,
        "service_request": request,
        "request_digest": request_digest,
        "decision_digest": evidence["decision"]["digest"],
        "analyzer_receipt_digest": analyzer["run_receipt_digest"],
        "changed_paths": changed_paths,
    }


def _request_v3(
    archive: _Archive,
    evidence: dict[str, Any],
    label: str,
    *,
    journal_timestamp: int,
    previous: dict[str, Any] | None = None,
    reference_request: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    item = archive.files[f"requests/{label}.json"]
    request = _canonical_document(item.raw, f"{label} service request")
    if (
        item.mode != 0o400
        or request.get("schema")
        != "aragorn/protected-install-broker-request/v3"
        or set(request) != _REQUEST_FIELDS
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} service request schema, fields, or mode changed"
        )
    if any(not _digest(request[field]) for field in _REQUEST_DIGEST_FIELDS):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} service request digest changed"
        )
    source_request = request["source_request"]
    if source_request != build_gateway_request(
        source_request.get("owner"),
        source_request.get("repository"),
        source_request.get("commit"),
        source_request.get("skill_path"),
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} service source request is not canonical"
        )
    recursive = request["recursive"]
    if (
        not isinstance(recursive, dict)
        or set(recursive)
        != {
            "root_manifest_digest",
            "expansion_digest",
            "expansion_proof_digest",
            "release_asset_result_digests",
        }
        or not _digest(recursive["root_manifest_digest"])
        or not _digest(recursive["expansion_digest"])
        or (
            recursive["expansion_proof_digest"] is not None
            and not _digest(recursive["expansion_proof_digest"])
        )
        or not isinstance(recursive["release_asset_result_digests"], list)
        or any(
            not _digest(value)
            for value in recursive["release_asset_result_digests"]
        )
        or recursive["release_asset_result_digests"]
        != sorted(set(recursive["release_asset_result_digests"]))
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} recursive service binding changed"
        )

    authority = evidence.get("request_authority")
    credential = authority.get("credential") if isinstance(authority, dict) else None
    request_digest = _sha256(item.raw)
    if (
        not isinstance(credential, dict)
        or set(authority)
        != {
            "authority",
            "request_digest",
            "request_schema",
            "credential",
        }
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
        or authority["authority"]
        != "PROTECTED_CANONICAL_REQUEST_CREDENTIAL"
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
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} request credential evidence changed"
        )
    credential_second = credential["ctime_ns"] // 1_000_000_000
    expires = request["expires_at_unix"]
    now = evidence.get("claim", {}).get("fresh", {}).get(
        "claim_now_unix",
        journal_timestamp // 1_000_000,
    )
    if (
        isinstance(expires, bool)
        or not isinstance(expires, int)
        or expires != credential_second + _REQUEST_TTL_SECONDS
        or isinstance(now, bool)
        or not isinstance(now, int)
        or not credential_second <= now <= credential_second + 5
        or now >= expires
        or not credential_second
        <= journal_timestamp // 1_000_000
        <= credential_second + 5
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} request freshness changed"
        )

    if previous is None:
        expected_active = None
        expected_diff = None
    else:
        previous_source = previous["evidence"]["source"]
        expected_active = {
            "context_id": previous["context_id"],
            "manifest_digest": previous["manifest_digest"],
            "source_request": previous["request"],
            "quarantine_receipt_digest": previous_source[
                "quarantine_receipt_digest"
            ],
            "gateway_profile_digest": previous_source[
                "gateway_profile_digest"
            ],
            "recursive": previous_source["recursive"],
        }
        expected_diff = evidence["transition"]["manifest_diff"]["digest"]
    analyzer = evidence["analyzer"]
    if reference_request is None:
        analyzer_pins = {
            "expected_analyzer_implementation_digest": analyzer[
                "implementation_digest"
            ],
            "expected_analyzer_executable_digest": analyzer[
                "executable_digest"
            ],
            "expected_analyzer_configuration_digest": analyzer[
                "configuration_digest"
            ],
            "expected_analyzer_verifier_digest": analyzer[
                "verifier_implementation_digest"
            ],
        }
        target_runtime = evidence["context"]["target_runtime_digest"]
        runtime_conformance = evidence["context"][
            "runtime_conformance_digest"
        ]
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
        runtime_conformance = reference_request[
            "runtime_conformance_digest"
        ]
        context_id = request["context_id"]
    expected = {
        "schema": "aragorn/protected-install-broker-request/v3",
        "expires_at_unix": credential_second + _REQUEST_TTL_SECONDS,
        "operation": "install" if previous is None else "update",
        "expected_active": expected_active,
        "expected_manifest_diff_digest": expected_diff,
        "target_runtime_digest": target_runtime,
        "runtime_conformance_digest": runtime_conformance,
        "manifest_digest": evidence["source"]["manifest_digest"],
        "quarantine_receipt_digest": evidence["source"][
            "quarantine_receipt_digest"
        ],
        "gateway_profile_digest": evidence["source"][
            "gateway_profile_digest"
        ],
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
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} canonical service request does not replay"
        )
    return request, request_digest


def _source(
    cas: CAS,
    capture: dict[str, Any],
    evidence: dict[str, Any],
    *,
    graph_version: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    source = evidence["source"]
    recursive = source["recursive"]
    verifier_field = (
        "recursive_v3_verifier_digest"
        if graph_version == 3
        else "recursive_v4_verifier_digest"
    )
    if (
        source["artifact_graph_verifier_implementation_digest"]
        != capture["runtime"][verifier_field]
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "source graph verifier binding changed"
        )
    root_manifest = load_verified_retained_manifest(
        cas,
        recursive["root_manifest_digest"],
    )
    receipt = _cas_document(
        cas,
        source["quarantine_receipt_digest"],
        "quarantine receipt",
    )
    result = {
        "manifest_digest": source["manifest_digest"],
        "graph_digest": source["artifact_graph_digest"],
        "root_manifest_digest": recursive["root_manifest_digest"],
        "expansion_digest": recursive["expansion_digest"],
        "expansion_proof_digest": recursive["expansion_proof_digest"],
        "quarantine_receipt_digest": source["quarantine_receipt_digest"],
        "gateway_profile_digest": source["gateway_profile_digest"],
        "source_proof_digest": source["source_proof_digest"],
        "root_handoff_manifest_digest": receipt["handoff_manifest_digest"],
    }
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
        result,
    )
    if graph_version == 3:
        graph = _verify_graph(cas, stub, receipt, result)
    else:
        graph = _verify_graph_v4(cas, receipt, source)
    expected = {
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
    if source != expected:
        raise ProtectedRecursiveV3LiveArchiveError(
            "source evidence does not replay"
        )
    return graph, result, receipt


def _verify_graph_v4(
    cas: CAS,
    receipt: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    module = github_recursive_artifact_graph_v4
    recursive = source["recursive"]
    expansion = module._load_expansion(cas, recursive["expansion_digest"])
    if expansion.get("root_manifest_digest") != recursive["root_manifest_digest"]:
        raise ProtectedRecursiveV3LiveArchiveError(
            "release expansion root changed"
        )
    retained = load_verified_retained_manifest(cas, source["manifest_digest"])
    if retained != module._derive_expanded_manifest(cas, expansion):
        raise ProtectedRecursiveV3LiveArchiveError(
            "release installable manifest changed"
        )
    closure = expansion.get("closure")
    complete = (
        isinstance(closure, dict)
        and closure.get("status") == "complete"
        and closure.get("unresolved") == []
    )
    has_objects = bool(expansion.get("objects"))
    proof = recursive["expansion_proof_digest"]
    if complete or has_objects:
        if proof is None:
            raise ProtectedRecursiveV3LiveArchiveError(
                "release expansion omits membership proof"
            )
        module.verify_github_expansion_proof(
            cas,
            proof,
            expected_expansion_digest=recursive["expansion_digest"],
            expected_root_manifest_digest=recursive["root_manifest_digest"],
        )
    elif proof is not None:
        raise ProtectedRecursiveV3LiveArchiveError(
            "empty incomplete release expansion claims a proof"
        )
    release_assets = module._load_release_assets(
        cas,
        recursive["release_asset_result_digests"],
    )
    edges, scan_unresolved, static_total, static_captured, used = (
        module._scan_recursive(
            cas,
            expansion,
            release_assets=release_assets,
            release_asset_contract=True,
        )
    )
    if used != set(release_assets):
        raise ProtectedRecursiveV3LiveArchiveError(
            "retained release asset is absent from source references"
        )
    unresolved = set(scan_unresolved)
    accounted = bool(release_assets) and module._release_asset_candidates(edges) == used
    if not complete:
        for reason in module._expansion_unresolved(closure):
            if (
                reason["reason_code"] == "GITHUB_RELEASE_ASSET_NOT_RETAINED"
                and accounted
            ):
                continue
            unresolved.add(
                f"EXPANSION_{reason['reason_code']}:{reason['subject']}"
            )
    ordered = sorted(unresolved)
    expected = {
        "schema": module.RELEASE_ASSET_SCHEMA,
        "authority": module._AUTHORITY,
        "verifier": {
            "name": module.VERIFIER,
            "version": module.RELEASE_ASSET_VERIFIER_VERSION,
            "implementation_digest": source[
                "artifact_graph_verifier_implementation_digest"
            ],
        },
        "profile": module.RELEASE_ASSET_PROFILE,
        "root_manifest_digest": source["manifest_digest"],
        "root_github_manifest_digest": recursive["root_manifest_digest"],
        "source_proof_digest": receipt["source_proof_digest"],
        "quarantine_receipt_digest": source["quarantine_receipt_digest"],
        "gateway_profile_digest": source["gateway_profile_digest"],
        "expansion_digest": recursive["expansion_digest"],
        "expansion_proof_digest": proof,
        "tree_digest": retained["tree_digest"],
        "artifacts": retained["files"],
        "edges": edges,
        "coverage": {
            "statically_resolvable": {
                "captured": static_captured,
                "total": static_total,
            },
            "unresolved_required": len(ordered),
        },
        "closure": {
            "scope": "artifact_graph",
            "profile": module.RELEASE_ASSET_PROFILE,
            "status": "incomplete" if ordered else "complete",
            "unresolved": ordered,
        },
    }
    graph = _cas_document(
        cas,
        source["artifact_graph_digest"],
        "release artifact graph",
    )
    if graph != expected or canonical_digest(graph) != source["artifact_graph_digest"]:
        raise ProtectedRecursiveV3LiveArchiveError(
            "release artifact graph does not replay"
        )
    return graph


def _release_error(
    archive: _Archive,
    capture: dict[str, Any],
    evidence: dict[str, Any],
    coordinator: dict[str, Any],
    *,
    journal_timestamp: int,
    reference_request: dict[str, Any],
) -> dict[str, Any]:
    forbidden = {"context", "transaction", "claim", "active"}
    if (
        evidence.get("schema")
        != "aragorn/openclaw-github-protected-install-broker-evidence/v1"
        or evidence.get("slice_status") != "ERROR"
        or evidence.get("mode") != "github-live"
        or evidence.get("producer_implementation_digest")
        != capture["runtime"]["broker_digest"]
        or evidence.get("decision", {}).get("verdict") != "ERROR"
        or evidence["decision"].get("installer_work_eligible") is not False
        or evidence.get("analyzer") != {"run_receipt_digests": []}
        or forbidden & set(evidence)
        or evidence.get("error")
        != {
            "type": "INCOMPLETE_ARTIFACT_GRAPH",
            "message": (
                "GitHub artifact closure is incomplete; protected install is blocked"
            ),
        }
        or evidence.get("transition")
        != {"operation": "install", "expected_active": None, "manifest_diff": None}
        or evidence.get("verified_sequence")
        != [
            "quarantine-custody",
            "recursive-github-markdown/v2-closure",
            "decision-v3-error-replay",
        ]
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "release-bearing broker did not fail closed"
        )
    if evidence["source"]["request"] != capture["epochs"]["release_error"]["request"]:
        raise ProtectedRecursiveV3LiveArchiveError(
            "release-bearing source request changed"
        )
    request, request_digest = _request_v3(
        archive,
        evidence,
        "release-error",
        journal_timestamp=journal_timestamp,
        reference_request=reference_request,
    )
    cas = archive.cases["release-error"]
    graph, result, _receipt = _source(cas, capture, evidence, graph_version=4)
    release_digests = evidence["source"]["recursive"][
        "release_asset_result_digests"
    ]
    pin_file = archive.files["runtime/release-asset-pins.json"]
    pins = _canonical_document(pin_file.raw, "release asset pins")
    if (
        _sha256(pin_file.raw)
        != "sha256:0b731f61f98f022c1ef9b5aeeafa5d9a68ee093985ade9f9ed4ab6d0ea8bdbab"
        or len(pins) != 1
        or len(release_digests) != 1
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "release asset pin selection changed"
        )
    url, pin = next(iter(pins.items()))
    release_result = _cas_document(
        cas,
        release_digests[0],
        "release asset result",
    )
    verified_asset = verify_github_release_asset_result(
        release_result,
        evidence_cas=CAS(cas.root, read_only=True),
        expected_url=url,
        expected_release_id=pin["release_id"],
        expected_asset_id=pin["asset_id"],
        expected_digest=pin["digest"],
        expected_github_digest=pin["github_digest"],
        expected_content_type=pin["content_type"],
        expected_redirected=pin["redirected"],
    )
    decision_record = _decision_record(cas, evidence, capture, [])
    decision = _verify_decision(
        cas,
        decision_record,
        graph,
        result,
    )
    _verify_handoff(
        cas,
        archive.blobs["release-error"],
        {
            **result,
            "handoff_manifest_digest": _handoff_digest(
                cas,
                archive.blobs["release-error"],
                evidence["source"]["manifest_digest"],
            ),
        },
        decision_record=decision_record,
    )
    if (
        graph["schema"] != "aragorn/admission-artifact-graph/v4"
        or graph["profile"] != "recursive-github-markdown/v2"
        or graph["closure"]["status"] != "incomplete"
        or graph["coverage"]["unresolved_required"] != 9
        or not any(
            reason.startswith("GITHUB_RELEASE_ASSET_NOT_ANALYZED:")
            for reason in graph["closure"]["unresolved"]
        )
        or decision["verdict"] != "ERROR"
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "release-bearing graph did not remain non-ALLOW"
        )
    intent = _document(archive, "evidence/release-error-intent.json")
    source_request = evidence["source"]["request"]
    if intent != {
        "schema": "aragorn/protected-install-intent/v1",
        "operation": "install",
        **{
            field: source_request[field]
            for field in ("owner", "repository", "commit", "skill_path")
        },
    }:
        raise ProtectedRecursiveV3LiveArchiveError(
            "release-bearing coordinator intent changed"
        )
    protected = _document(
        archive,
        "evidence/release-error-protected-state.json",
    )
    expected_empty = {
        "coordinator_state": "absent",
        "entry_count": 0,
        "tree_snapshot_sha256": (
            "a995c7eaac46db3288ab8ebbcb2d914c201478b46bdd90b5116b14ba392df701"
        ),
    }
    if (
        protected
        != {
            "schema": "aragorn/protected-state-comparison/v1",
            "epoch": "release-bearing-empty-root",
            "protected_root": "/var/lib/aragorn-protected/skills",
            "before": expected_empty,
            "after": expected_empty,
            "byte_identical": True,
        }
        or any(
            name.startswith("protected/release-error/")
            for name in archive.files | archive.directories | archive.symlinks
        )
        or archive.directories.get("protected/release-error") != 0o700
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "release-bearing failure changed protected state"
        )
    if (
        coordinator.get("schema")
        != "aragorn/protected-install-coordinator-result/v1"
        or coordinator.get("status") != "ERROR"
        or coordinator.get("installer_work_eligible") is not False
        or coordinator.get("runtime_conformance_qualified") is not False
        or coordinator.get("error", {}).get("type")
        != "ProtectedInstallCoordinatorError"
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "release-bearing coordinator result changed"
        )
    return {
        "request": evidence["source"]["request"],
        "request_digest": request_digest,
        "request_expires_at_unix": request["expires_at_unix"],
        "manifest_digest": evidence["source"]["manifest_digest"],
        "graph_digest": evidence["source"]["artifact_graph_digest"],
        "graph_schema": graph["schema"],
        "closure_status": graph["closure"]["status"],
        "unresolved_required": graph["coverage"]["unresolved_required"],
        "release_asset_result_digest": release_digests[0],
        "release_asset_digest": verified_asset["asset"]["digest"],
        "release_asset_bytes": verified_asset["asset"]["size"],
        "analyzer_run_receipts": 0,
        "decision_digest": evidence["decision"]["digest"],
        "verdict": decision["verdict"],
        "error_type": evidence["error"]["type"],
        "protected_entries_before": 0,
        "protected_entries_after": 0,
        "recorded_protected_state_unchanged": True,
        "published": False,
    }


def _final_publication(
    archive: _Archive,
    install: dict[str, Any],
    update: dict[str, Any],
) -> None:
    state = _document(archive, "protected/coordinator-state.json")
    expected = {
        "schema": "aragorn/protected-install-coordinator-state/v2",
        "assurance": "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "expected_active": {
            "context_id": update["context_id"],
            "manifest_digest": update["manifest_digest"],
            "source_request": update["request"],
            "quarantine_receipt_digest": update["evidence"]["source"][
                "quarantine_receipt_digest"
            ],
            "gateway_profile_digest": update["evidence"]["source"][
                "gateway_profile_digest"
            ],
            "recursive": update["evidence"]["source"]["recursive"],
        },
        "tree_digest": update["graph"]["tree_digest"],
        "version_path": update["version_path"],
        "service_request_digest": update["request_digest"],
    }
    link = archive.symlinks["protected/positive/aragorn-admitted"][1]
    install_claim = (
        "protected/positive/.aragorn-install-claims/"
        + install["context_id"][7:]
        + ".json"
    )
    update_claim = (
        "protected/positive/.aragorn-install-claims/"
        + update["context_id"][7:]
        + ".json"
    )
    if (
        state != expected
        or link != update["version_path"]
        or archive.files[install_claim].mode != 0o400
        or archive.files[update_claim].mode != 0o400
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "final protected publication changed"
        )


def _claim(archive: _Archive, evidence: dict[str, Any], label: str) -> None:
    context_id = evidence["context"]["context_id"]
    path = (
        "protected/positive/.aragorn-install-claims/"
        + context_id[7:]
        + ".json"
    )
    if (
        _document(archive, path) != evidence["transaction"]
        or archive.files[path].mode != 0o400
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} protected claim changed"
        )
    revocation_digest = _sha256(archive.files["runtime/revocations.json"].raw)
    claim = evidence["claim"]
    snapshots = (
        claim.get("initial_revocation_snapshot"),
        claim.get("fresh", {}).get("revocation_snapshot"),
    )
    if any(
        not isinstance(snapshot, dict)
        or snapshot.get("schema") != "aragorn/protected-install-revocations/v1"
        or snapshot.get("context_ids") != []
        or snapshot.get("digest") != revocation_digest
        or snapshot.get("owner_uid") != 0
        or snapshot.get("mode") != 0o400
        for snapshot in snapshots
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} revocation claim changed"
        )


def _installed(
    archive: _Archive,
    cas: CAS,
    evidence: dict[str, Any],
) -> Any:
    root = "protected/positive/" + evidence["transaction"]["version_path"]
    members = [
        ArchivedTreeMember(".", "directory", archive.directories[root], 0)
    ]
    members.extend(
        ArchivedTreeMember(
            name.removeprefix(root + "/"),
            "directory",
            mode,
            0,
        )
        for name, mode in archive.directories.items()
        if name.startswith(root + "/")
    )
    members.extend(
        ArchivedTreeMember(
            name.removeprefix(root + "/"),
            "file",
            item.mode,
            len(item.raw),
            item.raw,
        )
        for name, item in archive.files.items()
        if name.startswith(root + "/")
    )
    return verify_installed_tree_members(
        cas,
        evidence["source"]["manifest_digest"],
        members,
    )


def _decision_record(
    cas: CAS,
    evidence: dict[str, Any],
    capture: dict[str, Any],
    run_receipts: list[str],
) -> dict[str, Any]:
    digest = evidence["decision"]["digest"]
    decision = _cas_document(cas, digest, "decision")
    record = {
        "decision_digest": digest,
        "verdict": decision["verdict"],
        "reason_codes": decision["reason_codes"],
        "policy_digest": evidence["decision"]["policy_digest"],
        "analyzer_run_receipt_digests": run_receipts,
        "analyzer_verifier_digest": capture["runtime"][
            "analyzer_verifier_digest"
        ],
        "artifact_graph_verifier_digest": evidence["source"][
            "artifact_graph_verifier_implementation_digest"
        ],
    }
    if evidence["decision"] != {
        "digest": digest,
        "verdict": decision["verdict"],
        "policy_digest": record["policy_digest"],
        "installer_work_eligible": False,
    }:
        raise ProtectedRecursiveV3LiveArchiveError(
            "broker decision summary changed"
        )
    return record


def _handoff_digest(
    cas: CAS,
    blobs: dict[str, bytes],
    root_digest: str,
) -> str:
    matches = []
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
            matches.append(digest)
    if len(matches) != 1:
        raise ProtectedRecursiveV3LiveArchiveError(
            "expanded handoff selection changed"
        )
    _cas_document(cas, matches[0], "expanded handoff")
    return matches[0]


def _journal(
    archive: _Archive,
    path: str,
    expected_unit: str,
) -> dict[str, Any]:
    wrapper = _document(archive, path)
    if (
        set(wrapper)
        != {
            "MESSAGE",
            "_BOOT_ID",
            "_SYSTEMD_INVOCATION_ID",
            "_SYSTEMD_UNIT",
            "__REALTIME_TIMESTAMP",
        }
        or wrapper["_SYSTEMD_UNIT"] != expected_unit
        or not _hex(wrapper["_BOOT_ID"], 32)
        or not _hex(wrapper["_SYSTEMD_INVOCATION_ID"], 32)
        or not isinstance(wrapper["__REALTIME_TIMESTAMP"], str)
        or not wrapper["__REALTIME_TIMESTAMP"].isdigit()
        or not isinstance(wrapper["MESSAGE"], str)
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"journal wrapper changed: {path}"
        )
    message = _canonical_document(
        wrapper["MESSAGE"].encode("utf-8"),
        f"{path} message",
    )
    return {
        "boot": wrapper["_BOOT_ID"],
        "invocation": wrapper["_SYSTEMD_INVOCATION_ID"],
        "timestamp": int(wrapper["__REALTIME_TIMESTAMP"]),
        "message": message,
    }


def _journal_lineage(
    wrappers: dict[str, dict[str, Any]],
    coordinator: dict[str, Any],
) -> None:
    ordered = [
        wrappers["install"],
        wrappers["update"],
        wrappers["release-error"],
        coordinator,
    ]
    if (
        len({item["boot"] for item in ordered}) != 1
        or len({item["invocation"] for item in ordered}) != 4
        or [item["timestamp"] for item in ordered]
        != sorted(item["timestamp"] for item in ordered)
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "journal boot, invocation, or time lineage changed"
        )


def _positive_result(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "request": value["request"],
        "request_digest": value["request_digest"],
        "context_id": value["context_id"],
        "manifest_digest": value["manifest_digest"],
        "graph_digest": value["evidence"]["source"]["artifact_graph_digest"],
        "graph_schema": value["graph"]["schema"],
        "closure_status": value["graph"]["closure"]["status"],
        "analyzer_run_receipts": 1,
        "analyzer_run_receipt_digest": value["analyzer_receipt_digest"],
        "decision_digest": value["decision_digest"],
        "verdict": "ALLOW",
        "installed_files": value["installed"].file_count,
        "installed_payload_bytes": value["installed"].payload_bytes,
        "tree_digest": value["installed"].tree_digest,
        "version_path": value["version_path"],
        "changed_paths": value["changed_paths"],
        "published": True,
    }


def _package_tree_digest(archive: _Archive, root: str) -> str:
    if root not in archive.directories:
        raise ProtectedRecursiveV3LiveArchiveError(
            "captured protected package root is absent"
        )
    prefix = root + "/"
    directories = {
        name: mode
        for name, mode in archive.directories.items()
        if name == root or name.startswith(prefix)
    }
    files = {
        name: item
        for name, item in archive.files.items()
        if name.startswith(prefix)
    }
    if (
        len(directories) + len(files) - 1 > 10_000
        or any(mode & 0o022 for mode in directories.values())
        or any(item.mode & 0o022 for item in files.values())
        or any(
            not any(
                child.startswith(name + "/")
                for child in (directories | files)
            )
            for name in directories
        )
        or any(len(item.raw) > 64 * 1024 * 1024 for item in files.values())
        or sum(len(item.raw) for item in files.values())
        > 256 * 1024 * 1024
    ):
        raise ProtectedRecursiveV3LiveArchiveError(
            "captured protected package metadata is unsafe"
        )
    digest = hashlib.sha256()
    for name, item in sorted(files.items()):
        relative = name.removeprefix(prefix)
        try:
            encoded = relative.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ProtectedRecursiveV3LiveArchiveError(
                "captured package path is not UTF-8"
            ) from exc
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(item.mode.to_bytes(4, "big"))
        digest.update(len(item.raw).to_bytes(8, "big"))
        digest.update(hashlib.sha256(item.raw).digest())
    return "sha256:" + digest.hexdigest()


def _gateway_tree_digest(archive: _Archive, root: str) -> str:
    prefix = root + "/"
    records: list[dict[str, Any]] = [
        {"path": ".", "kind": "directory", "mode": archive.directories[root]}
    ]
    records.extend(
        {
            "path": name.removeprefix(prefix),
            "kind": "directory",
            "mode": mode,
        }
        for name, mode in archive.directories.items()
        if name.startswith(prefix)
    )
    records.extend(
        {
            "path": name.removeprefix(prefix),
            "kind": "file",
            "mode": item.mode,
            "size": len(item.raw),
            "digest": _sha256(item.raw),
        }
        for name, item in archive.files.items()
        if name.startswith(prefix)
    )
    records.sort(key=lambda record: (str(record["path"]), str(record["kind"])))
    return _sha256(canonical_json(records))


def _document(archive: _Archive, path: str) -> dict[str, Any]:
    try:
        item = archive.files[path]
    except KeyError as exc:
        raise ProtectedRecursiveV3LiveArchiveError(
            f"archive omits {path}"
        ) from exc
    return _canonical_document(item.raw, path)


def _json_document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} is invalid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise ProtectedRecursiveV3LiveArchiveError(
            f"{label} must be a JSON object"
        )
    return document


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _cas_document(cas: CAS, digest: str, label: str) -> dict[str, Any]:
    return _canonical_document(
        cas.read(digest, max_bytes=_MAX_MEMBER_BYTES),
        label,
    )


def _walk(value: object) -> list[object]:
    if isinstance(value, dict):
        return [value, *(item for child in value.values() for item in _walk(child))]
    if isinstance(value, list):
        return [value, *(item for child in value for item in _walk(child))]
    return [value]


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and _hex(value[7:], 64)
    )


def _hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _positive_integer(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0
