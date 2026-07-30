"""Strict offline verification of the supported production-ingress capture."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import tarfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from . import (
    decision_receipt,
    github_gateway_live_evidence,
    github_recursive_artifact_graph,
)
from .artifact_closure import ArtifactClosureError
from .cas import CAS, CASError
from .github_quarantine_receipt import (
    GitHubQuarantineReceiptError,
    github_source_closure_digest,
)
from .oci_worker_protocol import canonical_digest, canonical_json
from .protected_install_transition_replay import (
    _decision as _replay_decision,
)
from .protected_install_transition_replay import (
    _pinned_bytes,
)

ARCHIVE_DIGEST = (
    "sha256:f8fe80fa4c14928364461ae38a0d5db471dabc48a2572e830e4dd3e864962c2d"
)
ARCHIVE_NAME = "phase1-supported-ingress-live-c87b82b9b7a4-2026-07-29.tar.xz"
ARCHIVE_PATH = f"benchmark/evidence/{ARCHIVE_NAME}"
AUTHORITY = "LIVE_PRODUCTION_INGRESS_ONLY_NOT_INSTALLER_OR_RUNTIME_AUTHORITY"

_ROOT = "phase1-supported-ingress-live-c87b82b9b7a4-2026-07-29"
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_MAX_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 96 * 1024 * 1024
_EXPECTED_INVENTORY = {
    "members": 401,
    "regular_files": 256,
    "directories": 141,
    "symlinks": 4,
    "payload_bytes": 84_594_092,
}
_SOURCE = {
    "commit": "c87b82b9b7a4b8465b9958d33d997fd014f49257",
    "tree": "e410790b58cec1b61feb8260dd890cefe3170116",
    "signature": "GOOD_SSH_SIGNATURE",
    "signing_key_fingerprint": ("SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk"),
    "transfer_archive_digest": (
        "sha256:56b4650b154ad6c4e2fd77513ffbe9d58f4ed377b2b847a3f37803f3e3d9a02a"
    ),
}
_LIMITATIONS = [
    "SUPPORTED_PROFILE_IS_PUBLIC_GITHUB_EXACT_COMMIT_ONLY",
    "ONE_BYTE_IDENTICAL_AND_ONE_BYTE_CHANGING_UPDATE_LIVE_SLICE_ONLY",
    "REQUEST_V4_RELEASE_ASSET_CUSTODY_IS_A_SEPARATE_PINNED_LEAF",
    "LEGACY_INSTALL_UPDATE_AND_RELEASE_ERROR_CASES_HAVE_NO_RETAINED_CAS",
    "NO_INSTALLER_AUTHORITY",
    "NO_RUNTIME_CONFORMANCE_AUTHORITY",
    "NO_PUBLIC_RELEASE_AUTHORITY",
]
_EXPECTED_CASES = {
    "install": {
        "exit": 0,
        "operation": "install",
        "status": "COMPLETED_NOT_INSTALLER_AUTHORITY",
        "request": (
            "anthropics",
            "skills",
            "00756142ab04c82a447693cf373c4e0c554d1005",
            "template",
        ),
    },
    "update": {
        "exit": 0,
        "operation": "update",
        "status": "COMPLETED_NOT_INSTALLER_AUTHORITY",
        "request": (
            "anthropics",
            "skills",
            "2235be7c60b551f5de82ade908fd3816455afcda",
            "template",
        ),
    },
    "release-error": {
        "exit": 4,
        "operation": "install",
        "status": "ERROR",
        "request": (
            "bitwisecook",
            "tcl-lsp",
            "a998dc7b578329c2c63b26ce21686f020a78a0b6",
            ".claude/skills/dockerfile-generate",
        ),
    },
    "recursive-metrics": {
        "exit": 4,
        "operation": "install",
        "status": "ERROR",
        "request": (
            "anthropics",
            "claude-plugins-official",
            "6b708ace50a2a9869c3d21ca7df2b04defc82f2b",
            "plugins/plugin-dev/skills/hook-development",
        ),
        "coverage": (13, 13, 18),
    },
    "byte-update-base": {
        "exit": 0,
        "operation": "install",
        "status": "COMPLETED_NOT_INSTALLER_AUTHORITY",
        "request": (
            "obra",
            "superpowers",
            "f57638a74759376871509ccf080e606f62052f1b",
            "skills/requesting-code-review",
        ),
        "coverage": (0, 0, 0),
    },
    "byte-update-next": {
        "exit": 0,
        "operation": "update",
        "status": "COMPLETED_NOT_INSTALLER_AUTHORITY",
        "request": (
            "obra",
            "superpowers",
            "9ccce3bf07a40e45259004a330409ba00970eff7",
            "skills/requesting-code-review",
        ),
        "coverage": (0, 0, 0),
    },
}
_RELEASE_IDENTITY = {
    "schema": "aragorn/protected-broker-launch-identity/v1",
    "broker": {
        "digest": (
            "sha256:377b1a5330cc6b9bea1984917804ee7c59538d53ac5e283a75f3394d438616ff"
        ),
        "path": (
            "benchmark/admission/openclaw-v2026.7.1/"
            "protected-install-broker-recursive-v3.py"
        ),
    },
    "launcher": {
        "digest": (
            "sha256:e27b2ed1be6e24d758b148e9d6f9740d4e1c5cd74e87462d2fb2d9686dc5810b"
        ),
        "path": "/usr/libexec/aragorn/aragorn-protected-install-launcher.py",
    },
    "package": {
        "root": "/opt/aragorn-broker-c87b82b9b7a4",
        "tree_digest": (
            "sha256:26f93ed9bafb847bd0616b9533cf8d8100a3dadb3980038bba2536699603fb22"
        ),
    },
    "python": {
        "digest": (
            "sha256:d7dc1ef6da10929a8bb44e1e3f1d666b83fa746f92db9c50f889e4c747c6dc26"
        ),
        "path": "/usr/bin/python3.14",
    },
}
_CURRENT_ARTIFACT_GRAPH_VERIFIER_DIGEST = (
    "sha256:7e8afe5cdd521ef7240f11afc7501b3b4fb5c4c17b217bda1ab7abc4fd2c3ff6"
)
_CURRENT_ANALYZER = {
    "name": "aragorn-agent-skill-threats",
    "version": "0.1.0-phase0-v7",
    "implementation_digest": (
        "sha256:7e8afe5cdd521ef7240f11afc7501b3b4fb5c4c17b217bda1ab7abc4fd2c3ff6"
    ),
    "configuration_digest": (
        "sha256:9f5e1b57b9a1099db6b9f3aa88ab283f947b43e7a4c421e90f16bf2a5a93765a"
    ),
    "executable_digest": (
        "sha256:d7dc1ef6da10929a8bb44e1e3f1d666b83fa746f92db9c50f889e4c747c6dc26"
    ),
    "verifier_implementation_digest": (
        "sha256:6d4a54c3206e9ab5cc767131f35de7587f7f6d05707a69d9f52028fda5821e45"
    ),
    "execution_identity": {
        "uid": 983,
        "user": "aragorn-analyze",
        "gid": 983,
        "group": "aragorn-analyze",
        "supplementary_groups": [],
    },
}
_CURRENT_ANALYZER_RUN_RECEIPTS = {
    "install": (
        "sha256:e7656d36cf8f3c7bec4f920e57d1307aa7031295cce78d806348bf708967d8f0"
    ),
    "update": (
        "sha256:fc71bafeff5baf1cd605bb92460162ac4225ae752611c0bde64bc7be334f3701"
    ),
    "byte-update-base": (
        "sha256:44e984812d34a33560d7f7360e81d1738dd74e64ab99124a9468a863d774c063"
    ),
    "byte-update-next": (
        "sha256:a4b3f82b624969bfe26d72345d17897dc0d77ce4f97f7341feb7a796c2a8a814"
    ),
}
_CURRENT_POLICY_DIGEST = (
    "sha256:aa90f135d9634ce22428ffd17a780044b11ae13755b7c16ea427ae8aa684232f"
)
_CURRENT_GATEWAY_IDENTITY = {
    "package_tree_digest": (
        "sha256:222e68541b5df619390b669edab3048a34ac393d1af94367837cc27ed9a25f13"
    ),
    "python_executable_digest": _RELEASE_IDENTITY["python"]["digest"],
}
_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")


class SupportedIngressLiveArchiveError(ValueError):
    """The retained supported-ingress archive is malformed or inconsistent."""


@dataclass(frozen=True)
class _File:
    raw: bytes
    mode: int


@dataclass
class _Archive:
    files: dict[str, _File]
    directories: dict[str, int]
    symlinks: dict[str, tuple[int, str]]
    inventory: dict[str, int]
    records: list[dict[str, Any]]


@dataclass(frozen=True)
class _Case:
    summary: dict[str, Any]
    result: dict[str, Any]
    broker: dict[str, Any]
    submission: dict[str, Any]
    manifest: dict[str, Any] | None
    blobs: dict[str, bytes] | None


def verify_supported_ingress_live_archive(
    archive_path: str | Path,
) -> dict[str, Any]:
    """Derive the bounded production-ingress qualification from retained bytes."""

    try:
        raw = _pinned_bytes(
            archive_path,
            ARCHIVE_DIGEST,
            "supported-ingress live archive",
            _MAX_ARCHIVE_BYTES,
        )
        if (
            len(raw) < 18
            or raw[:8] != b"\xfd7zXZ\x00\x00\x04"
            or raw[-4:] != b"\x00\x04YZ"
        ):
            raise SupportedIngressLiveArchiveError(
                "archive XZ stream is not normalized"
            )

        archive = _load(raw)
        source, source_index, source_package_digest = _verify_provenance(archive)
        runtime = _verify_runtime(
            archive,
            source_index=source_index,
            source_package_digest=source_package_digest,
        )
        cases = {
            name: _verify_case(archive, name, expected)
            for name, expected in _EXPECTED_CASES.items()
        }
        numerical_gate = _verify_transitions(archive, cases)

        capture = _json(archive, "capture.json", newline=True)
        capture_inventory = {
            "digest": canonical_digest(archive.records),
            "members_excluding_capture": len(archive.records),
            "directory": sum(item["type"] == "directory" for item in archive.records),
            "file": sum(item["type"] == "file" for item in archive.records),
            "symlink": sum(item["type"] == "symlink" for item in archive.records),
        }
        evidence_coverage = {
            "fully_replayed_cases": [
                "byte-update-base",
                "byte-update-next",
                "recursive-metrics",
            ],
            "live_summary_only_cases": [
                "install",
                "release-error",
                "update",
            ],
        }
        expected_capture = {
            "schema": "aragorn/phase1-supported-ingress-live-capture/v1",
            "assurance": (
                "LIVE_PRODUCTION_INGRESS_QUALIFICATION_ONLY_"
                "NOT_INSTALLER_OR_RUNTIME_AUTHORITY"
            ),
            "profile": "public-github-exact-commit-supported-acquisition/v1",
            "source": source,
            "runtime": runtime,
            "evidence_coverage": evidence_coverage,
            "cases": {
                "release-error": {
                    **cases["release-error"].summary,
                    "protected_state_unchanged": True,
                    "fail_closed_reason_retained": True,
                    "release_pin_set_digest": cases["release-error"].broker["source"][
                        "recursive"
                    ]["release_pin_set_digest"],
                    "release_asset_result_digests": cases["release-error"].broker[
                        "source"
                    ]["recursive"]["release_asset_result_digests"],
                },
                "install": cases["install"].summary,
                "update": {
                    **cases["update"].summary,
                    "active_tree_byte_identical": True,
                },
                "recursive-metrics": {
                    **cases["recursive-metrics"].summary,
                    "protected_state_unchanged": True,
                    "static_references_resolved": 13,
                    "static_references_total": 13,
                    "unresolved_required_fail_closed": 18,
                },
                "byte-update-base": {
                    **cases["byte-update-base"].summary,
                    "installed_files": 2,
                    "installed_digest_mismatches": 0,
                },
                "byte-update-next": {
                    **cases["byte-update-next"].summary,
                    "installed_files": 2,
                    "installed_digest_mismatches": 0,
                    "changed_paths": ["SKILL.md"],
                },
            },
            "current_runtime_numerical_gate": numerical_gate,
            "decision": {
                "status": "PASS",
                "supported_ingress_qualified": True,
                "installer_work_eligible": False,
                "runtime_conformance_qualified": False,
                "public_release_eligible": False,
            },
            "limitations": _LIMITATIONS,
            "inventory": capture_inventory,
        }
        if capture != expected_capture:
            raise SupportedIngressLiveArchiveError(
                "capture document does not match independently derived evidence"
            )

        return {
            "schema": "aragorn/phase1-supported-ingress-live-qualification/v1",
            "authority": AUTHORITY,
            "archive": {
                "path": ARCHIVE_PATH,
                "digest": ARCHIVE_DIGEST,
                "bytes": len(raw),
                **archive.inventory,
                "inventory_digest": capture_inventory["digest"],
            },
            "profile": expected_capture["profile"],
            "source": source,
            "runtime": runtime,
            "evidence_coverage": evidence_coverage,
            "cases": expected_capture["cases"],
            "current_runtime_numerical_gate": numerical_gate,
            "qualification": expected_capture["decision"],
            "limitations": _LIMITATIONS,
            "status": "PASS",
        }
    except SupportedIngressLiveArchiveError:
        raise
    except Exception as exc:
        raise SupportedIngressLiveArchiveError(
            f"cannot verify supported-ingress live archive: {exc}"
        ) from exc


def _load(raw: bytes) -> _Archive:
    files: dict[str, _File] = {}
    directories: dict[str, int] = {}
    symlinks: dict[str, tuple[int, str]] = {}
    counts = {
        "members": 0,
        "regular_files": 0,
        "directories": 0,
        "symlinks": 0,
        "payload_bytes": 0,
    }
    previous: tuple[str, ...] = ()
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=BytesIO(raw), mode="r|xz") as source:
            for member in source:
                if counts["members"] >= _EXPECTED_INVENTORY["members"]:
                    raise SupportedIngressLiveArchiveError(
                        "archive member count exceeds its limit"
                    )
                counts["members"] += 1
                name = _safe_name(member)
                order = PurePosixPath(name).parts
                if name in seen or (previous and order <= previous):
                    raise SupportedIngressLiveArchiveError(
                        "archive members are repeated or not name-sorted"
                    )
                seen.add(name)
                previous = order
                relative = _relative(name)
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                    or member.mtime != 0
                    or member.pax_headers
                    or getattr(member, "sparse", None)
                    or member.devmajor
                    or member.devminor
                    or member.mode & ~0o777
                ):
                    raise SupportedIngressLiveArchiveError(
                        f"archive metadata is not normalized: {name}"
                    )
                if member.isdir():
                    if member.size or member.linkname:
                        raise SupportedIngressLiveArchiveError(
                            f"archive directory metadata changed: {name}"
                        )
                    directories[relative] = member.mode
                    counts["directories"] += 1
                    continue
                if member.issym():
                    if (
                        member.size
                        or member.linkname.startswith("/")
                        or "\\" in member.linkname
                        or "\x00" in member.linkname
                        or any(
                            part in {"", ".", ".."}
                            for part in PurePosixPath(member.linkname).parts
                        )
                    ):
                        raise SupportedIngressLiveArchiveError(
                            f"archive symlink is unsafe: {name}"
                        )
                    symlinks[relative] = (member.mode, member.linkname)
                    counts["symlinks"] += 1
                    continue
                if not member.isfile() or member.linkname:
                    raise SupportedIngressLiveArchiveError(
                        f"archive contains a hard link or special member: {name}"
                    )
                if member.size > _MAX_MEMBER_BYTES:
                    raise SupportedIngressLiveArchiveError(
                        f"archive member exceeds its byte limit: {name}"
                    )
                stream = source.extractfile(member)
                content = b"" if stream is None else stream.read(member.size + 1)
                if len(content) != member.size:
                    raise SupportedIngressLiveArchiveError(
                        f"archive member size changed: {name}"
                    )
                counts["payload_bytes"] += len(content)
                if counts["payload_bytes"] > _MAX_PAYLOAD_BYTES:
                    raise SupportedIngressLiveArchiveError(
                        "archive payload exceeds its byte limit"
                    )
                files[relative] = _File(content, member.mode)
                counts["regular_files"] += 1
    except SupportedIngressLiveArchiveError:
        raise
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise SupportedIngressLiveArchiveError(
            f"archive stream is invalid: {exc}"
        ) from exc

    if counts != _EXPECTED_INVENTORY or directories.get("") != 0o700:
        raise SupportedIngressLiveArchiveError("archive inventory changed")
    if "capture.json" not in files:
        raise SupportedIngressLiveArchiveError("archive omits capture.json")
    for name, (_, target) in symlinks.items():
        resolved = (PurePosixPath(name).parent / target).as_posix()
        if resolved not in directories and resolved not in files:
            raise SupportedIngressLiveArchiveError(
                f"archive symlink target is absent: {name}"
            )

    records: list[dict[str, Any]] = []
    names = (set(directories) | set(files) | set(symlinks)) - {
        "",
        "capture.json",
    }
    for name in sorted(names, key=lambda value: PurePosixPath(value).parts):
        if name in directories:
            records.append(
                {"path": name, "mode": directories[name], "type": "directory"}
            )
        elif name in files:
            item = files[name]
            records.append(
                {
                    "path": name,
                    "mode": item.mode,
                    "type": "file",
                    "bytes": len(item.raw),
                    "digest": _digest(item.raw),
                }
            )
        else:
            mode, target = symlinks[name]
            records.append(
                {
                    "path": name,
                    "mode": mode,
                    "type": "symlink",
                    "target": target,
                }
            )
    return _Archive(files, directories, symlinks, counts, records)


def _safe_name(member: tarfile.TarInfo) -> str:
    name = member.name
    if (
        not name
        or len(name) > 512
        or name.startswith("/")
        or "\\" in name
        or "\x00" in name
        or "//" in name
    ):
        raise SupportedIngressLiveArchiveError("archive member path is unsafe")
    normalized = name[:-1] if member.isdir() and name.endswith("/") else name
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or path.as_posix() != normalized
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise SupportedIngressLiveArchiveError("archive member path is non-canonical")
    return normalized


def _relative(name: str) -> str:
    if name == _ROOT:
        return ""
    prefix = _ROOT + "/"
    if not name.startswith(prefix):
        raise SupportedIngressLiveArchiveError(
            "archive member escaped its retained root"
        )
    return name.removeprefix(prefix)


def _verify_provenance(
    archive: _Archive,
) -> tuple[dict[str, Any], dict[str, str], str]:
    fingerprint = _SOURCE["signing_key_fingerprint"]
    signature = (
        'Good "git" signature for yousif.snazhat@gmail.com with ED25519 key '
        f"{fingerprint}\n"
    ).encode()
    commit_raw = _file(archive, "provenance/commit-object.txt", 0o644)
    commit_id = hashlib.sha1(
        b"commit " + str(len(commit_raw)).encode() + b"\0" + commit_raw
    ).hexdigest()
    source_archive = _file(archive, "provenance/source-archive.tar", 0o644)
    signing_key = _file(archive, "provenance/signing-key.pub", 0o644)
    if (
        commit_id != _SOURCE["commit"]
        or not commit_raw.startswith(
            (
                f"tree {_SOURCE['tree']}\n"
                "parent 1488a105802c6094bd990b5ad4f634fbdeed965d\n"
            ).encode()
        )
        or _file(archive, "provenance/git-verify-commit.txt", 0o644) != signature
        or _file(archive, "provenance/signing-key-fingerprint.txt", 0o644)
        != f"256 {fingerprint} yousif.snazhat@gmail.com (ED25519)\n".encode()
        or _file(archive, "provenance/git-show.txt", 0o644).splitlines()[:2]
        != [
            f"commit {_SOURCE['commit']}".encode(),
            signature.rstrip(b"\n"),
        ]
        or _file(archive, "provenance/source-archive.sha256", 0o644)
        != (
            _SOURCE["transfer_archive_digest"][7:] + "  /tmp/aragorn-c87b82b9b7a4.tar\n"
        ).encode()
        or _digest(source_archive) != _SOURCE["transfer_archive_digest"]
    ):
        raise SupportedIngressLiveArchiveError("signed source provenance is invalid")
    source_tree, source_index, package_digest = _verify_source_archive(source_archive)
    if source_tree != _SOURCE["tree"]:
        raise SupportedIngressLiveArchiveError(
            "retained source archive does not reproduce the signed Git tree"
        )
    _verify_commit_signature(commit_raw, signing_key)
    return dict(_SOURCE), source_index, package_digest


def _verify_source_archive(
    raw: bytes,
) -> tuple[str, dict[str, str], str]:
    files: dict[str, tuple[int, bytes]] = {}
    directories: set[str] = set()
    counts = {"members": 0, "files": 0, "directories": 0, "payload_bytes": 0}
    try:
        with tarfile.open(fileobj=BytesIO(raw), mode="r|") as source:
            for member in source:
                counts["members"] += 1
                if counts["members"] > 552:
                    raise SupportedIngressLiveArchiveError(
                        "source archive member count exceeds its limit"
                    )
                name = (
                    member.name[:-1]
                    if member.isdir() and member.name.endswith("/")
                    else member.name
                )
                path = PurePosixPath(name)
                pax = dict(member.pax_headers)
                pax_valid = pax.pop("comment", None) == _SOURCE["commit"] and (
                    not pax or pax == {"path": name}
                )
                if (
                    not name
                    or len(name) > 512
                    or name.startswith("/")
                    or "\x00" in name
                    or "//" in name
                    or path.is_absolute()
                    or path.as_posix() != name
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or name in files
                    or name in directories
                    or member.uid
                    or member.gid
                    or member.uname != "root"
                    or member.gname != "root"
                    or member.mtime != 1_785_376_453
                    or not pax_valid
                    or getattr(member, "sparse", None)
                    or member.devmajor
                    or member.devminor
                    or member.mode not in {0o664, 0o775}
                ):
                    raise SupportedIngressLiveArchiveError(
                        "source archive metadata is unsafe or changed"
                    )
                if member.isdir():
                    if member.mode != 0o775 or member.size or member.linkname:
                        raise SupportedIngressLiveArchiveError(
                            "source archive directory metadata changed"
                        )
                    directories.add(name)
                    counts["directories"] += 1
                    continue
                if not member.isfile() or member.linkname:
                    raise SupportedIngressLiveArchiveError(
                        "source archive contains a link or special member"
                    )
                if member.size > _MAX_MEMBER_BYTES:
                    raise SupportedIngressLiveArchiveError(
                        "source archive member exceeds its byte limit"
                    )
                stream = source.extractfile(member)
                content = b"" if stream is None else stream.read(member.size + 1)
                if len(content) != member.size:
                    raise SupportedIngressLiveArchiveError(
                        "source archive member size changed"
                    )
                counts["payload_bytes"] += len(content)
                if counts["payload_bytes"] > 256 * 1024 * 1024:
                    raise SupportedIngressLiveArchiveError(
                        "source archive payload exceeds its byte limit"
                    )
                files[name] = (member.mode & ~0o022, content)
                counts["files"] += 1
    except SupportedIngressLiveArchiveError:
        raise
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise SupportedIngressLiveArchiveError(
            f"source archive stream is invalid: {exc}"
        ) from exc

    if counts != {
        "members": 552,
        "files": 507,
        "directories": 45,
        "payload_bytes": 52_168_369,
    }:
        raise SupportedIngressLiveArchiveError("source archive inventory changed")
    implied_directories = {
        PurePosixPath(*parts[:index]).as_posix()
        for name in files
        for parts in (PurePosixPath(name).parts,)
        for index in range(1, len(parts))
    }
    if directories != implied_directories:
        raise SupportedIngressLiveArchiveError(
            "source archive contains an empty or missing directory"
        )

    package_root = _RELEASE_IDENTITY["package"]["root"] + "/"
    package_index: dict[str, str] = {}
    package_digest = hashlib.sha256()
    for name, (mode, content) in sorted(files.items()):
        encoded = name.encode("utf-8")
        content_digest = hashlib.sha256(content).digest()
        package_digest.update(len(encoded).to_bytes(8, "big"))
        package_digest.update(encoded)
        package_digest.update(mode.to_bytes(4, "big"))
        package_digest.update(len(content).to_bytes(8, "big"))
        package_digest.update(content_digest)
        package_index[package_root + name] = content_digest.hex()
    return (
        _git_tree_digest(files),
        package_index,
        "sha256:" + package_digest.hexdigest(),
    )


def _git_tree_digest(files: dict[str, tuple[int, bytes]]) -> str:
    root: dict[str, Any] = {}
    for name, (mode, content) in files.items():
        node = root
        parts = PurePosixPath(name).parts
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            if not isinstance(child, dict):
                raise SupportedIngressLiveArchiveError(
                    "source archive path prefix changed type"
                )
            node = child
        if parts[-1] in node:
            raise SupportedIngressLiveArchiveError("source archive path is repeated")
        blob = hashlib.sha1(
            b"blob " + str(len(content)).encode() + b"\0" + content
        ).digest()
        node[parts[-1]] = (b"100755" if mode & 0o111 else b"100644", blob)

    def tree(node: dict[str, Any]) -> bytes:
        rows = []
        for name, value in node.items():
            encoded = name.encode("utf-8")
            if isinstance(value, dict):
                mode = b"40000"
                identity = tree(value)
                order = encoded + b"/"
            else:
                mode, identity = value
                order = encoded
            rows.append((order, mode, encoded, identity))
        payload = b"".join(
            mode + b" " + name + b"\0" + identity
            for _order, mode, name, identity in sorted(rows)
        )
        return hashlib.sha1(
            b"tree " + str(len(payload)).encode() + b"\0" + payload
        ).digest()

    return tree(root).hex()


def _verify_commit_signature(commit_raw: bytes, signing_key: bytes) -> None:
    if (
        _digest(signing_key)
        != "sha256:6f59baeb5dfc86fd26e9765735c2a32ddf6b14d6d825474152eb9c2afdb5b651"
    ):
        raise SupportedIngressLiveArchiveError("retained signing key identity changed")
    try:
        key_type, encoded, comment = signing_key.decode("ascii").strip().split()
        key_blob = base64.b64decode(encoded, validate=True)
    except (UnicodeDecodeError, ValueError) as exc:
        raise SupportedIngressLiveArchiveError(
            "retained signing key is malformed"
        ) from exc
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(key_blob).digest()
    ).decode("ascii").rstrip("=")
    if (
        key_type != "ssh-ed25519"
        or comment != "yousif.snazhat@gmail.com"
        or fingerprint != _SOURCE["signing_key_fingerprint"]
    ):
        raise SupportedIngressLiveArchiveError(
            "retained signing key fingerprint changed"
        )

    git = Path("/usr/bin/git")
    if not git.is_file():
        raise SupportedIngressLiveArchiveError(
            "system Git is required for SSH commit verification"
        )
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    try:
        with TemporaryDirectory(prefix="aragorn-ingress-signature-") as temporary:
            root = Path(temporary)
            repository = root / "objects.git"
            allowed_signers = root / "allowed_signers"
            allowed_signers.write_bytes(b"yousif.snazhat@gmail.com " + signing_key)
            initialized = subprocess.run(
                [git, "init", "--bare", "--quiet", repository],
                env=environment,
                capture_output=True,
                timeout=10,
                check=False,
            )
            hashed = subprocess.run(
                [
                    git,
                    f"--git-dir={repository}",
                    "hash-object",
                    "-t",
                    "commit",
                    "-w",
                    "--stdin",
                ],
                input=commit_raw,
                env=environment,
                capture_output=True,
                timeout=10,
                check=False,
            )
            verified = subprocess.run(
                [
                    git,
                    f"--git-dir={repository}",
                    "-c",
                    "gpg.format=ssh",
                    "-c",
                    f"gpg.ssh.allowedSignersFile={allowed_signers}",
                    "verify-commit",
                    _SOURCE["commit"],
                ],
                env=environment,
                capture_output=True,
                timeout=10,
                check=False,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SupportedIngressLiveArchiveError(
            f"cannot cryptographically verify signed commit: {exc}"
        ) from exc
    signature_output = verified.stdout + verified.stderr
    if (
        initialized.returncode
        or hashed.returncode
        or hashed.stdout != (_SOURCE["commit"] + "\n").encode()
        or verified.returncode
        or _SOURCE["signing_key_fingerprint"].encode() not in signature_output
        or b'Good "git" signature' not in signature_output
    ):
        raise SupportedIngressLiveArchiveError(
            "signed commit cryptographic verification failed"
        )


def _verify_runtime(
    archive: _Archive,
    *,
    source_index: dict[str, str],
    source_package_digest: str,
) -> dict[str, Any]:
    identity_raw = _file(archive, "runtime/protected-broker-release.json", 0o400)
    identity = _decode(identity_raw, "release identity", newline=False)
    if identity != _RELEASE_IDENTITY:
        raise SupportedIngressLiveArchiveError("release identity changed")

    pairs = (
        (
            "runtime/aragorn-protected-install.service",
            ("runtime/package/packaging/systemd/aragorn-protected-install.service"),
        ),
        (
            "runtime/aragorn-protected-install-coordinator.service",
            (
                "runtime/package/packaging/systemd/"
                "aragorn-protected-install-coordinator.service"
            ),
        ),
        (
            "runtime/aragorn-protected-install-coordinator.path",
            (
                "runtime/package/packaging/systemd/"
                "aragorn-protected-install-coordinator.path"
            ),
        ),
        (
            "runtime/aragorn-protected-install-coordinator.py",
            (
                "runtime/package/packaging/libexec/"
                "aragorn-protected-install-coordinator.py"
            ),
        ),
        (
            "runtime/aragorn-protected-install-launcher.py",
            ("runtime/package/packaging/libexec/aragorn-protected-install-launcher.py"),
        ),
        (
            "runtime/aragorn.sysusers",
            "runtime/package/packaging/systemd/aragorn-gateway.sysusers",
        ),
        (
            "runtime/aragorn.tmpfiles",
            "runtime/package/packaging/systemd/aragorn-gateway.tmpfiles",
        ),
        (
            "runtime/provisioning-script.sh",
            "procedure/aragorn-provision-ingress-v1.sh",
        ),
    )
    if any(_file(archive, left) != _file(archive, right) for left, right in pairs):
        raise SupportedIngressLiveArchiveError(
            "installed runtime bytes do not match the retained package"
        )

    package_index = _package_index(
        _file(archive, "runtime/package-files.sha256", 0o600)
    )
    if (
        package_index != source_index
        or source_package_digest != _RELEASE_IDENTITY["package"]["tree_digest"]
    ):
        raise SupportedIngressLiveArchiveError(
            "full signed source does not reproduce the live package identity"
        )

    broker_raw = _file(
        archive, "runtime/package/protected-install-broker-recursive-v3.py"
    )
    launcher_raw = _file(
        archive,
        "runtime/package/packaging/libexec/aragorn-protected-install-launcher.py",
    )
    coordinator_raw = _file(
        archive,
        "runtime/package/packaging/libexec/aragorn-protected-install-coordinator.py",
    )
    provisioning_raw = _file(archive, "runtime/provisioning-script.sh", 0o500)
    if (
        _digest(broker_raw) != _RELEASE_IDENTITY["broker"]["digest"]
        or _digest(launcher_raw) != _RELEASE_IDENTITY["launcher"]["digest"]
        or _digest(coordinator_raw)
        != "sha256:93d509eb96ef350b0011c4c9fcb5837bd42a5a0560e02fa047e32061a31f0c19"
        or _digest(provisioning_raw)
        != "sha256:ecf54f4545dfcea176702910de1d7756cb01904a4bb4fc809c5f7eef92f07712"
    ):
        raise SupportedIngressLiveArchiveError(
            "runtime implementation identity changed"
        )

    _verify_systemd(archive)
    return {
        "vm": "aragorn-phase1-ingress-v3-20260729a",
        "release_identity_digest": _digest(identity_raw),
        "package_tree_digest": _RELEASE_IDENTITY["package"]["tree_digest"],
        "provisioning_script_digest": _digest(provisioning_raw),
        "production_path_active": True,
        "evidence_path_inactive": True,
        "host_share_mounts": 0,
    }


def _verify_systemd(archive: _Archive) -> None:
    expected_controls = {
        "/etc/aragorn/protected-broker-release.json root:root 400 668",
        "/etc/systemd/system/aragorn-protected-install.service root:root 644 2021",
        (
            "/etc/systemd/system/aragorn-protected-install-coordinator.service "
            "root:root 644 1717"
        ),
        (
            "/etc/systemd/system/aragorn-protected-install-coordinator.path "
            "root:root 644 305"
        ),
        "/etc/sysusers.d/aragorn.conf root:root 644 179",
        "/etc/tmpfiles.d/aragorn.conf root:root 644 496",
        (
            "/usr/libexec/aragorn/aragorn-protected-install-coordinator.py "
            "root:root 555 4241"
        ),
        (
            "/usr/libexec/aragorn/aragorn-protected-install-launcher.py "
            "root:root 555 17316"
        ),
        ("/var/lib/aragorn-provision-c87b82b9b7a4.sh root:root 500 15023"),
        "/run/aragorn-protected-install root:root 700 40",
        "/var/lib/aragorn-quarantine root:root 700 4096",
        "/var/lib/aragorn-protected root:aragorn-runtime 750 4096",
        "/var/lib/aragorn-protected/skills root:aragorn-runtime 750 4096",
    }
    controls = set(_text(archive, "runtime/control-stat.txt", 0o600).splitlines())
    mounts = _text(archive, "runtime/mounts.txt", 0o600)
    if (
        controls != expected_controls
        or _text(archive, "runtime/final-production-path-state.txt", 0o600)
        != "active\n"
        or _text(archive, "runtime/final-evidence-path-state.txt", 0o600)
        != "inactive\n"
        or _text(archive, "runtime/final-run-state.txt", 0o600)
        != "submission.lock f 0:0 600 0\n"
        or _text(archive, "runtime/runtime-group.txt", 0o600)
        != "aragorn-runtime:x:982:\n"
        or any(marker in mounts for marker in ("virtiofs", "9p", "/Users/yousi"))
    ):
        raise SupportedIngressLiveArchiveError("runtime ownership or isolation changed")

    cat_pairs = (
        (
            "runtime/path-cat.txt",
            "/etc/systemd/system/aragorn-protected-install-coordinator.path",
            "runtime/aragorn-protected-install-coordinator.path",
        ),
        (
            "runtime/service-cat.txt",
            "/etc/systemd/system/aragorn-protected-install-coordinator.service",
            "runtime/aragorn-protected-install-coordinator.service",
        ),
        (
            "runtime/install-service-cat.txt",
            "/etc/systemd/system/aragorn-protected-install.service",
            "runtime/aragorn-protected-install.service",
        ),
    )
    if any(
        _file(archive, captured, 0o600)
        != f"# {installed}\n".encode() + _file(archive, retained, 0o644)
        for captured, installed, retained in cat_pairs
    ):
        raise SupportedIngressLiveArchiveError("effective systemd unit bytes changed")

    path_show = _text(archive, "runtime/path-show.txt", 0o600)
    service_show = _text(archive, "runtime/service-show.txt", 0o600)
    required_path = {
        "ActiveState=active",
        "SubState=waiting",
        ("FragmentPath=/etc/systemd/system/aragorn-protected-install-coordinator.path"),
        "UnitFileState=enabled",
        ("Paths=/run/aragorn-protected-install/intent.json (PathChanged)"),
    }
    required_service = {
        (
            "FragmentPath=/etc/systemd/system/"
            "aragorn-protected-install-coordinator.service"
        ),
        "RefuseManualStart=yes",
        "NoNewPrivileges=yes",
        "User=root",
        "Group=root",
    }
    if (
        not required_path.issubset(path_show.splitlines())
        or not required_service.issubset(service_show.splitlines())
        or any(
            marker in path_show + service_show
            for marker in ("DropInPaths=", "ExecStartPre=", "ExecStartPost=")
        )
    ):
        raise SupportedIngressLiveArchiveError(
            "effective systemd command surface changed"
        )


def _verify_case(
    archive: _Archive,
    name: str,
    expected: dict[str, Any],
) -> _Case:
    root = f"cases/{name}"
    is_error = expected["status"] == "ERROR"
    if (
        _text(archive, f"{root}/status.txt", 0o600) != f"{expected['exit']}\n"
        or _file(archive, f"{root}/stderr.txt", 0o600)
        or _text(archive, f"{root}/run-state.txt", 0o600)
        != "submission.lock f 0:0 600 0\n"
        or _text(archive, f"{root}/path-show.txt", 0o600)
        != "ActiveState=active\nSubState=waiting\nResult=success\n"
    ):
        raise SupportedIngressLiveArchiveError(
            f"{name} command status or ingress cleanup changed"
        )

    result_raw = _file(archive, f"{root}/stdout.json", 0o600)
    result = _decode(result_raw, f"{name} coordinator result", newline=True)
    if (
        result.get("schema") != "aragorn/protected-install-coordinator-result/v1"
        or result.get("assurance")
        != "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        or result.get("status") != expected["status"]
        or result.get("installer_work_eligible") is not False
        or result.get("runtime_conformance_qualified") is not False
    ):
        raise SupportedIngressLiveArchiveError(f"{name} coordinator result changed")

    observed_root = f"{root}/observed"
    observed_names = sorted(
        path for path in archive.files if path.startswith(observed_root + "/")
    )
    if (
        len(observed_names) != 2
        or not observed_names[0].endswith("/00-intent.json")
        or "/01-submission-result-" not in observed_names[1]
    ):
        raise SupportedIngressLiveArchiveError(
            f"{name} observed submission inventory changed"
        )
    submission_raw = _file(archive, observed_names[0], 0o400)
    wrapper_raw = _file(archive, observed_names[1], 0o400)
    submission = _decode(submission_raw, f"{name} submission", newline=False)
    wrapper = _decode(wrapper_raw, f"{name} result wrapper", newline=False)
    owner, repository, commit, skill_path = expected["request"]
    intent = {
        "schema": "aragorn/protected-install-intent/v1",
        "operation": expected["operation"],
        "owner": owner,
        "repository": repository,
        "commit": commit,
        "skill_path": skill_path,
    }
    submission_id = submission.get("submission_id")
    if (
        set(submission) != {"schema", "submission_id", "intent"}
        or submission.get("schema") != "aragorn/protected-install-submission/v1"
        or not isinstance(submission_id, str)
        or not _HEX_64.fullmatch(submission_id)
        or submission.get("intent") != intent
    ):
        raise SupportedIngressLiveArchiveError(f"{name} submission changed")

    submission_digest = _digest(submission_raw)
    intent_digest = canonical_digest(intent)
    if (
        set(wrapper)
        != {
            "schema",
            "submission_id",
            "submission_digest",
            "intent_digest",
            "coordinator_result",
        }
        or wrapper.get("schema") != "aragorn/protected-install-submission-result/v1"
        or wrapper.get("submission_id") != submission_id
        or wrapper.get("submission_digest") != submission_digest
        or wrapper.get("intent_digest") != intent_digest
        or wrapper.get("coordinator_result") != result
        or not observed_names[1].endswith(f"/01-submission-result-{submission_id}.json")
    ):
        raise SupportedIngressLiveArchiveError(
            f"{name} submission/result correlation changed"
        )

    observed = _json(archive, f"{root}/observed.json", newline=True)
    records = {}
    for record_name, raw in (
        ("intent.json", submission_raw),
        (f"submission-result-{submission_id}.json", wrapper_raw),
    ):
        digest = _digest(raw)
        records[f"{record_name}.{digest[7:]}"] = {
            "name": record_name,
            "mode": 0o400,
            "size": len(raw),
            "digest": digest,
        }
    if observed != {
        "schema": "aragorn/production-ingress-observation/v1",
        "files": records,
    }:
        raise SupportedIngressLiveArchiveError(f"{name} observed manifest changed")

    request = {
        "schema": "aragorn/github-gateway-request/v1",
        "owner": owner,
        "repository": repository,
        "commit": commit,
        "skill_path": skill_path,
    }
    if not is_error and (
        result.get("source_request") != request
        or result.get("operation") != expected["operation"]
    ):
        raise SupportedIngressLiveArchiveError(f"{name} result source binding changed")

    broker_raw = _file(archive, f"{root}/broker-output.json", 0o600)
    broker = _decode(broker_raw, f"{name} broker output", newline=True)
    expected_slice = "ERROR" if is_error else "PASS"
    expected_verdict = "ERROR" if is_error else "ALLOW"
    authority = broker.get("request_authority", {})
    credential = authority.get("credential", {})
    if (
        broker.get("schema")
        != "aragorn/openclaw-github-protected-install-broker-evidence/v1"
        or broker.get("slice_status") != expected_slice
        or broker.get("decision", {}).get("verdict") != expected_verdict
        or broker.get("source", {}).get("request") != request
        or broker.get("producer_implementation_digest")
        != _RELEASE_IDENTITY["broker"]["digest"]
        or authority.get("authority") != "PROTECTED_CANONICAL_REQUEST_CREDENTIAL"
        or authority.get("request_schema")
        != "aragorn/protected-install-broker-request/v4"
        or credential.get("uid") != 0
        or credential.get("gid") != 0
        or credential.get("mode") != 0o400
        or credential.get("path")
        != "/run/credentials/aragorn-protected-install.service/install-request"
    ):
        raise SupportedIngressLiveArchiveError(f"{name} broker evidence changed")

    _verify_case_journals(archive, name, result, broker, is_error=is_error)
    manifest = None
    blobs = None
    if "coverage" in expected:
        manifest, blobs = _verify_quarantine_case(
            archive,
            name,
            request,
            broker,
            expected["coverage"],
        )

    if is_error:
        unresolved = broker.get("source", {}).get("closure", {}).get("unresolved", [])
        if (
            broker.get("analyzer") != {"run_receipt_digests": []}
            or broker.get("transaction") is not None
            or broker.get("active") is not None
            or (
                name == "release-error"
                and not any(
                    isinstance(value, str)
                    and value.startswith(
                        "GITHUB_RELEASE_ASSET_RUNTIME_CONSUMER_UNPROVEN:"
                    )
                    for value in unresolved
                )
            )
        ):
            raise SupportedIngressLiveArchiveError(
                f"{name} did not retain its fail-closed result"
            )
    else:
        transaction = broker.get("transaction", {})
        active = broker.get("active", {})
        source = broker.get("source", {})
        decision_summary = broker.get("decision", {})
        expected_run_receipt = _CURRENT_ANALYZER_RUN_RECEIPTS.get(name)
        if (
            transaction.get("schema") != "aragorn/protected-install-transaction/v1"
            or transaction.get("operation") != expected["operation"]
            or transaction.get("context_id") != result.get("context_id")
            or transaction.get("manifest_digest") != result.get("manifest_digest")
            or transaction.get("tree_digest")
            != broker.get("source", {}).get("tree_digest")
            or transaction.get("version_path") != active.get("link_target")
            or active.get("tree_digest") != transaction.get("tree_digest")
            or authority.get("request_digest") != result.get("service_request_digest")
            or expected_run_receipt is None
            or broker.get("analyzer")
            != {
                **_CURRENT_ANALYZER,
                "run_receipt_digest": expected_run_receipt,
            }
            or source.get("artifact_graph_verifier_implementation_digest")
            != _CURRENT_ARTIFACT_GRAPH_VERIFIER_DIGEST
            or source.get("artifact_graph_profile") != "recursive-github-markdown/v1"
            or source.get("gateway") != _CURRENT_GATEWAY_IDENTITY
            or set(decision_summary)
            != {"digest", "verdict", "policy_digest", "installer_work_eligible"}
            or decision_summary.get("policy_digest") != _CURRENT_POLICY_DIGEST
            or decision_summary.get("installer_work_eligible") is not False
        ):
            raise SupportedIngressLiveArchiveError(
                f"{name} protected transaction binding changed"
            )

    return _Case(
        {
            "cli_exit": expected["exit"],
            "status": expected["status"],
            "source_request": request,
            "submission_id": submission_id,
            "submission_digest": submission_digest,
            "intent_digest": intent_digest,
            "result_wrapper_digest": _digest(wrapper_raw),
            "coordinator_result_digest": _digest(result_raw),
            "broker_evidence_digest": _digest(broker_raw),
            "production_unit_journal_bound": True,
            "submission_namespace_cleaned": True,
        },
        result,
        broker,
        submission,
        manifest,
        blobs,
    )


def _verify_quarantine_case(
    archive: _Archive,
    name: str,
    request: dict[str, Any],
    broker: dict[str, Any],
    expected_coverage: tuple[int, int, int],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    root = f"cases/{name}"
    before = _hex_lines(archive, f"{root}/quarantine-before.txt")
    after = _hex_lines(archive, f"{root}/quarantine-after.txt")
    namespace = _text(
        archive,
        f"{root}/quarantine-namespace.txt",
        0o600,
    ).removesuffix("\n")
    if (
        namespace != canonical_digest(request)[7:]
        or after != sorted([*before, namespace])
        or len(after) != len(before) + 1
    ):
        raise SupportedIngressLiveArchiveError(
            f"{name} quarantine namespace transition changed"
        )

    cas_root = f"{root}/quarantine"
    prefix = f"{cas_root}/blobs/sha256/"
    blobs: dict[str, bytes] = {}
    for path, item in archive.files.items():
        if not path.startswith(cas_root + "/"):
            continue
        relative = path.removeprefix(prefix)
        parts = relative.split("/")
        if (
            not path.startswith(prefix)
            or len(parts) != 2
            or len(parts[0]) != 2
            or len(parts[1]) != 62
            or not _HEX_64.fullmatch(parts[0] + parts[1])
            or item.mode != 0o444
        ):
            raise SupportedIngressLiveArchiveError(
                f"{name} quarantine CAS path or mode changed"
            )
        digest = "sha256:" + parts[0] + parts[1]
        if digest in blobs or _digest(item.raw) != digest:
            raise SupportedIngressLiveArchiveError(
                f"{name} quarantine CAS blob identity changed"
            )
        blobs[digest] = item.raw

    expected_directories = {
        cas_root,
        f"{cas_root}/blobs",
        f"{cas_root}/blobs/sha256",
        *(f"{cas_root}/blobs/sha256/{digest[7:9]}" for digest in blobs),
    }
    actual_directories = {
        path
        for path in archive.directories
        if path == cas_root or path.startswith(cas_root + "/")
    }
    if (
        not blobs
        or actual_directories != expected_directories
        or any(archive.directories[path] != 0o700 for path in actual_directories)
        or any(
            path == cas_root or path.startswith(cas_root + "/")
            for path in archive.symlinks
        )
    ):
        raise SupportedIngressLiveArchiveError(
            f"{name} quarantine CAS inventory changed"
        )

    source = broker.get("source", {})
    recursive = source.get("recursive", {})
    root_manifest = _cas_document(
        blobs,
        recursive.get("root_manifest_digest"),
        "aragorn/github-manifest/v1",
        f"{name} GitHub root manifest",
    )
    manifest, files = _verify_retained_manifests(
        blobs,
        root_manifest,
        source.get("manifest_digest"),
        request,
        name,
    )
    graph = _cas_document(
        blobs,
        source.get("artifact_graph_digest"),
        "aragorn/admission-artifact-graph/v3",
        f"{name} artifact graph",
    )
    captured, total, unresolved = expected_coverage
    expected_graph_keys = {
        "schema",
        "authority",
        "verifier",
        "profile",
        "root_manifest_digest",
        "root_github_manifest_digest",
        "source_proof_digest",
        "quarantine_receipt_digest",
        "gateway_profile_digest",
        "expansion_digest",
        "expansion_proof_digest",
        "tree_digest",
        "artifacts",
        "edges",
        "coverage",
        "closure",
    }
    if (
        set(graph) != expected_graph_keys
        or graph["authority"] != "CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
        or source.get("artifact_graph_verifier_implementation_digest")
        != _CURRENT_ARTIFACT_GRAPH_VERIFIER_DIGEST
        or source.get("gateway") != _CURRENT_GATEWAY_IDENTITY
        or graph["verifier"]
        != {
            "name": "aragorn/admission-artifact-graph-verifier",
            "version": "3",
            "implementation_digest": _CURRENT_ARTIFACT_GRAPH_VERIFIER_DIGEST,
        }
        or graph["profile"] != source.get("artifact_graph_profile")
        or graph["root_manifest_digest"] != source.get("manifest_digest")
        or graph["root_github_manifest_digest"] != recursive.get("root_manifest_digest")
        or graph["source_proof_digest"] != source.get("source_proof_digest")
        or graph["quarantine_receipt_digest"] != source.get("quarantine_receipt_digest")
        or graph["gateway_profile_digest"] != source.get("gateway_profile_digest")
        or graph["expansion_digest"] != recursive.get("expansion_digest")
        or graph["expansion_proof_digest"] != recursive.get("expansion_proof_digest")
        or graph["tree_digest"] != source.get("tree_digest")
        or graph["artifacts"] != files
        or graph["coverage"]
        != {
            "statically_resolvable": {"captured": captured, "total": total},
            "unresolved_required": unresolved,
        }
        or sum(edge.get("status") == "resolved" for edge in graph["edges"]) != captured
        or graph["closure"] != source.get("closure")
        or len(graph["closure"].get("unresolved", [])) != unresolved
        or source.get("artifact_count") != len(files)
    ):
        raise SupportedIngressLiveArchiveError(
            f"{name} artifact graph or coverage changed"
        )

    decision = _cas_document(
        blobs,
        broker.get("decision", {}).get("digest"),
        "aragorn/decision/v3",
        f"{name} decision",
    )
    if (
        decision.get("authority") != "EVIDENCE_SUMMARY_ONLY_NOT_INSTALLER_AUTHORITY"
        or decision.get("artifact_graph_digest") != source.get("artifact_graph_digest")
        or decision.get("manifest_digest") != source.get("manifest_digest")
        or decision.get("tree_digest") != source.get("tree_digest")
        or decision.get("artifact_digests")
        != sorted(entry["digest"] for entry in files)
        or decision.get("policy", {}).get("digest") != _CURRENT_POLICY_DIGEST
        or broker.get("decision", {}).get("policy_digest") != _CURRENT_POLICY_DIGEST
        or decision.get("verdict") != broker.get("decision", {}).get("verdict")
        or (
            unresolved
            and (
                "ARTIFACT_CLOSURE_INCOMPLETE" not in decision.get("reason_codes", [])
                or decision.get("analyzers") != []
                or broker.get("error", {}).get("type") != "INCOMPLETE_ARTIFACT_GRAPH"
                or broker.get("transition")
                != {
                    "operation": "install",
                    "expected_active": None,
                    "manifest_diff": None,
                }
            )
        )
    ):
        raise SupportedIngressLiveArchiveError(f"{name} decision binding changed")
    if not unresolved:
        _verify_current_allow_chain(blobs, broker, graph, decision, name)

    expansion = _cas_document(
        blobs,
        recursive.get("expansion_digest"),
        "aragorn/github-expansion/v1",
        f"{name} recursive expansion",
    )
    manifest_source = root_manifest["source"]
    expansion_source = {
        key: manifest_source[key]
        for key in (
            "host",
            "owner",
            "repository",
            "commit",
            "commit_tree",
            "skill_path",
            "api_version",
        )
    }
    references = expansion.get("references")
    accounting = expansion.get("accounting", {}).get("references")
    comparator = {
        "schema": "aragorn/benchmark-subject-manifest/v1",
        "tree_digest": source.get("tree_digest"),
        "files": files,
    }
    expected_comparator_manifest = None if captured else canonical_digest(comparator)
    expected_comparator_tree = None if captured else source.get("tree_digest")
    expected_reference_counts = (
        {"resolved_in_root": 13, "total_edges": 22, "unresolved": 9}
        if captured
        else {"resolved_in_root": 0, "total_edges": 0, "unresolved": 0}
    )
    if (
        expansion.get("source") != expansion_source
        or expansion.get("root_manifest_digest")
        != recursive.get("root_manifest_digest")
        or expansion.get("root_tree_digest") != source.get("tree_digest")
        or expansion.get("objects") != []
        or expansion.get("comparator_subject_manifest_digest")
        != expected_comparator_manifest
        or expansion.get("comparator_subject_tree_digest") != expected_comparator_tree
        or not isinstance(references, list)
        or len(references) != expected_reference_counts["total_edges"]
        or not isinstance(accounting, dict)
        or any(
            accounting.get(key) != value
            for key, value in expected_reference_counts.items()
        )
        or sum(item.get("status") == "root_resolved" for item in references)
        != expected_reference_counts["resolved_in_root"]
        or sum(item.get("status") == "unresolved" for item in references)
        != expected_reference_counts["unresolved"]
        or any(
            item.get("source_blob_digest") not in blobs
            or item.get("source_commit") != request["commit"]
            for item in references
        )
    ):
        raise SupportedIngressLiveArchiveError(
            f"{name} recursive expansion accounting changed"
        )

    receipt = _cas_document(
        blobs,
        source.get("quarantine_receipt_digest"),
        "aragorn/github-quarantine-receipt/v1",
        f"{name} quarantine receipt",
    )
    if (
        receipt.get("request") != request
        or receipt.get("request_digest") != canonical_digest(request)
        or receipt.get("manifest_digest") != recursive.get("root_manifest_digest")
        or receipt.get("tree_digest") != source.get("tree_digest")
        or receipt.get("file_count") != len(files)
        or receipt.get("source_proof_digest") != source.get("source_proof_digest")
        or receipt.get("source_closure_digest") != source.get("source_closure_digest")
        or receipt.get("gateway") != source.get("gateway")
        or receipt.get("gateway_profile_digest") != source.get("gateway_profile_digest")
        or receipt.get("containment_profile") != source.get("containment_profile")
        or receipt.get("protected_cas", {}).get("owner_uid") != 0
        or receipt.get("protected_cas", {}).get("mode") != 0o700
    ):
        raise SupportedIngressLiveArchiveError(
            f"{name} quarantine receipt binding changed"
        )
    _verify_source_closure(
        blobs,
        receipt["manifest_digest"],
        receipt["source_proof_digest"],
        receipt["handoff_manifest_digest"],
        receipt["source_closure_digest"],
        name,
    )
    _verify_current_decision_chain(
        blobs,
        broker,
        decision,
        receipt,
        root_manifest,
        request,
        name,
    )
    return manifest, blobs


def _verify_retained_manifests(
    blobs: dict[str, bytes],
    root_manifest: dict[str, Any],
    manifest_digest: object,
    request: dict[str, Any],
    name: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = root_manifest.get("source", {})
    expected_source = {
        "kind": "github_commit",
        "host": "github.com",
        "owner": request["owner"],
        "repository": request["repository"],
        "commit": request["commit"],
        "repository_hash_algorithm": "sha1",
        "commit_tree": source.get("commit_tree"),
        "skill_path": request["skill_path"],
        "skill_tree": source.get("skill_tree"),
        "api_version": "2026-03-10",
    }
    entries = root_manifest.get("files")
    if (
        set(root_manifest) != {"schema", "source", "tree_digest", "files", "closure"}
        or source != expected_source
        or not _HEX_40.fullmatch(str(source.get("commit_tree", "")))
        or not _HEX_40.fullmatch(str(source.get("skill_tree", "")))
        or root_manifest.get("closure")
        != {"scope": "source_tree", "status": "complete"}
        or not isinstance(entries, list)
        or not entries
        or len(entries) > 256
    ):
        raise SupportedIngressLiveArchiveError(f"{name} GitHub root manifest changed")

    files: list[dict[str, Any]] = []
    previous = ""
    casefolded: set[str] = set()
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else None
        digest = entry.get("digest") if isinstance(entry, dict) else None
        size = entry.get("size") if isinstance(entry, dict) else None
        executable = entry.get("executable") if isinstance(entry, dict) else None
        git_blob = entry.get("git_blob_sha1") if isinstance(entry, dict) else None
        parsed = PurePosixPath(path) if isinstance(path, str) else None
        content = blobs.get(digest) if isinstance(digest, str) else None
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "size", "digest", "executable", "git_blob_sha1"}
            or parsed is None
            or parsed.is_absolute()
            or parsed.as_posix() != path
            or any(part in {"", ".", ".."} for part in parsed.parts)
            or path <= previous
            or path.casefold() in casefolded
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(executable, bool)
            or not isinstance(digest, str)
            or not _HEX_64.fullmatch(digest.removeprefix("sha256:"))
            or not isinstance(git_blob, str)
            or not _HEX_40.fullmatch(git_blob)
            or content is None
            or len(content) != size
            or hashlib.sha1(b"blob " + str(size).encode() + b"\0" + content).hexdigest()
            != git_blob
        ):
            raise SupportedIngressLiveArchiveError(
                f"{name} GitHub manifest file changed"
            )
        previous = path
        casefolded.add(path.casefold())
        files.append(
            {
                "path": path,
                "size": size,
                "digest": digest,
                "executable": executable,
            }
        )

    tree_digest = canonical_digest(files)
    manifest = _cas_document(
        blobs,
        manifest_digest,
        "aragorn/manifest/v1",
        f"{name} install manifest",
    )
    if root_manifest.get("tree_digest") != tree_digest or manifest != {
        "schema": "aragorn/manifest/v1",
        "source": {
            "kind": "local",
            "path": (
                f"/aragorn/github/{request['owner']}/{request['repository']}/"
                f"{request['commit']}/{request['skill_path']}"
            ),
        },
        "tree_digest": tree_digest,
        "files": files,
        "closure": {"scope": "source_tree", "status": "complete"},
    }:
        raise SupportedIngressLiveArchiveError(
            f"{name} retained install manifest changed"
        )
    return manifest, files


def _verify_source_closure(
    blobs: dict[str, bytes],
    manifest_digest: str,
    source_proof_digest: str,
    handoff_manifest_digest: str,
    expected_closure_digest: str,
    name: str,
) -> None:
    try:
        with TemporaryDirectory(prefix="aragorn-source-closure-") as temporary:
            root = Path(temporary) / "cas"
            writable = CAS(root)
            for digest, raw in blobs.items():
                writable.put_expected(
                    BytesIO(raw),
                    expected_digest=digest,
                    max_bytes=len(raw),
                )
            derived = github_source_closure_digest(
                CAS(root, read_only=True),
                manifest_digest=manifest_digest,
                source_proof_digest=source_proof_digest,
                handoff_manifest_digest=handoff_manifest_digest,
            )
    except (
        ArtifactClosureError,
        CASError,
        GitHubQuarantineReceiptError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise SupportedIngressLiveArchiveError(
            f"{name} source closure changed: {exc}"
        ) from exc
    if derived != expected_closure_digest:
        raise SupportedIngressLiveArchiveError(f"{name} source closure digest changed")


def _verify_current_decision_chain(
    blobs: dict[str, bytes],
    broker: dict[str, Any],
    decision: dict[str, Any],
    receipt: dict[str, Any],
    root_manifest: dict[str, Any],
    request: dict[str, Any],
    name: str,
) -> None:
    source = broker["source"]
    recursive = source["recursive"]
    run_receipt = _CURRENT_ANALYZER_RUN_RECEIPTS.get(name)
    run_receipts = [] if run_receipt is None else [run_receipt]
    try:
        with TemporaryDirectory(prefix="aragorn-decision-replay-") as temporary:
            root = Path(temporary) / "cas"
            writable = CAS(root)
            for digest, raw in blobs.items():
                writable.put_expected(
                    BytesIO(raw),
                    expected_digest=digest,
                    max_bytes=len(raw),
                )
            cas = writable
            github_gateway_live_evidence._verify_receipt(
                cas,
                receipt,
                request=request,
                manifest=root_manifest,
                manifest_digest=recursive["root_manifest_digest"],
                receipt_digest=source["quarantine_receipt_digest"],
                profile_digest=source["gateway_profile_digest"],
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
                    or expected_gateway_profile_digest
                    != source["gateway_profile_digest"]
                ):
                    raise SupportedIngressLiveArchiveError(
                        f"{name} historical receipt replay binding changed"
                    )
                return receipt

            with patch.object(
                github_recursive_artifact_graph,
                "verify_github_quarantine_receipt",
                side_effect=offline_receipt,
            ):
                replayed = decision_receipt.verify_decision_v3(
                    cas,
                    broker["decision"]["digest"],
                    expected_manifest_digest=source["manifest_digest"],
                    expected_artifact_graph_digest=source["artifact_graph_digest"],
                    expected_policy_digest=_CURRENT_POLICY_DIGEST,
                    expected_analyzer_run_receipt_digests=run_receipts,
                    expected_analyzer_verifier_digest=_CURRENT_ANALYZER[
                        "verifier_implementation_digest"
                    ],
                    expected_artifact_graph_verifier_digest=(
                        _CURRENT_ARTIFACT_GRAPH_VERIFIER_DIGEST
                    ),
                    expected_quarantine_receipt_digest=source[
                        "quarantine_receipt_digest"
                    ],
                    expected_gateway_profile_digest=source["gateway_profile_digest"],
                )
    except (CASError, OSError, TypeError, ValueError) as exc:
        raise SupportedIngressLiveArchiveError(
            f"{name} graph and decision replay changed: {exc}"
        ) from exc
    if replayed != decision:
        raise SupportedIngressLiveArchiveError(
            f"{name} graph and decision replay changed"
        )


def _verify_current_allow_chain(
    blobs: dict[str, bytes],
    broker: dict[str, Any],
    graph: dict[str, Any],
    decision: dict[str, Any],
    name: str,
) -> None:
    expected_run_receipt = _CURRENT_ANALYZER_RUN_RECEIPTS.get(name)
    expected_analyzer = {
        **_CURRENT_ANALYZER,
        "run_receipt_digest": expected_run_receipt,
    }
    if expected_run_receipt is None or broker.get("analyzer") != expected_analyzer:
        raise SupportedIngressLiveArchiveError(
            f"{name} analyzer selection or execution identity changed"
        )

    try:
        with TemporaryDirectory(prefix="aragorn-analyzer-replay-") as temporary:
            root = Path(temporary) / "cas"
            writable = CAS(root)
            for digest, raw in blobs.items():
                writable.put_expected(
                    BytesIO(raw),
                    expected_digest=digest,
                    max_bytes=len(raw),
                )
            replayed, _closure, result, analyzer_request = _replay_decision(
                CAS(root, read_only=True),
                broker["decision"]["digest"],
                graph,
                _CURRENT_POLICY_DIGEST,
                expected_run_receipt,
                _CURRENT_ANALYZER["verifier_implementation_digest"],
            )
    except (
        CASError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise SupportedIngressLiveArchiveError(
            f"{name} analyzer and decision replay changed: {exc}"
        ) from exc

    expected_request_analyzer = {
        "name": _CURRENT_ANALYZER["name"],
        "version": _CURRENT_ANALYZER["version"],
        "config_digest": _CURRENT_ANALYZER["configuration_digest"],
        "executable_digest": _CURRENT_ANALYZER["executable_digest"],
    }
    configuration = _decode(
        result.raw_configuration,
        f"{name} analyzer configuration",
        newline=False,
    )
    argv = configuration.get("argv")
    implementation_binding = (
        f"expected='{_CURRENT_ANALYZER['implementation_digest']}'\n"
    )
    if (
        replayed != decision
        or decision.get("verdict") != "ALLOW"
        or not result.ok
        or result.name != _CURRENT_ANALYZER["name"]
        or result.version != _CURRENT_ANALYZER["version"]
        or result.config_digest != _CURRENT_ANALYZER["configuration_digest"]
        or result.executable_digest != _CURRENT_ANALYZER["executable_digest"]
        or result.observations
        or result.raw_stdout != b""
        or result.raw_stderr != b""
        or analyzer_request.get("analyzer") != expected_request_analyzer
        or analyzer_request.get("subject_digest") != graph.get("tree_digest")
        or set(configuration)
        != {
            "argv",
            "executable_digest",
            "name",
            "operator_argv0",
            "version",
        }
        or configuration.get("name") != _CURRENT_ANALYZER["name"]
        or configuration.get("version") != _CURRENT_ANALYZER["version"]
        or configuration.get("executable_digest")
        != _CURRENT_ANALYZER["executable_digest"]
        or configuration.get("operator_argv0") != _RELEASE_IDENTITY["python"]["path"]
        or not isinstance(argv, list)
        or len(argv) != 4
        or argv[:3] != [_RELEASE_IDENTITY["python"]["path"], "-B", "-c"]
        or not isinstance(argv[3], str)
        or implementation_binding not in argv[3]
    ):
        raise SupportedIngressLiveArchiveError(
            f"{name} analyzer and decision replay binding changed"
        )


def _cas_document(
    blobs: dict[str, bytes],
    digest: object,
    schema: str,
    label: str,
) -> dict[str, Any]:
    if (
        not isinstance(digest, str)
        or not _HEX_64.fullmatch(digest.removeprefix("sha256:"))
        or digest not in blobs
    ):
        raise SupportedIngressLiveArchiveError(f"{label} is absent from the CAS")
    document = _decode(blobs[digest], label, newline=False)
    if document.get("schema") != schema or canonical_digest(document) != digest:
        raise SupportedIngressLiveArchiveError(f"{label} identity changed")
    return document


def _hex_lines(archive: _Archive, path: str) -> list[str]:
    raw = _file(archive, path, 0o600)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SupportedIngressLiveArchiveError(
            f"archive digest list is not ASCII: {path}"
        ) from exc
    values = text.splitlines()
    if (
        not raw.endswith(b"\n")
        or not values
        or values != sorted(set(values))
        or any(not _HEX_64.fullmatch(value) for value in values)
    ):
        raise SupportedIngressLiveArchiveError(f"archive digest list changed: {path}")
    return values


def _verify_case_journals(
    archive: _Archive,
    name: str,
    result: dict[str, Any],
    broker: dict[str, Any],
    *,
    is_error: bool,
) -> None:
    root = f"cases/{name}"
    coordinator_rows = _json_lines(
        _file(archive, f"{root}/coordinator-journal.jsonl", 0o600),
        f"{name} coordinator journal",
    )
    messages = [
        row
        for row in coordinator_rows
        if row.get("_SYSTEMD_UNIT") == "aragorn-protected-install-coordinator.service"
        and row.get("_UID") == "0"
        and row.get("_GID") == "0"
        and row.get("SYSLOG_IDENTIFIER") == "aragorn-protected-install-coordinator"
        and row.get("MESSAGE") == canonical_json(result).decode()
    ]
    show = _key_values(_text(archive, f"{root}/coordinator-show.txt", 0o600))
    expected_show = (
        {
            "ActiveState": "failed",
            "SubState": "failed",
            "Result": "exit-code",
            "ExecMainStatus": "4",
        }
        if is_error
        else {
            "ActiveState": "inactive",
            "SubState": "dead",
            "Result": "success",
            "ExecMainStatus": "0",
        }
    )
    if len(messages) != 1 or show != {
        **expected_show,
        "InvocationID": messages[0].get("_SYSTEMD_INVOCATION_ID"),
    }:
        raise SupportedIngressLiveArchiveError(
            f"{name} production coordinator journal binding changed"
        )

    invocation = _text(
        archive, f"{root}/install-invocation-id.txt", 0o600
    ).removesuffix("\n")
    install_rows = _json_lines(
        _file(archive, f"{root}/install-journal.jsonl", 0o600),
        f"{name} install journal",
    )
    bound = [
        row
        for row in install_rows
        if row.get("_SYSTEMD_UNIT") == "aragorn-protected-install.service"
        and row.get("_SYSTEMD_INVOCATION_ID") == invocation
        and row.get("_UID") == "0"
        and row.get("_GID") == "0"
        and row.get("SYSLOG_IDENTIFIER") == "aragorn-protected-install"
    ]
    full_rows = _json_lines(
        _file(archive, f"{root}/install-journal-full.jsonl", 0o600),
        f"{name} full install journal",
    )
    broker_bound = [
        row
        for row in full_rows
        if row.get("_SYSTEMD_UNIT") == "aragorn-protected-install.service"
        and row.get("_SYSTEMD_INVOCATION_ID") == invocation
        and row.get("_UID") == "0"
        and row.get("_GID") == "0"
        and row.get("SYSLOG_IDENTIFIER") == "aragorn-protected-install"
        and row.get("MESSAGE") == canonical_json(broker).decode()
    ]
    if (
        not _HEX_32.fullmatch(invocation)
        or len(bound) != 1
        or len(full_rows) != 1
        or len(broker_bound) != 1
    ):
        raise SupportedIngressLiveArchiveError(
            f"{name} protected-install invocation binding changed"
        )


def _verify_current_numerical_merge(archive: _Archive) -> None:
    script_digest = (
        "sha256:2a1169d1d57f0498f95c138e4ea9dbde862d01ef60ca20dc2e2b3b347076a68e"
    )
    transfer_digest = (
        "sha256:8658fe46a22b96eb0f7d987f49eeb117c45f687551902060758c5ab855c4cae2"
    )
    inventory = {
        "digest": (
            "sha256:77d99da51a9be00838bf52f0a900c6387658f53540df527f7d5df58be744d589"
        ),
        "directories": 110,
        "members": 267,
        "payload_bytes": 15_323_428,
        "regular_files": 155,
        "symlinks": 2,
    }
    merge_map = {
        "schema": "aragorn/supported-ingress-evidence-merge-map/v2",
        "source_root": "/var/lib/aragorn-supported-ingress-lineage-v2",
        "source_archive_root": "aragorn-supported-ingress-lineage-v2",
        "destination_root": _ROOT,
        "executed_script": {
            "path": "procedure/aragorn-supported-ingress-lineage-v2.sh",
            "digest": script_digest,
        },
        "transfer_archive": {
            "path": "procedure/current-numerical-transfer.tar",
            "digest": transfer_digest,
            "bytes": 15_605_760,
            "inventory": inventory,
        },
        "mapping_policy": ("STRIP_SOURCE_ARCHIVE_ROOT_COPY_EXCEPT_DECLARED_TRANSFORMS"),
        "mappings": {
            "protected-before": "protected-before-current-numerical",
            "final-production-path-state.txt": (
                "runtime/current-numerical-production-path-state.txt"
            ),
            "final-evidence-path-state.txt": (
                "runtime/current-numerical-evidence-path-state.txt"
            ),
            "final-run-state.txt": "runtime/current-numerical-run-state.txt",
        },
        "removed_paths": [
            "cases/byte-update-base/ready",
            "cases/byte-update-base/stop",
            "cases/byte-update-next/ready",
            "cases/byte-update-next/stop",
            "cases/recursive-metrics/ready",
            "cases/recursive-metrics/stop",
        ],
        "mode_normalizations": [
            {
                "path": ("protected-after-byte-update-base/skills/aragorn-admitted"),
                "source_mode": 0o777,
                "destination_mode": 0o755,
            },
            {
                "path": ("protected-after-byte-update-next/skills/aragorn-admitted"),
                "source_mode": 0o777,
                "destination_mode": 0o755,
            },
        ],
        "archive_metadata_normalization": {
            "uid": 0,
            "gid": 0,
            "uname": "root",
            "gname": "root",
            "mtime": 0,
        },
    }
    if (
        _digest(
            _file(
                archive,
                "procedure/aragorn-supported-ingress-lineage-v2.sh",
                0o500,
            )
        )
        != script_digest
        or _json(
            archive,
            "procedure/current-numerical-merge-map.json",
            newline=True,
        )
        != merge_map
    ):
        raise SupportedIngressLiveArchiveError(
            "current numerical merge declaration changed"
        )

    transfer = _file(
        archive,
        merge_map["transfer_archive"]["path"],
        0o400,
    )
    if len(transfer) != 15_605_760 or _digest(transfer) != transfer_digest:
        raise SupportedIngressLiveArchiveError(
            "current numerical transfer archive identity changed"
        )
    records, payloads = _transfer_inventory(
        transfer,
        merge_map["source_archive_root"],
    )
    actual_inventory = {
        "digest": canonical_digest(records),
        "directories": sum(item["type"] == "directory" for item in records),
        "members": len(records),
        "payload_bytes": sum(item.get("bytes", 0) for item in records),
        "regular_files": sum(item["type"] == "file" for item in records),
        "symlinks": sum(item["type"] == "symlink" for item in records),
    }
    if actual_inventory != inventory:
        raise SupportedIngressLiveArchiveError(
            "current numerical transfer inventory changed"
        )

    mappings = merge_map["mappings"]
    removed = set(merge_map["removed_paths"])
    normalizations = {
        item["path"]: (item["source_mode"], item["destination_mode"])
        for item in merge_map["mode_normalizations"]
    }
    used_mappings: set[str] = set()
    used_removed: set[str] = set()
    used_normalizations: set[str] = set()
    mapped_targets: set[str] = set()
    for record in records:
        path = record["path"]
        if path in removed:
            used_removed.add(path)
            if _archive_has_member(archive, path):
                raise SupportedIngressLiveArchiveError(
                    "current numerical removed transfer member is present"
                )
            continue

        matches = [
            (source, target)
            for source, target in mappings.items()
            if path == source or path.startswith(source + "/")
        ]
        if len(matches) > 1:
            raise SupportedIngressLiveArchiveError(
                "current numerical transfer mapping is ambiguous"
            )
        if matches:
            source, target = matches[0]
            used_mappings.add(source)
            destination = target + path[len(source) :]
        else:
            destination = path
        if destination in mapped_targets:
            raise SupportedIngressLiveArchiveError(
                "current numerical transfer mapping collides"
            )
        mapped_targets.add(destination)

        expected_mode = record["mode"]
        if path in normalizations:
            source_mode, expected_mode = normalizations[path]
            used_normalizations.add(path)
            if record["type"] != "symlink" or record["mode"] != source_mode:
                raise SupportedIngressLiveArchiveError(
                    "current numerical source mode normalization changed"
                )

        if record["type"] == "directory":
            matches_destination = (
                archive.directories.get(destination) == expected_mode
                and destination not in archive.files
                and destination not in archive.symlinks
            )
        elif record["type"] == "file":
            matches_destination = (
                archive.files.get(destination) == _File(payloads[path], expected_mode)
                and destination not in archive.directories
                and destination not in archive.symlinks
            )
        else:
            matches_destination = (
                archive.symlinks.get(destination) == (expected_mode, record["target"])
                and destination not in archive.directories
                and destination not in archive.files
            )
        if not matches_destination:
            raise SupportedIngressLiveArchiveError(
                f"current numerical transfer mapping changed: {path}"
            )

    if (
        used_mappings != set(mappings)
        or used_removed != removed
        or used_normalizations != set(normalizations)
    ):
        raise SupportedIngressLiveArchiveError(
            "current numerical transfer declaration is unused or incomplete"
        )


def _transfer_inventory(
    raw: bytes,
    expected_root: str,
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    records: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {}
    seen: set[str] = set()
    payload_bytes = 0
    try:
        with tarfile.open(fileobj=BytesIO(raw), mode="r:") as source:
            for member in source:
                if len(records) >= 512:
                    raise SupportedIngressLiveArchiveError(
                        "current numerical transfer member count exceeds its limit"
                    )
                name = member.name
                parsed = PurePosixPath(name)
                if (
                    not name
                    or parsed.is_absolute()
                    or "\\" in name
                    or "\x00" in name
                    or parsed.as_posix() != name
                    or any(part in {"", ".", ".."} for part in parsed.parts)
                    or parsed.parts[0] != expected_root
                ):
                    raise SupportedIngressLiveArchiveError(
                        "current numerical transfer path is non-canonical"
                    )
                relative = (
                    ""
                    if len(parsed.parts) == 1
                    else PurePosixPath(*parsed.parts[1:]).as_posix()
                )
                if relative in seen:
                    raise SupportedIngressLiveArchiveError(
                        "current numerical transfer member is duplicated"
                    )
                seen.add(relative)
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                    or member.pax_headers
                    or getattr(member, "sparse", None)
                    or member.devmajor
                    or member.devminor
                    or member.mode & ~0o777
                    or isinstance(member.mtime, bool)
                    or not isinstance(member.mtime, (int, float))
                    or member.mtime < 0
                    or int(member.mtime) != member.mtime
                ):
                    raise SupportedIngressLiveArchiveError(
                        "current numerical transfer metadata changed"
                    )

                record: dict[str, Any] = {
                    "path": relative,
                    "mode": member.mode,
                }
                if member.isdir():
                    if member.size or member.linkname:
                        raise SupportedIngressLiveArchiveError(
                            "current numerical transfer directory changed"
                        )
                    record["type"] = "directory"
                elif member.issym():
                    target = PurePosixPath(member.linkname)
                    if (
                        member.size
                        or not member.linkname
                        or target.is_absolute()
                        or "\\" in member.linkname
                        or "\x00" in member.linkname
                        or target.as_posix() != member.linkname
                        or any(part in {"", ".", ".."} for part in target.parts)
                    ):
                        raise SupportedIngressLiveArchiveError(
                            "current numerical transfer symlink is unsafe"
                        )
                    record.update(type="symlink", target=member.linkname)
                elif member.isfile() and not member.linkname:
                    if member.size > _MAX_MEMBER_BYTES:
                        raise SupportedIngressLiveArchiveError(
                            "current numerical transfer member exceeds its byte limit"
                        )
                    stream = source.extractfile(member)
                    payload = b"" if stream is None else stream.read(member.size + 1)
                    if len(payload) != member.size:
                        raise SupportedIngressLiveArchiveError(
                            "current numerical transfer member size changed"
                        )
                    payload_bytes += len(payload)
                    if payload_bytes > 16 * 1024 * 1024:
                        raise SupportedIngressLiveArchiveError(
                            "current numerical transfer payload exceeds its limit"
                        )
                    payloads[relative] = payload
                    record.update(
                        type="file",
                        bytes=len(payload),
                        digest=_digest(payload),
                    )
                else:
                    raise SupportedIngressLiveArchiveError(
                        "current numerical transfer contains an unsupported member"
                    )
                records.append(record)
    except SupportedIngressLiveArchiveError:
        raise
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise SupportedIngressLiveArchiveError(
            f"current numerical transfer archive is invalid: {exc}"
        ) from exc
    records.sort(key=lambda item: item["path"])
    return records, payloads


def _archive_has_member(archive: _Archive, path: str) -> bool:
    return (
        path in archive.files or path in archive.directories or path in archive.symlinks
    )


def _verify_transitions(
    archive: _Archive,
    cases: dict[str, _Case],
) -> dict[str, Any]:
    if (
        _snapshot_records(archive, "protected-before")
        != _snapshot_records(archive, "protected-after-release-error")
        or _file(archive, "cases/release-error/protected.diff", 0o600)
        or any(
            name.startswith("protected-after-release-error/")
            and name.endswith("coordinator-active.json")
            for name in archive.files
        )
    ):
        raise SupportedIngressLiveArchiveError("release-error changed protected state")

    active_records: dict[str, list[dict[str, Any]]] = {}
    for name in ("install", "update"):
        snapshot = f"protected-after-{name}"
        state = _json(archive, f"{snapshot}/coordinator-active.json", newline=False)
        result = cases[name].result
        broker = cases[name].broker
        link_path = f"{snapshot}/skills/aragorn-admitted"
        mode, target = archive.symlinks.get(link_path, (None, None))
        expected_active = state.get("expected_active", {})
        if (
            mode != 0o755
            or target != broker.get("active", {}).get("link_target")
            or target != state.get("version_path")
            or state.get("schema") != "aragorn/protected-install-coordinator-state/v3"
            or state.get("assurance")
            != "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
            or state.get("service_request_digest")
            != result.get("service_request_digest")
            or state.get("tree_digest") != broker.get("active", {}).get("tree_digest")
            or expected_active.get("source_request")
            != cases[name].summary["source_request"]
            or expected_active.get("context_id") != result.get("context_id")
            or expected_active.get("manifest_digest") != result.get("manifest_digest")
        ):
            raise SupportedIngressLiveArchiveError(
                f"{name} protected state binding changed"
            )
        active_records[name] = _snapshot_records(
            archive,
            f"{snapshot}/skills/{target}",
            include_root=False,
        )

    update = cases["update"].broker
    manifest_diff = (
        update.get("transition", {}).get("manifest_diff", {}).get("document", {})
    )
    if (
        active_records["install"] != active_records["update"]
        or cases["install"].result.get("manifest_digest")
        == cases["update"].result.get("manifest_digest")
        or manifest_diff.get("changed_paths") != []
        or manifest_diff.get("added_paths") != []
        or manifest_diff.get("removed_paths") != []
        or manifest_diff.get("old", {}).get("tree_digest")
        != manifest_diff.get("new", {}).get("tree_digest")
        or update.get("transition", {}).get("previous_source", {}).get("request")
        != cases["install"].summary["source_request"]
    ):
        raise SupportedIngressLiveArchiveError(
            "update byte-identity or manifest transition changed"
        )

    _verify_current_numerical_merge(archive)
    if (
        _snapshot_records(archive, "protected-before-current-numerical")
        != _snapshot_records(archive, "protected-after-recursive-metrics")
        or _file(archive, "cases/recursive-metrics/protected.diff", 0o600)
        or any(
            name.startswith("protected-after-recursive-metrics/")
            and name.endswith("coordinator-active.json")
            for name in archive.files
        )
    ):
        raise SupportedIngressLiveArchiveError(
            "recursive-metrics changed protected state"
        )

    base_files = _verify_active_snapshot(
        archive,
        "protected-after-byte-update-base",
        cases["byte-update-base"],
    )
    next_files = _verify_active_snapshot(
        archive,
        "protected-after-byte-update-next",
        cases["byte-update-next"],
    )
    base_by_path = {item["path"]: item for item in base_files}
    next_by_path = {item["path"]: item for item in next_files}
    added = sorted(set(next_by_path) - set(base_by_path))
    removed = sorted(set(base_by_path) - set(next_by_path))
    changed = sorted(
        path
        for path in set(base_by_path) & set(next_by_path)
        if base_by_path[path] != next_by_path[path]
    )
    next_case = cases["byte-update-next"]
    base_case = cases["byte-update-base"]
    transition = next_case.broker.get("transition", {})
    retained_diff = transition.get("manifest_diff", {})
    diff_document = retained_diff.get("document", {})
    if next_case.blobs is None:
        raise SupportedIngressLiveArchiveError("byte update CAS is absent")
    cas_diff = _cas_document(
        next_case.blobs,
        retained_diff.get("digest"),
        "aragorn/manifest-update-diff/v1",
        "byte update manifest diff",
    )
    expected_diff = {
        "schema": "aragorn/manifest-update-diff/v1",
        "authority": "UPDATE_DIFF_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY",
        "old": {
            "manifest_digest": base_case.broker["source"]["manifest_digest"],
            "tree_digest": base_case.broker["source"]["tree_digest"],
        },
        "new": {
            "manifest_digest": next_case.broker["source"]["manifest_digest"],
            "tree_digest": next_case.broker["source"]["tree_digest"],
        },
        "added_paths": added,
        "removed_paths": removed,
        "changed_paths": changed,
    }
    if (
        added != []
        or removed != []
        or changed != ["SKILL.md"]
        or diff_document != expected_diff
        or cas_diff != expected_diff
        or canonical_digest(expected_diff) != retained_diff.get("digest")
        or not _file(archive, "cases/byte-update-next/protected.diff", 0o600)
        or transition.get("expected_active")
        != {
            "context_id": base_case.result["context_id"],
            "manifest_digest": base_case.result["manifest_digest"],
        }
        or transition.get("previous_source", {}).get("request")
        != base_case.summary["source_request"]
        or next_case.broker.get("transaction", {}).get("expected_active")
        != transition.get("expected_active")
    ):
        raise SupportedIngressLiveArchiveError(
            "byte-changing update transition changed"
        )

    base_target = base_case.broker["active"]["link_target"]
    if _snapshot_records(
        archive,
        f"protected-after-byte-update-base/skills/{base_target}",
    ) != _snapshot_records(
        archive,
        f"protected-after-byte-update-next/skills/{base_target}",
    ):
        raise SupportedIngressLiveArchiveError(
            "byte update changed its retained predecessor tree"
        )

    if (
        _text(
            archive,
            "runtime/current-numerical-production-path-state.txt",
            0o600,
        )
        != "active\n"
        or _text(
            archive,
            "runtime/current-numerical-evidence-path-state.txt",
            0o600,
        )
        != "inactive\n"
        or _text(archive, "runtime/current-numerical-run-state.txt", 0o600)
        != "submission.lock f 0:0 600 0\n"
    ):
        raise SupportedIngressLiveArchiveError(
            "current numerical runtime state changed"
        )

    return {
        "implementation": {
            "source_commit": _SOURCE["commit"],
            "package_tree_digest": _RELEASE_IDENTITY["package"]["tree_digest"],
            "broker_digest": _RELEASE_IDENTITY["broker"]["digest"],
        },
        "installed_trees": 2,
        "installed_files": len(base_files) + len(next_files),
        "installed_digest_mismatches": 0,
        "changed_paths": 1,
        "static_references_resolved": 13,
        "static_references_total": 13,
        "minimum_static_reference_resolution_percent": 95,
        "unresolved_required_fail_closed": 18,
        "unresolved_required_total": 18,
        "observed_outcome": "ERROR",
        "status": "PASS",
    }


def _verify_active_snapshot(
    archive: _Archive,
    snapshot: str,
    case: _Case,
) -> list[dict[str, Any]]:
    if case.manifest is None or case.blobs is None:
        raise SupportedIngressLiveArchiveError(
            f"{snapshot} retained manifest or CAS is absent"
        )
    state = _json(archive, f"{snapshot}/coordinator-active.json", newline=False)
    result = case.result
    broker = case.broker
    transaction = broker.get("transaction", {})
    link_path = f"{snapshot}/skills/aragorn-admitted"
    mode, target = archive.symlinks.get(link_path, (None, None))
    expected_active = state.get("expected_active", {})
    if (
        mode != 0o755
        or target != broker.get("active", {}).get("link_target")
        or target != state.get("version_path")
        or state.get("schema") != "aragorn/protected-install-coordinator-state/v3"
        or state.get("assurance")
        != "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        or state.get("service_request_digest") != result.get("service_request_digest")
        or state.get("tree_digest") != broker.get("active", {}).get("tree_digest")
        or expected_active.get("source_request") != case.summary["source_request"]
        or expected_active.get("context_id") != result.get("context_id")
        or expected_active.get("manifest_digest") != result.get("manifest_digest")
        or transaction.get("version_path") != target
    ):
        raise SupportedIngressLiveArchiveError(
            f"{snapshot} protected state binding changed"
        )

    context_id = result["context_id"].removeprefix("sha256:")
    claim = _json(
        archive,
        f"{snapshot}/skills/.aragorn-install-claims/{context_id}.json",
        newline=False,
    )
    if claim != transaction:
        raise SupportedIngressLiveArchiveError(
            f"{snapshot} protected transaction claim changed"
        )

    active_root = f"{snapshot}/skills/{target}"
    expected_files: dict[str, dict[str, Any]] = {}
    expected_directories = {active_root}
    for entry in case.manifest["files"]:
        path = f"{active_root}/{entry['path']}"
        expected_files[path] = entry
        parts = PurePosixPath(entry["path"]).parts
        expected_directories.update(
            f"{active_root}/{'/'.join(parts[:depth])}" for depth in range(1, len(parts))
        )
    actual_files = {
        path for path in archive.files if path.startswith(active_root + "/")
    }
    actual_directories = {
        path
        for path in archive.directories
        if path == active_root or path.startswith(active_root + "/")
    }
    if (
        actual_files != set(expected_files)
        or actual_directories != expected_directories
        or any(archive.directories[path] != 0o555 for path in actual_directories)
        or any(path.startswith(active_root + "/") for path in archive.symlinks)
    ):
        raise SupportedIngressLiveArchiveError(
            f"{snapshot} installed tree inventory changed"
        )

    records = []
    for path, entry in sorted(expected_files.items()):
        item = archive.files[path]
        retained = case.blobs.get(entry["digest"])
        expected_mode = 0o555 if entry["executable"] else 0o444
        if item.mode != expected_mode or retained is None or item.raw != retained:
            raise SupportedIngressLiveArchiveError(
                f"{snapshot} installed file bytes changed"
            )
        records.append(
            {
                "path": entry["path"],
                "size": len(item.raw),
                "digest": _digest(item.raw),
                "executable": entry["executable"],
            }
        )
    return records


def _snapshot_records(
    archive: _Archive,
    root: str,
    *,
    include_root: bool = False,
) -> list[dict[str, Any]]:
    prefix = root + "/"
    names = sorted(
        name
        for name in (archive.directories | archive.files | archive.symlinks)
        if (include_root and name == root) or name.startswith(prefix)
    )
    records = []
    for name in names:
        relative = name.removeprefix(prefix)
        if name in archive.directories:
            records.append(
                {
                    "path": relative,
                    "mode": archive.directories[name],
                    "type": "directory",
                }
            )
        elif name in archive.files:
            item = archive.files[name]
            records.append(
                {
                    "path": relative,
                    "mode": item.mode,
                    "type": "file",
                    "bytes": len(item.raw),
                    "digest": _digest(item.raw),
                }
            )
        else:
            mode, target = archive.symlinks[name]
            records.append(
                {
                    "path": relative,
                    "mode": mode,
                    "type": "symlink",
                    "target": target,
                }
            )
    return records


def _package_index(raw: bytes) -> dict[str, str]:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise SupportedIngressLiveArchiveError("package index is not ASCII") from exc
    result: dict[str, str] = {}
    previous = ""
    for line in lines:
        escaped = line.startswith("\\")
        if escaped:
            line = line[1:]
        digest, separator, path = line.partition("  ")
        if escaped:
            if "\\n" in path:
                raise SupportedIngressLiveArchiveError("package index changed")
            path = path.replace("\\\\", "\\")
        if (
            separator != "  "
            or not _HEX_64.fullmatch(digest)
            or not path.startswith("/opt/aragorn-broker-c87b82b9b7a4/")
            or path <= previous
            or path in result
        ):
            raise SupportedIngressLiveArchiveError("package index changed")
        previous = path
        result[path] = digest
    return result


def _file(
    archive: _Archive,
    path: str,
    mode: int | None = None,
) -> bytes:
    item = archive.files.get(path)
    if item is None or (mode is not None and item.mode != mode):
        raise SupportedIngressLiveArchiveError(
            f"archive file is absent or has the wrong mode: {path}"
        )
    return item.raw


def _text(archive: _Archive, path: str, mode: int | None = None) -> str:
    try:
        return _file(archive, path, mode).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SupportedIngressLiveArchiveError(
            f"archive text is not UTF-8: {path}"
        ) from exc


def _json(
    archive: _Archive,
    path: str,
    *,
    newline: bool,
) -> dict[str, Any]:
    return _decode(_file(archive, path), path, newline=newline)


def _decode(raw: bytes, label: str, *, newline: bool) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise SupportedIngressLiveArchiveError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise SupportedIngressLiveArchiveError(f"{label} is not a JSON object")
    expected = canonical_json(value) + (b"\n" if newline else b"")
    if raw != expected:
        raise SupportedIngressLiveArchiveError(f"{label} is not canonical JSON")
    return value


def _json_lines(raw: bytes, label: str) -> list[dict[str, Any]]:
    if not raw.endswith(b"\n"):
        raise SupportedIngressLiveArchiveError(f"{label} does not end with a newline")
    try:
        rows = [json.loads(line) for line in raw.splitlines()]
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise SupportedIngressLiveArchiveError(
            f"{label} contains invalid JSON"
        ) from exc
    if not rows or len(rows) > 64 or not all(isinstance(row, dict) for row in rows):
        raise SupportedIngressLiveArchiveError(f"{label} record count or shape changed")
    return rows


def _key_values(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in result:
            raise SupportedIngressLiveArchiveError("systemd show output is malformed")
        result[key] = value
    return result


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
