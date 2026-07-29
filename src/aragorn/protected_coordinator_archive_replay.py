"""Strict offline replay for the retained Phase 1 coordinator archive."""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
from io import BytesIO
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

from . import (
    admission_artifact_graph,
    decision_receipt,
    github_gateway_live_evidence,
)
from .artifact_closure import canonical_json, load_verified_retained_manifest
from .cas import CAS
from .manifest_diff import diff_verified_manifests_between
from .oci_worker_protocol import canonical_digest

AUTHORITY = "OFF_HOST_COORDINATOR_REPLAY_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
ARCHIVE_DIGEST = (
    "sha256:707fb29a9a22dad7ac9e9bd2c7e39a831a1e1d994ce625ef7ee8102f24b04397"
)

_OLD_ROOT = "918090c29df9d1dfc1f79e0534cb67d961403b4c89567c565ad4de52a042f0a1"
_NEW_ROOT = "0cac984f8f4e1311fa166d8578b7ba77b4c87c1e96421ad403aeaaa0f9c6ee0f"
_OLD_CONTEXT = "sha256:1f8f1bb579d441710b1dfee0cceea744eff9adf76f4a6512ed640b18c93fc4b5"
_NEW_CONTEXT = "sha256:79ebd365ace7a7d528a3e5bf50fe9ec83d93109d5c74e46f6b52f3dcd15e6655"
_OLD_MANIFEST = (
    "sha256:9153af66b0f2e0a5d8700e22e6161fac770eacd6f44c86de21d9aaae8658b1a6"
)
_NEW_MANIFEST = (
    "sha256:99c08a9f18b3c4d0b7a07f058f93e69df6c1e4176ffe0f209a085ba317d6c82d"
)
_OLD_RECEIPT = "sha256:08e9a0548f09a75e7ad860ff3bb6c0198cd337213f1a7dc750d7b9a571cf8a06"
_NEW_RECEIPT = "sha256:bb371d002f0da17acfad1adc2096f59cc7020d7435e95542c648a9f8079c10d5"
_OLD_GRAPH = "sha256:69ca2ee837df93259d49a536930c1fff3fe577291c94c3a1f38233d1a5690c66"
_NEW_GRAPH = "sha256:f3270848b45e30cff4f50e39f0e64ae1c3db47103dbe0b07389a10c9f7dab7ba"
_OLD_DECISION = (
    "sha256:c816a84e766da00f8e241585464fd999354e1128208979ae4d0f9e5a845007bc"
)
_NEW_DECISION = (
    "sha256:ef007da3853c4a75d0630031a66d61b2bf7c7fa4b7350012ec20d4c61c808f16"
)
_OLD_ANALYZER_RECEIPT = (
    "sha256:f4a53da102e89cc7dbb27e5a0a8d4bdee1b6ce90567733be25e03292daec94e0"
)
_NEW_ANALYZER_RECEIPT = (
    "sha256:840de02cddbaf8de3272d6fde6e8aa6f856e9d965318fcbf52aba1e39fe9f5a4"
)
_POLICY = "sha256:4f428c98005397217c76a1c5dfbf7bd3d52226679a592185857293407bbab7b5"
_GRAPH_VERIFIER = (
    "sha256:0e8063b1b2e855523379c813cdfcdda642e261027d1f289737437a060699d86a"
)
_ANALYZER_VERIFIER = (
    "sha256:9f008f75c522176aa8df6b282687626db4c0acd178ca69cdc0b9c841e23d8164"
)
_GATEWAY_PROFILE = (
    "sha256:c092fc29fed9f5a77e887cabb1f2ffc07315ac3f9b0f0fa566310fea844b96a9"
)
_TREE = "sha256:d409d3747207c4ac4b50002c256557c43262457e988de92189b9f8324beb5b7b"
_SKILL = "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
_DIFF = "sha256:aabccf12691487c6ed0a080d7fedbe8e1b9e6b08dd7a1868e15ac914da6e1f09"
_OLD_VERSION = (
    ".aragorn-versions/aragorn-admitted/"
    "1f8f1bb579d441710b1dfee0cceea744eff9adf76f4a6512ed640b18c93fc4b5-"
    "9153af66b0f2e0a5d8700e22e6161fac770eacd6f44c86de21d9aaae8658b1a6"
)
_NEW_VERSION = (
    ".aragorn-versions/aragorn-admitted/"
    "79ebd365ace7a7d528a3e5bf50fe9ec83d93109d5c74e46f6b52f3dcd15e6655-"
    "99c08a9f18b3c4d0b7a07f058f93e69df6c1e4176ffe0f209a085ba317d6c82d"
)
_PROTECTED = "var/lib/aragorn-protected/skills"
_ACTIVE = f"{_PROTECTED}/aragorn-admitted"
_STATE = "var/lib/aragorn-protected/coordinator-active.json"
_RELEASE = "etc/aragorn/protected-broker-release.json"
_ARCHIVE_MTIME = 1_785_314_776
_MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
_MAX_MEMBER_BYTES = 8 * 1024 * 1024
_EXPECTED_PAYLOAD_BYTES = 15_058_400

_BLOBS = {
    _OLD_ROOT: {
        "08e9a0548f09a75e7ad860ff3bb6c0198cd337213f1a7dc750d7b9a571cf8a06": 1479,
        "20e355db465dffba3edc3e751f47b6ad9843725678d8eb175c2a4eed16b1f36c": 1350,
        "4f428c98005397217c76a1c5dfbf7bd3d52226679a592185857293407bbab7b5": 288,
        "5c11175d7728408342a4719a082af8d114094f626e6a148cef859f349a1ee2dc": 499,
        "69ca2ee837df93259d49a536930c1fff3fe577291c94c3a1f38233d1a5690c66": 1089,
        "6e349197989f75e92bafabf5ec3388414835a4205f099d26356f4d43a9237b2a": 265,
        "9153af66b0f2e0a5d8700e22e6161fac770eacd6f44c86de21d9aaae8658b1a6": 731,
        "9bb6da9b6aca8716f753940f26c762e3e38b8a79284f6524a5392ce0f3913010": 36,
        "c816a84e766da00f8e241585464fd999354e1128208979ae4d0f9e5a845007bc": 1245,
        "d65006cf23ca52a0dd5f3a5c3584fb3e2c876b670dea68c7cc8dc8f7a7d5fc97": 761,
        "d7dc1ef6da10929a8bb44e1e3f1d666b83fa746f92db9c50f889e4c747c6dc26": 7_503_168,
        "dc3dbb98c5b9983f1dc938a522a5ab2b2f9ff7a6d6d54daccdc4bc75ed6d9a39": 974,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": 0,
        "e3f4e711dd4defdfa291e16c686f8670882a65e647501978298e0fdfc5173b88": 1745,
        "eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa": 140,
        "f4a53da102e89cc7dbb27e5a0a8d4bdee1b6ce90567733be25e03292daec94e0": 627,
    },
    _NEW_ROOT: {
        "4f428c98005397217c76a1c5dfbf7bd3d52226679a592185857293407bbab7b5": 288,
        "78bcbe8dbcee265bfeb09b08ade12cf3c91a275ba7892a5f3f4b06af7384e8a3": 974,
        "840de02cddbaf8de3272d6fde6e8aa6f856e9d965318fcbf52aba1e39fe9f5a4": 627,
        "8f37c542cc7b7e41affb55bf9cabe44ada98064e7526b1db8840026d9dde477e": 265,
        "99c08a9f18b3c4d0b7a07f058f93e69df6c1e4176ffe0f209a085ba317d6c82d": 731,
        "9bb6da9b6aca8716f753940f26c762e3e38b8a79284f6524a5392ce0f3913010": 36,
        "a2d3e43f1afd5b84ff34ee21c373444bf64fc447dcc6b03e88e3d425e61aa165": 761,
        "aabccf12691487c6ed0a080d7fedbe8e1b9e6b08dd7a1868e15ac914da6e1f09": 539,
        "bb371d002f0da17acfad1adc2096f59cc7020d7435e95542c648a9f8079c10d5": 1479,
        "d7dc1ef6da10929a8bb44e1e3f1d666b83fa746f92db9c50f889e4c747c6dc26": 7_503_168,
        "de58950e6df623902264c93ddad66fe3e84d9725c91362dfb30937d7c46acc64": 1074,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": 0,
        "e3f4e711dd4defdfa291e16c686f8670882a65e647501978298e0fdfc5173b88": 1745,
        "eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa": 140,
        "ed012a3576f9a34661a8fbe005cedaf7d54159ce1398e2c199c545fa93a34bd7": 499,
        "ef007da3853c4a75d0630031a66d61b2bf7c7fa4b7350012ec20d4c61c808f16": 1245,
        "f3270848b45e30cff4f50e39f0e64ae1c3db47103dbe0b07389a10c9f7dab7ba": 1089,
    },
}


def _named(size: int, mode: int, digest: str) -> tuple[int, int, str]:
    return size, mode, digest


_NAMED_FILES = {
    f"{_PROTECTED}/.aragorn-install-claims/{_OLD_CONTEXT[7:]}.json": _named(
        796, 0o400, "01824fae922a430f0c4021ce9ffa6b81787044649adfaf112af9b0f395526094"
    ),
    f"{_PROTECTED}/.aragorn-install-claims/{_NEW_CONTEXT[7:]}.json": _named(
        971, 0o400, "3fe3ea205d43be98334a1b76975ea5336ccbe67b2575710ae1217e9b22e2b039"
    ),
    f"{_PROTECTED}/{_OLD_VERSION}/SKILL.md": _named(140, 0o444, _SKILL[7:]),
    f"{_PROTECTED}/{_NEW_VERSION}/SKILL.md": _named(140, 0o444, _SKILL[7:]),
    _STATE: _named(
        1081, 0o400, "26573abb5c4f174798511f363b92b2a520d799e95904f4dd823f64027b90ee13"
    ),
    "etc/systemd/system/aragorn-protected-install-coordinator-evidence.service": _named(
        1723, 0o644, "251e282fee8394233be5926718852852f70d04b2708c35b40189c75cb20bd6c6"
    ),
    "etc/systemd/system/aragorn-protected-install-coordinator-evidence.path": _named(
        259, 0o644, "689c6f7c094a38b62f097bab0bf3d36e5090ccbef5fb56557e02a6b0bcc59562"
    ),
    "etc/systemd/system/aragorn-protected-install.service": _named(
        2021, 0o644, "7087601d0602d2ab64a7386b2c6a5da91c3cf6755b473a99b600ae78f5e95228"
    ),
    _RELEASE: _named(
        655, 0o400, "5b8e4a4c10fcae0a2968501257907125cb8d67e80d8f9ce0abdfbf68a6d54664"
    ),
    "etc/aragorn/phase1-coordinator-evidence-enabled": _named(
        0, 0o400, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ),
    "usr/libexec/aragorn/aragorn-protected-install-coordinator.py": _named(
        4241, 0o555, "93d509eb96ef350b0011c4c9fcb5837bd42a5a0560e02fa047e32061a31f0c19"
    ),
    "usr/libexec/aragorn/aragorn-protected-install-launcher.py": _named(
        17316, 0o555, "e27b2ed1be6e24d758b148e9d6f9740d4e1c5cd74e87462d2fb2d9686dc5810b"
    ),
}

_LOCAL_BINDINGS = {
    "etc/systemd/system/aragorn-protected-install-coordinator-evidence.service": (
        "packaging/systemd/aragorn-protected-install-coordinator-evidence.service"
    ),
    "etc/systemd/system/aragorn-protected-install-coordinator-evidence.path": (
        "packaging/systemd/aragorn-protected-install-coordinator-evidence.path"
    ),
    "etc/systemd/system/aragorn-protected-install.service": (
        "packaging/systemd/aragorn-protected-install.service"
    ),
    "usr/libexec/aragorn/aragorn-protected-install-coordinator.py": (
        "packaging/libexec/aragorn-protected-install-coordinator.py"
    ),
    "usr/libexec/aragorn/aragorn-protected-install-launcher.py": (
        "packaging/libexec/aragorn-protected-install-launcher.py"
    ),
}


class ProtectedCoordinatorArchiveReplayError(ValueError):
    """The retained coordinator archive is malformed or inconsistent."""


def verify_protected_coordinator_archive(
    archive_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Replay the pinned archive without re-attesting its live Linux state."""

    try:
        raw = _pinned_archive(archive_path)
        files = _load_archive(raw)
        with TemporaryDirectory(prefix="aragorn-coordinator-replay-") as temporary:
            cases = _retained_cases(files, Path(temporary))
            old = _source(
                cases[_OLD_ROOT],
                request={
                    "schema": "aragorn/github-gateway-request/v1",
                    "owner": "anthropics",
                    "repository": "skills",
                    "commit": "00756142ab04c82a447693cf373c4e0c554d1005",
                    "skill_path": "template",
                },
                manifest_digest=_OLD_MANIFEST,
                receipt_digest=_OLD_RECEIPT,
                graph_digest=_OLD_GRAPH,
                decision_digest=_OLD_DECISION,
                analyzer_receipt_digest=_OLD_ANALYZER_RECEIPT,
            )
            new = _source(
                cases[_NEW_ROOT],
                request={
                    "schema": "aragorn/github-gateway-request/v1",
                    "owner": "anthropics",
                    "repository": "skills",
                    "commit": "2235be7c60b551f5de82ade908fd3816455afcda",
                    "skill_path": "template",
                },
                manifest_digest=_NEW_MANIFEST,
                receipt_digest=_NEW_RECEIPT,
                graph_digest=_NEW_GRAPH,
                decision_digest=_NEW_DECISION,
                analyzer_receipt_digest=_NEW_ANALYZER_RECEIPT,
            )
            _update_diff(cases[_OLD_ROOT], cases[_NEW_ROOT])
            _installed(files, cases, old, new)
            coordinator = _coordinator(files, new)

        return {
            "schema": "aragorn/protected-coordinator-archive-replay/v1",
            "authority": AUTHORITY,
            "archive_digest": ARCHIVE_DIGEST,
            "archive": {
                "members": 89,
                "regular_files": 45,
                "directories": 43,
                "symlinks": 1,
                "payload_bytes": _EXPECTED_PAYLOAD_BYTES,
                "metadata": "EXACT_CANONICAL_PINNED_TAR_INVENTORY",
            },
            "install": {
                "request": old["request"],
                "manifest_digest": _OLD_MANIFEST,
                "quarantine_receipt_digest": _OLD_RECEIPT,
                "decision_digest": _OLD_DECISION,
                "verdict": "ALLOW",
                "cas_blob_count": len(_BLOBS[_OLD_ROOT]),
            },
            "update": {
                "request": new["request"],
                "manifest_digest": _NEW_MANIFEST,
                "quarantine_receipt_digest": _NEW_RECEIPT,
                "decision_digest": _NEW_DECISION,
                "manifest_diff_digest": _DIFF,
                "verdict": "ALLOW",
                "cas_blob_count": len(_BLOBS[_NEW_ROOT]),
            },
            "protected_state": {
                "install_context_id": _OLD_CONTEXT,
                "update_context_id": _NEW_CONTEXT,
                "active_version_path": _NEW_VERSION,
                "tree_digest": _TREE,
                "skill_digest": _SKILL,
                "skill_bytes": 140,
            },
            "coordinator": coordinator,
            "custody_replay": (
                "HISTORICAL_UID_MODE_DEVICE_INODE_AND_CLOCK_VALUES_BOUND_"
                "BUT_NOT_REATTESTED"
            ),
            "runtime_replay": (
                "COORDINATOR_AND_PROTECTED_SERVICE_RUNTIME_NOT_REEXECUTED"
            ),
            "phase1_exit_eligible": False,
        }
    except ProtectedCoordinatorArchiveReplayError:
        raise
    except Exception as exc:
        raise ProtectedCoordinatorArchiveReplayError(
            f"cannot verify retained coordinator archive: {exc}"
        ) from exc


def _pinned_archive(path: str | os.PathLike[str]) -> bytes:
    candidate = Path(path)
    if candidate.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise ProtectedCoordinatorArchiveReplayError("archive exceeds size limit")
    raw = candidate.read_bytes()
    if _digest(raw) != ARCHIVE_DIGEST:
        raise ProtectedCoordinatorArchiveReplayError(
            "archive digest is not the retained identity"
        )
    return raw


def _load_archive(raw: bytes) -> dict[str, bytes]:
    expected_files = _expected_files()
    expected_directories = _expected_directories()
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    symlinks: dict[str, str] = {}
    payload_bytes = 0
    with tarfile.open(fileobj=BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) != 89:
            raise ProtectedCoordinatorArchiveReplayError("archive member count changed")
        for member in members:
            name = _member_name(member)
            if (
                member.uid != 0
                or member.gid != 0
                or member.uname
                or member.gname
                or member.mtime != _ARCHIVE_MTIME
                or member.pax_headers
                or member.devmajor != 0
                or member.devminor != 0
            ):
                raise ProtectedCoordinatorArchiveReplayError(
                    f"archive metadata changed: {name}"
                )
            if name in files or name in directories or name in symlinks:
                raise ProtectedCoordinatorArchiveReplayError(
                    f"archive repeats a member: {name}"
                )
            if member.type == tarfile.REGTYPE:
                expected = expected_files.get(name)
                if expected is None:
                    raise ProtectedCoordinatorArchiveReplayError(
                        f"archive has an unexpected file: {name}"
                    )
                size, mode, digest = expected
                if (
                    member.size != size
                    or member.mode != mode
                    or size > _MAX_MEMBER_BYTES
                ):
                    raise ProtectedCoordinatorArchiveReplayError(
                        f"archive file metadata changed: {name}"
                    )
                stream = archive.extractfile(member)
                content = b"" if stream is None else stream.read(size + 1)
                if (
                    len(content) != size
                    or hashlib.sha256(content).hexdigest() != digest
                ):
                    raise ProtectedCoordinatorArchiveReplayError(
                        f"archive file content changed: {name}"
                    )
                files[name] = content
                payload_bytes += size
            elif member.type == tarfile.DIRTYPE:
                if (
                    name not in expected_directories
                    or member.size
                    or member.mode
                    != (
                        0o700
                        if name.startswith("var/lib/aragorn-quarantine/")
                        else _protected_directory_mode(name)
                    )
                ):
                    raise ProtectedCoordinatorArchiveReplayError(
                        f"archive directory metadata changed: {name}"
                    )
                directories.add(name)
            elif member.type == tarfile.SYMTYPE:
                if (
                    name != _ACTIVE
                    or member.mode != 0o777
                    or member.size
                    or member.linkname != _NEW_VERSION
                ):
                    raise ProtectedCoordinatorArchiveReplayError(
                        "archive active symlink changed"
                    )
                symlinks[name] = member.linkname
            else:
                raise ProtectedCoordinatorArchiveReplayError(
                    f"archive member type is unsafe: {name}"
                )
    if (
        set(files) != set(expected_files)
        or directories != expected_directories
        or symlinks != {_ACTIVE: _NEW_VERSION}
        or payload_bytes != _EXPECTED_PAYLOAD_BYTES
    ):
        raise ProtectedCoordinatorArchiveReplayError("archive exact inventory changed")
    return files


def _member_name(member: tarfile.TarInfo) -> str:
    name = (
        member.name[:-1]
        if member.isdir() and member.name.endswith("/")
        else member.name
    )
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or path.as_posix() != name
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in name
        or "\0" in name
    ):
        raise ProtectedCoordinatorArchiveReplayError("archive member path is unsafe")
    return name


def _expected_files() -> dict[str, tuple[int, int, str]]:
    expected = dict(_NAMED_FILES)
    for root, blobs in _BLOBS.items():
        for digest, size in blobs.items():
            path = (
                f"var/lib/aragorn-quarantine/{root}/blobs/sha256/"
                f"{digest[:2]}/{digest[2:]}"
            )
            expected[path] = (size, 0o444, digest)
    return expected


def _expected_directories() -> set[str]:
    expected = {
        _PROTECTED,
        f"{_PROTECTED}/.aragorn-install-claims",
        f"{_PROTECTED}/.aragorn-versions",
        f"{_PROTECTED}/.aragorn-versions/aragorn-admitted",
        f"{_PROTECTED}/{_OLD_VERSION}",
        f"{_PROTECTED}/{_NEW_VERSION}",
    }
    for root, blobs in _BLOBS.items():
        prefix = f"var/lib/aragorn-quarantine/{root}"
        expected.update({prefix, f"{prefix}/blobs", f"{prefix}/blobs/sha256"})
        expected.update(f"{prefix}/blobs/sha256/{digest[:2]}" for digest in blobs)
    return expected


def _protected_directory_mode(name: str) -> int:
    if name in {_PROTECTED, f"{_PROTECTED}/.aragorn-install-claims"}:
        return 0o700
    if name in {
        f"{_PROTECTED}/.aragorn-versions",
        f"{_PROTECTED}/.aragorn-versions/aragorn-admitted",
    }:
        return 0o755
    return 0o555


def _retained_cases(files: dict[str, bytes], temporary: Path) -> dict[str, CAS]:
    cases = {}
    for root, inventory in _BLOBS.items():
        writable = CAS(temporary / root)
        for digest, size in inventory.items():
            path = (
                f"var/lib/aragorn-quarantine/{root}/blobs/sha256/"
                f"{digest[:2]}/{digest[2:]}"
            )
            writable.put_expected(
                BytesIO(files[path]),
                expected_digest=f"sha256:{digest}",
                max_bytes=size,
            )
        cases[root] = CAS(writable.root, read_only=True)
    return cases


def _source(
    cas: CAS,
    *,
    request: dict[str, str],
    manifest_digest: str,
    receipt_digest: str,
    graph_digest: str,
    decision_digest: str,
    analyzer_receipt_digest: str,
) -> dict[str, Any]:
    manifest = load_verified_retained_manifest(cas, manifest_digest)
    receipt = github_gateway_live_evidence._canonical_cas_document(
        cas, receipt_digest, "quarantine receipt"
    )
    github_gateway_live_evidence._verify_receipt(
        cas,
        receipt,
        request=request,
        manifest=manifest,
        manifest_digest=manifest_digest,
        receipt_digest=receipt_digest,
        profile_digest=_GATEWAY_PROFILE,
    )
    graph = _graph(cas, graph_digest, manifest, receipt)
    decision = _decision(
        cas,
        decision_digest,
        graph,
        analyzer_receipt_digest,
    )
    if (
        manifest["tree_digest"] != _TREE
        or manifest["files"]
        != [
            {
                "path": "SKILL.md",
                "size": 140,
                "digest": _SKILL,
                "executable": False,
                "git_blob_sha1": "50a4f9b104357d96361e257adb70454604cd15c0",
            }
        ]
        or decision["verdict"] != "ALLOW"
    ):
        raise ProtectedCoordinatorArchiveReplayError(
            "source manifest or decision changed"
        )
    return {
        "request": request,
        "manifest": manifest,
        "receipt": receipt,
        "graph": graph,
    }


def _graph(
    cas: CAS,
    digest: str,
    manifest: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    graph = github_gateway_live_evidence._canonical_cas_document(
        cas, digest, "artifact graph"
    )
    edges, unresolved = admission_artifact_graph._scan_admission_markdown(
        cas, manifest, scan_references=True, unresolved=set()
    )
    expected = {
        "schema": "aragorn/admission-artifact-graph/v2",
        "authority": "CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY",
        "verifier": {
            "name": admission_artifact_graph.VERIFIER,
            "version": admission_artifact_graph.GITHUB_VERIFIER_VERSION,
            "implementation_digest": _GRAPH_VERIFIER,
        },
        "profile": admission_artifact_graph.GITHUB_PROFILE,
        "root_manifest_digest": receipt["manifest_digest"],
        "source_proof_digest": receipt["source_proof_digest"],
        "quarantine_receipt_digest": canonical_digest(receipt),
        "gateway_profile_digest": _GATEWAY_PROFILE,
        "tree_digest": manifest["tree_digest"],
        "artifacts": [
            {key: entry[key] for key in ("path", "size", "digest", "executable")}
            for entry in manifest["files"]
        ],
        "edges": edges,
        "closure": {
            "scope": "artifact_graph",
            "profile": admission_artifact_graph.GITHUB_PROFILE,
            "status": "incomplete" if unresolved else "complete",
            "unresolved": unresolved,
        },
    }
    if graph != expected or canonical_digest(graph) != digest:
        raise ProtectedCoordinatorArchiveReplayError("artifact graph does not replay")
    return graph


def _decision(
    cas: CAS,
    digest: str,
    graph: dict[str, Any],
    analyzer_receipt_digest: str,
) -> dict[str, Any]:
    decision = github_gateway_live_evidence._canonical_cas_document(
        cas, digest, "decision"
    )
    validated_policy, policy = decision_receipt._load_policy(cas, _POLICY)
    results, records = decision_receipt._replay_analyzers(
        cas,
        decision["analyzers"],
        tree_digest=graph["tree_digest"],
        verifier_digest=_ANALYZER_VERIFIER,
        expected_run_receipt_digests=[analyzer_receipt_digest],
    )
    evaluated = decision_receipt.evaluate_policy(
        policy, closure=graph["closure"], results=results
    )
    expected = {
        "schema": "aragorn/decision/v3",
        "authority": "EVIDENCE_SUMMARY_ONLY_NOT_INSTALLER_AUTHORITY",
        "verdict": evaluated.verdict,
        "manifest_digest": graph["root_manifest_digest"],
        "artifact_graph_digest": canonical_digest(graph),
        "tree_digest": graph["tree_digest"],
        "artifact_digests": sorted(
            artifact["digest"] for artifact in graph["artifacts"]
        ),
        "policy": {
            "id": validated_policy["id"],
            "version": validated_policy["version"],
            "digest": _POLICY,
        },
        "analyzers": records,
        "reason_codes": list(evaluated.reason_codes),
    }
    if decision != expected or canonical_digest(decision) != digest:
        raise ProtectedCoordinatorArchiveReplayError("decision does not replay")
    return decision


def _update_diff(old: CAS, new: CAS) -> None:
    expected = diff_verified_manifests_between(old, _OLD_MANIFEST, new, _NEW_MANIFEST)
    retained = _canonical_document(new.read(_DIFF, max_bytes=4096), "manifest diff")
    if retained != expected or canonical_digest(retained) != _DIFF:
        raise ProtectedCoordinatorArchiveReplayError(
            "retained manifest diff does not replay"
        )


def _installed(
    files: dict[str, bytes],
    cases: dict[str, CAS],
    old: dict[str, Any],
    new: dict[str, Any],
) -> None:
    old_claim = _canonical_document(
        files[f"{_PROTECTED}/.aragorn-install-claims/{_OLD_CONTEXT[7:]}.json"],
        "install claim",
    )
    new_claim = _canonical_document(
        files[f"{_PROTECTED}/.aragorn-install-claims/{_NEW_CONTEXT[7:]}.json"],
        "update claim",
    )
    destination = {
        "root_device": 64769,
        "root_inode": 524931,
        "target_name": "aragorn-admitted",
    }
    base = {
        "schema": "aragorn/protected-install-transaction/v1",
        "authority": "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "tree_digest": _TREE,
        "destination": destination,
    }
    if old_claim != {
        **base,
        "context_id": _OLD_CONTEXT,
        "context_digest": (
            "sha256:e78a467ba78a94a7244efae58ce47e109c82520dc7572666d40f06f2ee2d5919"
        ),
        "operation": "install",
        "expected_active": None,
        "manifest_digest": _OLD_MANIFEST,
        "version_path": _OLD_VERSION,
    } or new_claim != {
        **base,
        "context_id": _NEW_CONTEXT,
        "context_digest": (
            "sha256:6151497b18f9453a2a3bd97b6f7c671d160ea86ad2b242121a8c76c9ce490161"
        ),
        "operation": "update",
        "expected_active": {
            "context_id": _OLD_CONTEXT,
            "manifest_digest": _OLD_MANIFEST,
        },
        "manifest_digest": _NEW_MANIFEST,
        "version_path": _NEW_VERSION,
    }:
        raise ProtectedCoordinatorArchiveReplayError(
            "install/update transaction lineage changed"
        )
    for root, version, phase in (
        (_OLD_ROOT, _OLD_VERSION, old),
        (_NEW_ROOT, _NEW_VERSION, new),
    ):
        installed = files[f"{_PROTECTED}/{version}/SKILL.md"]
        if (
            installed != cases[root].read(_SKILL, max_bytes=140)
            or phase["manifest"]["files"][0]["digest"] != _SKILL
        ):
            raise ProtectedCoordinatorArchiveReplayError(
                "protected version bytes differ from the retained manifest"
            )


def _coordinator(files: dict[str, bytes], new: dict[str, Any]) -> dict[str, Any]:
    state = _canonical_document(files[_STATE], "coordinator state")
    expected_active = {
        "context_id": _NEW_CONTEXT,
        "manifest_digest": _NEW_MANIFEST,
        "source_request": new["request"],
        "quarantine_receipt_digest": _NEW_RECEIPT,
        "gateway_profile_digest": _GATEWAY_PROFILE,
    }
    if state != {
        "schema": "aragorn/protected-install-coordinator-state/v1",
        "assurance": "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "expected_active": expected_active,
        "tree_digest": _TREE,
        "version_path": _NEW_VERSION,
        "service_request_digest": (
            "sha256:d86e53e01a104f3437b0459e76b54abafe00768e350f3837013f2ea991ee1497"
        ),
    }:
        raise ProtectedCoordinatorArchiveReplayError(
            "coordinator state lineage changed"
        )
    release = _canonical_document(files[_RELEASE], "release identity")
    expected_release = {
        "schema": "aragorn/protected-broker-launch-identity/v1",
        "broker": {
            "path": "benchmark/admission/openclaw-v2026.7.1/protected-install-broker.py",
            "digest": (
                "sha256:79f6bfd8e76852bce610322415467b2ede4816fb75fc5f865384a731f1e8f935"
            ),
        },
        "launcher": {
            "path": "/usr/libexec/aragorn/aragorn-protected-install-launcher.py",
            "digest": (
                "sha256:e27b2ed1be6e24d758b148e9d6f9740d4e1c5cd74e87462d2fb2d9686dc5810b"
            ),
        },
        "package": {
            "root": "/opt/aragorn-broker-f66f78b75df9",
            "tree_digest": (
                "sha256:05c573fa441c40d0cb6a8094d351554fa2c0272e6a9f64ec97b7c8a2e09b7170"
            ),
        },
        "python": {
            "path": "/usr/bin/python3.14",
            "digest": (
                "sha256:d7dc1ef6da10929a8bb44e1e3f1d666b83fa746f92db9c50f889e4c747c6dc26"
            ),
        },
    }
    if release != expected_release:
        raise ProtectedCoordinatorArchiveReplayError("release identity changed")
    root = Path(__file__).resolve().parents[2]
    for archived, relative in _LOCAL_BINDINGS.items():
        if files[archived] != (root / relative).read_bytes():
            raise ProtectedCoordinatorArchiveReplayError(
                f"archived service code differs from the repository: {relative}"
            )
    broker = (root / release["broker"]["path"]).read_bytes()
    if _digest(broker) != release["broker"]["digest"]:
        raise ProtectedCoordinatorArchiveReplayError(
            "release broker digest differs from the repository"
        )
    return {
        "state_digest": _digest(files[_STATE]),
        "release_digest": _digest(files[_RELEASE]),
        "coordinator_digest": (
            "sha256:"
            + _NAMED_FILES[
                "usr/libexec/aragorn/aragorn-protected-install-coordinator.py"
            ][2]
        ),
        "launcher_digest": release["launcher"]["digest"],
        "protected_service_digest": (
            "sha256:"
            + _NAMED_FILES["etc/systemd/system/aragorn-protected-install.service"][2]
        ),
        "service_request_digest": state["service_request_digest"],
    }


def _canonical_document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProtectedCoordinatorArchiveReplayError(
            f"{label} is invalid JSON"
        ) from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise ProtectedCoordinatorArchiveReplayError(f"{label} is not canonical JSON")
    return document


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ProtectedCoordinatorArchiveReplayError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise ProtectedCoordinatorArchiveReplayError(f"non-finite JSON number: {value}")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
