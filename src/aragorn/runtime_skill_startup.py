"""Private, no-PID byte check for a future fixed-profile startup guard.

Nothing installs or invokes this check at service startup. Callers must already
have authenticated the worker binding and the actual gateway configuration;
this module does not read credentials or confer provenance on caller data.
The returned snapshot proves only agreement at this check, not process
consumption, subsequent gateway state, or an atomic stop/start transition.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .oci_worker_protocol import canonical_digest, canonical_json
from .protected_skill_quarantine import require_not_quarantined_at
from .runtime_action_broker import (
    RuntimeActionBrokerError,
    _file_identity,
    _parse_canonical_document,
    _release_lock_and_close,
    require_owned_directory,
)
from .runtime_action_worker import RuntimeActionWorkerBinding
from .runtime_active_skill_lineage import (
    ACTIVE_RUNTIME_RECORD,
    DEFAULT_PROTECTED_INSTALL_ROOT,
    _acquire_shared_lock,
    _active_link,
    _open_directory_at,
    _open_protected_root,
    _require_safe_ancestry,
    _version_names,
    parse_active_runtime_record,
)

_PROTECTED_ROOT = DEFAULT_PROTECTED_INSTALL_ROOT
_EXTERNAL_SOURCE = Path("/opt/aragorn/runtime-profile/template-skill/SKILL.md")
_EXPECTED_INSTALL_UID = 0
_SKILL_NAME = "template-skill"
_WORKSPACE = "/var/lib/aragorn-agent-gateway/workspace"
_MAX_RECORD_BYTES = 4096
_MAX_SKILL_BYTES = 1024 * 1024
_MAX_TREE_ENTRIES = 64
_MAX_CONFIG_BYTES = 64 * 1024
_SCHEMA = "aragorn/runtime-skill-startup-byte-check/v1"
_AUTHORITY = (
    "POINT_IN_TIME_BYTE_BINDING_ONLY_NOT_STARTUP_ENFORCEMENT_OR_PROCESS_CONSUMPTION"
)


class RuntimeSkillStartupError(RuntimeError):
    """The fixed-profile byte snapshot cannot be safely verified."""


@dataclass(frozen=True, slots=True)
class _HeldEntry:
    parent_fd: int | None
    name: str | Path
    fd: int
    before: os.stat_result


def _digest(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise RuntimeSkillStartupError(f"{label} digest is not canonical")
    return value


def _binding_document(binding: RuntimeActionWorkerBinding) -> dict[str, Any]:
    if type(binding) is not RuntimeActionWorkerBinding:
        raise RuntimeSkillStartupError("worker binding type is invalid")
    if type(binding.policy_version) is not int or binding.policy_version <= 0:
        raise RuntimeSkillStartupError("worker policy version is invalid")
    return {
        "runtime_digest": _digest(binding.runtime_digest, "worker runtime"),
        "active_skill_digest": _digest(binding.active_skill_digest, "worker skill"),
        "policy_digest": _digest(binding.policy_digest, "worker policy"),
        "policy_version": binding.policy_version,
    }


def _configuration(config: Mapping[str, Any]) -> tuple[bytes, str]:
    if type(config) is not dict:
        raise RuntimeSkillStartupError("gateway config must be a verified JSON object")
    raw = canonical_json(config)
    if len(raw) > _MAX_CONFIG_BYTES:
        raise RuntimeSkillStartupError("gateway config exceeds the byte bound")
    snapshot = _parse_canonical_document(raw, "gateway config")
    skills = snapshot.get("skills")
    if type(skills) is not dict:
        raise RuntimeSkillStartupError("gateway skill selection is missing")
    activation = skills.get("activation")
    if type(activation) is not dict:
        raise RuntimeSkillStartupError("gateway external activation is missing")
    sources = activation.get("sources")
    if type(sources) is not list or len(sources) != 1 or type(sources[0]) is not dict:
        raise RuntimeSkillStartupError("gateway must select one fixed external skill")
    configured_hex = sources[0].get("sha256")
    if type(configured_hex) is not str:
        raise RuntimeSkillStartupError("configured external skill digest is invalid")
    configured_digest = _digest("sha256:" + configured_hex, "configured external skill")
    expected_skills = {
        "activation": {
            "authority": "external",
            "sources": [
                {
                    "filePath": str(_EXTERNAL_SOURCE),
                    "name": _SKILL_NAME,
                    "sha256": configured_hex,
                }
            ],
        },
        "allowBundled": [_SKILL_NAME],
        "load": {
            "allowSymlinkTargets": [],
            "extraDirs": [str(_EXTERNAL_SOURCE.parent)],
            "watch": False,
        },
        "workshop": {"restoreAuthority": "external"},
    }
    expected_agents = {
        "defaults": {
            "model": {"primary": "aragorn-runtime-action-mock/fixture-model"},
            "sandbox": {"mode": "off"},
            "skills": [_SKILL_NAME],
            "workspace": _WORKSPACE,
        },
        "list": [
            {
                "id": "main",
                "runtime": {"type": "embedded"},
                "sandbox": {"mode": "off"},
                "skills": [_SKILL_NAME],
                "workspace": _WORKSPACE,
            }
        ],
    }
    # Canonical bytes distinguish JSON false from 0 and reject extra selectors.
    if canonical_json(skills) != canonical_json(expected_skills) or canonical_json(
        snapshot.get("agents")
    ) != canonical_json(expected_agents):
        raise RuntimeSkillStartupError(
            "gateway skill selection is not the fixed V3 profile"
        )
    return raw, configured_digest


def _check_entries(entries: list[_HeldEntry]) -> None:
    for entry in entries:
        named = os.stat(entry.name, dir_fd=entry.parent_fd, follow_symlinks=False)
        if _file_identity(entry.before) != _file_identity(os.fstat(entry.fd)) or (
            _file_identity(entry.before) != _file_identity(named)
        ):
            raise RuntimeSkillStartupError(f"measured entry changed: {entry.name}")


def _open_directory(
    parent_fd: int,
    name: str,
    mode: int,
    entries: list[_HeldEntry],
) -> int:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    fd = _open_directory_at(parent_fd, name, _EXPECTED_INSTALL_UID, mode, name)
    entries.append(_HeldEntry(parent_fd, name, fd, before))
    _check_entries(entries[-1:])
    return fd


def _read_file(
    parent_fd: int,
    name: str,
    entries: list[_HeldEntry],
    *,
    max_bytes: int,
    exact_mode: int | None = 0o444,
) -> tuple[bytes, os.stat_result]:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )
    entries.append(_HeldEntry(parent_fd, name, fd, before))
    metadata = os.fstat(fd)
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != _EXPECTED_INSTALL_UID
        or metadata.st_nlink != 1
        or mode not in {0o444, 0o555}
        or (exact_mode is not None and mode != exact_mode)
        or not 0 <= metadata.st_size <= max_bytes
    ):
        raise RuntimeSkillStartupError(f"measured file metadata is unsafe: {name}")
    _check_entries(entries[-1:])
    raw = bytearray()
    while len(raw) <= max_bytes:
        chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) != metadata.st_size or len(raw) > max_bytes:
        raise RuntimeSkillStartupError(f"measured file size changed: {name}")
    _check_entries(entries[-1:])
    return bytes(raw), metadata


def _measure_tree(version_fd: int, entries: list[_HeldEntry]) -> tuple[str, str]:
    """Match inventory's canonical file list, with nonblocking immutable reads."""
    files: list[dict[str, Any]] = []
    seen = 0
    total_bytes = 0
    nested_count = 0

    def walk(directory_fd: int, prefix: str) -> None:
        nonlocal seen, total_bytes, nested_count
        names = []
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                seen += 1
                if seen > _MAX_TREE_ENTRIES:
                    raise RuntimeSkillStartupError("installed tree exceeds entry bound")
                names.append(entry.name)
        for name in sorted(names):
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            path = prefix + name
            if stat.S_ISDIR(metadata.st_mode):
                nested_count += 1
                if prefix or nested_count > 1:
                    raise RuntimeSkillStartupError(
                        "installed tree directory layout is unsafe"
                    )
                child = _open_directory(directory_fd, name, 0o555, entries)
                before_count = len(files)
                walk(child, path + "/")
                if len(files) == before_count:
                    raise RuntimeSkillStartupError(
                        "installed tree has an unbound empty directory"
                    )
                continue
            raw, opened = _read_file(
                directory_fd,
                name,
                entries,
                max_bytes=_MAX_SKILL_BYTES - total_bytes,
                exact_mode=0o444 if path == "SKILL.md" else None,
            )
            total_bytes += len(raw)
            files.append(
                {
                    "path": path,
                    "size": len(raw),
                    "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "executable": stat.S_IMODE(opened.st_mode) == 0o555,
                }
            )

    walk(version_fd, "")
    files.sort(key=lambda item: item["path"])
    skill = next((entry for entry in files if entry["path"] == "SKILL.md"), None)
    if skill is None or skill["size"] == 0:
        raise RuntimeSkillStartupError("installed root SKILL.md is missing or empty")
    _check_entries(entries)
    return canonical_digest(files), skill["digest"]


def _external_parent(entries: list[_HeldEntry]) -> int:
    if (
        not _EXTERNAL_SOURCE.is_absolute()
        or _EXTERNAL_SOURCE.name != "SKILL.md"
        or _EXTERNAL_SOURCE.resolve(strict=True) != _EXTERNAL_SOURCE
    ):
        raise RuntimeSkillStartupError("external skill source path is not canonical")
    parent = _EXTERNAL_SOURCE.parent
    _require_safe_ancestry(parent, _EXPECTED_INSTALL_UID)
    before = os.lstat(parent)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    entries.append(_HeldEntry(None, parent, fd, before))
    metadata = require_owned_directory(
        fd,
        expected_uid=_EXPECTED_INSTALL_UID,
        require_owner_write=False,
        label="external skill directory",
    )
    if stat.S_IMODE(metadata.st_mode) != 0o555:
        raise RuntimeSkillStartupError("external skill directory mode is unsafe")
    _check_entries(entries[-1:])
    return fd


def _strict_transaction(record: dict[str, Any]) -> dict[str, Any]:
    transaction = record["transaction"]
    for field in ("context_digest", "context_id", "manifest_digest", "tree_digest"):
        _digest(transaction[field], "installed transaction " + field)
    if transaction["expected_active"] is not None:
        for field in ("context_id", "manifest_digest"):
            _digest(
                transaction["expected_active"][field], "installed predecessor " + field
            )
    destination = transaction["destination"]
    if (
        type(destination["root_device"]) is not int
        or type(destination["root_inode"]) is not int
        or type(destination["target_name"]) is not str
        or type(transaction["version_path"]) is not str
    ):
        raise RuntimeSkillStartupError(
            "installed transaction identity types are invalid"
        )
    return transaction


def _installed_snapshot(
    root_fd: int, entries: list[_HeldEntry]
) -> tuple[dict[str, Any], str, str, os.stat_result]:
    """Measure installed bytes under the caller's already-held root SH or EX.

    The caller must safely open the fixed root, acquire its lock, and register
    its named/FD baseline in entries before calling. This helper never changes
    that lock or closes descriptors. All descriptors it opens are appended to
    entries even on failure; the caller owns their eventual cleanup. It checks
    neither external selection nor denial state, and confers no response or
    transaction authorization. Recheck the active link and entries before any
    later effect; publication can legitimately change only the root baseline.
    """
    if type(root_fd) is not int or root_fd < 0:
        raise RuntimeSkillStartupError("installed snapshot root descriptor is invalid")
    roots = [entry for entry in entries if entry.fd == root_fd]
    if (
        len(roots) != 1
        or roots[0].parent_fd is not None
        or roots[0].name != _PROTECTED_ROOT
    ):
        raise RuntimeSkillStartupError(
            "installed snapshot root baseline is missing or unbound"
        )
    root_state = require_owned_directory(
        root_fd,
        expected_uid=_EXPECTED_INSTALL_UID,
        require_owner_write=True,
        label="installed snapshot root",
    )
    _check_entries(entries)
    record_raw, _ = _read_file(
        root_fd, ACTIVE_RUNTIME_RECORD, entries, max_bytes=_MAX_RECORD_BYTES
    )
    record = parse_active_runtime_record(record_raw)
    transaction = _strict_transaction(record)
    destination = transaction["destination"]
    if (
        destination["root_device"] != root_state.st_dev
        or destination["root_inode"] != root_state.st_ino
    ):
        raise RuntimeSkillStartupError("installed transaction is bound to another root")
    target = destination["target_name"]
    version_name = _version_names(transaction, target)
    active_before = _active_link(
        root_fd, target, transaction["version_path"], _EXPECTED_INSTALL_UID
    )
    versions_fd = _open_directory(root_fd, ".aragorn-versions", 0o755, entries)
    target_fd = _open_directory(versions_fd, target, 0o755, entries)
    version_fd = _open_directory(target_fd, version_name, 0o555, entries)
    tree_digest, installed_digest = _measure_tree(version_fd, entries)
    if tree_digest != transaction["tree_digest"]:
        raise RuntimeSkillStartupError("installed tree is unbound to the active record")
    return record, tree_digest, installed_digest, active_before


def _verify_runtime_skill_startup(
    binding: RuntimeActionWorkerBinding,
    gateway_config: Mapping[str, Any],
) -> dict[str, Any]:
    """Check already-authenticated inputs against fixed paths; release root SH.

    The caller must later arrange mandatory invocation and authenticated gateway
    config delivery. This private API has no PID, process/grant evidence, CLI,
    startup side effect, denial publication authority, or delivery guarantee.
    Root-owned cooperating publishers must honor the existing install lock.
    The active record selects the installed target; this is byte agreement, not
    authorization of its transaction or a grant for a particular target name.
    """
    entries: list[_HeldEntry] = []
    root_fd = -1
    locked = False
    try:
        binding_snapshot = _binding_document(binding)
        config_raw, configured_digest = _configuration(gateway_config)
        if (
            not isinstance(_PROTECTED_ROOT, Path)
            or not _PROTECTED_ROOT.is_absolute()
            or _PROTECTED_ROOT == Path(_PROTECTED_ROOT.anchor)
            or type(_EXPECTED_INSTALL_UID) is not int
            or _EXPECTED_INSTALL_UID < 0
        ):
            raise RuntimeSkillStartupError("fixed protected root identity is invalid")
        root_fd = _open_protected_root(_PROTECTED_ROOT, _EXPECTED_INSTALL_UID)
        root_state = os.fstat(root_fd)
        _acquire_shared_lock(root_fd, None)
        locked = True
        entries.append(_HeldEntry(None, _PROTECTED_ROOT, root_fd, root_state))
        record, tree_digest, installed_digest, active_before = _installed_snapshot(
            root_fd, entries
        )
        transaction = record["transaction"]
        target = transaction["destination"]["target_name"]
        external_fd = _external_parent(entries)
        external_raw, _ = _read_file(
            external_fd, _EXTERNAL_SOURCE.name, entries, max_bytes=_MAX_SKILL_BYTES
        )
        external_digest = "sha256:" + hashlib.sha256(external_raw).hexdigest()
        if not external_raw or not (
            installed_digest
            == external_digest
            == binding_snapshot["active_skill_digest"]
            == configured_digest
        ):
            raise RuntimeSkillStartupError(
                "installed, external, worker, and configured skill bytes disagree"
            )
        require_not_quarantined_at(
            root_fd, installed_digest, expected_uid=_EXPECTED_INSTALL_UID
        )
        active_after = _active_link(
            root_fd, target, transaction["version_path"], _EXPECTED_INSTALL_UID
        )
        if _file_identity(active_before) != _file_identity(active_after):
            raise RuntimeSkillStartupError(
                "installed active link changed during the check"
            )
        _check_entries(entries)
        _require_safe_ancestry(_PROTECTED_ROOT.parent, _EXPECTED_INSTALL_UID)
        _require_safe_ancestry(_EXTERNAL_SOURCE.parent, _EXPECTED_INSTALL_UID)
        if (
            _PROTECTED_ROOT.resolve(strict=True) != _PROTECTED_ROOT
            or _EXTERNAL_SOURCE.resolve(strict=True) != _EXTERNAL_SOURCE
            or _binding_document(binding) != binding_snapshot
            or canonical_json(gateway_config) != config_raw
        ):
            raise RuntimeSkillStartupError(
                "startup check inputs changed during verification"
            )
        return {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "active_record_digest": canonical_digest(record),
            "tree_digest": tree_digest,
            "active_skill_digest": installed_digest,
            "source_name": _SKILL_NAME,
            "source_path": str(_EXTERNAL_SOURCE),
            "gateway_config_digest": "sha256:" + hashlib.sha256(config_raw).hexdigest(),
            "worker_binding_digest": canonical_digest(binding_snapshot),
        }
    except RuntimeSkillStartupError:
        raise
    except (
        OSError,
        RuntimeActionBrokerError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise RuntimeSkillStartupError(
            f"startup skill bytes cannot be verified: {exc}"
        ) from exc
    finally:
        cleanup_error = _release_lock_and_close(
            root_fd, locked, *(entry.fd for entry in entries if entry.fd != root_fd)
        )
        if cleanup_error is not None:
            raise RuntimeSkillStartupError(
                "startup byte check cleanup failed"
            ) from cleanup_error
