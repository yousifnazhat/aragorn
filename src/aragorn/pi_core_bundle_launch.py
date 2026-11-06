"""Protected Pi bundle preparation and one-shot activation publication.

This is a supervisor-side gate, not an exec/systemd wrapper. It never starts a
process. A future confined launcher must consume the returned exact bytes and
supply its own child PID to bind_pi_worker_activation. The worker cannot choose
that expected PID or publish this protected record. Neither a prepared bundle
nor this record proves loaded JavaScript custody, health, or an allowed effect.
"""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import socket
import time
from collections.abc import Collection, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import runtime_active_skill_lineage as lineage_base
from .artifact_closure import load_verified_retained_manifest
from .cas import CAS
from .materialization import verify_materialized_source_tree
from .oci_worker_protocol import canonical_digest, canonical_json
from .protected_install_context import verify_protected_install_context_v2
from .runtime_action_broker import _peer_credentials, _read_owned_bytes_at, _require_digest
from .runtime_active_skill_lineage_v2 import hold_runtime_active_skill_lineage
from .runtime_process_profile import (
    PROFILE_AUTHORITY, PROFILE_SCHEMA, RuntimeProcessProfile,
    measure_runtime_process_profile, open_peer_pidfd, require_live_pidfd,
    runtime_process_profile,
)

_DEPLOYMENT_FIELDS = {
    "runtime_commit_or_image", "adapter", "configuration", "worker",
    "os_profile", "policy", "aragorn_version",
}
_MAX_LIFETIME_NS = 30_000_000_000


class PiBundleLaunchError(ValueError):
    """Preparation or binding failed; no automatic retry is permitted."""


@dataclass(slots=True)
class _Lease:
    active: bool = True
    bind_attempted: bool = False


@dataclass(frozen=True, slots=True)
class PreparedPiBundle:
    activation_id: str
    system_prompt: str
    members: tuple[tuple[str, bytes], ...]
    context_digest: str
    manifest_digest: str
    tree_digest: str
    active_record_digest: str
    skill_digest: str
    deployment_digest: str
    policy_digest: str
    expires_at_monotonic_ns: int
    profile_digest: str
    runtime_digest: str
    executable_digest: str
    skill_path: Path
    _lease: _Lease = field(repr=False, compare=False)


def _root() -> None:
    if os.geteuid() != 0:
        raise PiBundleLaunchError("protected Pi supervisor must be root")


def _profile(profile: RuntimeProcessProfile) -> None:
    if type(profile) is not RuntimeProcessProfile or runtime_process_profile({
        "schema": PROFILE_SCHEMA, "authority": PROFILE_AUTHORITY,
        "runtime_digest": profile.runtime_digest,
        "executable_digest": profile.executable_digest,
        "cgroup": profile.cgroup, "skill_path": str(profile.skill_path),
    }) != profile:
        raise PiBundleLaunchError("Pi process profile is not canonical")


@contextmanager
def hold_prepared_pi_bundle(
    cas: CAS, context: Mapping, *, profile: RuntimeProcessProfile,
    grant: Mapping, protected_root: Path, runtime_conformance_digest: str,
    deployment: Mapping, revoked_context_ids: Collection[str], now_unix: int,
    deadline: float,
) -> Iterator[PreparedPiBundle]:
    """Hold current admission and installed bytes while preparing one worker.

    All parameters originate in the protected supervisor, not in Pi requests.
    Deployment digests are expectations, not measurements of a compiled target.
    The existing narrow installed-tree limits are retained. Executable members
    are deliberately refused until a descendant/script launcher is implemented.
    """
    _root()
    _profile(profile)
    if (type(now_unix) is not int or now_unix < 0 or
            type(deadline) not in (int, float) or not math.isfinite(deadline) or
            deadline <= time.monotonic() or deadline > time.monotonic() + 30):
        raise PiBundleLaunchError("Pi preparation deadline is invalid")
    if not isinstance(deployment, Mapping) or set(deployment) != _DEPLOYMENT_FIELDS:
        raise PiBundleLaunchError("Pi deployment dimensions are incomplete")
    pins = {key: _require_digest(deployment[key], key) for key in _DEPLOYMENT_FIELDS}
    if pins["runtime_commit_or_image"] != profile.runtime_digest:
        raise PiBundleLaunchError("Pi runtime is not bound to deployment")
    # Copy mutable caller inputs before any admission/lineage operation.
    import json
    context = json.loads(canonical_json(context))
    grant = json.loads(canonical_json(grant))
    revoked_context_ids = tuple(revoked_context_ids)
    if context.get("policy_digest") != pins["policy"]:
        raise PiBundleLaunchError("Pi admission policy is not deployment-bound")
    root_fd = -1
    lease = _Lease()
    try:
        root_fd = lineage_base._open_protected_root(protected_root, 0)
        # Here PID only identifies the preparing supervisor for the legacy tree
        # verifier's consistency check; this is NOT worker-process attribution.
        attribution = {"pid": os.getpid(), "skill_path": str(profile.skill_path),
                       "active_skill_digest": grant.get("active_skill_digest")}
        with hold_runtime_active_skill_lineage(
            os.getpid(), attribution, grant, protected_root=protected_root,
            expected_install_uid=0, deadline=deadline,
        ) as lineage:
            state = os.fstat(root_fd)
            if (state.st_dev, state.st_ino) != (lineage["root_device"], lineage["root_inode"]):
                raise PiBundleLaunchError("Pi protected root changed")
            verified = verify_protected_install_context_v2(
                cas, context, root_fd, now_unix=now_unix,
                expected_context_digest=grant["install_context_digest"],
                expected_target_name=lineage["target_name"],
                expected_runtime_conformance_digest=runtime_conformance_digest,
                measured_target_runtime_digest=profile.runtime_digest,
                revoked_context_ids=revoked_context_ids,
            )
            if (verified.context_digest != lineage["context_digest"] or
                    verified.manifest_digest != lineage["manifest_digest"] or
                    lineage["version_path"] != (
                        f".aragorn-versions/{verified.target_name}/"
                        f"{verified.context_id[7:]}-{verified.manifest_digest[7:]}"
                    ) or
                    profile.skill_path != protected_root / lineage["version_path"] / "SKILL.md"):
                raise PiBundleLaunchError("Pi admission and installed version differ")
            manifest = load_verified_retained_manifest(cas, verified.manifest_digest)
            if any(entry["executable"] for entry in manifest["files"]):
                raise PiBundleLaunchError("Pi script execution is not supported in this slice")
            version_fd = os.dup(root_fd)
            try:
                for index, part in enumerate(lineage["version_path"].split("/")):
                    child = lineage_base._open_directory_at(
                        version_fd, part, 0, 0o555 if index == 2 else 0o755, "Pi version")
                    previous = version_fd
                    version_fd = child
                    os.close(previous)
                if (os.fstat(version_fd).st_dev, os.fstat(version_fd).st_ino) != (
                        lineage["version_device"], lineage["version_inode"]):
                    raise PiBundleLaunchError("Pi bundle descriptor changed")
                if verify_materialized_source_tree(cas, verified.manifest_digest, version_fd) != lineage["tree_digest"]:
                    raise PiBundleLaunchError("Pi retained bundle tree differs")
                members = []
                for entry in manifest["files"]:
                    parts = entry["path"].split("/")
                    parent_fd = version_fd
                    try:
                        if len(parts) == 2:
                            parent_fd = lineage_base._open_directory_at(
                                version_fd, parts[0], 0, 0o555, "Pi bundle member directory")
                        elif len(parts) != 1:
                            raise PiBundleLaunchError("Pi bundle exceeds supported depth")
                        raw = _read_owned_bytes_at(parent_fd, parts[-1], max_bytes=1024 * 1024,
                            expected_uid=0, exact_mode=0o444, label="Pi admitted member")
                    finally:
                        if parent_fd != version_fd:
                            os.close(parent_fd)
                    if len(raw) != entry["size"] or "sha256:" + hashlib.sha256(raw).hexdigest() != entry["digest"]:
                        raise PiBundleLaunchError("Pi consumed member differs from admitted bytes")
                    members.append((entry["path"], raw))
                verify_materialized_source_tree(cas, verified.manifest_digest, version_fd)
            finally:
                os.close(version_fd)
            skill_raw = dict(members).get("SKILL.md", b"")
            if not skill_raw or len(skill_raw) > 32 * 1024:
                raise PiBundleLaunchError("Pi prompt is empty or exceeds worker limit")
            system_prompt = skill_raw.decode("utf-8", errors="strict")
            remaining = verified.expires_at_unix - max(now_unix, time.time())
            if remaining <= 0 or time.monotonic() >= deadline:
                raise PiBundleLaunchError("Pi admission expired during preparation")
            expires = min(int(deadline * 1e9), time.monotonic_ns() + _MAX_LIFETIME_NS,
                          time.monotonic_ns() + int(remaining * 1e9))
            prepared = PreparedPiBundle(
                secrets.token_hex(16), system_prompt, tuple(members), verified.context_digest,
                verified.manifest_digest, lineage["tree_digest"], lineage["active_record_digest"],
                grant["active_skill_digest"], canonical_digest(pins), pins["policy"], expires, profile.digest,
                profile.runtime_digest, profile.executable_digest, profile.skill_path, lease,
            )
            yield prepared
    finally:
        lease.active = False
        if root_fd >= 0:
            os.close(root_fd)


def bind_pi_worker_activation(
    prepared: PreparedPiBundle, connection: socket.socket, *, expected_pid: int,
    expected_uid: int, expected_gid: int, profile: RuntimeProcessProfile,
    activation_path: Path,
) -> dict:
    """Publish once for an externally launched, kernel-authenticated worker.

    expected_pid is the protected supervisor's actual child PID, never a value
    from the worker. This operation does not launch that child or enable an
    effect. Errors preserve any partially published file for inspection; there
    is no deletion, retry or fallback to the legacy UID-only request handler.
    """
    from .pi_core_worker_identity import _boot_id, validate_activation
    _root()
    if type(prepared) is not PreparedPiBundle or not prepared._lease.active or prepared._lease.bind_attempted:
        raise PiBundleLaunchError("Pi preparation is inactive or already consumed")
    prepared._lease.bind_attempted = True
    _profile(profile)
    if profile.digest != prepared.profile_digest or profile.skill_path != prepared.skill_path:
        raise PiBundleLaunchError("Pi activation profile changed")
    if any(type(value) is not int or value <= 0 or value > 0xffffffff
           for value in (expected_pid, expected_uid, expected_gid)):
        raise PiBundleLaunchError("Pi expected child identity is invalid")
    if tuple(_peer_credentials(connection)) != (expected_pid, expected_uid, expected_gid):
        raise PiBundleLaunchError("Pi accepted peer is not the supervisor's child")
    if time.monotonic_ns() >= prepared.expires_at_monotonic_ns:
        raise PiBundleLaunchError("Pi preparation expired")
    pidfd = open_peer_pidfd(connection, expected_pid)
    parent_fd = -1
    try:
        observed = measure_runtime_process_profile(expected_pid, pidfd, profile,
            expected_uid=expected_uid, expected_gid=expected_gid)
        if observed["active_skill_digest"] != prepared.skill_digest:
            raise PiBundleLaunchError("Pi peer sees different admitted instructions")
        boot_id = _boot_id()
        document = {
            "schema": "aragorn/pi-core-activation/v1",
            "authority": "PROTECTED_LAUNCHER_BINDING_ONLY_NOT_EFFECT_AUTHORITY",
            "activation_id": prepared.activation_id, "session_id": prepared.activation_id,
            "run_id": prepared.activation_id, "pid": expected_pid, "uid": expected_uid,
            "gid": expected_gid, "start_time_ticks": observed["start_time_ticks"],
            "mount_namespace": observed["mount_namespace"], "cgroup": observed["cgroup"],
            "profile_digest": prepared.profile_digest, "runtime_digest": prepared.runtime_digest,
            "executable_digest": prepared.executable_digest, "active_skill_digest": prepared.skill_digest,
            "install_context_digest": prepared.context_digest, "source_manifest_digest": prepared.manifest_digest,
            "tree_digest": prepared.tree_digest, "active_record_digest": prepared.active_record_digest,
            "deployment_digest": prepared.deployment_digest,
            "policy_digest": prepared.policy_digest,
            "expires_at_monotonic_ns": prepared.expires_at_monotonic_ns, "boot_id": boot_id,
        }
        validate_activation(document)
        if (not isinstance(activation_path, Path) or
                activation_path.name != prepared.activation_id + ".json"):
            raise PiBundleLaunchError("Pi activation filename must match fresh identity")
        parent_fd = lineage_base._open_protected_root(activation_path.parent, 0)
        if measure_runtime_process_profile(expected_pid, pidfd, profile,
                expected_uid=expected_uid, expected_gid=expected_gid) != observed:
            raise PiBundleLaunchError("Pi child identity changed during binding")
        require_live_pidfd(pidfd)
        if time.monotonic_ns() >= prepared.expires_at_monotonic_ns:
            raise PiBundleLaunchError("Pi preparation expired before publication")
        descriptor = os.open(activation_path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        try:
            raw = canonical_json(document)
            view = memoryview(raw)
            while view:
                size = os.write(descriptor, view)
                if size <= 0:
                    raise PiBundleLaunchError("Pi activation publication stalled")
                view = view[size:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o444)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_fd)
        return document
    finally:
        try:
            if parent_fd >= 0:
                os.close(parent_fd)
        finally:
            os.close(pidfd)
