"""Private exact-byte install transaction primitives without installer authority."""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Callable, Collection, Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any

from .artifact_closure import load_verified_retained_manifest
from .cas import CAS
from .materialization import (
    _freeze_materialized_source_tree,
    verify_materialized_source_tree,
)
from .oci_worker_protocol import canonical_json
from .protected_install_context import (
    VerifiedInstallContextV2,
    verify_protected_install_context_v2,
)

_VERSIONS_DIRECTORY = ".aragorn-versions"
_CLAIMS_DIRECTORY = ".aragorn-install-claims"
_ACTIVE_RUNTIME_RECORD = ".aragorn-active-runtime.json"
_RECORD_AUTHORITY = "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
_ACTIVE_RUNTIME_SCHEMA = "aragorn/protected-active-runtime/v1"
_ACTIVE_RUNTIME_AUTHORITY = (
    "BROKER_ACTIVE_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
)
_MAX_DEPTH = 8
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class ProtectedInstallTransactionError(ValueError):
    """A private exact-byte transaction failed without granting authority."""

    def __init__(
        self,
        message: str,
        *,
        recovery: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.recovery = None if recovery is None else dict(recovery)


def _publish_protected_install_transaction(
    cas: CAS,
    context: Mapping[str, Any],
    root_fd: int,
    *,
    now_unix: int,
    claim_now_unix: int,
    expected_context_digest: str,
    expected_target_name: str,
    expected_runtime_conformance_digest: str,
    measured_target_runtime_digest: str,
    revoked_context_ids: Collection[str],
    expected_active_cas: CAS | None = None,
    claim_state_provider: Callable[[], tuple[int, Collection[str]]] | None = None,
) -> dict[str, Any]:
    """Apply one context-bound link switch without granting installer authority.

    The caller must be a dedicated broker and the only writer below ``root_fd``.
    This private primitive is intentionally absent from the CLI. Its directory
    lock coordinates cooperating broker processes but does not defend against a
    malicious process running as the broker UID.

    Failure before the immutable claim is linked consumes no context. Failure
    after that point retains the claim plus any staged, versioned, or active
    state for explicit recovery and never attempts or reports an automatic
    rollback.

    ``claim_state_provider``, when supplied, is called after staging and replaces
    ``claim_now_unix`` plus ``revoked_context_ids`` for the final pre-claim
    verification. Otherwise ``claim_now_unix`` is an injected trusted clock
    reading taken after staging and must not precede ``now_unix``.

    Updates and rollbacks must supply the separately verified CAS that retains
    the exact active predecessor. Fresh installs must not supply one.
    """

    broker_root_fd = -1
    versions_fd = -1
    target_versions_fd = -1
    claims_fd = -1
    staging_fd = -1
    locked = False
    claimed = False
    staging_name: str | None = None
    claim_temporary_name: str | None = None
    activation_temporary_name: str | None = None
    record: dict[str, Any] | None = None
    try:
        if os.name != "posix":
            raise ProtectedInstallTransactionError(
                "protected install transactions are unsupported on this platform"
            )
        if isinstance(root_fd, bool) or not isinstance(root_fd, int) or root_fd < 0:
            raise ProtectedInstallTransactionError(
                "protected install root fd is invalid"
            )
        if (
            isinstance(claim_now_unix, bool)
            or not isinstance(claim_now_unix, int)
            or isinstance(now_unix, bool)
            or not isinstance(now_unix, int)
            or claim_now_unix < now_unix
        ):
            raise ProtectedInstallTransactionError(
                "protected install claim time is invalid"
            )
        required_dir_fd = {
            os.link,
            os.mkdir,
            os.open,
            os.readlink,
            os.rename,
            os.stat,
            os.symlink,
            os.unlink,
        }
        if not required_dir_fd.issubset(os.supports_dir_fd):
            raise ProtectedInstallTransactionError(
                "descriptor-relative protected installation is unsupported"
            )
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - non-POSIX import guard
            raise ProtectedInstallTransactionError(
                "protected install transaction locking is unsupported"
            ) from exc

        broker_root_fd = os.dup(root_fd)
        os.set_inheritable(broker_root_fd, False)
        root_state = _require_broker_directory(
            broker_root_fd,
            "protected install root",
            require_owner_write=True,
        )
        fcntl.flock(broker_root_fd, fcntl.LOCK_EX)
        locked = True
        locked_root_state = _require_broker_directory(
            broker_root_fd,
            "protected install root",
            require_owner_write=True,
        )
        if _inode(locked_root_state) != _inode(root_state):
            raise ProtectedInstallTransactionError(
                "protected install root identity changed"
            )

        versions_fd = _open_or_create_broker_directory(
            broker_root_fd,
            _VERSIONS_DIRECTORY,
            mode=0o755,
            label="protected install versions directory",
        )
        claims_fd = _open_or_create_broker_directory(
            broker_root_fd,
            _CLAIMS_DIRECTORY,
            mode=0o700,
            label="protected install claims directory",
        )
        verified = verify_protected_install_context_v2(
            cas,
            context,
            broker_root_fd,
            now_unix=now_unix,
            expected_context_digest=expected_context_digest,
            expected_target_name=expected_target_name,
            expected_runtime_conformance_digest=(expected_runtime_conformance_digest),
            measured_target_runtime_digest=measured_target_runtime_digest,
            revoked_context_ids=revoked_context_ids,
        )
        if verified.expected_active_context_id is None:
            if expected_active_cas is not None:
                raise ProtectedInstallTransactionError(
                    "fresh protected install must not supply a predecessor CAS"
                )
            predecessor_cas = cas
        else:
            if expected_active_cas is None:
                raise ProtectedInstallTransactionError(
                    "protected update requires its predecessor CAS"
                )
            predecessor_cas = expected_active_cas
        target_versions_fd = _open_or_create_broker_directory(
            versions_fd,
            verified.target_name,
            mode=0o755,
            label="protected install target versions directory",
        )

        claim_name = _claim_name(verified.context_id)
        _require_absent(claims_fd, claim_name, "protected install context is consumed")
        expected_active_inode = _verify_expected_active(
            predecessor_cas,
            verified,
            broker_root_fd,
            target_versions_fd,
        )

        version_name = _version_name(
            verified.context_id,
            verified.manifest_digest,
        )
        _require_absent(
            target_versions_fd,
            version_name,
            "protected install version already exists without a new claim",
        )

        manifest = load_verified_retained_manifest(cas, verified.manifest_digest)
        staging_name, staging_fd = _create_staging_directory(target_versions_fd)
        _materialize_verified_manifest(cas, manifest, staging_fd)
        tree_digest = verify_materialized_source_tree(
            cas,
            verified.manifest_digest,
            staging_fd,
        )
        _freeze_materialized_source_tree(staging_fd, manifest)
        if (
            verify_materialized_source_tree(
                cas,
                verified.manifest_digest,
                staging_fd,
            )
            != tree_digest
        ):
            raise ProtectedInstallTransactionError(
                "protected install staging changed while it was frozen"
            )
        os.fchmod(staging_fd, 0o555)
        os.fsync(staging_fd)

        claim_revoked_context_ids = revoked_context_ids
        if claim_state_provider is not None:
            try:
                claim_now_unix, claim_revoked_context_ids = claim_state_provider()
            except Exception as exc:
                raise ProtectedInstallTransactionError(
                    f"cannot obtain fresh protected install claim state: {exc}"
                ) from exc
            if (
                isinstance(claim_now_unix, bool)
                or not isinstance(claim_now_unix, int)
                or claim_now_unix < now_unix
            ):
                raise ProtectedInstallTransactionError(
                    "fresh protected install claim time is invalid"
                )
        claim_context = verify_protected_install_context_v2(
            cas,
            context,
            broker_root_fd,
            now_unix=claim_now_unix,
            expected_context_digest=expected_context_digest,
            expected_target_name=expected_target_name,
            expected_runtime_conformance_digest=(expected_runtime_conformance_digest),
            measured_target_runtime_digest=measured_target_runtime_digest,
            revoked_context_ids=claim_revoked_context_ids,
        )
        if claim_context != verified:
            raise ProtectedInstallTransactionError(
                "protected install context changed before claim"
            )
        _require_absent(
            claims_fd,
            claim_name,
            "protected install context is consumed",
        )
        _require_absent(
            target_versions_fd,
            version_name,
            "protected install version appeared before claim",
        )
        _verify_expected_active(
            predecessor_cas,
            claim_context,
            broker_root_fd,
            target_versions_fd,
            expected_inode=expected_active_inode,
        )

        version_path = _version_path(
            claim_context.target_name,
            claim_context.context_id,
            claim_context.manifest_digest,
        )
        record = _transaction_record(
            claim_context,
            tree_digest=tree_digest,
            version_path=version_path,
        )
        record_bytes = canonical_json(record)
        claim_temporary_name, claim_fd = _create_record_file(
            claims_fd,
            prefix=".aragorn-claim-",
        )
        try:
            _write_all(claim_fd, record_bytes)
            os.fchmod(claim_fd, 0o400)
            os.fsync(claim_fd)
        finally:
            os.close(claim_fd)
        os.link(
            claim_temporary_name,
            claim_name,
            src_dir_fd=claims_fd,
            dst_dir_fd=claims_fd,
            follow_symlinks=False,
        )
        claimed = True
        os.fsync(claims_fd)
        os.unlink(claim_temporary_name, dir_fd=claims_fd)
        claim_temporary_name = None

        staging_state = os.fstat(staging_fd)
        named_staging_state = os.stat(
            staging_name,
            dir_fd=target_versions_fd,
            follow_symlinks=False,
        )
        if _inode(staging_state) != _inode(named_staging_state):
            raise ProtectedInstallTransactionError(
                "protected install staging identity changed before versioning"
            )
        os.rename(
            staging_name,
            version_name,
            src_dir_fd=target_versions_fd,
            dst_dir_fd=target_versions_fd,
        )
        staging_name = None
        os.fsync(target_versions_fd)
        named_version_state = os.stat(
            version_name,
            dir_fd=target_versions_fd,
            follow_symlinks=False,
        )
        if _inode(staging_state) != _inode(named_version_state):
            raise ProtectedInstallTransactionError(
                "protected install version identity is indeterminate"
            )

        activation_temporary_name = _create_activation_link(
            broker_root_fd,
            version_path,
        )
        temporary_link_state = os.stat(
            activation_temporary_name,
            dir_fd=broker_root_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISLNK(temporary_link_state.st_mode)
            or temporary_link_state.st_uid != os.geteuid()
            or temporary_link_state.st_nlink != 1
            or os.readlink(
                activation_temporary_name,
                dir_fd=broker_root_fd,
            )
            != version_path
        ):
            raise ProtectedInstallTransactionError(
                "temporary protected install activation link is invalid"
            )

        _verify_expected_active(
            predecessor_cas,
            verified,
            broker_root_fd,
            target_versions_fd,
            expected_inode=expected_active_inode,
        )
        _rename_activation_link(
            broker_root_fd,
            activation_temporary_name,
            verified.target_name,
        )
        activation_temporary_name = None
        active_state = _verify_active_link(
            broker_root_fd,
            verified.target_name,
            version_path,
        )
        if _inode(active_state) != _inode(temporary_link_state):
            raise ProtectedInstallTransactionError(
                "protected install active-link identity is indeterminate"
            )
        _verify_version_tree(
            cas,
            verified.manifest_digest,
            target_versions_fd,
            version_name,
        )
        _publish_active_runtime_record(broker_root_fd, record)
        os.fsync(broker_root_fd)
        return record
    except Exception as exc:
        if claimed:
            raise ProtectedInstallTransactionError(
                "protected install transaction failed after consuming its "
                "single-use context; recoverable state was retained and no "
                f"rollback was attempted: {exc}",
                recovery=record,
            ) from exc
        if staging_name is not None and staging_fd >= 0 and target_versions_fd >= 0:
            try:
                _remove_staging_tree(
                    target_versions_fd,
                    staging_fd,
                    staging_name,
                )
                staging_name = None
            except Exception as cleanup_exc:
                raise ProtectedInstallTransactionError(
                    "protected install transaction failed before consuming its "
                    f"context and staging cleanup failed: {cleanup_exc}"
                ) from cleanup_exc
        raise ProtectedInstallTransactionError(
            f"protected install transaction failed before consuming its context: {exc}"
        ) from exc
    finally:
        if not claimed and claim_temporary_name is not None and claims_fd >= 0:
            try:
                os.unlink(claim_temporary_name, dir_fd=claims_fd)
            except OSError:
                pass
        if locked:
            fcntl.flock(broker_root_fd, fcntl.LOCK_UN)
        for descriptor in (
            staging_fd,
            claims_fd,
            target_versions_fd,
            versions_fd,
            broker_root_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)


def _verify_expected_active(
    cas: CAS,
    context: VerifiedInstallContextV2,
    root_fd: int,
    target_versions_fd: int,
    *,
    expected_inode: tuple[int, int] | None = None,
) -> tuple[int, int] | None:
    if context.expected_active_context_id is None:
        try:
            os.stat(
                context.target_name,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            if expected_inode is not None:
                raise ProtectedInstallTransactionError(
                    "fresh protected install target identity changed"
                )
            return None
        raise ProtectedInstallTransactionError(
            "fresh protected install target already exists"
        )

    if context.expected_active_manifest_digest is None:
        raise ProtectedInstallTransactionError(
            "protected install expected active binding is incomplete"
        )
    version_name = _version_name(
        context.expected_active_context_id,
        context.expected_active_manifest_digest,
    )
    version_path = _version_path(
        context.target_name,
        context.expected_active_context_id,
        context.expected_active_manifest_digest,
    )
    active_state = _verify_active_link(
        root_fd,
        context.target_name,
        version_path,
    )
    active_inode = _inode(active_state)
    if expected_inode is not None and active_inode != expected_inode:
        raise ProtectedInstallTransactionError(
            "protected install active-link identity changed"
        )
    _verify_version_tree(
        cas,
        context.expected_active_manifest_digest,
        target_versions_fd,
        version_name,
    )
    return active_inode


def _verify_active_link(
    root_fd: int,
    target_name: str,
    expected_version_path: str,
) -> os.stat_result:
    before = os.stat(
        target_name,
        dir_fd=root_fd,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISLNK(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or os.readlink(target_name, dir_fd=root_fd) != expected_version_path
    ):
        raise ProtectedInstallTransactionError(
            "protected install active link does not match the expected state"
        )
    after = os.stat(
        target_name,
        dir_fd=root_fd,
        follow_symlinks=False,
    )
    if _inode(before) != _inode(after):
        raise ProtectedInstallTransactionError(
            "protected install active link changed while it was read"
        )
    return after


def _verify_version_tree(
    cas: CAS,
    manifest_digest: str,
    target_versions_fd: int,
    version_name: str,
) -> str:
    version_fd = os.open(
        version_name,
        _DIRECTORY_FLAGS,
        dir_fd=target_versions_fd,
    )
    try:
        state = _require_broker_directory(
            version_fd,
            "protected install immutable version",
            require_owner_write=False,
        )
        named_state = os.stat(
            version_name,
            dir_fd=target_versions_fd,
            follow_symlinks=False,
        )
        if _inode(state) != _inode(named_state):
            raise ProtectedInstallTransactionError(
                "protected install immutable version identity changed"
            )
        return verify_materialized_source_tree(
            cas,
            manifest_digest,
            version_fd,
        )
    finally:
        os.close(version_fd)


def _materialize_verified_manifest(
    cas: CAS,
    manifest: Mapping[str, Any],
    staging_fd: int,
) -> None:
    directories: set[tuple[str, ...]] = set()
    for entry in manifest["files"]:
        parts = PurePosixPath(entry["path"]).parts
        if len(parts) - 1 > _MAX_DEPTH:
            raise ProtectedInstallTransactionError(
                "protected install manifest exceeds the supported depth"
            )
        directories.update(parts[:depth] for depth in range(1, len(parts)))

    for parts in sorted(directories, key=lambda item: (len(item), item)):
        parent_fd = _open_directory_components(staging_fd, parts[:-1])
        try:
            os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)

    file_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for entry in manifest["files"]:
        parts = PurePosixPath(entry["path"]).parts
        parent_fd = _open_directory_components(staging_fd, parts[:-1])
        descriptor = -1
        try:
            content = cas.read(entry["digest"], max_bytes=entry["size"])
            if len(content) != entry["size"]:
                raise ProtectedInstallTransactionError(
                    "retained source blob size changed during materialization"
                )
            descriptor = os.open(
                parts[-1],
                file_flags,
                0o600,
                dir_fd=parent_fd,
            )
            _write_all(descriptor, content)
            os.fchmod(descriptor, 0o555 if entry["executable"] else 0o444)
            os.fsync(descriptor)
            os.fsync(parent_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_fd)
    os.fsync(staging_fd)


def _open_directory_components(
    root_fd: int,
    components: Sequence[str],
) -> int:
    current_fd = os.dup(root_fd)
    os.set_inheritable(current_fd, False)
    try:
        for component in components:
            if component in {"", ".", ".."} or "/" in component:
                raise ProtectedInstallTransactionError(
                    "protected install path component is invalid"
                )
            next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        result = current_fd
        current_fd = -1
        return result
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def _open_or_create_broker_directory(
    parent_fd: int,
    name: str,
    *,
    mode: int,
    label: str,
) -> int:
    created = False
    try:
        os.mkdir(name, mode=mode, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        pass
    descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    try:
        if created:
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            os.fsync(parent_fd)
        state = _require_broker_directory(
            descriptor,
            label,
            require_owner_write=True,
        )
        named_state = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if _inode(state) != _inode(named_state):
            raise ProtectedInstallTransactionError(f"{label} identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _require_broker_directory(
    descriptor: int,
    label: str,
    *,
    require_owner_write: bool,
) -> os.stat_result:
    state = os.fstat(descriptor)
    mode = stat.S_IMODE(state.st_mode)
    if (
        not stat.S_ISDIR(state.st_mode)
        or state.st_nlink < 1
        or state.st_uid != os.geteuid()
        or mode & 0o022
        or not mode & 0o100
        or (require_owner_write and not mode & 0o200)
    ):
        raise ProtectedInstallTransactionError(
            f"{label} must be broker-owned and protected"
        )
    return state


def _create_staging_directory(parent_fd: int) -> tuple[str, int]:
    for _ in range(100):
        name = f".aragorn-stage-{secrets.token_hex(12)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o700)
        os.fsync(parent_fd)
        return name, descriptor
    raise ProtectedInstallTransactionError(
        "cannot allocate protected install staging directory"
    )


def _remove_staging_tree(parent_fd: int, staging_fd: int, name: str) -> None:
    opened = os.fstat(staging_fd)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        _inode(opened) != _inode(named)
        or not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.geteuid()
    ):
        raise ProtectedInstallTransactionError(
            "protected install staging identity changed during cleanup"
        )

    def remove_children(directory_fd: int, depth: int) -> None:
        if depth > _MAX_DEPTH:
            raise ProtectedInstallTransactionError(
                "protected install staging cleanup exceeded supported depth"
            )
        os.fchmod(directory_fd, 0o700)
        with os.scandir(directory_fd) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            if metadata.st_uid != os.geteuid():
                raise ProtectedInstallTransactionError(
                    "protected install staging cleanup found foreign ownership"
                )
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                os.unlink(entry.name, dir_fd=directory_fd)
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                raise ProtectedInstallTransactionError(
                    "protected install staging cleanup found a special entry"
                )
            child_fd = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
            try:
                if _inode(os.fstat(child_fd)) != _inode(metadata):
                    raise ProtectedInstallTransactionError(
                        "protected install staging cleanup identity changed"
                    )
                remove_children(child_fd, depth + 1)
            finally:
                os.close(child_fd)
            os.rmdir(entry.name, dir_fd=directory_fd)
        os.fsync(directory_fd)

    remove_children(staging_fd, 0)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _create_record_file(parent_fd: int, *, prefix: str) -> tuple[str, int]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for _ in range(100):
        name = f"{prefix}{secrets.token_hex(12)}"
        try:
            return name, os.open(name, flags, 0o400, dir_fd=parent_fd)
        except FileExistsError:
            continue
    raise ProtectedInstallTransactionError(
        "cannot allocate protected install claim staging file"
    )


def _create_activation_link(root_fd: int, version_path: str) -> str:
    for _ in range(100):
        name = f".aragorn-activate-{secrets.token_hex(12)}"
        try:
            os.symlink(version_path, name, dir_fd=root_fd)
        except FileExistsError:
            continue
        return name
    raise ProtectedInstallTransactionError(
        "cannot allocate protected install activation link"
    )


def _publish_active_runtime_record(
    root_fd: int,
    transaction: Mapping[str, Any],
) -> None:
    raw = canonical_json(
        {
            "schema": _ACTIVE_RUNTIME_SCHEMA,
            "authority": _ACTIVE_RUNTIME_AUTHORITY,
            "transaction": transaction,
        }
    )
    temporary_name, descriptor = _create_record_file(
        root_fd,
        prefix=".aragorn-active-runtime-",
    )
    try:
        try:
            _write_all(descriptor, raw)
            os.fchmod(descriptor, 0o444)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o444
                or metadata.st_size != len(raw)
            ):
                raise ProtectedInstallTransactionError(
                    "protected active-runtime record metadata is unsafe"
                )
        finally:
            os.close(descriptor)
        os.rename(
            temporary_name,
            _ACTIVE_RUNTIME_RECORD,
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )
        temporary_name = ""
        os.fsync(root_fd)
        retained_fd = os.open(
            _ACTIVE_RUNTIME_RECORD,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=root_fd,
        )
        try:
            retained = os.read(retained_fd, len(raw) + 1)
            metadata = os.fstat(retained_fd)
            if (
                retained != raw
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o444
            ):
                raise ProtectedInstallTransactionError(
                    "protected active-runtime record changed"
                )
        finally:
            os.close(retained_fd)
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=root_fd)
            except OSError:
                pass


def _rename_activation_link(
    root_fd: int,
    temporary_name: str,
    target_name: str,
) -> None:
    os.rename(
        temporary_name,
        target_name,
        src_dir_fd=root_fd,
        dst_dir_fd=root_fd,
    )


def _require_absent(parent_fd: int, name: str, message: str) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ProtectedInstallTransactionError(message)


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise ProtectedInstallTransactionError(
                "protected install write made no progress"
            )
        remaining = remaining[written:]


def _transaction_record(
    context: VerifiedInstallContextV2,
    *,
    tree_digest: str,
    version_path: str,
) -> dict[str, Any]:
    expected_active = (
        None
        if context.expected_active_context_id is None
        else {
            "context_id": context.expected_active_context_id,
            "manifest_digest": context.expected_active_manifest_digest,
        }
    )
    return {
        "schema": "aragorn/protected-install-transaction/v1",
        "authority": _RECORD_AUTHORITY,
        "context_digest": context.context_digest,
        "context_id": context.context_id,
        "operation": context.operation,
        "expected_active": expected_active,
        "manifest_digest": context.manifest_digest,
        "tree_digest": tree_digest,
        "destination": {
            "root_device": context.root_device,
            "root_inode": context.root_inode,
            "target_name": context.target_name,
        },
        "version_path": version_path,
    }


def _claim_name(context_id: str) -> str:
    return f"{context_id.removeprefix('sha256:')}.json"


def _version_name(context_id: str, manifest_digest: str) -> str:
    return (
        f"{context_id.removeprefix('sha256:')}-"
        f"{manifest_digest.removeprefix('sha256:')}"
    )


def _version_path(
    target_name: str,
    context_id: str,
    manifest_digest: str,
) -> str:
    return (
        f"{_VERSIONS_DIRECTORY}/{target_name}/"
        f"{_version_name(context_id, manifest_digest)}"
    )


def _inode(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino
