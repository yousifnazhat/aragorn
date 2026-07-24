"""Bounded, cross-owner CAS handoff for protocol-v2 benchmark jobs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

from .benchmark_semantic_closure_v2 import (
    SemanticClosureError,
    derive_worker_input_cas_closure,
    derive_worker_input_closure,
    derive_worker_output_cas_closure,
    derive_worker_output_closure,
)
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HANDOFF_KEYS = {"schema", "kind", "root_digest", "blobs", "total_bytes"}
_BLOB_KEYS = {"digest", "size"}
# Input includes up to 128 MiB each for subject files and the bounded manifest,
# plus an 8 MiB policy and 64 KiB request; 288 MiB is the rounded hard ceiling.
_LIMITS = {
    "worker_input": {
        "blobs": 10_016,
        "blob_bytes": 128 * 1024 * 1024,
        "total_bytes": 288 * 1024 * 1024,
    },
    "worker_output": {
        "blobs": 25_000,
        "blob_bytes": 128 * 1024 * 1024,
        "total_bytes": 512 * 1024 * 1024,
    },
}
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024
_MAX_DIRECTORY_DEPTH = 1024


class HandoffError(ValueError):
    """A protocol-v2 CAS closure could not cross a principal boundary safely."""


def build_handoff_manifest(
    *,
    kind: str,
    root_digest: str,
    blobs: dict[str, int],
) -> dict[str, Any]:
    """Build one canonical declaration for an exact transferable CAS closure."""

    if not isinstance(blobs, dict):
        raise HandoffError("handoff blobs must be a digest-to-size object")
    try:
        copied_blobs = dict(blobs)
        entries = sorted(copied_blobs.items())
    except (RuntimeError, TypeError) as exc:
        raise HandoffError("handoff blobs could not be copied canonically") from exc
    document = {
        "schema": "aragorn/benchmark-cas-handoff/v1",
        "kind": kind,
        "root_digest": root_digest,
        "blobs": [{"digest": digest, "size": size} for digest, size in entries],
        "total_bytes": sum(
            size for size in copied_blobs.values() if isinstance(size, int)
        ),
    }
    validate_handoff_manifest(document)
    return document


def validate_handoff_manifest(document: object) -> None:
    """Validate the exact bounded handoff manifest contract."""

    handoff = _exact_object(document, _HANDOFF_KEYS, "handoff manifest")
    if handoff["schema"] != "aragorn/benchmark-cas-handoff/v1":
        raise HandoffError("handoff manifest schema is unsupported")
    kind = handoff["kind"]
    if not isinstance(kind, str) or kind not in _LIMITS:
        raise HandoffError("handoff manifest kind is unsupported")
    limits = _LIMITS[kind]
    root_digest = _digest(handoff["root_digest"], "handoff manifest root_digest")

    blobs = handoff["blobs"]
    if not isinstance(blobs, list) or not 1 <= len(blobs) <= limits["blobs"]:
        raise HandoffError("handoff manifest blobs must be a bounded non-empty array")
    normalized: list[tuple[str, int]] = []
    for index, raw_blob in enumerate(blobs):
        label = f"handoff manifest blobs[{index}]"
        blob = _exact_object(raw_blob, _BLOB_KEYS, label)
        digest = _digest(blob["digest"], f"{label}.digest")
        size = blob["size"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= limits["blob_bytes"]
        ):
            raise HandoffError(f"{label}.size is outside the bounded range")
        normalized.append((digest, size))
    if normalized != sorted(normalized):
        raise HandoffError("handoff manifest blobs must be sorted by digest")
    digests = [digest for digest, _size in normalized]
    if len(digests) != len(set(digests)):
        raise HandoffError("handoff manifest repeats a blob digest")
    if root_digest not in digests:
        raise HandoffError("handoff manifest root_digest is not retained")

    total_bytes = handoff["total_bytes"]
    if (
        isinstance(total_bytes, bool)
        or not isinstance(total_bytes, int)
        or not 0 <= total_bytes <= limits["total_bytes"]
    ):
        raise HandoffError("handoff manifest total_bytes is outside the bounded range")
    if total_bytes != sum(size for _digest_value, size in normalized):
        raise HandoffError("handoff manifest total_bytes does not match its blobs")


def handoff_manifest_digest(document: object) -> str:
    """Return the canonical SHA-256 identity of a valid handoff manifest."""

    validate_handoff_manifest(document)
    return canonical_digest(document)


def build_worker_input_handoff_manifest(
    source_cas: CAS,
    request_digest: str,
    *,
    expected_verifier_challenge: str,
) -> dict[str, Any]:
    """Build a handoff manifest from the request's exact semantic closure."""

    try:
        blobs = derive_worker_input_cas_closure(
            source_cas,
            request_digest,
            expected_challenge=expected_verifier_challenge,
        )
        return build_handoff_manifest(
            kind="worker_input",
            root_digest=request_digest,
            blobs=blobs,
        )
    except (SemanticClosureError, CASError) as exc:
        raise HandoffError(f"cannot derive worker-input closure: {exc}") from exc


def build_worker_output_handoff_manifest(
    source_cas: CAS,
    result_digest: str,
    *,
    expected_request_digest: str,
    expected_verifier_challenge: str,
) -> dict[str, Any]:
    """Build a handoff manifest from the result's exact semantic closure."""

    try:
        blobs = derive_worker_output_cas_closure(
            source_cas,
            result_digest,
            expected_request_digest=expected_request_digest,
            expected_challenge=expected_verifier_challenge,
        )
        return build_handoff_manifest(
            kind="worker_output",
            root_digest=result_digest,
            blobs=blobs,
        )
    except (SemanticClosureError, CASError) as exc:
        raise HandoffError(f"cannot derive worker-output closure: {exc}") from exc


def export_handoff(
    source_cas: CAS,
    manifest: object,
    destination: str | os.PathLike[str],
    *,
    expected_request_digest: str | None = None,
    expected_verifier_challenge: str | None = None,
) -> str:
    """Publish a semantically verified closure as a fresh transport directory."""

    return _export_handoff(
        source_cas,
        manifest,
        destination,
        expected_request_digest=expected_request_digest,
        expected_verifier_challenge=expected_verifier_challenge,
        semantic_validation=True,
    )


def export_declared_byte_transport(
    source_cas: CAS,
    manifest: object,
    destination: str | os.PathLike[str],
) -> str:
    """Export declared bytes only; this is never semantic handoff acceptance."""

    return _export_handoff(
        source_cas,
        manifest,
        destination,
        expected_request_digest=None,
        expected_verifier_challenge=None,
        semantic_validation=False,
    )


def _export_handoff(
    source_cas: CAS,
    manifest: object,
    destination: str | os.PathLike[str],
    *,
    expected_request_digest: str | None,
    expected_verifier_challenge: str | None,
    semantic_validation: bool,
) -> str:
    """Implement the shared immutable byte export."""

    try:
        raw_manifest = canonical_json(manifest)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise HandoffError(f"cannot copy handoff manifest canonically: {exc}") from exc
    frozen_manifest = _decode_manifest(raw_manifest)
    validate_handoff_manifest(frozen_manifest)
    if semantic_validation:
        _verify_semantic_manifest_from_cas(
            source_cas,
            frozen_manifest,
            expected_request_digest=expected_request_digest,
            expected_verifier_challenge=expected_verifier_challenge,
        )
    target = _fresh_destination(destination, source_root=source_cas.root)
    manifest_digest = "sha256:" + hashlib.sha256(raw_manifest).hexdigest()
    staging: Path | None = None
    published = False
    try:
        staging = Path(tempfile.mkdtemp(prefix=".aragorn-handoff-", dir=target.parent))
        blobs_directory = staging / "blobs"
        blobs_directory.mkdir(mode=0o700)
        for item in frozen_manifest["blobs"]:
            digest = item["digest"]
            size = item["size"]
            source_cas.verify(digest, max_bytes=size)
            blob_path = blobs_directory / digest.removeprefix("sha256:")
            source_cas.materialize(digest, blob_path, root=staging)
            metadata = os.lstat(blob_path)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != size:
                raise HandoffError(f"exported blob size changed: {digest}")
        _write_new_file(staging, "manifest.json", raw_manifest)
        _fsync_directory(blobs_directory)
        _fsync_directory(staging)
        os.rename(staging, target)
        published = True
        _fsync_directory(target.parent)
        return manifest_digest
    except HandoffError:
        raise
    except (CASError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HandoffError(f"cannot export handoff: {exc}") from exc
    finally:
        if staging is not None and not published:
            shutil.rmtree(staging, ignore_errors=True)


def import_handoff(
    source: str | os.PathLike[str],
    destination_cas: CAS,
    *,
    expected_manifest_digest: str,
    expected_kind: str,
    expected_root_digest: str,
    expected_request_digest: str | None = None,
    expected_verifier_challenge: str | None = None,
) -> dict[str, Any]:
    """Semantically verify one handoff before receiver-owned CAS publication."""

    return _import_handoff(
        source,
        destination_cas,
        expected_manifest_digest=expected_manifest_digest,
        expected_kind=expected_kind,
        expected_root_digest=expected_root_digest,
        expected_request_digest=expected_request_digest,
        expected_verifier_challenge=expected_verifier_challenge,
        semantic_validation=True,
    )


def import_declared_byte_transport(
    source: str | os.PathLike[str],
    destination_cas: CAS,
    *,
    expected_manifest_digest: str,
    expected_kind: str,
    expected_root_digest: str,
) -> dict[str, Any]:
    """Import declared bytes only; this is never semantic handoff acceptance."""

    return _import_handoff(
        source,
        destination_cas,
        expected_manifest_digest=expected_manifest_digest,
        expected_kind=expected_kind,
        expected_root_digest=expected_root_digest,
        expected_request_digest=None,
        expected_verifier_challenge=None,
        semantic_validation=False,
    )


def _import_handoff(
    source: str | os.PathLike[str],
    destination_cas: CAS,
    *,
    expected_manifest_digest: str,
    expected_kind: str,
    expected_root_digest: str,
    expected_request_digest: str | None,
    expected_verifier_challenge: str | None,
    semantic_validation: bool,
) -> dict[str, Any]:
    """Implement shared staged import and digest verification."""

    expected_manifest_digest = _digest(
        expected_manifest_digest,
        "expected handoff manifest digest",
    )
    if expected_kind not in _LIMITS:
        raise HandoffError("expected handoff kind is unsupported")
    expected_root_digest = _digest(
        expected_root_digest,
        "expected handoff root digest",
    )

    root_fd = -1
    blobs_fd = -1
    destination_fd = -1
    staging_fd = -1
    staging_name: str | None = None
    try:
        root_fd = _open_bundle_root(source)
        destination_fd = _open_existing_directory(
            destination_cas.root,
            "destination CAS",
        )
        if _directories_overlap(root_fd, destination_fd):
            raise HandoffError("handoff source and destination CAS must not overlap")
        root_before = os.fstat(root_fd)
        if _list_names(root_fd, "handoff root", maximum=2) != [
            "blobs",
            "manifest.json",
        ]:
            raise HandoffError("handoff root has missing or unknown entries")

        raw_manifest = _read_named_file(
            root_fd,
            "manifest.json",
            max_bytes=_MAX_MANIFEST_BYTES,
            label="handoff manifest",
        )
        actual_manifest_digest = "sha256:" + hashlib.sha256(raw_manifest).hexdigest()
        if actual_manifest_digest != expected_manifest_digest:
            raise HandoffError("handoff manifest digest does not match expectation")
        manifest = _decode_manifest(raw_manifest)
        validate_handoff_manifest(manifest)
        if manifest["kind"] != expected_kind:
            raise HandoffError("handoff kind does not match expectation")
        if manifest["root_digest"] != expected_root_digest:
            raise HandoffError("handoff root digest does not match expectation")

        blobs_fd = _open_directory_at(root_fd, "blobs", "handoff blobs")
        blobs_before = os.fstat(blobs_fd)
        expected_names = [
            item["digest"].removeprefix("sha256:") for item in manifest["blobs"]
        ]
        if _list_names(
            blobs_fd,
            "handoff blobs",
            maximum=_LIMITS[expected_kind]["blobs"],
        ) != sorted(expected_names):
            raise HandoffError("handoff blobs do not match the exact manifest")

        staging_fd, staging_name = _create_private_staging(destination_fd)
        source_identities: dict[str, tuple[int, ...]] = {}
        for item in manifest["blobs"]:
            source_identities[item["digest"]] = _stage_blob(
                blobs_fd,
                item["digest"],
                item["size"],
                staging_fd,
            )

        if _stable_identity(root_before) != _stable_identity(os.fstat(root_fd)):
            raise HandoffError("handoff root changed while it was imported")
        if _stable_identity(blobs_before) != _stable_identity(os.fstat(blobs_fd)):
            raise HandoffError("handoff blobs changed while they were imported")
        if _list_names(root_fd, "handoff root", maximum=2) != [
            "blobs",
            "manifest.json",
        ]:
            raise HandoffError("handoff root changed while it was imported")
        if _list_names(
            blobs_fd,
            "handoff blobs",
            maximum=_LIMITS[expected_kind]["blobs"],
        ) != sorted(expected_names):
            raise HandoffError("handoff blobs changed while they were imported")
        if (
            _read_named_file(
                root_fd,
                "manifest.json",
                max_bytes=_MAX_MANIFEST_BYTES,
                label="handoff manifest",
            )
            != raw_manifest
        ):
            raise HandoffError("handoff manifest changed while it was imported")
        for item in manifest["blobs"]:
            _verify_named_blob_identity(
                blobs_fd,
                item["digest"],
                source_identities[item["digest"]],
            )
        if semantic_validation:
            _verify_semantic_manifest_from_staging(
                staging_fd,
                manifest,
                expected_request_digest=expected_request_digest,
                expected_verifier_challenge=expected_verifier_challenge,
            )

        # No untrusted-input validation remains after this point. Only the
        # receiver-owned, digest-verified snapshot can enter the trusted CAS.
        # Publish the root last so an operational failure cannot expose a root
        # before every other declared blob has been retained.
        commit_order = [
            item
            for item in manifest["blobs"]
            if item["digest"] != manifest["root_digest"]
        ] + [
            item
            for item in manifest["blobs"]
            if item["digest"] == manifest["root_digest"]
        ]
        for item in commit_order:
            _commit_staged_blob(
                staging_fd,
                item["digest"],
                item["size"],
                destination_cas,
            )
        for item in manifest["blobs"]:
            destination_cas.verify(item["digest"], max_bytes=item["size"])
        return json.loads(canonical_json(manifest))
    except HandoffError:
        raise
    except (CASError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HandoffError(f"cannot import handoff: {exc}") from exc
    finally:
        if staging_fd >= 0:
            _remove_private_staging(
                destination_fd,
                staging_fd,
                staging_name,
            )
        if destination_fd >= 0:
            os.close(destination_fd)
        if blobs_fd >= 0:
            os.close(blobs_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _fresh_destination(
    destination: str | os.PathLike[str],
    *,
    source_root: Path,
) -> Path:
    try:
        supplied = Path(os.path.abspath(os.path.expanduser(os.fspath(destination))))
        if not supplied.name or supplied == Path(supplied.anchor):
            raise HandoffError("handoff destination must not be a filesystem root")
        parent = supplied.parent.resolve(strict=True)
        target = parent / supplied.name
        parent_metadata = os.lstat(parent)
    except HandoffError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HandoffError(f"invalid handoff destination: {exc}") from exc
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise HandoffError("handoff destination parent must be a directory")
    if os.name == "posix" and (
        parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise HandoffError(
            "handoff destination parent must be owned by the current user "
            "and not group or other writable"
        )
    if os.path.lexists(target):
        raise HandoffError(f"handoff destination already exists: {target}")
    source = source_root.resolve(strict=True)
    if _paths_overlap(source, target):
        raise HandoffError("handoff destination must not overlap its source CAS")
    return target


def _open_bundle_root(source: str | os.PathLike[str]) -> int:
    try:
        descriptor = _open_existing_directory(source, "handoff source")
    except HandoffError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HandoffError(f"invalid handoff source: {exc}") from exc
    return descriptor


def _open_existing_directory(
    path: str | os.PathLike[str],
    label: str,
) -> int:
    """Open a directory through a canonical parent and bind its final entry."""

    descriptor = -1
    parent_fd = -1
    try:
        supplied = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
        if supplied == Path(supplied.anchor):
            return _open_absolute_directory(supplied, label)
        parent = supplied.parent.resolve(strict=True)
        parent_fd = _open_absolute_directory(parent, f"{label} parent")
        before = os.stat(
            supplied.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise HandoffError(f"{label} must be a real directory")
        flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(supplied.name, flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        current = os.stat(
            supplied.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not (
            _directory_identity(before)
            == _directory_identity(opened)
            == _directory_identity(current)
        ):
            raise HandoffError(f"{label} changed while it was opened")
        if not stat.S_ISDIR(opened.st_mode):
            raise HandoffError(f"{label} must be a directory")
        result = descriptor
        descriptor = -1
        return result
    except HandoffError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise HandoffError(f"{label} is not a stable directory: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _open_absolute_directory(path: Path, label: str) -> int:
    if not path.is_absolute():
        raise HandoffError(f"{label} path must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(path.anchor, flags)
        for part in path.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        result = descriptor
        descriptor = -1
        return result
    except OSError as exc:
        raise HandoffError(
            f"{label} contains a symlink or non-directory component: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_directory_at(parent_fd: int, name: str, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise HandoffError(f"{label} is not a real directory: {exc}") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise HandoffError(f"{label} is not a directory")
    return descriptor


def _create_private_staging(parent_fd: int) -> tuple[int, str]:
    for _ in range(100):
        name = f".aragorn-handoff-import-{secrets.token_hex(12)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError as exc:
            raise HandoffError(f"cannot create handoff import staging: {exc}") from exc
        descriptor = -1
        try:
            descriptor = _open_directory_at(
                parent_fd,
                name,
                "handoff import staging",
            )
            os.fchmod(descriptor, 0o700)
            return descriptor, name
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
    raise HandoffError("cannot allocate handoff import staging")


def _remove_private_staging(
    parent_fd: int,
    staging_fd: int,
    name: str | None,
) -> None:
    try:
        with os.scandir(staging_fd) as entries:
            for entry in entries:
                try:
                    os.unlink(entry.name, dir_fd=staging_fd)
                except OSError:
                    pass
    except OSError:
        pass
    finally:
        os.close(staging_fd)
    if parent_fd >= 0 and name is not None:
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            pass


def _verify_semantic_manifest_from_cas(
    source_cas: CAS,
    manifest: dict[str, Any],
    *,
    expected_request_digest: str | None,
    expected_verifier_challenge: str | None,
) -> None:
    if manifest["kind"] == "worker_input":
        if expected_request_digest is not None:
            raise HandoffError(
                "expected request digest is valid only for worker_output"
            )
        if expected_verifier_challenge is None:
            raise HandoffError("worker_input requires an expected verifier challenge")
        try:
            derived = derive_worker_input_cas_closure(
                source_cas,
                manifest["root_digest"],
                expected_challenge=expected_verifier_challenge,
            )
        except SemanticClosureError as exc:
            raise HandoffError(
                f"worker-input semantic closure is invalid: {exc}"
            ) from exc
        _require_exact_semantic_closure(manifest, derived)
        return

    if expected_request_digest is None or expected_verifier_challenge is None:
        raise HandoffError(
            "semantic worker_output requires an expected request digest "
            "and verifier challenge"
        )
    try:
        derived = derive_worker_output_cas_closure(
            source_cas,
            manifest["root_digest"],
            expected_request_digest=expected_request_digest,
            expected_challenge=expected_verifier_challenge,
        )
    except SemanticClosureError as exc:
        raise HandoffError(f"worker-output semantic closure is invalid: {exc}") from exc
    _require_exact_semantic_closure(manifest, derived)


def _verify_semantic_manifest_from_staging(
    staging_fd: int,
    manifest: dict[str, Any],
    *,
    expected_request_digest: str | None,
    expected_verifier_challenge: str | None,
) -> None:
    def read_blob(digest: str, maximum: int) -> bytes:
        return _read_named_file(
            staging_fd,
            digest.removeprefix("sha256:"),
            max_bytes=maximum,
            label=f"staged {manifest['kind'].replace('_', '-')} blob {digest}",
        )

    if manifest["kind"] == "worker_input":
        if expected_request_digest is not None:
            raise HandoffError(
                "expected request digest is valid only for worker_output"
            )
        if expected_verifier_challenge is None:
            raise HandoffError("worker_input requires an expected verifier challenge")
        try:
            derived = derive_worker_input_closure(
                read_blob,
                manifest["root_digest"],
                expected_challenge=expected_verifier_challenge,
            )
        except SemanticClosureError as exc:
            raise HandoffError(
                f"worker-input semantic closure is invalid: {exc}"
            ) from exc
        _require_exact_semantic_closure(manifest, derived)
        return

    if expected_request_digest is None or expected_verifier_challenge is None:
        raise HandoffError(
            "semantic worker_output requires an expected request digest "
            "and verifier challenge"
        )
    try:
        derived = derive_worker_output_closure(
            read_blob,
            manifest["root_digest"],
            expected_request_digest=expected_request_digest,
            expected_challenge=expected_verifier_challenge,
        )
    except SemanticClosureError as exc:
        raise HandoffError(f"worker-output semantic closure is invalid: {exc}") from exc
    _require_exact_semantic_closure(manifest, derived)


def _require_exact_semantic_closure(
    manifest: dict[str, Any],
    derived: dict[str, int],
) -> None:
    declared = {item["digest"]: item["size"] for item in manifest["blobs"]}
    if declared == derived:
        return
    missing = sorted(set(derived) - set(declared))[:8]
    extra = sorted(set(declared) - set(derived))[:8]
    wrong_size = sorted(
        digest
        for digest in set(declared) & set(derived)
        if declared[digest] != derived[digest]
    )[:8]
    label = manifest["kind"].replace("_", "-")
    raise HandoffError(
        f"{label} handoff is not the exact semantic closure; "
        f"missing={missing!r}, extra={extra!r}, wrong_size={wrong_size!r}"
    )


def _read_named_file(
    parent_fd: int,
    name: str,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise HandoffError(f"{label} must be a singly linked regular file")
        if before.st_size > max_bytes:
            raise HandoffError(f"{label} exceeds its byte limit")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            raw = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
        if len(raw) > max_bytes:
            raise HandoffError(f"{label} exceeds its byte limit")
        if len(raw) != before.st_size or _stable_identity(before) != _stable_identity(
            after
        ):
            raise HandoffError(f"{label} changed while it was read")
        return raw
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _decode_manifest(raw: bytes) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise HandoffError(f"invalid handoff manifest JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise HandoffError("handoff manifest must be a JSON object")
    if canonical_json(document) != raw:
        raise HandoffError("handoff manifest must be canonical JSON")
    return document


def _stage_blob(
    directory_fd: int,
    digest: str,
    size: int,
    staging_fd: int,
) -> tuple[int, ...]:
    name = digest.removeprefix("sha256:")
    read_flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    source_descriptor = -1
    staging_descriptor = -1
    source_stream = None
    staging_stream = None
    try:
        source_descriptor = os.open(name, read_flags, dir_fd=directory_fd)
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise HandoffError(
                f"handoff blob is not a singly linked regular file: {digest}"
            )
        if before.st_size != size:
            raise HandoffError(f"handoff blob size does not match: {digest}")
        staging_descriptor = os.open(
            name,
            write_flags,
            0o600,
            dir_fd=staging_fd,
        )
        content_digest = hashlib.sha256()
        total = 0
        source_stream = os.fdopen(source_descriptor, "rb", closefd=True)
        source_descriptor = -1
        staging_stream = os.fdopen(staging_descriptor, "wb", closefd=True)
        staging_descriptor = -1
        with source_stream, staging_stream:
            while True:
                chunk = source_stream.read(_COPY_CHUNK_BYTES)
                if not isinstance(chunk, bytes):
                    raise HandoffError(f"handoff blob is not a byte stream: {digest}")
                if not chunk:
                    break
                total += len(chunk)
                if total > size:
                    raise HandoffError(f"handoff blob size does not match: {digest}")
                staging_stream.write(chunk)
                content_digest.update(chunk)
            after = os.fstat(source_stream.fileno())
            if total != size:
                raise HandoffError(f"handoff blob size does not match: {digest}")
            if _stable_identity(before) != _stable_identity(after):
                raise HandoffError(f"handoff blob changed while imported: {digest}")
            actual = "sha256:" + content_digest.hexdigest()
            if actual != digest:
                raise HandoffError(f"handoff blob digest does not match: {digest}")
            staging_stream.flush()
            os.fchmod(staging_stream.fileno(), 0o444)
            os.fsync(staging_stream.fileno())

        return _stable_identity(after)
    finally:
        if staging_stream is not None and not staging_stream.closed:
            staging_stream.close()
        if source_stream is not None and not source_stream.closed:
            source_stream.close()
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)


def _verify_named_blob_identity(
    directory_fd: int,
    digest: str,
    expected: tuple[int, ...],
) -> None:
    name = digest.removeprefix("sha256:")
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise HandoffError(f"handoff blob changed while imported: {digest}") from exc
    if _stable_identity(current) != expected:
        raise HandoffError(f"handoff blob changed while imported: {digest}")


def _commit_staged_blob(
    staging_fd: int,
    digest: str,
    size: int,
    destination_cas: CAS,
) -> None:
    name = digest.removeprefix("sha256:")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=staging_fd)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != size
        ):
            raise HandoffError(f"staged handoff blob is invalid: {digest}")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            actual = destination_cas.put_expected(
                stream,
                expected_digest=digest,
                max_bytes=size,
            )
            after = os.fstat(stream.fileno())
        if _stable_identity(before) != _stable_identity(after):
            raise HandoffError(f"staged handoff blob changed: {digest}")
        if actual != digest:
            raise HandoffError(f"staged handoff blob digest does not match: {digest}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_new_file(directory: Path, name: str, content: bytes) -> None:
    directory_fd = -1
    descriptor = -1
    try:
        directory_fd = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o444,
            dir_fd=directory_fd,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), 0o444)
            os.fsync(stream.fileno())
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            os.close(directory_fd)


def _list_names(directory_fd: int, label: str, *, maximum: int) -> list[str]:
    try:
        names = []
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum:
                    raise HandoffError(f"{label} exceeds its entry limit")
    except OSError as exc:
        raise HandoffError(f"cannot enumerate {label}: {exc}") from exc
    if len(names) != len(set(names)):
        raise HandoffError(f"{label} repeats an entry")
    return sorted(names)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _directories_overlap(first_fd: int, second_fd: int) -> bool:
    """Bind ancestor checks to opened directories rather than path strings."""

    return _directory_is_ancestor(first_fd, second_fd) or _directory_is_ancestor(
        second_fd,
        first_fd,
    )


def _directory_is_ancestor(ancestor_fd: int, descendant_fd: int) -> bool:
    expected = _directory_identity(os.fstat(ancestor_fd))
    current_fd = os.dup(descendant_fd)
    try:
        for _ in range(_MAX_DIRECTORY_DEPTH):
            current = _directory_identity(os.fstat(current_fd))
            if current == expected:
                return True
            parent_fd = _open_directory_at(
                current_fd,
                "..",
                "directory ancestry",
            )
            parent = _directory_identity(os.fstat(parent_fd))
            if parent == current:
                os.close(parent_fd)
                return False
            os.close(current_fd)
            current_fd = parent_fd
        raise HandoffError("directory ancestry exceeds its depth limit")
    finally:
        os.close(current_fd)


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _exact_object(
    value: object,
    expected: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HandoffError(f"{label} must be a JSON object")
    if set(value) != expected:
        raise HandoffError(f"{label} has missing or unknown fields")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise HandoffError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HandoffError(f"duplicate handoff manifest JSON key: {key}")
        result[key] = value
    return result


def _reject_float(value: str) -> None:
    raise HandoffError(f"handoff manifest JSON number must be an integer: {value}")


def _reject_constant(value: str) -> None:
    raise HandoffError(f"non-finite handoff manifest JSON value: {value}")
