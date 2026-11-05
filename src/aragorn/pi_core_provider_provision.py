"""Absent-only provisioning of exactly two reviewed public provider inputs.

This copies a public profile and dedicated CA bytes, not credentials, service
code, an interpreter or a service unit. No target activation, trust validation,
rollback or repair occurs. Every partial destination is retained on failure.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from collections.abc import Mapping

from . import pi_core_openai_responses as codec
from . import pi_core_os_provision as provision
from .oci_worker_protocol import canonical_digest, canonical_json

PROFILE = "etc/aragorn/pi-provider-profile.json"
CA = "etc/aragorn/pi-provider-ca.pem"
DIRECTORIES = ("etc", "etc/aragorn")
RECEIPT = "provider-inputs-receipt.json"
SCHEMA = "aragorn/pi-core-provider-inputs/v1"
STATUS = "PROVISIONED_PUBLIC_INPUTS_ONLY_NOT_SERVICE_READY"
_MAXIMUM = {PROFILE: 4096, CA: 1024 * 1024}


class PiProviderProvisionError(provision.PiOsProvisionError):
    """Preserve all output; a refusal never authorizes cleanup or retry."""


def _require(condition, reason):
    if not condition:
        raise PiProviderProvisionError(reason)


def _exact_names(directory, expected):
    names = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.name not in expected or entry.name in names:
                return False
            names.add(entry.name)
    return names == expected


def _read_public(parent, name, maximum, deadline, *, protected=False):
    """Read only a fixed public leaf, with bounded bytes and retained identity."""
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 0 < before.st_size <= maximum, "provider public member is unsafe or exceeds bound")
        descriptor = os.open(name, provision._FILE, dir_fd=parent)
        if protected:
            provision._owner(descriptor, 0o444, directory=False)
        _require(provision._identity(os.fstat(descriptor)) == provision._identity(before),
                 "provider public member changed before read")
        chunks, size = [], 0
        while True:
            provision._deadline(deadline)
            chunk = os.read(descriptor, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            _require(size <= maximum and size <= before.st_size, "provider public member grew during read")
        _require(size == before.st_size and provision._identity(os.fstat(descriptor)) ==
                 provision._identity(before) == provision._identity(
                     os.stat(name, dir_fd=parent, follow_symlinks=False)),
                 "provider public member changed during read")
        return b"".join(chunks), before
    finally:
        provision._close_all([descriptor])


def _public_tree(root, deadline, *, protected=False):
    """Inspect only the fixed two public paths; never inventory unknown leaves."""
    descriptors = []
    try:
        provision._deadline(deadline)
        _require(_exact_names(root, {"etc"}), "provider source contains unexpected root entries")
        etc = os.open("etc", provision._DIRECTORY, dir_fd=root)
        descriptors.append(etc)
        _require(_exact_names(etc, {"aragorn"}), "provider source contains unexpected etc entries")
        directory = os.open("aragorn", provision._DIRECTORY, dir_fd=etc)
        descriptors.append(directory)
        names = {Path(PROFILE).name, Path(CA).name}
        _require(_exact_names(directory, names), "provider source contains unexpected public entries")
        held = [root, etc, directory]
        if protected:
            for fd, mode in zip(held, (0o755, 0o555, 0o555)):
                provision._owner(fd, mode, directory=True)
        identities = [provision._identity(os.fstat(fd)) for fd in held]
        contents, files = {}, []
        for path in sorted(_MAXIMUM):
            raw, info = _read_public(directory, Path(path).name, _MAXIMUM[path], deadline, protected=protected)
            contents[path] = raw
            files.append({"path": path, "size": len(raw),
                          "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                          "executable": bool(info.st_mode & 0o111)})
        _require([provision._identity(os.fstat(fd)) for fd in held] == identities and
                 provision._identity(os.stat("etc", dir_fd=root, follow_symlinks=False)) == identities[1] and
                 provision._identity(os.stat("aragorn", dir_fd=etc, follow_symlinks=False)) == identities[2] and
                 _exact_names(root, {"etc"}) and _exact_names(etc, {"aragorn"}) and
                 _exact_names(directory, names), "provider source directory changed during read")
        return {"schema": "aragorn/pi-core-protected-tree/v1", "files": files,
                "directories": list(DIRECTORIES)}, contents
    finally:
        provision._close_all(list(reversed(descriptors)))


def provision_pi_provider_inputs(*, source: Path, manifest: Mapping, manifest_digest: str,
                                profile: Mapping, destination_parent: Path,
                                deployment_name: str, deadline: float) -> dict:
    """Install exact public inputs into a new protected ``name/root`` bundle.

    The caller independently approves the manifest and profile. A receipt binds
    only these copied public bytes, never installed service/runtime readiness.
    Failures retain output and attach ``pi_provider_provisioning_observation``.
    """
    observation = {"schema": "aragorn/pi-core-provider-provisioning-observation/v1",
                   "created": False, "completed": False, "credential_read": False,
                   "activation_performed": False, "rollback_performed": False}
    descriptors = []
    try:
        provision._require_root()
        provision._deadline(deadline)
        _require(type(deployment_name) is str and provision._NAME.fullmatch(deployment_name) is not None,
                 "invalid provider deployment name")
        _require(isinstance(source, Path) and source.is_absolute() and source != Path("/") and
                 ".." not in source.parts and isinstance(destination_parent, Path) and
                 destination_parent.is_absolute() and ".." not in destination_parent.parts,
                 "provider source and destination must be absolute safe paths")
        target = destination_parent / deployment_name
        _require(not target.is_relative_to(source) and not source.is_relative_to(target),
                 "provider source and destination overlap")
        pinned = provision._manifest(manifest, manifest_digest)
        _require(pinned["directories"] == list(DIRECTORIES) and
                 [row["path"] for row in pinned["files"]] == sorted(_MAXIMUM) and
                 all(not row["executable"] and 0 < row["size"] <= _MAXIMUM[row["path"]]
                     for row in pinned["files"]), "provider manifest must contain only two non-executable public inputs")
        approved_profile = codec.validate_profile(profile)
        profile_raw = canonical_json(approved_profile)
        source_fd = provision._source(source)
        descriptors.append(source_fd)
        observed, contents = _public_tree(source_fd, deadline)
        _require(observed == pinned, "provider source differs from reviewed closure")
        _require(contents[PROFILE] == profile_raw, "provider profile bytes differ from canonical approved profile")
        _require("sha256:" + hashlib.sha256(contents[CA]).hexdigest() == approved_profile["ca_digest"],
                 "provider CA bytes differ from approved profile pin")
        _require(contents[CA].isascii(), "provider CA bytes must be ASCII; TLS trust remains unvalidated")
        parent = provision.lineage._open_protected_root(destination_parent, provision._ROOT_UID)
        descriptors.append(parent)
        _require(os.fstat(parent).st_gid == provision._ROOT_GID, "provider destination parent is not root-group owned")
        provision._deadline(deadline)
        observation["created"] = None
        deployment = provision._new_directory(parent, deployment_name)
        descriptors.append(deployment)
        observation.update(created=True, destination=str(target))
        root = provision._new_directory(deployment, "root")
        descriptors.append(root)
        provision._install_tree(source_fd, root, pinned, deadline)
        installed, installed_contents = _public_tree(root, deadline, protected=True)
        final_source, _ = _public_tree(source_fd, deadline)
        _require(installed == pinned == final_source and installed_contents == contents,
                 "provider inputs changed during provisioning")
        # The reused installer verifies exact root:root ownership and modes on
        # every created member: root 0755, descendants 0555, public leaves 0444.
        provision._owner(root, 0o755, directory=True)
        _require(provision._identity(os.fstat(deployment)) == provision._identity(
                     os.stat(deployment_name, dir_fd=parent, follow_symlinks=False)),
                 "provider deployment destination changed")
        provision._deadline(deadline)
        receipt = {"schema": SCHEMA, "status": STATUS,
                   "input_root": str(target / "root"), "input_closure_digest": manifest_digest,
                   "profile_digest": canonical_digest(approved_profile), "ca_digest": approved_profile["ca_digest"],
                   "credential_read": False, "activation_performed": False,
                   "service_ready": False, "phase3_exit_eligible": False}
        raw = canonical_json(receipt)
        receipt_fd = os.open(RECEIPT, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=deployment)
        descriptors.append(receipt_fd)
        os.fchown(receipt_fd, provision._ROOT_UID, provision._ROOT_GID)
        provision._write_all(receipt_fd, raw, deadline)
        os.fchmod(receipt_fd, 0o444)
        provision._owner(receipt_fd, 0o444, directory=False)
        os.fsync(receipt_fd)
        os.lseek(receipt_fd, 0, os.SEEK_SET)
        _require(os.read(receipt_fd, len(raw) + 1) == raw, "provider receipt readback mismatch")
        _require(provision._identity(os.fstat(receipt_fd)) == provision._identity(
                     os.stat(RECEIPT, dir_fd=deployment, follow_symlinks=False)) and
                 provision._identity(os.fstat(root)) == provision._identity(
                     os.stat("root", dir_fd=deployment, follow_symlinks=False)) and
                 _exact_names(deployment, {"root", RECEIPT}),
                 "provider bundle custody changed during receipt publication")
        os.fchmod(deployment, 0o755)
        provision._owner(deployment, 0o755, directory=True)
        os.fsync(deployment)
        os.fsync(parent)
        named_parent = provision.lineage._open_protected_root(destination_parent, provision._ROOT_UID)
        descriptors.append(named_parent)
        _require(provision._identity(os.fstat(named_parent)) == provision._identity(os.fstat(parent)) and
                 provision._identity(os.fstat(deployment)) == provision._identity(
                     os.stat(deployment_name, dir_fd=parent, follow_symlinks=False)) and
                 provision._identity(os.fstat(root)) == provision._identity(
                     os.stat("root", dir_fd=deployment, follow_symlinks=False)) and
                 provision._identity(os.fstat(receipt_fd)) == provision._identity(
                     os.stat(RECEIPT, dir_fd=deployment, follow_symlinks=False)),
                 "provider bundle named custody changed before completion")
        provision._deadline(deadline)
        observation.update(completed=True, receipt_digest=canonical_digest(receipt))
        return receipt
    except BaseException as error:
        error.pi_provider_provisioning_observation = observation
        raise
    finally:
        try:
            provision._close_all(list(reversed(descriptors)))
        except BaseException as error:
            observation["completed"] = False
            error.pi_provider_provisioning_observation = observation
            raise
