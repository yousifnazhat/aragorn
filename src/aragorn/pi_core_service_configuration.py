"""Exact protected public service configuration, without service activation.

Three independently approved canonical documents are installed absent-only and
held through the existing bounded file/tree custody helpers. Configuration is
not a current capability grant, loaded-code proof, channel/process identity or
permission to activate a service. Mount the three fixed files individually so
the separately held provider profile/CA do not share a directory replacement.
No credentials, service units, runtime bytes, retries or repairs are introduced.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path

from . import pi_core_os_provision as provision
from . import pi_core_provider_provision as public_inputs
from . import pi_core_service_entry as entry
from . import pi_core_service_provision as custody
from .oci_worker_protocol import canonical_digest, canonical_json

ROLES = ("action", "sensor", "provider")
PATHS = {role: "etc/aragorn/pi-" + role + "-service.json" for role in ROLES}
DIRECTORIES = ["etc", "etc/aragorn"]
RECEIPT = "service-configuration-receipt.json"
SCHEMA = "aragorn/pi-core-service-configuration/v1"
STATUS = "PROVISIONED_SERVICE_CONFIGURATION_NOT_STARTED_OR_SERVICE_READY"
AUTHORITY = "HELD_SERVICE_CONFIGURATION_BYTES_NOT_PROCESS_OR_REQUEST_AUTHORITY"
_SEAL = object()
_PROVIDER_SEAL = object()


class PiServiceConfigurationError(provision.PiOsProvisionError):
    """Refusal or cleanup hold; preserve partial outputs and never retry."""


def _require(condition, reason):
    if not condition:
        raise PiServiceConfigurationError(reason)


def _copy(value):
    return json.loads(canonical_json(value))


def validate_service_configurations(configurations):
    """Validate static data joins, not current policy, lease or sensor state."""
    _require(type(configurations) is dict and set(configurations) == set(ROLES),
             "exact action, sensor and provider configurations are required")
    result = {}
    for role in ROLES:
        raw = canonical_json(configurations[role])
        _require(0 < len(raw) <= entry.MAX_CONFIG, "service configuration exceeds its fixed bound")
        result[role] = entry.validate_configuration(json.loads(raw), role)
    identities = result["action"]["identities"]
    _require(all(result[role]["identities"] == identities for role in ROLES),
             "service configurations disagree on role identities")
    _require(result["action"]["capability_grant"] == result["sensor"]["capability_grant"],
             "action and sensor configurations disagree on the approved grant")
    return result


def _inputs(manifest, manifest_digest, configurations, configurations_digest):
    pinned = provision._manifest(manifest, manifest_digest)
    _require(type(configurations_digest) is str and provision._DIGEST.fullmatch(configurations_digest),
             "invalid expected service configuration digest")
    configs = validate_service_configurations(configurations)
    _require(canonical_digest(configs) == configurations_digest, "service configuration pin differs")
    expected = [{"path": PATHS[role], "size": len(canonical_json(configs[role])),
                 "digest": canonical_digest(configs[role]), "executable": False} for role in ROLES]
    expected.sort(key=lambda row: row["path"])
    _require(pinned["directories"] == DIRECTORIES and pinned["files"] == expected,
             "service manifest must bind only the three exact canonical configuration files")
    return pinned, configs


def _receipt(root, manifest_digest, configs, configs_digest):
    return {"schema": SCHEMA, "status": STATUS, "configuration_root": str(root),
            "configuration_closure_digest": manifest_digest, "configurations_digest": configs_digest,
            "configuration_digests": {role: canonical_digest(configs[role]) for role in ROLES},
            "identities_digest": canonical_digest(configs["action"]["identities"]),
            "credential_read": False, "activation_performed": False, "service_ready": False,
            "current_grant_authority": False, "phase3_exit_eligible": False}


def provision_pi_service_configuration(*, source, manifest, manifest_digest, configurations,
                                       configurations_digest, destination_parent, deployment_name, deadline):
    """Copy exactly three public documents into a fresh protected bundle."""
    observation = {"schema": "aragorn/pi-core-service-configuration-provisioning/v1",
                   "created": False, "completed": False, "credential_read": False,
                   "activation_performed": False, "rollback_performed": False}
    fds = []
    try:
        provision._require_root()
        provision._deadline(deadline)
        pinned, configs = _inputs(manifest, manifest_digest, configurations, configurations_digest)
        custody._path(source)
        custody._path(destination_parent)
        _require(type(deployment_name) is str and provision._NAME.fullmatch(deployment_name),
                 "invalid configuration deployment name")
        target = destination_parent / deployment_name
        _require(not target.is_relative_to(source) and not source.is_relative_to(target),
                 "configuration source and destination overlap")
        source_fd = provision._source(source)
        fds.append(source_fd)
        custody._tree(source_fd, pinned, deadline, protected=False)
        parent = provision.lineage._open_protected_root(destination_parent, provision._ROOT_UID)
        fds.append(parent)
        _require(os.fstat(parent).st_gid == provision._ROOT_GID, "configuration destination group is unsafe")
        provision._deadline(deadline)
        observation["created"] = None
        deployment = provision._new_directory(parent, deployment_name)
        fds.append(deployment)
        observation.update(created=True, destination=str(target))
        root = provision._new_directory(deployment, "root")
        fds.append(root)
        provision._install_tree(source_fd, root, pinned, deadline)
        custody._tree(root, pinned, deadline, protected=True)
        custody._tree(source_fd, pinned, deadline, protected=False)
        receipt = _receipt(target / "root", manifest_digest, configs, configurations_digest)
        raw = canonical_json(receipt)
        descriptor = os.open(RECEIPT, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=deployment)
        fds.append(descriptor)
        os.fchown(descriptor, provision._ROOT_UID, provision._ROOT_GID)
        provision._write_all(descriptor, raw, deadline)
        os.fchmod(descriptor, 0o444)
        provision._owner(descriptor, 0o444, directory=False)
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        _require(os.read(descriptor, len(raw) + 1) == raw, "configuration receipt readback differs")
        os.fchmod(deployment, 0o755)
        provision._owner(deployment, 0o755, directory=True)
        os.fsync(deployment)
        os.fsync(parent)
        named_parent = provision.lineage._open_protected_root(destination_parent, provision._ROOT_UID)
        fds.append(named_parent)
        _require(provision._identity(os.fstat(named_parent)) == provision._identity(os.fstat(parent)),
                 "configuration destination parent changed")
        for held, owner, name in ((deployment, parent, deployment_name), (root, deployment, "root"),
                                  (descriptor, deployment, RECEIPT)):
            _require(provision._identity(os.fstat(held)) == provision._identity(
                os.stat(name, dir_fd=owner, follow_symlinks=False)), "configuration installed name custody changed")
        custody._exact_names(deployment, {"root", RECEIPT}, deadline)
        provision._deadline(deadline)
        observation.update(completed=True, receipt_digest=canonical_digest(receipt))
        return receipt
    except BaseException as error:
        error.pi_service_configuration_observation = observation
        raise
    finally:
        try:
            provision._close_all(list(reversed(fds)))
        except BaseException as error:
            observation["completed"] = False
            error.pi_service_configuration_observation = observation
            raise


class PiServiceConfiguration:
    """Active custody of fixed installed public bytes, not request authority."""

    __slots__ = ("_seal", "_path", "_chain", "_identities", "_root_fd", "_receipt_fd", "_root_identity",
                 "_receipt_identity", "_manifest", "_configurations", "_receipt", "_deadline", "_active", "_observation")

    def __init__(self, seal, path, chain, root_fd, receipt_fd, manifest, configurations, receipt, deadline):
        _require(seal is _SEAL, "service configuration requires verified installed custody")
        self._seal, self._path, self._chain = seal, path, chain
        self._identities = [(provision._identity if index == len(chain) - 1 else custody._directory_identity)(os.fstat(fd))
                            for index, fd in enumerate(chain)]
        self._root_fd, self._receipt_fd = root_fd, receipt_fd
        self._root_identity, self._receipt_identity = provision._identity(os.fstat(root_fd)), provision._identity(os.fstat(receipt_fd))
        self._manifest, self._configurations, self._receipt = _copy(manifest), _copy(configurations), _copy(receipt)
        self._deadline, self._active = deadline, True
        self._observation = {"schema": "aragorn/pi-core-held-service-configuration/v1", "authority": AUTHORITY,
            "configuration_closure_digest": receipt["configuration_closure_digest"],
            "configurations_digest": receipt["configurations_digest"], "receipt_digest": canonical_digest(receipt),
            "identities_digest": receipt["identities_digest"], "configuration_digests": receipt["configuration_digests"],
            "service_ready": False, "current_grant_authority": False, "phase3_exit_eligible": False}

    def _live(self):
        _require(type(self) is PiServiceConfiguration and getattr(self, "_seal", None) is _SEAL and
                 getattr(self, "_active", False), "service configuration custody is inactive or was not minted")
        provision._require_root()
        provision._deadline(self._deadline)

    @property
    def root(self):
        self._live()
        return self._path / "root"

    @property
    def root_fd(self):
        self._live()
        return self._root_fd

    @property
    def deadline(self):
        self._live()
        return self._deadline

    @property
    def configurations(self):
        self._live()
        return _copy(self._configurations)

    @property
    def identities(self):
        self._live()
        return _copy(self._configurations["action"]["identities"])

    @property
    def observation(self):
        self._live()
        return _copy(self._observation)

    def guard(self, *, deadline=None):
        self._live()
        bounded = self._deadline if deadline is None else deadline
        provision._deadline(bounded)
        _require(bounded <= self._deadline, "configuration guard cannot extend its held deadline")
        custody._chain_guard(self._path, self._chain, self._identities, bounded)
        deployment = self._chain[-1]
        provision._owner(deployment, 0o755, directory=True)
        custody._exact_names(deployment, {"root", RECEIPT}, bounded)
        for fd, name, expected in ((self._root_fd, "root", self._root_identity),
                                    (self._receipt_fd, RECEIPT, self._receipt_identity)):
            _require(provision._identity(os.fstat(fd)) == expected == provision._identity(
                os.stat(name, dir_fd=deployment, follow_symlinks=False)), "held configuration member custody changed")
        provision._owner(self._receipt_fd, 0o444, directory=False)
        raw = canonical_json(self._receipt)
        provision._deadline(bounded)
        os.lseek(self._receipt_fd, 0, os.SEEK_SET)
        _require(os.read(self._receipt_fd, len(raw) + 1) == raw, "held configuration receipt bytes changed")
        provision._deadline(bounded)
        custody._tree(self._root_fd, self._manifest, bounded, protected=True)
        custody._chain_guard(self._path, self._chain, self._identities, bounded)
        for fd, name, expected in ((self._root_fd, "root", self._root_identity),
                                    (self._receipt_fd, RECEIPT, self._receipt_identity)):
            _require(provision._identity(os.fstat(fd)) == expected == provision._identity(
                os.stat(name, dir_fd=deployment, follow_symlinks=False)), "held configuration changed during guard")
        provision._deadline(bounded)


@contextmanager
def hold_pi_service_configuration(deployment_path, *, receipt_digest, manifest, manifest_digest,
                                  configurations, configurations_digest, deadline):
    """Mint held custody only from actual installed bytes and independent pins.

    The root descriptor is borrowed. Exact tree/name/receipt checks run at entry,
    every explicit guard and successful exit. Close uncertainty remains a hold;
    no close retry or cleanup of partial installed artifacts is performed.
    """
    fds, held = [], None
    try:
        provision._require_root()
        provision._deadline(deadline)
        pinned, configs = _inputs(manifest, manifest_digest, configurations, configurations_digest)
        _require(type(receipt_digest) is str and provision._DIGEST.fullmatch(receipt_digest),
                 "invalid configuration receipt pin")
        chain = custody._open_chain(deployment_path, deadline)
        fds.extend(chain)
        deployment = chain[-1]
        provision._owner(deployment, 0o755, directory=True)
        custody._exact_names(deployment, {"root", RECEIPT}, deadline)
        root = os.open("root", provision._DIRECTORY, dir_fd=deployment)
        fds.append(root)
        descriptor = os.open(RECEIPT, provision._FILE, dir_fd=deployment)
        fds.append(descriptor)
        provision._owner(descriptor, 0o444, directory=False)
        expected = _receipt(deployment_path / "root", manifest_digest, configs, configurations_digest)
        _require(canonical_digest(expected) == receipt_digest and os.fstat(descriptor).st_size == len(canonical_json(expected)),
                 "installed configuration receipt disagrees with independent pins")
        held = PiServiceConfiguration(_SEAL, deployment_path, chain, root, descriptor, pinned, configs, expected, deadline)
        held.guard()
        yield held
        held.guard()
    finally:
        if held is not None:
            held._active = False
        provision._close_all(list(reversed(fds)))


def _provider_manifest(manifest, manifest_digest):
    pinned = provision._manifest(manifest, manifest_digest)
    _require(pinned["directories"] == list(public_inputs.DIRECTORIES) and
             [row["path"] for row in pinned["files"]] == sorted(public_inputs._MAXIMUM) and
             all(not row["executable"] and 0 < row["size"] <= public_inputs._MAXIMUM[row["path"]]
                 for row in pinned["files"]), "provider manifest must bind only the two fixed public inputs")
    return pinned


def _provider_tree(root_fd, manifest, deadline):
    observed, contents = public_inputs._public_tree(root_fd, deadline, protected=True)
    _require(observed == manifest, "held provider inputs differ from their independent manifest")
    raw = contents[public_inputs.PROFILE]
    profile = public_inputs.codec.validate_profile(json.loads(raw))
    _require(canonical_json(profile) == raw, "held provider profile is not exact canonical data")
    ca = contents[public_inputs.CA]
    _require(ca.isascii() and "sha256:" + public_inputs.hashlib.sha256(ca).hexdigest() == profile["ca_digest"],
             "held provider CA differs from the approved public profile")
    return profile


def _provider_receipt(root, manifest_digest, profile):
    # Exact existing installer receipt, not a new or self-authorizing format.
    return {"schema": public_inputs.SCHEMA, "status": public_inputs.STATUS,
            "input_root": str(root), "input_closure_digest": manifest_digest,
            "profile_digest": canonical_digest(profile), "ca_digest": profile["ca_digest"],
            "credential_read": False, "activation_performed": False,
            "service_ready": False, "phase3_exit_eligible": False}


class PiProviderInputs:
    """Held approved public profile/CA bytes, never a credential or egress grant."""

    __slots__ = ("_seal", "_path", "_chain", "_identities", "_root_fd", "_receipt_fd", "_root_identity",
                 "_receipt_identity", "_manifest", "_profile", "_receipt", "_deadline", "_active", "_observation")

    def __init__(self, seal, path, chain, root_fd, receipt_fd, manifest, profile, receipt, deadline):
        _require(seal is _PROVIDER_SEAL, "provider inputs require verified installed custody")
        self._seal, self._path, self._chain = seal, path, chain
        self._identities = [(provision._identity if index == len(chain) - 1 else custody._directory_identity)(os.fstat(fd))
                            for index, fd in enumerate(chain)]
        self._root_fd, self._receipt_fd = root_fd, receipt_fd
        self._root_identity, self._receipt_identity = provision._identity(os.fstat(root_fd)), provision._identity(os.fstat(receipt_fd))
        self._manifest, self._profile, self._receipt = _copy(manifest), _copy(profile), _copy(receipt)
        self._deadline, self._active = deadline, True
        self._observation = {"schema": "aragorn/pi-core-held-provider-inputs/v1",
            "authority": "HELD_PUBLIC_PROVIDER_INPUTS_NOT_CREDENTIAL_OR_EGRESS_AUTHORITY",
            "input_closure_digest": receipt["input_closure_digest"], "profile_digest": receipt["profile_digest"],
            "ca_digest": receipt["ca_digest"], "receipt_digest": canonical_digest(receipt),
            "credential_read": False, "service_ready": False, "phase3_exit_eligible": False}

    def _live(self):
        _require(type(self) is PiProviderInputs and getattr(self, "_seal", None) is _PROVIDER_SEAL and
                 getattr(self, "_active", False), "provider input custody is inactive or was not minted")
        provision._require_root()
        provision._deadline(self._deadline)

    @property
    def root(self):
        self._live()
        return self._path / "root"

    @property
    def root_fd(self):
        self._live()
        return self._root_fd

    @property
    def profile(self):
        self._live()
        return _copy(self._profile)

    @property
    def deadline(self):
        self._live()
        return self._deadline

    @property
    def observation(self):
        self._live()
        return _copy(self._observation)

    def guard(self, *, deadline=None):
        self._live()
        bounded = self._deadline if deadline is None else deadline
        provision._deadline(bounded)
        _require(bounded <= self._deadline, "provider guard cannot extend its held deadline")
        custody._chain_guard(self._path, self._chain, self._identities, bounded)
        deployment = self._chain[-1]
        provision._owner(deployment, 0o755, directory=True)
        custody._exact_names(deployment, {"root", public_inputs.RECEIPT}, bounded)
        for fd, name, expected in ((self._root_fd, "root", self._root_identity),
                                    (self._receipt_fd, public_inputs.RECEIPT, self._receipt_identity)):
            _require(provision._identity(os.fstat(fd)) == expected == provision._identity(
                os.stat(name, dir_fd=deployment, follow_symlinks=False)), "held provider member custody changed")
        provision._owner(self._receipt_fd, 0o444, directory=False)
        raw = canonical_json(self._receipt)
        provision._deadline(bounded)
        os.lseek(self._receipt_fd, 0, os.SEEK_SET)
        _require(os.read(self._receipt_fd, len(raw) + 1) == raw, "held provider receipt bytes changed")
        provision._deadline(bounded)
        _require(_provider_tree(self._root_fd, self._manifest, bounded) == self._profile,
                 "held provider profile changed")
        custody._chain_guard(self._path, self._chain, self._identities, bounded)
        for fd, name, expected in ((self._root_fd, "root", self._root_identity),
                                    (self._receipt_fd, public_inputs.RECEIPT, self._receipt_identity)):
            _require(provision._identity(os.fstat(fd)) == expected == provision._identity(
                os.stat(name, dir_fd=deployment, follow_symlinks=False)), "held provider changed during guard")
        provision._deadline(bounded)


@contextmanager
def hold_pi_provider_inputs(deployment_path, *, receipt_digest, manifest, manifest_digest, deadline):
    """Hold the existing public-input installer output; never read a secret."""
    fds, held = [], None
    try:
        provision._require_root()
        provision._deadline(deadline)
        pinned = _provider_manifest(manifest, manifest_digest)
        _require(type(receipt_digest) is str and provision._DIGEST.fullmatch(receipt_digest),
                 "invalid public provider receipt pin")
        chain = custody._open_chain(deployment_path, deadline)
        fds.extend(chain)
        deployment = chain[-1]
        provision._owner(deployment, 0o755, directory=True)
        custody._exact_names(deployment, {"root", public_inputs.RECEIPT}, deadline)
        root = os.open("root", provision._DIRECTORY, dir_fd=deployment)
        fds.append(root)
        profile = _provider_tree(root, pinned, deadline)
        descriptor = os.open(public_inputs.RECEIPT, provision._FILE, dir_fd=deployment)
        fds.append(descriptor)
        provision._owner(descriptor, 0o444, directory=False)
        expected = _provider_receipt(deployment_path / "root", manifest_digest, profile)
        _require(canonical_digest(expected) == receipt_digest and os.fstat(descriptor).st_size == len(canonical_json(expected)),
                 "installed provider receipt disagrees with independent pins")
        held = PiProviderInputs(_PROVIDER_SEAL, deployment_path, chain, root, descriptor, pinned, profile, expected, deadline)
        held.guard()
        yield held
        held.guard()
    finally:
        if held is not None:
            held._active = False
        provision._close_all(list(reversed(fds)))
