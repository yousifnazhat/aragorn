"""Fresh fixed action or provider storage, not policy, health or grant authority.

Partial names survive every failure. No existing destination is adopted,
repaired, migrated, removed or retried; only this call's descriptors close.
"""

from dataclasses import asdict
import json
import os
import stat
from pathlib import Path

from . import pi_core_os_provision as provision
from . import pi_core_service_configuration as configuration_module
from . import pi_core_service_provision as custody
from . import runtime_action_broker as broker
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-broker-base-installation/v1"
AUTHORITY = "FRESH_BASE_CONTROLS_ONLY_NOT_POLICY_HEALTH_GRANT_OR_PHASE3"
DESTINATION = configuration_module.entry.EFFECT_ROOT
PROVIDER_DESTINATION = Path("/var/lib/aragorn-runtime-provider")
PROVIDER_SCHEMA = "aragorn/pi-core-provider-base-installation/v1"
_CONTROL_NAMES = {"socket_path": "broker.sock", "instance_lock_path": "instance.lock",
    "lock_path": "broker.lock", "policy_path": "policy.json", "revocations_path": "revocations.json",
    "health_path": "health.json", "observation_path": "observation.json", "state_path": "state.json"}


class PiBrokerBaseProvisionError(RuntimeError):
    """Preserve the destination and evidence; this is not retry permission."""


def _require(condition, reason):
    if not condition:
        raise PiBrokerBaseProvisionError(reason)


def _metadata(fd, uid, gid, mode, *, directory):
    value = os.fstat(fd)
    _require((stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)) and
        value.st_uid == uid and value.st_gid == gid and stat.S_IMODE(value.st_mode) == mode and
        (value.st_nlink >= 1 if directory else value.st_nlink == 1), "BASE_MEMBER_METADATA")
    return value


def provision_pi_broker_base(*, configuration, base_state, base_state_digest, deadline):
    """Install exact empty base controls once, under independently held inputs."""
    return _install(configuration, base_state, base_state_digest, deadline, provider=False, config=None)


def provision_pi_provider_base(*, configuration, provider_config, base_state, base_state_digest, deadline):
    """Install only the root-owned storage consumed by protected provider admission."""
    return _install(configuration, base_state, base_state_digest, deadline, provider=True, config=provider_config)


def _install(configuration, base_state, base_state_digest, deadline, *, provider, config):
    destination = PROVIDER_DESTINATION if provider else DESTINATION
    observation = {"schema": PROVIDER_SCHEMA if provider else SCHEMA, "authority": AUTHORITY, "status": "REFUSED",
        "configuration_digest": None, "base_state_digest": None, "destination": str(destination),
        "mutation_attempted": False, "owned_handles_closed": False, "readback": None,
        "created_members": {}, "cleanup_uncertainty": [], "activation_performed": False, "service_ready": False,
        "current_grant_authority": False, "phase3_exit_eligible": False}
    if provider:
        observation["provider_config_digest"] = None
    owned, chain, directories, files = [], [], {}, {}
    failure = None
    chain_ids = []

    def guard():
        provision._deadline(deadline)
        configuration.guard(deadline=deadline)
        _require(canonical_digest(configuration.configurations) == observation["configuration_digest"],
                 "BASE_CONFIGURATION_CHANGED")
        for index, descriptor in enumerate(chain):
            custody._ancestor(descriptor)
            named = os.lstat("/") if index == 0 else os.stat(destination.parent.parts[index],
                dir_fd=chain[index - 1], follow_symlinks=False)
            _require(broker._directory_identity(os.fstat(descriptor)) == chain_ids[index] ==
                     broker._directory_identity(named), "BASE_PARENT_CHANGED")

    def directory(parent, name, uid, gid, mode):
        provision._deadline(deadline)
        os.mkdir(name, 0o700, dir_fd=parent)
        descriptor = os.open(name, provision._DIRECTORY, dir_fd=parent)
        owned.append(descriptor)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        metadata = _metadata(descriptor, uid, gid, mode, directory=True)
        _require(broker._directory_identity(metadata) == broker._directory_identity(
            os.stat(name, dir_fd=parent, follow_symlinks=False)), "BASE_DIRECTORY_CHANGED")
        observation["created_members"][name] = list(provision._identity(metadata))
        os.fsync(descriptor)
        os.fsync(parent)
        directories[name] = (descriptor, parent, uid, gid, mode, broker._directory_identity(metadata))
        return descriptor

    def file(parent, name, raw, uid, gid, mode):
        provision._deadline(deadline)
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        owned.append(descriptor)
        os.fchown(descriptor, uid, gid)
        provision._write_all(descriptor, raw, deadline)
        os.fchmod(descriptor, mode)
        metadata = _metadata(descriptor, uid, gid, mode, directory=False)
        _require(metadata.st_size == len(raw), "BASE_FILE_SIZE")
        observation["created_members"]["control/" + name] = list(provision._identity(metadata))
        os.fsync(descriptor)
        os.fsync(parent)
        files[name] = (descriptor, parent, uid, gid, mode, provision._identity(metadata), raw)

    try:
        provision._require_root()
        provision._deadline(deadline)
        _require(type(configuration) is configuration_module.PiServiceConfiguration,
                 "BASE_HELD_CONFIGURATION_REQUIRED")
        configuration.guard(deadline=deadline)
        configs = configuration_module.validate_service_configurations(configuration.configurations)
        observation["configuration_digest"] = canonical_digest(configs)
        ids = configs["action"]["identities"]
        uid, gid = ids["action"]["uid"], ids["action"]["gid"]
        if provider:
            _require(type(config) is broker.RuntimeActionBrokerConfig and config.expected_broker_uid == 0,
                     "PROVIDER_BASE_ROOT_CONFIG_REQUIRED")
            broker._validate_config(config)
            _require((config.control_root, config.protected_root, config.staging_root) == tuple(
                destination / name for name in ("control", "protected", "staging")) and all(
                getattr(config, field) == destination / "control" / name for field, name in _CONTROL_NAMES.items()),
                "PROVIDER_BASE_FIXED_PATHS_REQUIRED")
            _require((config.expected_runtime_uid, config.expected_runtime_gid) ==
                     (ids["worker"]["uid"], ids["worker"]["gid"]) and
                     (config.expected_peer_uid, config.expected_peer_gid) ==
                     (ids["sensor"]["uid"], ids["sensor"]["gid"]) and
                     config.expected_runtime_digest == configs["action"]["capability_grant"]["runtime_digest"],
                     "PROVIDER_BASE_IDENTITY_MISMATCH")
            document = {field: str(value) if isinstance(value, Path) else value
                        for field, value in asdict(config).items()}
            observation["provider_config_digest"] = canonical_digest(document)
            uid, gid = provision._ROOT_UID, provision._ROOT_GID
        _require(type(base_state) is dict and type(base_state_digest) is str and
                 provision._DIGEST.fullmatch(base_state_digest), "BASE_STATE_PIN_REQUIRED")
        raw = canonical_json(base_state)
        _require(len(raw) <= broker._MAX_CONTROL_BYTES and canonical_digest(base_state) == base_state_digest,
                 "BASE_STATE_PIN_MISMATCH")
        state = json.loads(raw)
        _require(broker._state(state) == state and state["consumed"] == [] and state["effect_journal"] is None,
                 "BASE_STATE_MUST_BE_CURRENT_AND_EMPTY")
        observation["base_state_digest"] = base_state_digest
        try:
            chain = custody._open_chain(destination.parent, deadline)
        except BaseException:
            observation["cleanup_uncertainty"].append("PARENT_ACQUISITION_CLEANUP_UNCONFIRMED")
            raise
        owned.extend(chain)
        chain_ids = [broker._directory_identity(os.fstat(fd)) for fd in chain]
        guard()
        parent = chain[-1]
        try:
            os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PiBrokerBaseProvisionError("BASE_DESTINATION_ALREADY_EXISTS")
        guard()
        observation["mutation_attempted"] = True
        # The provider root stays private; the action root opens only after installation.
        root = directory(parent, destination.name, provision._ROOT_UID, provision._ROOT_GID, 0o700)
        control = directory(root, "control", uid, gid, 0o700 if provider else 0o710)
        protected = directory(root, "protected", uid, gid, 0o700 if provider else 0o710)
        staging = directory(root, "staging", uid, gid, 0o700)
        _require(os.fstat(protected).st_dev == os.fstat(staging).st_dev and
                 len({(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in (control, protected, staging)}) == 3,
                 "BASE_ROOT_FILESYSTEM_OR_ALIAS")
        file(control, "broker.lock", b"", uid, gid, 0o600)
        file(control, "state.json", raw, uid, gid, 0o400)
        if provider:
            evidence = directory(control, "provider-evidence", uid, gid, 0o700)
            blobs = directory(evidence, "blobs", uid, gid, 0o700)
            sha = directory(blobs, "sha256", uid, gid, 0o700)
        guard()
        if not provider:
            os.fchmod(root, 0o755)
            metadata = _metadata(root, provision._ROOT_UID, provision._ROOT_GID, 0o755, directory=True)
            directories[destination.name] = (root, parent, provision._ROOT_UID, provision._ROOT_GID,
                                             0o755, broker._directory_identity(metadata))
        os.fsync(root)
        os.fsync(parent)
        guard()
        readback = {"directories": {}, "files": {}, "base_state": None}
        observation["readback"] = readback  # Preserve reached readback prefixes on refusal.
        for name, (descriptor, owner, owner_uid, owner_gid, mode, expected) in directories.items():
            provision._deadline(deadline)
            value = _metadata(descriptor, owner_uid, owner_gid, mode, directory=True)
            _require(broker._directory_identity(value) == expected == broker._directory_identity(
                os.stat(name, dir_fd=owner, follow_symlinks=False)), "BASE_DIRECTORY_READBACK_CHANGED")
            readback["directories"][name] = list(provision._identity(value))
        for name, (descriptor, owner, owner_uid, owner_gid, mode, expected, content) in files.items():
            provision._deadline(deadline)
            reader = os.open(name, provision._FILE, dir_fd=owner)
            owned.append(reader)
            before = _metadata(reader, owner_uid, owner_gid, mode, directory=False)
            _require(provision._identity(before) == expected == provision._identity(os.fstat(descriptor)) and
                     before.st_size == len(content), "BASE_FILE_READBACK_CHANGED")
            actual = os.read(reader, len(content) + 1)
            _require(actual == content and provision._identity(os.fstat(reader)) == expected ==
                provision._identity(os.stat(name, dir_fd=owner, follow_symlinks=False)), "BASE_FILE_READBACK_BYTES")
            readback["files"][name] = {"identity": list(expected), "digest": "sha256:" + provision.hashlib.sha256(actual).hexdigest()}
            if name == "state.json":
                readback["base_state"] = broker._parse_canonical_document(actual, "installed broker base state")
        custody._exact_names(root, {"control", "protected", "staging"}, deadline)
        custody._exact_names(control, {"broker.lock", "state.json", "provider-evidence"} if provider
                             else {"broker.lock", "state.json"}, deadline)
        if provider:
            custody._exact_names(evidence, {"blobs"}, deadline)
            custody._exact_names(blobs, {"sha256"}, deadline)
            custody._exact_names(sha, set(), deadline)
        custody._exact_names(protected, set(), deadline)
        custody._exact_names(staging, set(), deadline)
        guard()
    except BaseException as error:
        failure = error
    finally:
        for descriptor in reversed(owned):
            try:
                os.close(descriptor)
            except BaseException as error:
                observation["cleanup_uncertainty"].append("OWNED_DESCRIPTOR_CLOSE_UNCONFIRMED")
                failure = failure or error
        observation["owned_handles_closed"] = not observation["cleanup_uncertainty"]
    if failure is not None:
        observation["status"] = ("CLEANUP_HOLD" if observation["cleanup_uncertainty"] else
            "PARTIAL_OR_INDETERMINATE" if observation["mutation_attempted"] else "REFUSED")
        try:
            setattr(failure, "pi_provider_base_observation" if provider else "pi_broker_base_observation",
                    json.loads(canonical_json(observation)))
        except BaseException:
            pass  # Reporting failure must not replace the original failure.
        raise failure
    observation["status"] = "INSTALLED"
    return observation
