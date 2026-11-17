"""Fresh fixed action-broker storage, not policy, health or grant authority.

Partial names survive every failure. No existing destination is adopted,
repaired, migrated, removed or retried; only this call's descriptors close.
"""

import json
import os
import stat

from . import pi_core_os_provision as provision
from . import pi_core_service_configuration as configuration_module
from . import pi_core_service_provision as custody
from . import runtime_action_broker as broker
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-broker-base-installation/v1"
AUTHORITY = "FRESH_BASE_CONTROLS_ONLY_NOT_POLICY_HEALTH_GRANT_OR_PHASE3"
DESTINATION = configuration_module.entry.EFFECT_ROOT


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
    observation = {"schema": SCHEMA, "authority": AUTHORITY, "status": "REFUSED",
        "configuration_digest": None, "base_state_digest": None, "destination": str(DESTINATION),
        "mutation_attempted": False, "owned_handles_closed": False, "readback": None,
        "created_members": {}, "cleanup_uncertainty": [], "activation_performed": False, "service_ready": False,
        "current_grant_authority": False, "phase3_exit_eligible": False}
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
            named = os.lstat("/") if index == 0 else os.stat(DESTINATION.parent.parts[index],
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
        uid, gid = (configs["action"]["identities"]["action"][name] for name in ("uid", "gid"))
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
            chain = custody._open_chain(DESTINATION.parent, deadline)
        except BaseException:
            observation["cleanup_uncertainty"].append("PARENT_ACQUISITION_CLEANUP_UNCONFIRMED")
            raise
        owned.extend(chain)
        chain_ids = [broker._directory_identity(os.fstat(fd)) for fd in chain]
        guard()
        parent = chain[-1]
        try:
            os.stat(DESTINATION.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PiBrokerBaseProvisionError("BASE_DESTINATION_ALREADY_EXISTS")
        guard()
        observation["mutation_attempted"] = True
        # Keep the outer root inaccessible to the action identity until the
        # complete empty tree has been written. The final mode remains 0755.
        root = directory(parent, DESTINATION.name, provision._ROOT_UID, provision._ROOT_GID, 0o700)
        control = directory(root, "control", uid, gid, 0o710)
        protected = directory(root, "protected", uid, gid, 0o710)
        staging = directory(root, "staging", uid, gid, 0o700)
        _require(os.fstat(protected).st_dev == os.fstat(staging).st_dev and
                 len({(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in (control, protected, staging)}) == 3,
                 "BASE_ROOT_FILESYSTEM_OR_ALIAS")
        file(control, "broker.lock", b"", uid, gid, 0o600)
        file(control, "state.json", raw, uid, gid, 0o400)
        guard()
        os.fchmod(root, 0o755)
        metadata = _metadata(root, provision._ROOT_UID, provision._ROOT_GID, 0o755, directory=True)
        directories[DESTINATION.name] = (root, parent, provision._ROOT_UID, provision._ROOT_GID,
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
        custody._exact_names(control, {"broker.lock", "state.json"}, deadline)
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
            failure.pi_broker_base_observation = json.loads(canonical_json(observation))
        except BaseException:
            pass  # Reporting failure must not replace the original failure.
        raise failure
    observation["status"] = "INSTALLED"
    return observation
