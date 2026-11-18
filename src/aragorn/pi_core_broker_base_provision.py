"""Fresh fixed broker storage and explicit first provider policy publication.

Partial names survive every failure. Base installation never adopts an existing
destination; first policy publication never adopts existing controls or repairs
a prior attempt. Only this call's descriptors close.
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
from . import runtime_action_decision as decision
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-broker-base-installation/v1"
AUTHORITY = "FRESH_BASE_CONTROLS_ONLY_NOT_POLICY_HEALTH_GRANT_OR_PHASE3"
DESTINATION = configuration_module.entry.EFFECT_ROOT
PROVIDER_DESTINATION = Path("/var/lib/aragorn-runtime-provider")
PROVIDER_SCHEMA = "aragorn/pi-core-provider-base-installation/v1"
PROVIDER_INITIAL_POLICY_SCHEMA = "aragorn/pi-core-provider-initial-policy/v1"
PROVIDER_INITIAL_POLICY_AUTHORITY = "PINNED_INITIAL_POLICY_AND_REVOCATIONS_ONLY_NOT_HEALTH_OR_EXECUTION"
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


def _provider_config_digest(config, configs):
    destination = PROVIDER_DESTINATION
    ids = configs["action"]["identities"]
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
    return canonical_digest({key: str(value) if isinstance(value, Path) else value
                             for key, value in asdict(config).items()})


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
            observation["provider_config_digest"] = _provider_config_digest(config, configs)
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


def initialize_pi_provider_policy(*, configuration, provider_config, base_state, base_state_digest,
                                  policy, policy_digest, revocations, revocations_digest, deadline):
    """First publish two trusted rows only. A partial publish is never adopted or removed."""
    destination = PROVIDER_DESTINATION
    observation = {"schema": PROVIDER_INITIAL_POLICY_SCHEMA, "authority": PROVIDER_INITIAL_POLICY_AUTHORITY,
        "status": "REFUSED", "destination": str(destination), "configuration_digest": None,
        "provider_config_digest": None, "base_state_digest": None, "policy_digest": None,
        "revocations_digest": None, "mutation_attempted": False, "owned_handles_closed": False,
        "readback": None, "created_members": {}, "uncertain_creation": None, "cleanup_uncertainty": [],
        "activation_performed": False, "service_ready": False, "current_grant_authority": False,
        "phase3_exit_eligible": False}
    owned, chain, directories, files = [], [], {}, {}
    uid, gid = provision._ROOT_UID, provision._ROOT_GID
    failure = None

    def pinned(document, digest, field):
        _require(type(document) is dict and type(digest) is str and provision._DIGEST.fullmatch(digest),
                 "INITIAL_CONTROL_PIN_REQUIRED")
        raw = canonical_json(document)
        _require(len(raw) <= broker._MAX_CONTROL_BYTES and "sha256:" + provision.hashlib.sha256(raw).hexdigest()
                 == digest, "INITIAL_CONTROL_PIN_MISMATCH")
        observation[field] = digest
        return raw, json.loads(raw)

    def open_owned(name, flags, parent=None, mode=0o400):
        provision._deadline(deadline)
        fd = os.open(name, flags, mode, dir_fd=parent)
        owned.append(fd)
        return fd

    def fresh():
        floor = state["minimum_revocation_generation"]
        generation = broker.qualify_runtime_revocation_generation(policy_doc, revocation_doc,
            now_unix=int(broker.time.time()), minimum_revocation_generation=floor)
        _require(generation == floor, "INITIAL_REVOCATIONS_NOT_CURRENT_OR_EXACT_FLOOR")
        _require(grant["active_skill_digest"] not in revocation_doc["skill_digests"], "INITIAL_GRANT_REVOKED")

    def directory(parent, name):
        fd = open_owned(name, provision._DIRECTORY, parent)
        meta = _metadata(fd, uid, gid, 0o700, directory=True)
        directories[name] = fd, parent, broker._directory_identity(meta)
        return fd

    def register_file(name, fd, mode, raw):
        meta = _metadata(fd, uid, gid, mode, directory=False)
        _require(meta.st_size == len(raw), "INITIAL_CONTROL_SIZE")
        files[name] = fd, mode, raw, provision._identity(meta)

    def guard(*, retain=False):
        provision._deadline(deadline)
        configuration.guard(deadline=deadline)
        _require(canonical_digest(configuration.configurations) == observation["configuration_digest"],
                 "INITIAL_CONFIGURATION_CHANGED")
        custody._chain_guard(destination.parent, chain, chain_ids, deadline)
        readback = {"directories": {}, "files": {}, "base_state": None}
        if retain:
            observation["readback"] = readback
        for name, (fd, parent, identity) in directories.items():
            meta = _metadata(fd, uid, gid, 0o700, directory=True)
            _require(identity == broker._directory_identity(meta) == broker._directory_identity(
                os.stat(name, dir_fd=parent, follow_symlinks=False)), "INITIAL_DIRECTORY_CUSTODY_CHANGED")
            custody._exact_names(fd, set(files) | {"provider-evidence"} if name == "control" else tree[name], deadline)
            readback["directories"][name] = list(provision._identity(meta))
        _require(len({identity[:2] for _, _, identity in directories.values()}) == len(directories) and
                 os.fstat(protected).st_dev == os.fstat(staging).st_dev, "INITIAL_ROOT_FILESYSTEM_OR_ALIAS")
        for name, (fd, mode, raw, expected) in files.items():
            provision._deadline(deadline)
            meta = _metadata(fd, uid, gid, mode, directory=False)
            _require(provision._identity(meta) == expected and os.pread(fd, len(raw) + 1, 0) == raw and
                     expected == provision._identity(os.fstat(fd)) == provision._identity(
                         os.stat(name, dir_fd=control, follow_symlinks=False)), "INITIAL_CONTROL_READBACK_CHANGED")
            readback["files"][name] = {"identity": list(expected),
                "digest": "sha256:" + provision.hashlib.sha256(raw).hexdigest()}
            if name == "state.json":
                readback["base_state"] = json.loads(raw)
        for name, (fd, parent, _) in directories.items():
            expected = tuple(readback["directories"][name])
            _require(expected == provision._identity(os.fstat(fd)) == provision._identity(
                     os.stat(name, dir_fd=parent, follow_symlinks=False)), "INITIAL_NAMESPACE_CHANGED_DURING_GUARD")
        fresh()
        provision._deadline(deadline)

    try:
        provision._require_root()
        provision._deadline(deadline)
        _require(type(configuration) is configuration_module.PiServiceConfiguration, "BASE_HELD_CONFIGURATION_REQUIRED")
        configuration.guard(deadline=deadline)
        configs = configuration_module.validate_service_configurations(configuration.configurations)
        observation["configuration_digest"] = canonical_digest(configs)
        observation["provider_config_digest"] = _provider_config_digest(provider_config, configs)
        grant = configs["action"]["capability_grant"]
        state_raw, state = pinned(base_state, base_state_digest, "base_state_digest")
        _require(broker._state(state) == state and not state["consumed"] and state["effect_journal"] is None,
                 "BASE_STATE_MUST_BE_CURRENT_AND_EMPTY")
        policy_raw, policy_doc = pinned(policy, policy_digest, "policy_digest")
        revocations_raw, revocation_doc = pinned(revocations, revocations_digest, "revocations_digest")
        decision._policy(policy_doc)
        _require((policy_digest, policy_doc["version"], policy_doc["sensor_digest"]) ==
                 (grant["policy_digest"], grant["policy_version"], grant["sensor_digest"]), "INITIAL_POLICY_GRANT_MISMATCH")
        fresh()

        custody._path(destination)
        for name in destination.parent.parts:
            parent_fd = chain[-1] if chain else None
            fd = open_owned(name, provision._DIRECTORY, parent_fd)
            chain.append(fd)
            custody._ancestor(fd)
        chain_ids = [custody._directory_identity(os.fstat(fd)) for fd in chain[:-1]] + [
            provision._identity(os.fstat(chain[-1]))]
        root = directory(chain[-1], destination.name)
        control = directory(root, "control")
        lock = open_owned("broker.lock", provision._FILE, control)
        register_file("broker.lock", lock, 0o600, b"")
        _require(files["broker.lock"][3] == provision._identity(
            os.stat("broker.lock", dir_fd=control, follow_symlinks=False)), "INITIAL_LOCK_CUSTODY_CHANGED")
        broker._acquire_lock(lock, deadline)  # Released only by closing our held descriptor.
        protected, staging = directory(root, "protected"), directory(root, "staging")
        evidence = directory(control, "provider-evidence")
        blobs = directory(evidence, "blobs")
        directory(blobs, "sha256")
        tree = {destination.name: {"control", "protected", "staging"}, "protected": set(), "staging": set(),
                "provider-evidence": {"blobs"}, "blobs": {"sha256"}, "sha256": set()}
        register_file("state.json", open_owned("state.json", provision._FILE, control), 0o400, state_raw)
        for name, raw in (("policy.json", policy_raw), ("revocations.json", revocations_raw)):
            guard()
            provision._deadline(deadline)
            observation["mutation_attempted"] = True
            observation["uncertain_creation"] = "control/" + name
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o400, dir_fd=control)
            except FileExistsError:
                observation["uncertain_creation"] = None  # O_EXCL definitively refused the pre-existing name.
                raise
            owned.append(fd)
            observation["uncertain_creation"] = None
            observation["created_members"]["control/" + name] = None  # Returned FD, identity not yet read.
            observation["created_members"]["control/" + name] = list(provision._identity(os.fstat(fd)))
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o400)
            provision._write_all(fd, raw, deadline)
            os.fsync(fd)
            os.fsync(control)
            register_file(name, fd, 0o400, raw)
            observation["created_members"]["control/" + name] = list(files[name][3])
        guard(retain=True)
    except BaseException as error:
        failure = error
    finally:
        for fd in reversed(owned):
            try:
                os.close(fd)
            except BaseException as error:
                observation["cleanup_uncertainty"].append("OWNED_DESCRIPTOR_CLOSE_UNCONFIRMED")
                if failure is None:
                    failure = error
        observation["owned_handles_closed"] = not observation["cleanup_uncertainty"]
    if failure is None:
        try:
            provision._deadline(deadline)
            fresh()
        except BaseException as error:
            failure = error
    if failure is not None:
        observation["status"] = ("CLEANUP_HOLD" if observation["cleanup_uncertainty"] else
            "PARTIAL_OR_INDETERMINATE" if observation["mutation_attempted"] else "REFUSED")
        try:
            failure.pi_provider_initial_policy_observation = json.loads(canonical_json(observation))
        except BaseException:
            pass
        raise failure
    observation["status"] = "INSTALLED"
    return observation
