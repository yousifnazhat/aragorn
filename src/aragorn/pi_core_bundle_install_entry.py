"""Fixed managed install/update caller; materialization is not activation.

The independently pinned context supplies existing admission authority. This
caller does not issue contexts, grants, worker starts or telemetry claims.
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import stat
import time

from . import pi_core_coordinator_entry as coordinator
from . import pi_core_confined_launch as launch
from . import pi_core_source_inventory_prepare as inventory
from . import protected_install_v2 as publisher
from . import runtime_active_skill_lineage as lineage
from .artifact_closure import load_verified_retained_manifest
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_bundle_launch import _DEPLOYMENT_FIELDS
from .protected_install_context import verify_protected_install_context_v2

SCHEMA = "aragorn/pi-core-bundle-install-plan/v1"
_SOURCE_PATH = "opt/aragorn/src/aragorn/pi_core_bundle_install_entry.py"
_DESTINATION = Path("/var/lib/aragorn/admitted")
_FIELDS = {"schema", "host_profile_digest", "context", "candidate_cas_root",
    "predecessor_cas_root", "deployment", "launch", "runtime_conformance_digest", "revocations"}


class PiBundleInstallEntryError(RuntimeError):
    """Admission refused or publication/cleanup is uncertain; never retry here."""


def _custody(source_loader, host_custody, deadline):
    pin, sources, host = coordinator._custody(source_loader, host_custody, deadline)
    pins = source_loader.source_digests
    coordinator._require(_SOURCE_PATH in pins and any(
        type(row) is dict and row.get("module") == __name__ and
        row.get("path") == _SOURCE_PATH and row.get("digest") == pins[_SOURCE_PATH]
        for row in sources), "BUNDLE_INSTALL_ENTRY_SOURCE_NOT_CONSUMED")
    return pin, sources, host


def _plan(value, host_pin):
    coordinator._exact(value, _FIELDS)
    coordinator._require(value["schema"] == SCHEMA and value["host_profile_digest"] == host_pin,
                         "BUNDLE_INSTALL_PLAN_BINDING")
    coordinator._path(value["candidate_cas_root"])
    if value["predecessor_cas_root"] is not None:
        coordinator._path(value["predecessor_cas_root"])
    coordinator._pin(value["runtime_conformance_digest"])
    for name in ("context", "deployment", "launch", "revocations"):
        coordinator._reference(value[name])
    return value


def _revocations(value):
    coordinator._exact(value, {"schema", "context_ids"})
    rows = value["context_ids"]
    coordinator._require(value["schema"] == "aragorn/protected-install-revocations/v1" and
        type(rows) is list and len(rows) <= 4096 and all(type(item) is str for item in rows) and
        rows == sorted(set(rows)), "BUNDLE_INSTALL_REVOCATIONS")
    return tuple(coordinator._pin(item) for item in rows)


def _supported_bundle(cas, manifest_digest):
    manifest = load_verified_retained_manifest(cas, manifest_digest)
    files = manifest["files"]
    coordinator._require(0 < len(files) <= 64 and sum(row["size"] for row in files) <= 1024 * 1024 and
        all(not row["executable"] and len(row["path"].split("/")) <= 2 for row in files) and
        len({row["path"].split("/")[0] for row in files if "/" in row["path"]}) <= 1,
        "BUNDLE_INSTALL_UNSUPPORTED_PI_LAYOUT")
    skill = next((row for row in files if row["path"] == "SKILL.md"), None)
    coordinator._require(skill is not None and 0 < skill["size"] <= 32 * 1024,
                         "BUNDLE_INSTALL_SKILL_REQUIRED")
    raw = cas.read(skill["digest"], max_bytes=32 * 1024)
    coordinator._require(len(raw) == skill["size"], "BUNDLE_INSTALL_SKILL_SIZE")
    raw.decode("utf-8", errors="strict")


class _Destination:
    """Own the fixed leaf only; its parent is held by prepared-input custody."""

    def __init__(self, inputs, destination):
        self.inputs, self.fd, self.closed = inputs, None, False
        self.cleanup_uncertainty = []
        coordinator._exact(destination, {"root_device", "root_inode", "target_name"})
        coordinator._require(type(destination["root_device"]) is int and destination["root_device"] >= 0 and
            type(destination["root_inode"]) is int and destination["root_inode"] > 0,
            "BUNDLE_INSTALL_DESTINATION_IDENTITY")
        self.expected = (destination["root_device"], destination["root_inode"])

    def acquire(self):
        coordinator._require(self.fd is None and not self.closed, "BUNDLE_INSTALL_DESTINATION_ALREADY_OPEN")
        self.inputs.hold_directory(_DESTINATION.parent)
        self.parent = self.inputs.directories[-1][1][-1]
        self.fd = os.open(_DESTINATION.name, lineage._DIRECTORY_FLAGS, dir_fd=self.parent)
        self.guard()
        self.lock()

    def guard(self):
        coordinator._require(not self.closed and self.fd is not None, "BUNDLE_INSTALL_DESTINATION_ENDED")
        self.inputs.guard()
        held, named = os.fstat(self.fd), os.stat(_DESTINATION.name, dir_fd=self.parent, follow_symlinks=False)
        for value in (held, named):
            coordinator._require(stat.S_ISDIR(value.st_mode) and value.st_uid == value.st_gid == 0 and
                value.st_nlink > 0 and not value.st_mode & 0o7022 and value.st_mode & 0o300 == 0o300 and
                (value.st_dev, value.st_ino) == self.expected, "BUNDLE_INSTALL_DESTINATION_CHANGED")
        coordinator._require(not os.get_inheritable(self.fd), "BUNDLE_INSTALL_INHERITABLE_ROOT")

    def lock(self):
        self.guard()
        # The existing nested publishers duplicate this open-file description.
        # Their blocking flock is consequently reentrant, not a wait on a peer.
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.guard()

    def close(self):
        coordinator._require(not self.closed, "BUNDLE_INSTALL_CLOSE_ALREADY_ATTEMPTED")
        self.closed = True
        descriptor, self.fd = self.fd, None
        if descriptor is not None:
            try:
                # Close releases our lock; do not retry a possibly reused fd.
                os.close(descriptor)
            except BaseException:
                self.cleanup_uncertainty.append({"scope": "DESTINATION_CLOSE", "descriptors": [descriptor]})
                raise


def _installed_views(inputs, config, deployment):
    paths = (config.root_directory, config.runtime_directory, config.activation_directory, _DESTINATION)
    for index, path in enumerate(paths):
        launch._path(path, "managed install view")
        coordinator._require(all(path != other and path not in other.parents and other not in path.parents
            for other in paths[index + 1:]), "BUNDLE_INSTALL_VIEW_OVERLAP")
    roots = []
    for path in paths[:2]:
        inputs.hold_directory(path)
        fd = inputs.directories[-1][1][-1]
        inventory._directory(fd, readonly=True)
        roots.append(fd)
    os_manifest, directories, os_digest = launch._tree(roots[0])
    launch._require_empty_mountpoints(os_manifest, directories)
    os_files = {row["path"]: row for row in os_manifest["files"]}
    coordinator._require(os_files.get("usr/bin/env", {}).get("executable") is True,
                         "BUNDLE_INSTALL_OS_ENTRYPOINT_MISSING")
    runtime_manifest, _, _ = launch._tree(roots[1])
    runtime_digest = launch._runtime_inventory(runtime_manifest, config.compiled_receipt,
                                               config.compiled_receipt_digest)
    if config.source_observation is not None:
        gate = launch._source_gate_artifact(runtime_manifest, config.compiled_receipt)
        node = next(row for row in runtime_manifest["files"] if row["path"] == "node/bin/node")
        pins = config.source_observation["pins"]
        coordinator._require(gate["digest"] == pins["gate_digest"] and node["digest"] == pins["node_digest"],
                             "BUNDLE_INSTALL_SOURCE_GATE_BINDING")
    coordinator._require(os_digest == config.root_closure_digest == deployment["os_profile"] and
        runtime_digest == deployment["runtime_commit_or_image"] and
        launch.confined_configuration_digest(config) == deployment["configuration"],
        "BUNDLE_INSTALL_DEPLOYMENT_DIFFERS")
    for fd in roots:
        inventory._directory(fd, readonly=True)
    inputs.guard()
    return tuple(roots), runtime_digest


def _record(value):
    coordinator._require(type(value) is dict, "BUNDLE_INSTALL_PUBLISHER_RECORD")
    raw = canonical_json(value)
    coordinator._require(len(raw) <= 256 * 1024, "BUNDLE_INSTALL_RECORD_BOUND")
    return json.loads(raw)


def _readback(destination, transaction):
    # Publishers unlock the shared open-file description in their finally.
    destination.lock()
    raw = lineage._read_owned_bytes_at(destination.fd, lineage.ACTIVE_RUNTIME_RECORD,
        max_bytes=lineage._MAX_RECORD_BYTES, expected_uid=0, exact_mode=0o444,
        label="managed installed active record")
    retained = lineage.parse_active_runtime_record(raw)
    coordinator._require(retained["transaction"] == transaction, "BUNDLE_INSTALL_ACTIVE_RECORD_CHANGED")
    publisher.legacy._verify_active_link(destination.fd, transaction["destination"]["target_name"],
                                        transaction["version_path"])


def run(plan_path, expected_plan_digest, *, deadline_ns, source_loader, host_custody):
    """Materialize once from existing authority, never provision or activate."""
    observation = {"schema": "aragorn/pi-core-bundle-install-result/v1",
        "authority": "PROTECTED_MATERIALIZATION_ONLY_NOT_ACTIVATION_OR_PHASE3",
        "status": "REFUSED_OR_INDETERMINATE", "managed_call_attempted": False, "managed_result": None,
        "host_before": None, "host_after": None, "source_before": None, "source_after": None,
        "plan_digest": None, "deployment_digest": None, "context_digest": None,
        "owned_inputs_closed": False, "owned_destination_closed": False,
        "input_cleanup_uncertainty": [], "phase3_exit_eligible": False,
        "installation_attempted": False, "publication_state": "NOT_ATTEMPTED",
        "transaction": None, "recovery": None}
    inputs = destination = failure = None
    phase = "PREFLIGHT"
    try:
        coordinator._require(os.geteuid() == os.getegid() == 0, "BUNDLE_INSTALL_ROOT_REQUIRED")
        deadline = coordinator._deadline(deadline_ns)
        host_pin, observation["source_before"], observation["host_before"] = _custody(
            source_loader, host_custody, deadline)
        inputs = coordinator._Inputs(deadline)
        pin = coordinator._pin(expected_plan_digest)
        plan = _plan(inputs.read(coordinator._path(str(plan_path)), pin, coordinator._PLAN_LIMIT), host_pin)
        observation["plan_digest"] = pin
        phase = "PREPARED_INPUTS"
        context, deployment, document, revoked = [inputs.ref(plan[name])
            for name in ("context", "deployment", "launch", "revocations")]
        observation["context_digest"] = plan["context"]["digest"]
        observation["deployment_digest"] = plan["deployment"]["digest"]
        coordinator._exact(deployment, _DEPLOYMENT_FIELDS)
        for value in deployment.values():
            coordinator._pin(value)
        coordinator._require(type(context) is dict and context.get("operation") in {"install", "update"} and
            (plan["predecessor_cas_root"] is not None) == (context["operation"] == "update") and
            context.get("policy_digest") == deployment["policy"], "BUNDLE_INSTALL_CONTEXT_BINDING")
        config = coordinator._launch(document, "PROTECTED" if document.get("provider_route_digest") else "UNAVAILABLE")
        revoked_ids = _revocations(revoked)
        phase = "HELD_INPUTS"
        stores = []
        for name in ("candidate_cas_root", "predecessor_cas_root"):
            selected = plan[name]
            if selected is None:
                stores.append(None)
                continue
            path = coordinator._path(selected)
            coordinator._require(path != _DESTINATION and _DESTINATION not in path.parents,
                                 "BUNDLE_INSTALL_CAS_INSIDE_DESTINATION")
            inputs.hold_directory(path)
            stores.append(CAS(path, read_only=True))
        cas, predecessor = stores
        roots, runtime_digest = _installed_views(inputs, config, deployment)
        destination = _Destination(inputs, context.get("destination"))
        destination.acquire()

        def claim_state():
            inputs.guard()
            destination.guard()
            for fd in roots:
                inventory._directory(fd, readonly=True)
            current_pin, _, _ = _custody(source_loader, host_custody, deadline)
            coordinator._require(current_pin == host_pin, "BUNDLE_INSTALL_HOST_PROFILE_CHANGED")
            return int(time.time()), _revocations(inputs.ref(plan["revocations"]))

        now, revoked_ids = claim_state()
        verified = verify_protected_install_context_v2(cas, context, destination.fd, now_unix=now,
            expected_context_digest=observation["context_digest"],
            expected_target_name=context["destination"]["target_name"],
            expected_runtime_conformance_digest=plan["runtime_conformance_digest"],
            measured_target_runtime_digest=runtime_digest, revoked_context_ids=revoked_ids)
        _supported_bundle(cas, verified.manifest_digest)
        claim_state()
        phase = "INSTALLATION"
        observation["installation_attempted"] = True
        observation["publication_state"] = "UNKNOWN"
        try:
            result = publisher._publish_protected_install_transaction(cas, context, destination.fd,
                now_unix=now, claim_now_unix=now, expected_context_digest=observation["context_digest"],
                expected_target_name=verified.target_name,
                expected_runtime_conformance_digest=plan["runtime_conformance_digest"],
                measured_target_runtime_digest=runtime_digest, revoked_context_ids=revoked_ids,
                expected_active_cas=predecessor, claim_state_provider=claim_state)
        except BaseException as exc:
            try:
                if isinstance(exc, publisher.ProtectedInstallTransactionError) and exc.recovery is not None:
                    observation["recovery"] = _record(exc.recovery)
                    observation["publication_state"] = "RECOVERY_RECORD_RETAINED"
            except BaseException:
                # Keep the original effect failure and honest UNKNOWN state.
                # A malformed recovery record is not permission to retry.
                pass
            raise
        observation["transaction"] = _record(result)
        observation["publication_state"] = "PUBLISHER_RETURNED"
        phase = "POST_CALL_CUSTODY"
        _readback(destination, observation["transaction"])
        claim_state()
        after_pin, observation["source_after"], observation["host_after"] = _custody(
            source_loader, host_custody, deadline)
        coordinator._require(after_pin == host_pin, "BUNDLE_INSTALL_HOST_PROFILE_CHANGED")
    except BaseException as exc:
        failure = exc
    finally:
        if destination is not None:
            try:
                destination.close()
                observation["owned_destination_closed"] = True
            except BaseException as exc:
                failure = failure or exc
                phase = "DESTINATION_CLEANUP"
            observation["input_cleanup_uncertainty"].extend(destination.cleanup_uncertainty)
        if inputs is not None:
            try:
                inputs.close()
                observation["owned_inputs_closed"] = True
            except BaseException as exc:
                failure = failure or exc
                phase = "INPUT_CLEANUP"
            observation["input_cleanup_uncertainty"].extend(inputs.cleanup_uncertainty)
    if failure is not None:
        observation["status"] = ("CLEANUP_HOLD" if observation["installation_attempted"] or
            observation["input_cleanup_uncertainty"] or phase in {"DESTINATION_CLEANUP", "INPUT_CLEANUP"}
            else "REFUSED_OR_INDETERMINATE")
        observation["failure_stage"] = phase
        error = PiBundleInstallEntryError("BUNDLE_INSTALL_REFUSED_OR_CLEANUP_HOLD")
        error.observation = observation
        raise error from failure
    observation["status"] = "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED"
    return observation
