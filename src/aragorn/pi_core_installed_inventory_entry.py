"""Fixed, read-only inventory preparation under the pinned host bootstrap.

Only a caller-selected, already composed read-only worker view is accepted.
This entry neither creates that view nor grants launch or telemetry authority.
"""

from __future__ import annotations

import json
import os

from . import pi_core_coordinator_entry as coordinator
from . import pi_core_source_inventory_prepare as inventory
from .oci_worker_protocol import canonical_digest, canonical_json


SCHEMA = "aragorn/pi-core-installed-inventory-plan/v1"
_SOURCE_PATH = "opt/aragorn/src/aragorn/pi_core_installed_inventory_entry.py"
_FIELDS = {"schema", "host_profile_digest", "source_plan", "worker_view", "observer_root_identity"}
_ARTIFACTS = ("source_inventory", "loader_inventory", "profile", "preparation")


class PiInstalledInventoryEntryError(RuntimeError):
    """Preparation refused or ownership cleanup is uncertain; do not retry."""


def _custody(source_loader, host_custody, deadline):
    pin, sources, host = coordinator._custody(source_loader, host_custody, deadline)
    pins = source_loader.source_digests
    coordinator._require(_SOURCE_PATH in pins and any(
        type(row) is dict and row.get("module") == __name__ and
        row.get("path") == _SOURCE_PATH and row.get("digest") == pins[_SOURCE_PATH]
        for row in sources), "INSTALLED_INVENTORY_ENTRY_SOURCE_NOT_CONSUMED")
    return pin, sources, host


def _plan(value, host_pin):
    coordinator._exact(value, _FIELDS)
    coordinator._require(value["schema"] == SCHEMA and value["host_profile_digest"] == host_pin,
                         "INSTALLED_INVENTORY_PLAN_BINDING")
    coordinator._reference(value["source_plan"])
    coordinator._exact(value["worker_view"], {"path", "identity"})
    coordinator._path(value["worker_view"]["path"])
    inventory._identity(value["worker_view"]["identity"])
    inventory._identity(value["observer_root_identity"])
    return value


class _Views:
    """Own only the two named-view handles and protected worker ancestry."""

    def __init__(self, deadline):
        self.ancestry = coordinator._Inputs(deadline)
        self.observer = None
        self.worker = None
        self.expected_worker = self.expected_observer = None
        self.closed = False
        self.cleanup_uncertainty = []

    def acquire(self, worker_view, observer_identity):
        coordinator._require(not self.closed and self.worker is None and self.observer is None,
                             "INSTALLED_VIEW_ALREADY_ACQUIRED")
        self.expected_worker = dict(worker_view["identity"])
        self.expected_observer = dict(observer_identity)
        self.ancestry.hold_directory(coordinator._path(worker_view["path"]))
        self.worker = self.ancestry.directories[-1][1][-1]
        coordinator._require(inventory.base._file_identity(os.fstat(self.worker)) == self.expected_worker,
                             "INSTALLED_WORKER_ROOT_IDENTITY")
        self.observer = os.open("/", inventory._DIRECTORY_FLAGS)
        self.guard()

    def guard(self):
        coordinator._require(not self.closed and self.worker is not None and self.observer is not None,
                             "INSTALLED_VIEW_CUSTODY_ENDED")
        self.ancestry.guard()
        coordinator._require(not os.get_inheritable(self.worker) and not os.get_inheritable(self.observer),
                             "INSTALLED_VIEW_INHERITABLE_DESCRIPTOR")
        coordinator._require(inventory._directory(self.worker, readonly=True) == self.expected_worker,
                             "INSTALLED_WORKER_ROOT_CHANGED")
        coordinator._require(inventory._directory(self.observer, readonly=False) == self.expected_observer ==
                             inventory.base._file_identity(os.stat("/", follow_symlinks=False)),
                             "INSTALLED_OBSERVER_ROOT_CHANGED")

    def close(self):
        coordinator._require(not self.closed, "INSTALLED_VIEW_CLOSE_ALREADY_ATTEMPTED")
        self.closed = True
        failure = None
        if self.observer is not None:
            descriptor, self.observer = self.observer, None
            try:
                os.close(descriptor)
            except BaseException as exc:
                failure = exc
                self.cleanup_uncertainty.append({"scope": "OBSERVER_ROOT_CLOSE", "descriptors": [descriptor]})
        try:
            self.ancestry.close()
        except BaseException as exc:
            failure = failure or exc
        self.cleanup_uncertainty.extend(self.ancestry.cleanup_uncertainty)
        if failure is not None:
            raise PiInstalledInventoryEntryError("INSTALLED_VIEW_CLEANUP_UNCONFIRMED") from failure


def _artifacts(prepared, source_pin, plan, approved_source):
    coordinator._require(type(prepared) is inventory.PreparedPiSourceInventories,
                         "INSTALLED_INVENTORY_RESULT_TYPE")
    coordinator._require(canonical_digest(approved_source) == source_pin and approved_source["schema"] in
                         (inventory.PLAN_SCHEMA, inventory.RESTRICTED_PLAN_SCHEMA), "INSTALLED_INVENTORY_SOURCE_BINDING")
    documents = {name: inventory._document(getattr(prepared, name + "_raw")) for name in _ARTIFACTS}
    bundled = approved_source["schema"] == inventory.RESTRICTED_PLAN_SCHEMA
    schemas = {"source_inventory": inventory.node.SOURCE_SCHEMA,
               "loader_inventory": inventory.node.LOADER_SCHEMA,
               "profile": inventory.restricted.PROFILE_SCHEMA if bundled else inventory.node.PROFILE_SCHEMA,
               "preparation": inventory.RECEIPT_SCHEMA}
    coordinator._require(all(documents[name].get("schema") == schemas[name] for name in _ARTIFACTS),
                         "INSTALLED_INVENTORY_RESULT_SCHEMA")
    digests = {name: canonical_digest(document) for name, document in documents.items()}
    profile = inventory.node.validate_node_profile(documents["profile"])
    coordinator._require(profile["pins"] == {**approved_source["pins"],
        "source_inventory_digest": digests["source_inventory"], "loader_inventory_digest": digests["loader_inventory"]} and
        all(profile[key] == approved_source[key] for key in ("sources", "required_sources", "loader_files")),
        "INSTALLED_INVENTORY_PROFILE_BINDING")
    for artifact, member, declaration in (("source_inventory", "sources", "sources"),
                                         ("loader_inventory", "loaders", "loader_files")):
        measured = documents[artifact][member]
        coordinator._require(type(measured) is list and all(type(row) is dict and
            row.get("readonly_view") is True for row in measured) and
            sorted([{"path": row["path"], "digest": row["digest"]} for row in measured], key=lambda row: row["path"]) ==
            sorted(approved_source[declaration], key=lambda row: row["path"]), "INSTALLED_INVENTORY_ROW_BINDING")
    receipt = documents["preparation"]
    coordinator._require(receipt.get("authority") == inventory.AUTHORITY and
        receipt.get("phase3_exit_eligible") is False and receipt.get("expected_manifest_digest") == source_pin and
        receipt.get("worker_root_identity") == plan["worker_view"]["identity"] and
        receipt.get("observer_root_identity") == plan["observer_root_identity"] and
        all(receipt.get(name + "_digest") == digests[name] for name in ("profile", "source_inventory", "loader_inventory")),
        "INSTALLED_INVENTORY_RECEIPT_BINDING")
    return documents, digests


def run(plan_path, expected_plan_digest, *, deadline_ns, source_loader, host_custody):
    """Prepare from one pinned installed-view plan, without provisioning or launch."""
    observation = {"schema": "aragorn/pi-core-installed-inventory-result/v1",
        "authority": "ROOT_CALLER_CUSTODY_NOT_PILOT_OR_PHASE3_QUALIFICATION",
        "status": "REFUSED", "managed_call_attempted": False, "managed_result": None,
        "host_before": None, "host_after": None, "source_before": None, "source_after": None,
        "plan_digest": None, "deployment_digest": None, "owned_inputs_closed": False,
        "input_cleanup_uncertainty": [], "phase3_exit_eligible": False,
        "preparation_attempted": False, "owned_views_closed": False,
        "artifacts": None, "artifact_digests": None}
    inputs = views = failure = artifacts = digests = None
    phase = "PREFLIGHT"
    try:
        coordinator._require(os.geteuid() == os.getegid() == 0, "INSTALLED_INVENTORY_ROOT_REQUIRED")
        deadline = coordinator._deadline(deadline_ns)
        host_pin, observation["source_before"], observation["host_before"] = _custody(
            source_loader, host_custody, deadline)
        path, pin = coordinator._path(str(plan_path)), coordinator._pin(expected_plan_digest)
        inputs = coordinator._Inputs(deadline)
        plan = _plan(inputs.read(path, pin, coordinator._PLAN_LIMIT), host_pin)
        observation["plan_digest"] = pin
        phase = "PREPARED_INPUTS"
        source_plan = inputs.ref(plan["source_plan"])
        source_raw, source_pin = canonical_json(source_plan), plan["source_plan"]["digest"]
        approved_source = inventory._plan(source_raw, source_pin)
        inputs.guard()
        _custody(source_loader, host_custody, deadline)
        phase = "HELD_INPUTS"
        views = _Views(deadline)
        views.acquire(plan["worker_view"], plan["observer_root_identity"])
        inputs.guard()
        _custody(source_loader, host_custody, deadline)
        phase = "INVENTORY_PREPARATION"
        observation["preparation_attempted"] = True
        prepared = inventory.prepare_pi_source_inventories(source_raw,
            expected_manifest_digest=source_pin, worker_root_fd=views.worker,
            expected_worker_root_identity=plan["worker_view"]["identity"],
            observer_root_fd=views.observer, expected_observer_root_identity=plan["observer_root_identity"],
            deadline=deadline)
        artifacts, digests = _artifacts(prepared, source_pin, plan, approved_source)
        phase = "POST_CALL_CUSTODY"
        views.guard()
        inputs.guard()
        after_pin, observation["source_after"], observation["host_after"] = _custody(
            source_loader, host_custody, deadline)
        coordinator._require(after_pin == host_pin, "INSTALLED_INVENTORY_HOST_PROFILE_CHANGED")
    except BaseException as exc:
        failure = exc
        if isinstance(exc, inventory.PiSourceInventoryPreparationError) and (exc.held_fds or exc.ambiguous_fds):
            observation["input_cleanup_uncertainty"].append({"scope": "INVENTORY_HELPER_DESCRIPTORS",
                "held_fds": list(exc.held_fds), "ambiguous_fds": list(exc.ambiguous_fds)})
    finally:
        if views is not None:
            try:
                views.close()
                observation["owned_views_closed"] = True
            except BaseException as exc:
                failure = failure or exc
                phase = "HOLDER_CLEANUP"
            observation["input_cleanup_uncertainty"].extend(views.cleanup_uncertainty)
        if inputs is not None:
            try:
                inputs.close()
                observation["owned_inputs_closed"] = True
            except BaseException as exc:
                failure = failure or exc
                phase = "INPUT_CLEANUP"
            observation["input_cleanup_uncertainty"].extend(inputs.cleanup_uncertainty)
        observation["input_cleanup_uncertainty"] = json.loads(canonical_json(observation["input_cleanup_uncertainty"]))
    if failure is not None:
        observation["status"] = ("CLEANUP_HOLD" if observation["input_cleanup_uncertainty"] or
            phase in {"HOLDER_CLEANUP", "INPUT_CLEANUP"} else "REFUSED_OR_INDETERMINATE")
        observation["failure_stage"] = phase
        error = PiInstalledInventoryEntryError("INSTALLED_INVENTORY_REFUSED_OR_CLEANUP_HOLD")
        error.observation = observation
        raise error from failure
    observation["status"] = "INVENTORIES_PREPARED_NOT_QUALIFIED"
    observation["artifacts"], observation["artifact_digests"] = artifacts, digests
    return observation
