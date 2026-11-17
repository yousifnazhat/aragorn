"""One prepared VM-host coordinator call under the existing protected loader.

This entrypoint installs nothing, accepts no callable/command selectors, and
does not provision policy, grants, observations or health. The wrapper owns host
and source custody; this module owns only prepared-input and service holders.
"""

from __future__ import annotations

from contextlib import ExitStack
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

from . import pi_core_confined_launch as launch
from . import pi_core_managed_bootstrap as managed
from . import pi_core_provider_approval as approvals
from . import pi_core_provider_credential as credentials
from . import pi_core_service_configuration as configuration
from . import pi_core_service_provision as runtime
from . import runtime_action_broker as broker
from . import runtime_process_profile as process
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_worker import RuntimeActionWorkerBinding

SCHEMA = "aragorn/pi-core-coordinator-plan/v1"
_BOOTSTRAP = "_aragorn_pi_coordinator_bootstrap"
_SOURCE_BOOTSTRAP = "_aragorn_pi_service_source"
_PLAN_LIMIT = 64 * 1024
_DOCUMENT_LIMIT = 2 * 1024 * 1024
_TOTAL_LIMIT = 8 * 1024 * 1024
_PIN = re.compile(r"sha256:[a-f0-9]{64}\Z")
_PATH_FIELDS = {"socket_path", "instance_lock_path", "lock_path", "control_root",
    "protected_root", "staging_root", "policy_path", "revocations_path",
    "health_path", "observation_path", "state_path"}
_PLAN_FIELDS = {"schema", "mode", "host_profile_digest", "cas_root", "context",
    "deployment", "revoked_context_ids", "runtime_conformance_digest", "launch",
    "service_runtime", "service_configuration", "provider_inputs", "provider"}


class PiCoordinatorEntryError(RuntimeError):
    """A prepared call refused or cleanup is uncertain; never retry it here."""


def _require(value, reason):
    if not value:
        raise PiCoordinatorEntryError(reason)


def _pin(value):
    _require(type(value) is str and _PIN.fullmatch(value) is not None,
             "COORDINATOR_PIN_REQUIRED")
    return value


def _path(value):
    _require(type(value) is str and 0 < len(value) <= 4096 and
             value.startswith("/") and value != "/" and
             all(part not in {"", ".", ".."} for part in value.split("/")[1:]) and
             all(ord(char) >= 32 and ord(char) != 127 for char in value),
             "COORDINATOR_ABSOLUTE_PATH_REQUIRED")
    return Path(value)


def _exact(value, fields):
    _require(type(value) is dict and set(value) == set(fields),
             "COORDINATOR_DOCUMENT_FIELDS")


def _reference(value):
    _exact(value, {"path", "digest"})
    _path(value["path"])
    _pin(value["digest"])
    return value


def _deadline(value):
    _require(type(value) is int and 0 < value < 2**63,
             "COORDINATOR_ORIGINAL_DEADLINE_REQUIRED")
    bounded = math.nextafter(value / 1_000_000_000, 0.0)
    now = time.monotonic()
    _require(now < bounded <= now + 30 and time.monotonic_ns() < value,
             "COORDINATOR_DEADLINE_EXPIRED_OR_UNBOUNDED")
    return bounded


def _custody(source_loader, host_custody, deadline):
    host_type = getattr(sys.modules.get(_BOOTSTRAP), "PiCoordinatorHostCustody", None)
    source_type = getattr(sys.modules.get(_SOURCE_BOOTSTRAP), "PiServiceSourceLoader", None)
    _require(host_type is not None and source_type is not None and
             type(host_custody) is host_type and type(source_loader) is source_type,
             "COORDINATOR_PROTECTED_BOOTSTRAP_REQUIRED")
    host_custody.guard(deadline=deadline)
    host_pin = _pin(host_custody.manifest_digest)
    records = source_loader.snapshot()
    sources = source_loader.source_digests
    path = "opt/aragorn/src/aragorn/pi_core_coordinator_entry.py"
    _require(type(records) is list and type(sources) is dict and
             any(type(row) is dict and row.get("module") == __name__ and
                 row.get("path") == path and row.get("digest") == sources.get(path)
                 for row in records) and path in sources,
             "COORDINATOR_ENTRY_SOURCE_NOT_CONSUMED")
    return host_pin, json.loads(canonical_json(records)), host_custody.snapshot()


class _Inputs:
    """Held fixed-plan documents only; not a general configuration loader."""

    def __init__(self, deadline):
        self.deadline, self.rows, self.total = deadline, [], 0
        self.directories = []
        self.closed = False
        self.cleanup_uncertainty = []

    def _chain(self, path):
        try:
            return runtime._open_chain(path, self.deadline)
        except BaseException:
            # That helper owns partial descriptors until it returns. Do not
            # guess their numbers, retry closes, or claim their cleanup here.
            self.cleanup_uncertainty.append({"scope": "ANCESTRY_ACQUISITION", "path": str(path)})
            raise

    def _close_pending(self, descriptors):
        try:
            runtime.provision._close_all(descriptors)
        except BaseException:
            self.cleanup_uncertainty.append({"scope": "DESCRIPTOR_CLOSE", "descriptors": list(descriptors)})
            raise

    def read(self, path, pin, maximum):
        _require(not self.closed and not self.cleanup_uncertainty, "COORDINATOR_INPUT_CUSTODY_ENDED")
        _pin(pin)
        path = _path(str(path))
        for row in self.rows:
            if row["path"] == path:
                _require(row["pin"] == pin, "COORDINATOR_INPUT_PIN_CONFLICT")
                _require(len(row["raw"]) <= maximum, "COORDINATOR_REUSED_INPUT_BOUND")
                self.guard()
                return json.loads(row["raw"])
        chain = self._chain(path.parent)
        descriptor = -1
        try:
            identities = [broker._directory_identity(os.fstat(fd)) for fd in chain]
            identities[-1] = runtime.provision._identity(os.fstat(chain[-1]))
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=chain[-1])
            before = os.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                     before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400 and
                     0 < before.st_size <= maximum and not os.get_inheritable(descriptor),
                     "COORDINATOR_INPUT_METADATA")
            _require(self.total + before.st_size <= _TOTAL_LIMIT, "COORDINATOR_INPUT_TOTAL_BOUND")
            chunks, size = [], 0
            while True:
                _require(time.monotonic() < self.deadline, "COORDINATOR_INPUT_DEADLINE")
                chunk = os.read(descriptor, min(65536, maximum + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                _require(size <= before.st_size, "COORDINATOR_INPUT_GREW")
            raw = b"".join(chunks)
            document = broker._parse_canonical_document(raw, "prepared coordinator input")
            _require(len(raw) == before.st_size and canonical_digest(document) == pin and
                     broker._file_identity(before) == broker._file_identity(os.fstat(descriptor)) ==
                     broker._file_identity(os.stat(path.name, dir_fd=chain[-1], follow_symlinks=False)),
                     "COORDINATOR_INPUT_BYTES_OR_IDENTITY_CHANGED")
            row = dict(path=path, pin=pin, raw=raw, chain=chain, identities=identities,
                       fd=descriptor, identity=broker._file_identity(before))
            self.rows.append(row)
            chain, descriptor = [], -1
            self.total += size
            self.guard()
            return document
        finally:
            pending = ([descriptor] if descriptor >= 0 else []) + list(reversed(chain))
            self._close_pending(pending)

    def ref(self, value):
        value = _reference(value)
        return self.read(_path(value["path"]), value["digest"], _DOCUMENT_LIMIT)

    def hold_directory(self, path):
        _require(not self.closed and not self.cleanup_uncertainty, "COORDINATOR_INPUT_CUSTODY_ENDED")
        path = _path(str(path))
        chain = self._chain(path)
        try:
            identities = [broker._directory_identity(os.fstat(fd)) for fd in chain]
            identities[-1] = runtime.provision._identity(os.fstat(chain[-1]))
            self.directories.append((path, chain, identities))
            chain = []
            self.guard()
        finally:
            self._close_pending(list(reversed(chain)))

    def guard(self):
        _require(not self.closed and not self.cleanup_uncertainty and time.monotonic() < self.deadline,
                 "COORDINATOR_INPUT_CUSTODY_EXPIRED")
        for path, chain, identities in self.directories:
            runtime._chain_guard(path, chain, identities, self.deadline)
        for row in self.rows:
            runtime._chain_guard(row["path"].parent, row["chain"], row["identities"], self.deadline)
            _require(broker._file_identity(os.fstat(row["fd"])) == row["identity"] ==
                     broker._file_identity(os.stat(row["path"].name, dir_fd=row["chain"][-1],
                                                  follow_symlinks=False)),
                     "COORDINATOR_INPUT_CUSTODY_CHANGED")

    def close(self):
        _require(not self.closed, "COORDINATOR_INPUT_CLOSE_ALREADY_ATTEMPTED")
        self.closed = True
        pending = [fd for _, chain, _ in reversed(self.directories) for fd in reversed(chain)]
        self.directories.clear()
        for row in reversed(self.rows):
            pending += [row["fd"], *reversed(row["chain"])]
        self.rows.clear()
        self._close_pending(pending)
        _require(not self.cleanup_uncertainty, "COORDINATOR_INPUT_CLEANUP_UNCONFIRMED")


def _plan(value, host_pin, plan_path):
    _exact(value, _PLAN_FIELDS)
    _require(value["schema"] == SCHEMA and value["mode"] in {"UNAVAILABLE", "PROTECTED"} and
             value["host_profile_digest"] == host_pin, "COORDINATOR_PLAN_BINDING")
    _path(value["cas_root"])
    _pin(value["runtime_conformance_digest"])
    ids = value["revoked_context_ids"]
    _require(type(ids) is list and len(ids) <= 4096 and all(type(item) is str for item in ids) and
             ids == sorted(set(ids)), "COORDINATOR_REVOKED_CONTEXTS")
    for item in ids:
        _pin(item)
    refs = [_reference(value[name]) for name in ("context", "deployment", "launch")]
    for name, fields in (
        ("service_runtime", {"deployment_path", "receipt_digest", "manifest", "runtime_binding"}),
        ("service_configuration", {"deployment_path", "receipt_digest", "manifest", "configurations"}),
        ("provider_inputs", {"deployment_path", "receipt_digest", "manifest"}),
    ):
        section = value[name]
        _exact(section, fields)
        _path(section["deployment_path"])
        _pin(section["receipt_digest"])
        refs.extend(_reference(section[key]) for key in fields - {"deployment_path", "receipt_digest"})
    if value["mode"] == "UNAVAILABLE":
        _require(value["provider"] is None, "COORDINATOR_UNAVAILABLE_HAS_AUTHORITY")
    else:
        selected = value["provider"]
        _exact(selected, {"credential_source", "root_broker_config", "approval_intent"})
        secret = _path(selected["credential_source"])
        credentials._source_path(secret)
        refs += [_reference(selected[key]) for key in ("root_broker_config", "approval_intent")]
        _require(secret != plan_path and all(_path(ref["path"]) != secret for ref in refs),
                 "COORDINATOR_CREDENTIAL_IS_NOT_A_DOCUMENT")
    return value


def _launch(document, mode):
    _exact(document, launch.PiConfinedLaunchConfig.__dataclass_fields__)
    converted = dict(document)
    for key in ("root_directory", "runtime_directory", "activation_directory"):
        converted[key] = _path(converted[key])
    value = launch.PiConfinedLaunchConfig(**converted)
    _require(value.native_request is True and
             (value.provider_route_digest is not None) == (mode == "PROTECTED") and
             (mode != "PROTECTED" or value.source_observation is not None),
             "COORDINATOR_LAUNCH_MODE_DIFFERS")
    return value


def _broker_config(document):
    _exact(document, broker.RuntimeActionBrokerConfig.__dataclass_fields__)
    converted = {key: _path(value) if key in _PATH_FIELDS else value for key, value in document.items()}
    config = broker.RuntimeActionBrokerConfig(**converted)
    _require(config.expected_broker_uid == 0, "COORDINATOR_PROVIDER_REQUIRES_ROOT_CONTROL")
    broker._validate_config(config)
    return config


def run(plan_path, expected_plan_digest, *, deadline_ns, source_loader, host_custody):
    """Consume one approved prepared plan; never install, repair, or retry."""
    observation = {"schema": "aragorn/pi-core-coordinator-observation/v1",
        "authority": "ROOT_CALLER_CUSTODY_NOT_PILOT_OR_PHASE3_QUALIFICATION",
        "status": "REFUSED", "managed_call_attempted": False, "managed_result": None,
        "host_before": None, "host_after": None, "source_before": None, "source_after": None,
        "plan_digest": None, "deployment_digest": None, "owned_inputs_closed": False,
        "input_cleanup_uncertainty": [],
        "phase3_exit_eligible": False}
    inputs, failure, phase = None, None, "PREFLIGHT"
    try:
        _require(os.geteuid() == os.getegid() == 0, "COORDINATOR_ROOT_REQUIRED")
        deadline = _deadline(deadline_ns)
        host_pin, observation["source_before"], observation["host_before"] = _custody(
            source_loader, host_custody, deadline)
        path, pin = _path(str(plan_path)), _pin(expected_plan_digest)
        inputs = _Inputs(deadline)
        plan = _plan(inputs.read(path, pin, _PLAN_LIMIT), host_pin, path)
        observation["plan_digest"] = pin
        phase = "PREPARED_INPUTS"
        context, deployment = inputs.ref(plan["context"]), inputs.ref(plan["deployment"])
        observation["deployment_digest"] = plan["deployment"]["digest"]
        config = _launch(inputs.ref(plan["launch"]), plan["mode"])
        r, c, p = (plan[name] for name in ("service_runtime", "service_configuration", "provider_inputs"))
        runtime_args = dict(deployment_path=_path(r["deployment_path"]), receipt_digest=r["receipt_digest"],
            manifest=inputs.ref(r["manifest"]), manifest_digest=r["manifest"]["digest"],
            runtime_binding=inputs.ref(r["runtime_binding"]), runtime_binding_digest=r["runtime_binding"]["digest"], deadline=deadline)
        config_args = dict(deployment_path=_path(c["deployment_path"]), receipt_digest=c["receipt_digest"],
            manifest=inputs.ref(c["manifest"]), manifest_digest=c["manifest"]["digest"],
            configurations=inputs.ref(c["configurations"]), configurations_digest=c["configurations"]["digest"], deadline=deadline)
        public_args = dict(deployment_path=_path(p["deployment_path"]), receipt_digest=p["receipt_digest"],
            manifest=inputs.ref(p["manifest"]), manifest_digest=p["manifest"]["digest"], deadline=deadline)
        root_config = intent = None
        if plan["mode"] == "PROTECTED":
            root_config = _broker_config(inputs.ref(plan["provider"]["root_broker_config"]))
            intent = approvals.validate_intent(inputs.ref(plan["provider"]["approval_intent"]))
        inputs.guard()
        _custody(source_loader, host_custody, deadline)
        cas_root = _path(plan["cas_root"])
        inputs.hold_directory(cas_root)
        cas = CAS(cas_root, read_only=True)
        phase = "HELD_INPUTS"
        with ExitStack() as stack:
            held_runtime = stack.enter_context(runtime.hold_pi_service_runtime(**runtime_args))
            held_configuration = stack.enter_context(configuration.hold_pi_service_configuration(**config_args))
            held_provider = stack.enter_context(configuration.hold_pi_provider_inputs(**public_args))
            configs = held_configuration.configurations
            grant = configs["action"]["capability_grant"]
            _require(grant == configs["sensor"]["capability_grant"], "COORDINATOR_GRANTS_DIFFER")
            profile = process.runtime_process_profile(configs["sensor"]["observation_binding"]["runtime_profile"])
            binding = RuntimeActionWorkerBinding(*(grant[key] for key in
                ("runtime_digest", "active_skill_digest", "policy_digest", "policy_version")))
            provider = {}
            if root_config is not None:
                provider["provider_credential"] = stack.enter_context(credentials.hold_provider_credential(
                    _path(plan["provider"]["credential_source"]), provider_inputs=held_provider, deadline=deadline))
                provider["provider_approval"] = stack.enter_context(approvals.hold_provider_approval(
                    root_config, intent=intent, deadline=deadline))
            inputs.guard()
            _custody(source_loader, host_custody, deadline)
            phase = "MANAGED_CALL"
            observation["managed_call_attempted"] = True
            observation["managed_result"] = managed.run_native_pi_service_bootstrap(
                cas, context, profile=profile, grant=grant, protected_root=Path("/var/lib/aragorn/admitted"),
                runtime_conformance_digest=plan["runtime_conformance_digest"], deployment=deployment,
                revoked_context_ids=tuple(plan["revoked_context_ids"]), now_unix=int(time.time()), deadline=deadline,
                config=config, service_runtime=held_runtime, service_configuration=held_configuration,
                provider_inputs=held_provider, binding=binding, cleanup_timeout_seconds=5.0, **provider)
            _require(type(observation["managed_result"]) is dict and
                     observation["managed_result"].get("status") in {"BOOTSTRAP_COMPLETE", "REFUSED", "CLEANUP_HOLD"},
                     "COORDINATOR_MANAGED_RESULT_INVALID")
            phase = "POST_CALL_CUSTODY"
            inputs.guard()
            after_pin, observation["source_after"], observation["host_after"] = _custody(
                source_loader, host_custody, deadline)
            _require(after_pin == host_pin, "COORDINATOR_HOST_PROFILE_CHANGED")
            phase = "HOLDER_CLEANUP"
        returned_status = observation["managed_result"]["status"]
        observation["status"] = ("MANAGED_CALL_RETURNED_NOT_QUALIFIED" if returned_status == "BOOTSTRAP_COMPLETE"
                                 else "CLEANUP_HOLD" if returned_status == "CLEANUP_HOLD"
                                 else "REFUSED_OR_INDETERMINATE")
    except BaseException as exc:
        failure = exc
    finally:
        if inputs is not None:
            try:
                inputs.close()
                observation["owned_inputs_closed"] = True
            except BaseException as exc:
                failure = failure or exc
                phase = "INPUT_CLEANUP"
            observation["input_cleanup_uncertainty"] = json.loads(canonical_json(inputs.cleanup_uncertainty))
    if failure is not None:
        observation["status"] = "CLEANUP_HOLD" if phase in {"HOLDER_CLEANUP", "INPUT_CLEANUP"} else "REFUSED_OR_INDETERMINATE"
        observation["failure_stage"] = phase
        error = PiCoordinatorEntryError("COORDINATOR_REFUSED_OR_CLEANUP_HOLD")
        error.observation = observation
        raise error from failure
    return observation
