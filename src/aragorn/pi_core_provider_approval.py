"""Held root approval intent, bound once to an authenticated Pi activation.

This does not provision policy, health, credentials, observations or authority.
The caller must supply an operator-approved intent and authenticate the captured
activation before ``bind``. Session/run/tool IDs are deliberately absent from
the static request template; no validation-only placeholder is ever published.
Request issue/expiry times are not renewed, including during service startup.
"""

from __future__ import annotations

import os
import stat
import time
from contextlib import contextmanager

from . import pi_core_identity_handoff as channel
from . import pi_core_provider_mediation as mediation
from . import pi_core_worker_identity as identity
from . import runtime_action_broker as broker
from . import runtime_action_decision as decision
from .oci_worker_protocol import canonical_digest, canonical_json

INTENT_SCHEMA = "aragorn/pi-core-provider-intent/v1"
_SEAL = object()
_DERIVED = {"session_id", "run_id", "tool_call_id"}
_TEMPLATE_FIELDS = decision._REQUEST_FIELDS - _DERIVED


class PiProviderApprovalError(RuntimeError):
    """Protected approval preparation or its one-shot binding was refused."""


def _require(condition, reason):
    if not condition:
        raise PiProviderApprovalError(reason)


def validate_intent(value):
    """Validate metadata only; this is not proof of operator approval."""
    mediation._exact(value, {"schema", "route", "data_class", "payload_digest", "max_requests", "request"})
    _require(value["schema"] == INTENT_SCHEMA and type(value["data_class"]) is str and
             value["data_class"] in {"PUBLIC", "FABRICATED_OWNED_LAB"} and
             type(value["max_requests"]) is int and value["max_requests"] == 1,
             "PROVIDER_INTENT_REFUSED")
    route = mediation.validate_route(value["route"])
    broker._require_digest(value["payload_digest"], "provider intent payload")
    template = value["request"]
    mediation._exact(template, _TEMPLATE_FIELDS)
    # Only exercise the existing request parser; these IDs never leave here.
    broker._validate_runtime_action_request({**template, **{field: "validation-only" for field in _DERIVED}})
    _require(0 < template["expires_at_unix"] - template["issued_at_unix"] <=
             decision._MAX_REQUEST_LIFETIME_SECONDS, "PROVIDER_INTENT_LIFETIME_REFUSED")
    pins = {"operation_digest": canonical_digest(mediation._OPERATION),
            "path_digest": canonical_digest(route), "payload_digest": value["payload_digest"]}
    _require(all(template[key] == pin for key, pin in pins.items()), "PROVIDER_INTENT_PINS_REFUSED")
    _require(len(canonical_json(value)) <= mediation.MAX_FRAME, "PROVIDER_INTENT_LIMIT")
    return mediation._copy(value)


class PiProviderApproval:
    """An exact held root control directory and immutable detached intent.

    Only ``hold_provider_approval`` may construct this custody object. It does
    not hold the broker flock across service execution. Publication is one-shot
    and persistent; closing custody never removes approvals or replay claims.
    """

    __slots__ = ("_seal", "_active", "_pid", "_config", "_intent", "_intent_pin", "_deadline",
                 "_control_fd", "_lock_fd", "_root_identity", "_lock_identity",
                 "_attempted", "_published", "_publication_identity", "_publication_raw")

    def __init__(self, *, _seal=None):
        _require(_seal is _SEAL, "PROVIDER_APPROVAL_FACTORY_REQUIRED")
        self._seal, self._active = _seal, False
        self._attempted, self._published = False, False

    @property
    def config(self):
        return self._config

    @property
    def route_digest(self):
        return canonical_digest(self._intent["route"])

    def _custody(self, deadline):
        _require(type(self) is PiProviderApproval and self._seal is _SEAL and self._active,
                 "PROVIDER_APPROVAL_CUSTODY_REQUIRED")
        channel.validate_deadline(deadline)
        _require(deadline <= self._deadline and os.geteuid() == 0 and os.getegid() == 0 and
                 os.getpid() == self._pid,
                 "PROVIDER_APPROVAL_ROLE_OR_DEADLINE_CHANGED")
        _require(canonical_digest(self._intent) == self._intent_pin,
                 "PROVIDER_INTENT_CHANGED")
        action = self._intent["request"]
        _require(action["issued_at_unix"] <= time.time() < action["expires_at_unix"],
                 "PROVIDER_INTENT_EXPIRED_OR_FUTURE")
        broker._require_protected_ancestry(self._config.control_root.parent, 0)
        _require(broker._directory_identity(os.fstat(self._control_fd)) == self._root_identity ==
                 broker._directory_identity(os.lstat(self._config.control_root)),
                 "PROVIDER_CONTROL_ROOT_CHANGED")
        _require(broker._file_identity(os.fstat(self._lock_fd)) == self._lock_identity ==
                 broker._file_identity(os.stat(self._config.lock_path.name, dir_fd=self._control_fd,
                                               follow_symlinks=False)), "PROVIDER_CONTROL_LOCK_CHANGED")

    @contextmanager
    def _locked(self, deadline):
        self._custody(deadline)
        broker._acquire_lock(self._lock_fd, deadline)
        try:
            self._custody(deadline)
            yield
        finally:
            broker.fcntl.flock(self._lock_fd, broker.fcntl.LOCK_UN)

    def _ready(self, deadline):
        config = self._config
        load = lambda path, label: broker._load_control(self._control_fd, path, config, label)
        stored = load(config.state_path, "provider approval current state")
        state = broker._state(stored)
        _require(state == stored and state["effect_journal"] is None,
                 "PROVIDER_CONTROL_RECOVERY_REQUIRED")
        policy, rules = decision._policy(load(config.policy_path, "provider approval policy"))
        action = self._intent["request"]
        _require(canonical_digest(policy) == action["policy_digest"] and
                 policy["version"] == action["policy_version"] and
                 any(all(action[key] == value for key, value in rule.items()) for rule in rules),
                 "PROVIDER_APPROVAL_POLICY_MISMATCH")
        revocations = load(config.revocations_path, "provider approval revocations")
        health = load(config.health_path, "provider approval health")
        now = int(time.time())
        generation = broker.qualify_runtime_revocation_generation(policy, revocations,
            now_unix=now, minimum_revocation_generation=state["minimum_revocation_generation"])
        epoch = broker.qualify_runtime_health_epoch(policy, health,
            expected_runtime_digest=config.expected_runtime_digest, now_unix=now,
            minimum_mediator_health_epoch=state["minimum_mediator_health_epoch"])
        _require(generation is not None and epoch is not None and health["status"] == "healthy" and
                 action["active_skill_digest"] not in revocations["skill_digests"],
                 "PROVIDER_CONTROL_NOT_READY")
        # This existing observation is not claimed to describe the future worker.
        observation = load(config.observation_path, "provider approval observation")
        broker._observation(observation, observation.get("observed_at_unix"))
        decision._active(observation["active"])
        decision._measured_action(observation["measured_action"])
        self._custody(deadline)

    def _absent(self):
        mediation._absent_claim(self._control_fd, mediation.APPROVAL_NAME)

    def guard(self, *, deadline):
        """Recheck custody and current controls without writing or claiming work."""
        with self._locked(deadline):
            self._ready(deadline)
            if not self._published:
                self._absent()
            else:
                named = os.stat(mediation.APPROVAL_NAME, dir_fd=self._control_fd, follow_symlinks=False)
                _require(broker._file_identity(named) == self._publication_identity,
                         "PROVIDER_APPROVAL_CHANGED")
                raw = broker._read_owned_bytes_at(self._control_fd, mediation.APPROVAL_NAME,
                    max_bytes=mediation.MAX_FRAME, expected_uid=0, exact_mode=0o400,
                    label="held provider approval")
                _require(raw == self._publication_raw and self._publication_identity == broker._file_identity(
                         os.stat(mediation.APPROVAL_NAME, dir_fd=self._control_fd, follow_symlinks=False)),
                         "PROVIDER_APPROVAL_CHANGED")
                self._custody(deadline)

    def bind(self, request, activation, *, deadline):
        """Publish once after the caller authenticated actual captured identity.

        Times, runtime/skill/policy pins, operation, route and payload are fixed.
        Only session/run/tool IDs and the activation digest are derived here.
        Any attempted binding consumes this holder, including failed writes.
        """
        _require(not self._attempted, "PROVIDER_APPROVAL_ALREADY_ATTEMPTED")
        self._attempted = True
        self._custody(deadline)
        request = mediation.validate_provider_request(request)
        activation = identity.validate_activation(activation)
        _require(activation["runtime_digest"] == self._config.expected_runtime_digest and
                 activation["uid"] == self._config.expected_runtime_uid and
                 activation["gid"] == self._config.expected_runtime_gid and
                 time.monotonic_ns() < activation["expires_at_monotonic_ns"],
                 "PROVIDER_APPROVAL_ACTIVATION_MISMATCH")
        action = {**self._intent["request"], "session_id": activation["session_id"],
                  "run_id": activation["run_id"], "tool_call_id": canonical_digest(request)}
        approval = {**{key: self._intent[key] for key in
                      ("route", "data_class", "payload_digest", "max_requests")},
                    "schema": mediation.APPROVAL_SCHEMA, "authority": mediation.APPROVAL_AUTHORITY,
                    "activation_digest": canonical_digest(activation), "request": action}
        approval, _ = mediation._approval(approval, request, activation)
        raw = canonical_json(approval)
        _require(len(raw) <= mediation.MAX_FRAME, "PROVIDER_APPROVAL_LIMIT")
        with self._locked(deadline):
            self._ready(deadline)
            self._absent()
            mediation._absent_claim(self._control_fd, mediation._claim_name(activation))
            self._publish(raw, deadline)
        return mediation._copy(approval)

    def _publish(self, raw, deadline):
        # Retain incomplete temporary/public files on every failure. Only the
        # successful, exact temporary link is removed; replay claims are untouched.
        name, descriptor = broker.create_exclusive_file_at(self._control_fd,
            prefix=".provider-data-approval.", mode=0o400)
        try:
            pending = memoryview(raw)
            while pending:
                self._custody(deadline)
                written = os.write(descriptor, pending)
                _require(type(written) is int and 0 < written <= len(pending),
                         "PROVIDER_APPROVAL_WRITE_STALLED")
                pending = pending[written:]
            self._custody(deadline)
            os.fsync(descriptor)
            held = os.fstat(descriptor)
            named = os.stat(name, dir_fd=self._control_fd, follow_symlinks=False)
            _require(stat.S_ISREG(held.st_mode) and stat.S_IMODE(held.st_mode) == 0o400 and
                     held.st_uid == 0 and held.st_nlink == 1 and held.st_size == len(raw) and
                     broker._file_identity(held) == broker._file_identity(named),
                     "PROVIDER_APPROVAL_TEMP_CHANGED")
            self._custody(deadline)
            # link is atomic absent-only: never replace/adopt even identical bytes.
            os.link(name, mediation.APPROVAL_NAME, src_dir_fd=self._control_fd,
                    dst_dir_fd=self._control_fd, follow_symlinks=False)
            os.fsync(self._control_fd)
            linked = os.stat(mediation.APPROVAL_NAME, dir_fd=self._control_fd, follow_symlinks=False)
            held = os.fstat(descriptor)
            _require(linked.st_nlink == 2 and broker._file_identity(linked) == broker._file_identity(held) ==
                     broker._file_identity(os.stat(name, dir_fd=self._control_fd, follow_symlinks=False)),
                     "PROVIDER_APPROVAL_LINK_CHANGED")
            self._custody(deadline)
            os.unlink(name, dir_fd=self._control_fd)
            os.fsync(self._control_fd)
            held = os.fstat(descriptor)
            _require(held.st_nlink == 1 and broker._file_identity(held) == broker._file_identity(
                     os.stat(mediation.APPROVAL_NAME, dir_fd=self._control_fd, follow_symlinks=False)),
                     "PROVIDER_APPROVAL_PUBLICATION_CHANGED")
            observed = broker._read_owned_bytes_at(self._control_fd, mediation.APPROVAL_NAME,
                max_bytes=mediation.MAX_FRAME, expected_uid=0, exact_mode=0o400, label="published provider approval")
            _require(observed == raw and broker._file_identity(held) == broker._file_identity(
                     os.stat(mediation.APPROVAL_NAME, dir_fd=self._control_fd, follow_symlinks=False)),
                     "PROVIDER_APPROVAL_READBACK_CHANGED")
            self._custody(deadline)
            self._publication_identity, self._publication_raw = broker._file_identity(held), raw
            self._published = True
        finally:
            os.close(descriptor)


@contextmanager
def hold_provider_approval(config, *, intent, deadline):
    """Hold exact existing root controls; no installation, recovery or effects."""
    channel.validate_deadline(deadline)
    _require(type(config) is broker.RuntimeActionBrokerConfig and config.expected_broker_uid == 0 and
             os.geteuid() == 0 and os.getegid() == 0 and config.expected_runtime_uid is not None,
             "PROVIDER_APPROVAL_ROOT_CONFIG_REQUIRED")
    broker._validate_config(config)
    value = validate_intent(intent)
    _require(value["request"]["runtime_digest"] == config.expected_runtime_digest,
             "PROVIDER_APPROVAL_RUNTIME_MISMATCH")
    for path in (config.lock_path, config.instance_lock_path, config.socket_path, config.policy_path,
                 config.revocations_path, config.health_path, config.observation_path, config.state_path):
        _require(path.name != mediation.APPROVAL_NAME and not path.name.startswith("provider-activation-"),
                 "PROVIDER_APPROVAL_RESERVED_PATH")
    holder = PiProviderApproval(_seal=_SEAL)
    holder._config, holder._intent, holder._intent_pin = config, value, canonical_digest(value)
    holder._pid = os.getpid()
    holder._deadline = deadline
    holder._control_fd = holder._lock_fd = -1
    try:
        holder._control_fd = broker._open_protected_directory(config.control_root, 0, "provider approval control root")
        holder._lock_fd = broker._open_lock_file(holder._control_fd, config)
        holder._root_identity = broker._directory_identity(os.fstat(holder._control_fd))
        holder._lock_identity = broker._file_identity(os.fstat(holder._lock_fd))
        holder._active = True
        holder.guard(deadline=deadline)
        yield holder
    finally:
        holder._active = False
        failure = broker._release_lock_and_close(holder._lock_fd, False, holder._control_fd)
        if failure is not None:
            raise PiProviderApprovalError("PROVIDER_APPROVAL_CLOSE_FAILED") from failure
