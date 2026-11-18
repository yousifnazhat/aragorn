"""Pi-aware durable grant reconciliation, never effect or launch authority.

The operator supplies a protected grant/config and an original bounded deadline.
Recovery only reconciles exact retained receipts. Rotation archives the old
terminal state before publishing a distinct already-authorized grant; it does
not admit a bundle, prove a fresh activation, retry an effect or clear a journal.
Frozen predecessors remain unchanged, including their stricter receipt reader.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import math
import os
import stat
import time

from . import pi_core_request_broker as pi
from . import runtime_action_broker as broker
from . import runtime_action_broker_v2 as profile
from . import runtime_action_broker_v4 as grants
from .oci_worker_protocol import canonical_digest, canonical_json


def _require(condition, reason):
    if not condition:
        raise broker.RuntimeActionBrokerError(reason)


def _remaining(deadline):
    _require(type(deadline) in (int, float) and math.isfinite(deadline) and
             time.monotonic() < deadline, "Pi grant reconciliation deadline expired or invalid")


def _configuration(config, deadline):
    _remaining(deadline)
    _require(deadline - time.monotonic() <= 30, "Pi grant reconciliation budget is unbounded")
    _require(type(config) is grants.RuntimeActionBrokerV4Config,
             "Pi grant reconciliation requires the configured protected broker identity")
    # The frozen validator requires effective UID == expected_broker_uid and
    # preserves distinct worker/sensor/broker roles. Do not require root here.
    return grants._validate_config(config)


def _journal_clear(control_fd, config):
    # _load_state may migrate legacy bytes. Reconciliation must not silently
    # mutate a different state generation before its ambiguity guards run.
    base = config.broker.broker
    stored = broker._load_control(control_fd, base.state_path, base, "Pi recovery broker state")
    state = broker._state(stored)
    _require(state == stored, "Pi grant reconciliation requires current canonical broker state")
    _require(state["effect_journal"] is None, "Pi grant reconciliation holds an unresolved effect journal")


def _result_record(claim, receipt):
    # Dispatch on the effective result, never rewrite the original policy.
    _require(type(receipt) is dict and type(receipt.get("broker_result")) is dict,
             "Pi grant receipt is invalid")
    if receipt["broker_result"].get("verdict") != "BLOCK":
        return grants._result_record(claim, receipt)
    result = {"schema": "aragorn/runtime-capability-grant-result/v1",
        "authority": "BROKER_GRANT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": claim["grant_digest"], "lease_digest": claim["lease_digest"],
        "profile_result": pi._effective_profile_result(claim["profile_claim"], receipt)}
    return grants._grant_result(result, claim)


def _pending_matches(control_fd, config, claim):
    """Validate before publishing CONSUMED; remove only after the durable write."""
    expected = canonical_json(claim["profile_pending"])
    try:
        current = broker._read_owned_bytes_at(control_fd, config.broker.profile_pending_path.name,
            max_bytes=len(expected), expected_uid=config.broker.broker.expected_broker_uid,
            exact_mode=0o400, label="Pi exact pending receipt")
    except FileNotFoundError:
        return False
    _require(current == expected, "Pi pending receipt differs from retained claim")
    return True


def _terminal_receipt(control_fd, config, state):
    _require(state["status"] in grants._TERMINAL_STATES, "Pi grant is not terminal")
    grants._require_no_pending_at(control_fd, config)
    if state["status"] != "CONSUMED":
        grants._require_no_profile_receipt_at(control_fd, config)
        return None
    receipt = grants._load_profile_receipt(control_fd, config)
    _require(state["result"] == _result_record(state["claim"], receipt),
             "Pi grant terminal receipt changed")
    return receipt


def _require_no_terminal_archives(control_fd, digest):
    # Either name, even a symlink/partial archive, is evidence rather than
    # permission to resume. No read/repair of the frozen archive staging area.
    for kind in ("state", "profile-receipt"):
        try:
            os.stat(grants._archive_name(kind, digest), dir_fd=control_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise broker.RuntimeActionEffectIndeterminate("Pi terminal archive already exists; explicit reconciliation required")


def _named_receipt(control_fd, config, fd):
    """Only the original single-link, protected, canonical file may be retired."""
    name = config.broker.profile_receipt_path.name
    meta = os.fstat(fd)
    _require(stat.S_ISREG(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o400 and
             meta.st_uid == config.broker.broker.expected_broker_uid and
             meta.st_gid == os.fstat(control_fd).st_gid and meta.st_nlink == 1 and
             0 < meta.st_size <= grants._MAX_STATE_BYTES, "Pi terminal receipt metadata is unsafe")
    identity = broker._file_identity(meta)
    raw = os.pread(fd, meta.st_size + 1, 0)
    _require(len(raw) == meta.st_size and identity == broker._file_identity(os.fstat(fd)) ==
             broker._file_identity(os.stat(name, dir_fd=control_fd, follow_symlinks=False)),
             "Pi terminal receipt custody changed")
    return identity, raw


@contextmanager
def _hold_terminal_receipt(control_fd, config, state):
    if state["status"] != "CONSUMED":
        _terminal_receipt(control_fd, config, state)
        yield None
        return
    grants._require_no_pending_at(control_fd, config)
    try:
        fd = os.open(config.broker.profile_receipt_path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=control_fd)
    except FileNotFoundError as exc:
        raise broker.RuntimeActionBrokerError("Pi consumed grant has no active receipt; explicit reconciliation required") from exc
    primary = None
    try:
        identity, raw = _named_receipt(control_fd, config, fd)
        receipt = broker._parse_canonical_document(raw, "Pi original terminal receipt")
        _require(state["result"] == _result_record(state["claim"], receipt), "Pi grant terminal receipt changed")
        yield fd, identity, raw
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(fd)
        except BaseException as cleanup:
            error = broker.RuntimeActionEffectIndeterminate("Pi held terminal receipt close is uncertain")
            if primary is not None:
                error.add_note(f"Receipt close also failed: {type(cleanup).__name__}")
                raise error from primary
            raise error from cleanup


def _under_role_lock(config, deadline, operation, mutation_attempted, uncertain):
    """Keep the callback's original error if the frozen lock's finally also fails."""
    primary = None

    def guarded(control_fd):
        nonlocal primary
        try:
            return operation(control_fd)
        except BaseException as error:
            primary = error
            raise

    try:
        profile._with_profile_lock(config.broker, deadline, guarded)
    except BaseException as outer:
        # The frozen lock normally re-raises the callback exception or wraps
        # its OSError/ValueError directly. A different failure is independent.
        if primary is not None and outer is not primary and outer.__cause__ is not primary:
            combined = broker.RuntimeActionEffectIndeterminate("Pi role-lock cleanup is uncertain after callback failure")
            combined.pi_role_lock_cleanup_error = outer  # Includes its original low-level cleanup cause.
            raise combined from primary
        if mutation_attempted():
            raise broker.RuntimeActionEffectIndeterminate(uncertain) from outer
        raise


def recover_pi_runtime_capability_grant(config, *, deadline_monotonic):
    """Reconcile one exact receipt; missing/ambiguous evidence stays held."""
    grant = _configuration(config, deadline_monotonic)
    digest = canonical_digest(grant)
    result = None
    mutation_attempted = False

    def recover(control_fd):
        nonlocal result, mutation_attempted
        _remaining(deadline_monotonic)
        _journal_clear(control_fd, config)
        state = grants._load_state(control_fd, config, digest)
        status = state["status"]
        if status == "AVAILABLE":
            grants._require_no_pending_at(control_fd, config)
            grants._require_no_profile_receipt_at(control_fd, config)
            # Request handling invokes recovery directly. A restored AVAILABLE
            # file must not revive an already archived terminal grant.
            _remaining(deadline_monotonic)
            _require_no_terminal_archives(control_fd, digest)
            _remaining(deadline_monotonic)
            now = int(time.time())
            if now >= grant["expires_at_unix"]:
                _remaining(deadline_monotonic)
                mutation_attempted = True
            result = grants._refresh_available_grant(control_fd, config, grant, state, now)
        elif status in {"ABANDONED", "EXPIRED"}:
            if status == "EXPIRED":
                grants._require_expiration_matches_grant(state, grant)
            _terminal_receipt(control_fd, config, state)
            result = state
        else:
            receipt = grants._load_profile_receipt(control_fd, config)
            record = _result_record(state["claim"], receipt)
            pending = _pending_matches(control_fd, config, state["claim"]["profile_claim"])
            if status == "CONSUMED":
                _require(state["result"] == record, "Pi grant terminal receipt changed")
            else:
                _remaining(deadline_monotonic)
                mutation_attempted = True
                state = {**state, "status": "CONSUMED", "result": record}
                grants._publish_state(control_fd, config, state)
            if pending:
                _remaining(deadline_monotonic)
                mutation_attempted = True
                grants._discard_exact_profile_pending(control_fd, config, state["claim"]["profile_claim"])
            result = state
        _remaining(deadline_monotonic)

    _under_role_lock(config, deadline_monotonic, recover, lambda: mutation_attempted,
                     "Pi grant recovery publication or cleanup is uncertain")
    return json.loads(canonical_json(result))


def initialize_pi_runtime_capability_grant(config, *, now_unix=None, deadline_monotonic):
    """Initialize or rotate protected broker authority without reviving old grants.

    The managed caller must separately bind a fresh grant to a new admitted worker.
    This function never starts a service or automatically recovers CLAIMED state.
    """
    grant = _configuration(config, deadline_monotonic)
    fixed_now = None if now_unix is None else broker._uint(now_unix, "Pi grant time")
    digest = canonical_digest(grant)
    available = {"schema": "aragorn/runtime-capability-grant-state/v1",
        "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": digest, "status": "AVAILABLE", "claim": None, "result": None}
    result = None
    mutation_attempted = False

    def live():
        _remaining(deadline_monotonic)
        # A caller's sampled time cannot extend validity across archive or fsync.
        grants._require_live_grant(grant, int(time.time()))
        if fixed_now is not None:
            grants._require_live_grant(grant, fixed_now)

    def initialize(control_fd):
        nonlocal result, mutation_attempted
        _remaining(deadline_monotonic)
        _journal_clear(control_fd, config)
        now = int(time.time()) if fixed_now is None else fixed_now
        try:
            current = grants._load_any_state(control_fd, config)
        except FileNotFoundError:
            grants._require_no_pending_at(control_fd, config)
            grants._require_no_profile_receipt_at(control_fd, config)
            _require_no_terminal_archives(control_fd, digest)
            _require(grant["issued_at_unix"] <= now, "Pi grant is not yet valid")
            _remaining(deadline_monotonic)
            mutation_attempted = now >= grant["expires_at_unix"]
            result = grants._refresh_available_grant(control_fd, config, grant, available, now)
            if result["status"] == "AVAILABLE":
                live()
                mutation_attempted = True
                grants._publish_state(control_fd, config, result)
            _remaining(deadline_monotonic)
            return
        if current["grant_digest"] != digest:
            # Receipt validity and absence of pending work are established
            # before any immutable archive or replacement state publication.
            with _hold_terminal_receipt(control_fd, config, current) as held:
                live()
                _require_no_terminal_archives(control_fd, current["grant_digest"])
                _require_no_terminal_archives(control_fd, digest)
                archives = []
                if held is not None:
                    archives.append(("profile-receipt", held[2]))
                archives.append(("state", canonical_json(current)))
                for kind, raw in archives:
                    _remaining(deadline_monotonic)
                    mutation_attempted = True
                    grants._publish_immutable_at(control_fd, grants._archive_name(kind, current["grant_digest"]),
                        raw, config, f"Pi retained {kind} archive")
                if held is not None:
                    for kind, raw in archives:
                        _remaining(deadline_monotonic)
                        retained = broker._read_owned_bytes_at(control_fd, grants._archive_name(kind, current["grant_digest"]),
                            max_bytes=grants._MAX_STATE_BYTES, expected_uid=config.broker.broker.expected_broker_uid,
                            exact_mode=0o400, label=f"Pi retained {kind} archive")
                        _require(retained == raw, "Pi immutable terminal archive changed")
                    _require(grants._load_any_state(control_fd, config) == current, "Pi terminal state changed during rotation")
                    grants._require_no_pending_at(control_fd, config)
                    live()
                    fd, identity, raw = held
                    _require(_named_receipt(control_fd, config, fd) == (identity, raw), "Pi original terminal receipt changed")
                    # All legitimate writers share this role-private directory and lock.
                    # Never retry an uncertain unlink; the successors require absence.
                    os.unlink(config.broker.profile_receipt_path.name, dir_fd=control_fd)
                    os.fsync(control_fd)
                    grants._require_no_profile_receipt_at(control_fd, config)
                    _require(os.fstat(fd).st_nlink == 0, "Pi original terminal receipt retirement is uncertain")
                live()
                grants._publish_state(control_fd, config, available)
            result = available
        elif current["status"] == "AVAILABLE":
            grants._require_no_pending_at(control_fd, config)
            grants._require_no_profile_receipt_at(control_fd, config)
            _require_no_terminal_archives(control_fd, digest)
            _remaining(deadline_monotonic)
            mutation_attempted = now >= grant["expires_at_unix"]
            result = grants._refresh_available_grant(control_fd, config, grant, current, now)
        elif current["status"] == "CLAIMED":
            raise broker.RuntimeActionBrokerError("Pi unresolved grant claim requires exact recovery")
        else:
            if current["status"] == "EXPIRED":
                grants._require_expiration_matches_grant(current, grant)
            _terminal_receipt(control_fd, config, current)
            result = current
        _remaining(deadline_monotonic)

    _under_role_lock(config, deadline_monotonic, initialize, lambda: mutation_attempted,
                     "Pi grant initialization/archive or cleanup is uncertain")
    return json.loads(canonical_json(result))
