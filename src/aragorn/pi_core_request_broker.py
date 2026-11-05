"""Create-only Pi mediation with mandatory protected request provenance.

The frozen broker generations remain unchanged. This connected successor
composes their grant/profile/lineage and serialized effect primitives; neither
ordinary JSON nor the sensor's relay attribution can replace the live root
request channel. It installs no listener and performs no automatic effect retry.
Effective BLOCK receipts remain readable as terminal state, but frozen recovery
and archive validators refuse them. The separate pi_core_request_recovery API
reconciles those exact receipts and explicitly archives/rotates terminal grants;
this one-shot mediator never retries effects or revives old authority itself.
"""

from __future__ import annotations

import math
import os
import re
import time

from . import pi_core_request_handoff as handoff
from . import runtime_action_broker as broker
from . import runtime_action_broker_v2 as profile
from . import runtime_action_broker_v3 as leases
from . import runtime_action_broker_v4 as grants
from . import runtime_action_broker_v5 as lineage
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_worker import RuntimeActionWorkerBinding


def _require(condition, reason):
    if not condition:
        raise broker.RuntimeActionBrokerError(reason)


def _guard(authority, deadline):
    _require(time.monotonic() < deadline == authority.deadline,
             "Pi request original deadline expired or extended")
    try:
        authority.guard()
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        raise broker.RuntimeActionBrokerError("protected Pi request is no longer current") from exc
    _require(time.monotonic() < deadline, "Pi request expired during protected remeasurement")


def _bindings(authority, grant, observed, attribution):
    activation, worker_request = authority.activation, authority.worker_request
    binding = RuntimeActionWorkerBinding(grant["runtime_digest"], grant["active_skill_digest"],
                                         grant["policy_digest"], grant["policy_version"])
    try:
        handoff.validate_projection(observed["envelope"], worker_request, activation, binding)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        raise broker.RuntimeActionBrokerError("Pi request/envelope projection differs") from exc
    _require(canonical_digest(worker_request) == authority.request_digest,
             "protected Pi worker request digest differs")
    # This is an independent sensor leg, not an invented attribution copied from
    # root's handoff. The existing relay-attributed submission does not qualify.
    fields = ("pid", "uid", "gid", "start_time_ticks", "mount_namespace", "cgroup",
              "profile_digest", "runtime_digest", "executable_digest", "active_skill_digest")
    _require(all(attribution[key] == activation[key] for key in fields),
             "sensor attribution is not the protected Pi worker")
    _require(grant["source_manifest_digest"] == activation["source_manifest_digest"] and
             grant["install_context_digest"] == activation["install_context_digest"] and
             grant["runtime_profile_digest"] == activation["profile_digest"],
             "Pi activation and protected grant lineage differ")
    return activation


def _claim_grant(config, claim, grant, authority, deadline):
    """The frozen claim transition with its mandatory Pi guard inside the lock."""
    accepted = None
    publication_attempted = False

    def claim_once(control_fd):
        nonlocal accepted, publication_attempted
        _guard(authority, deadline)
        claimed_at = int(time.time())
        grants._require_live_grant(grant, claimed_at)
        lease = claim["lease"]
        _require(lease["issued_at_unix"] <= claimed_at < lease["expires_at_unix"],
                 "Pi runtime capability lease is stale")
        accepted = {**claim, "profile_claim": {**claim["profile_claim"], "claimed_at_unix": claimed_at}}
        grants._grant_claim(accepted, claim["grant_digest"])
        state = grants._load_state(control_fd, config, accepted["grant_digest"])
        _require(state["status"] == "AVAILABLE", "Pi runtime capability grant is consumed")
        grants._require_no_pending_at(control_fd, config)
        grants._discard_stale_profile_receipt(control_fd, config)
        publication_attempted = True
        grants._publish_state(control_fd, config, {**state, "status": "CLAIMED", "claim": accepted})

    try:
        profile._with_profile_lock(config.broker, deadline, claim_once)
    except BaseException as exc:
        if publication_attempted:
            raise broker.RuntimeActionEffectIndeterminate("Pi grant claim publication or cleanup is uncertain") from exc
        raise
    return accepted


def _effective_profile_result(claim, receipt):
    """Retain policy and effective decisions separately, without rewriting either.

    This is the finite effective-BLOCK relation from the retained effective-receipt
    successor, plus Pi's protected-request refusal. All other frozen receipt joins
    and the generic lease-result validator remain in force.
    """
    document = broker._exact(receipt, leases._PROFILE_RECEIPT_FIELDS, "Pi profile receipt")
    _require(document["schema"] == "aragorn/runtime-process-profile-receipt/v1" and
             document["authority"] == "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY" and
             document["submission_digest"] == claim["submission_digest"] and
             document["runtime_attribution_digest"] == claim["runtime_attribution_digest"] and
             document["runtime_attribution"] == claim["profile_pending"]["runtime_attribution"],
             "Pi effective profile receipt is unbound")
    result = broker._exact(document["broker_result"], leases._BROKER_RESULT_FIELDS, "Pi effective broker result")
    broker._require_digest(result["observation_digest"], "Pi effective observation digest")
    reasons, decision = result["reason_codes"], result["decision"]
    _require(document["broker_result_digest"] == canonical_digest(result) and
             result["schema"] == "aragorn/runtime-action-broker-result/v1" and
             result["authority"] == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY" and
             result["request_digest"] == claim["request_digest"] and result["target_name"] == claim["target_name"] and
             result["verdict"] == "BLOCK" and result["effect_status"] == "NOT_PERFORMED" and
             type(reasons) is list and bool(reasons) and all(type(code) is str for code in reasons),
             "Pi effective result is unbound")
    if decision is None:
        _require(reasons == ["BROKER_REPLAY_BLOCKED"], "Pi absent decision is not an exact replay refusal")
    else:
        _require(type(decision) is dict and decision.get("schema") == "aragorn/runtime-action-decision/v1" and
                 decision.get("authority") == "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY" and
                 decision.get("request_digest") == claim["request_digest"] and
                 type(decision.get("reason_codes")) is list and all(
                     type(code) is str and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code) and not code.startswith("BROKER_")
                     for code in decision["reason_codes"]) and
                 decision["reason_codes"] == sorted(set(decision["reason_codes"])) and
                 decision.get("verdict") in {"ALLOW", "BLOCK"} and
                 (decision["verdict"] == "ALLOW") == (decision["reason_codes"] == []),
                 "Pi recorded policy decision is invalid")
        snapshots = {"BROKER_RUNTIME_PIN_MISMATCH", "BROKER_SENSOR_PIN_MISMATCH",
                     "BROKER_EFFECT_MEASUREMENT_MISMATCH", "BROKER_EFFECT_BINDING_MISMATCH"}
        final = {"BROKER_CLOCK_ROLLBACK", "BROKER_CLOCK_UNSTABLE", "BROKER_CLAIM_STATE_CHANGED",
                 "BROKER_DEADLINE_EXPIRED", "BROKER_PI_REQUEST_REFUSED"}
        _require((decision["verdict"] == "BLOCK" and reasons == decision["reason_codes"]) or
                 (reasons == sorted(set(reasons)) and set(reasons) <= snapshots) or
                 (len(reasons) == 1 and reasons[0] in final), "Pi effective BLOCK reason is unsupported")
    record = {"schema": "aragorn/runtime-capability-lease-result/v1",
        "authority": "BROKER_LEASE_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "lease_digest": claim["lease_digest"], "submission_digest": claim["submission_digest"],
        "profile_receipt_digest": canonical_digest(document), "broker_result_digest": canonical_digest(result),
        "verdict": "BLOCK", "effect_status": "NOT_PERFORMED"}
    return grants._validate_profile_result(record, claim)


def _consume_grant(config, claim, result, deadline):
    if result["verdict"] != "BLOCK":
        return grants._consume_grant(config, claim, result, deadline)

    def consume(control_fd):
        state = grants._load_state(control_fd, config, claim["grant_digest"])
        _require(state["status"] == "CLAIMED" and state["claim"] == claim,
                 "Pi grant claim changed before effective-result consumption")
        grants._require_no_pending_at(control_fd, config)
        receipt = grants._load_profile_receipt(control_fd, config)
        recorded = _effective_profile_result(claim["profile_claim"], receipt)
        _require(recorded["broker_result_digest"] == canonical_digest(result),
                 "Pi grant effective result differs from retained receipt")
        record = {"schema": "aragorn/runtime-capability-grant-result/v1",
                  "authority": "BROKER_GRANT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
                  "grant_digest": claim["grant_digest"], "lease_digest": claim["lease_digest"],
                  "profile_result": recorded}
        grants._publish_state(control_fd, config, {**state, "status": "CONSUMED", "result": record})

    profile._with_profile_lock(config.broker, deadline, consume)


def mediate_pi_runtime_create(value, config: lineage.RuntimeActionBrokerV5Config, *,
                              authority: handoff.PiRequestAuthority, deadline_monotonic):
    """Redeem one sensor issuance only for the root-observed exact Pi request.

    The caller separately authenticates the sensor connection and owns the root
    channel context and its result handoff. This function never constructs a lease
    from root metadata, accepts an optional guard, or falls back to legacy dispatch.
    """
    _require(type(authority) is handoff.PiRequestAuthority,
             "a live protected Pi request context is required")
    _require(type(deadline_monotonic) in (int, float) and math.isfinite(deadline_monotonic) and
             time.monotonic() < deadline_monotonic == authority.deadline,
             "Pi broker original deadline is invalid")
    deadline = deadline_monotonic
    try:
        authority.begin()  # The authenticated context is one-use even on refusal.
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        raise broker.RuntimeActionBrokerError("Pi request authority cannot be consumed") from exc
    wrapped = broker._parse_canonical_document(canonical_json(value), "Pi sensor issuance")
    broker._exact(wrapped, lineage._LINEAGE_ISSUANCE_FIELDS, "Pi lineage issuance")
    _require(wrapped["schema"] == lineage.LINEAGE_ISSUANCE_SCHEMA and
             wrapped["authority"] == lineage.LINEAGE_ISSUANCE_AUTHORITY,
             "Pi lineage issuance identity differs")
    grant = lineage._validate_config(config)
    issuance = wrapped["issuance"]
    _submission, observed, attribution, submission_digest, lease = grants._issued_submission(
        issuance, config.broker, grant, int(time.time()))
    activation = _bindings(authority, grant, observed, attribution)
    claim_started = False
    try:
        with lineage.hold_runtime_active_skill_lineage(attribution["pid"], attribution, grant,
                protected_root=config.protected_install_root, deadline=deadline) as live_lineage:
            _require(canonical_json(live_lineage) == canonical_json(wrapped["lineage"]),
                     "Pi active-skill lineage changed before redemption")
            joins = {"active_record_digest": "active_record_digest", "context_digest": "install_context_digest",
                     "manifest_digest": "source_manifest_digest", "tree_digest": "tree_digest"}
            _require(all(live_lineage[key] == activation[field] for key, field in joins.items()),
                     "Pi protected active lineage differs from launch")
            claim = grants._build_claim(grant, lease, observed, attribution, submission_digest, int(time.time()))
            claim_started = True
            claim = _claim_grant(config.broker, claim, grant, authority, deadline)
            pending = claim["profile_claim"]["profile_pending"]
            # Failed publication may already have durably written. Never erase
            # or abandon an uncertain claim/pending write to permit a retry.
            try:
                profile._create_profile_pending(config.broker.broker, pending, deadline)
            except BaseException as exc:
                raise broker.RuntimeActionEffectIndeterminate("Pi profile pending publication is uncertain") from exc
            try:
                result = _mediate(observed, config.broker, grant, claim, authority, deadline)
            except broker.RuntimeActionEffectIndeterminate:
                raise
            except broker.RuntimeActionBrokerError:
                # _mediate guarantees this exception means no journal/effect
                # attempt and successful cleanup. Exact pending is discarded
                # before the existing no-effect terminal grant transition.
                try:
                    profile._discard_profile_pending(config.broker.broker, pending, deadline)
                    grants._abandon_grant(config.broker, claim, deadline)
                except BaseException as exc:
                    raise broker.RuntimeActionEffectIndeterminate("Pi pre-effect state finalization is uncertain") from exc
                raise
            receipt = {
                "schema": "aragorn/runtime-process-profile-receipt/v1",
                "authority": "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
                "submission_digest": submission_digest, "runtime_attribution": attribution,
                "runtime_attribution_digest": canonical_digest(attribution),
                "broker_result": result, "broker_result_digest": canonical_digest(result),
            }
            try:
                profile._persist_profile_receipt(config.broker.broker, receipt, deadline)
                profile._discard_profile_pending(config.broker.broker, pending, deadline)
                _consume_grant(config.broker, claim, result, deadline)
            except BaseException as exc:
                raise broker.RuntimeActionEffectIndeterminate("Pi result/receipt finalization is uncertain") from exc
            return result
    except lineage.RuntimeActionObservationPublisherError as exc:
        if claim_started:
            raise broker.RuntimeActionEffectIndeterminate("Pi claimed action has uncertain lineage cleanup") from exc
        raise broker.RuntimeActionBrokerError("Pi protected lineage could not be held") from exc


def _mediate(observed, grant_config, grant, claim, authority, deadline):
    """Fixed create orchestration over the unchanged durable broker primitives."""
    config = grant_config.broker.broker
    broker._validate_config(config)
    request, target_name, payload = broker._request_effect(observed["envelope"])
    control_fd = protected_fd = staging_fd = lock_fd = -1
    locked = journal_attempted = effect_committed = False
    try:
        control_fd, protected_fd, staging_fd = broker._open_broker_roots(config)
        lock_fd = broker._open_lock_file(control_fd, config)
        broker._acquire_lock(lock_fd, deadline)
        locked = True
        broker._recover_effect_journal(control_fd, protected_fd, staging_fd, config)
        action_digests = broker._action_digests(protected_fd, target_name, payload)
        now = broker._clock_value(lambda: int(time.time()))
        broker._publish_observed_state_locked(control_fd, config, request, action_digests, observed, now)
        state, observation_digest, decision, reasons = broker._evaluate_snapshot(
            control_fd, config, request, action_digests, now)
        request_digest = canonical_digest(request)

        def result(snapshot, observed_digest, codes, created=False):
            return broker._result(request_digest=request_digest, observation_digest=observed_digest,
                target_name=target_name, verdict="ALLOW" if created else "BLOCK", reason_codes=codes,
                effect_status="CREATED" if created else "NOT_PERFORMED", decision=snapshot)

        if any(row["request_digest"] == request_digest or row["observation_digest"] == observation_digest
               for row in state["consumed"]):
            return result(None, observation_digest, ["BROKER_REPLAY_BLOCKED"])
        _require(len(state["consumed"]) < broker._MAX_CONSUMED, "Pi broker replay state is full")
        state["consumed"].append({"request_digest": request_digest, "observation_digest": observation_digest,
                                  "expires_at_unix": now + broker._MAX_OBSERVATION_LIFETIME_SECONDS})
        state["consumed"] = sorted(state["consumed"], key=canonical_json)
        broker._commit_state(control_fd, config, state)
        if decision["verdict"] != "ALLOW" or reasons:
            return result(decision, observation_digest, reasons or decision["reason_codes"])
        final_observation, final_decision, final_reasons, journal_state = observation_digest, decision, [], None

        def authorize_link():
            nonlocal final_observation, final_decision, final_reasons, journal_state
            previous_now = now
            for _attempt in range(2):
                effect_now = broker._clock_value(lambda: int(time.time()))
                if effect_now < previous_now:
                    final_reasons = ["BROKER_CLOCK_ROLLBACK"]
                    return False
                final_state, final_observation, final_decision, final_reasons = broker._evaluate_snapshot(
                    control_fd, config, request, action_digests, effect_now, minimum_state=state)
                after = broker._clock_value(lambda: int(time.time()))
                if after == effect_now:
                    break
                if after < effect_now:
                    final_reasons = ["BROKER_CLOCK_ROLLBACK"]
                    return False
                previous_now = after
            else:
                final_reasons = ["BROKER_CLOCK_UNSTABLE"]
                return False
            if final_observation != observation_digest or not any(
                    row["request_digest"] == request_digest and row["observation_digest"] == observation_digest
                    for row in final_state["consumed"]) or final_decision["verdict"] != "ALLOW":
                final_reasons = final_reasons or final_decision["reason_codes"] or ["BROKER_CLAIM_STATE_CHANGED"]
                return False
            if time.monotonic() >= deadline:
                final_reasons = ["BROKER_DEADLINE_EXPIRED"]
                return False
            if final_reasons:
                return False
            try:
                os.stat(target_name, dir_fd=protected_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise broker.RuntimeActionBrokerError("Pi create target already exists")
            try:
                _guard(authority, deadline)
            except broker.RuntimeActionBrokerError:
                final_reasons = ["BROKER_PI_REQUEST_REFUSED"]
                return False
            journal_state = final_state
            return True

        def record_pending(staging_name, staged):
            nonlocal journal_state, journal_attempted
            _require(journal_state is not None and journal_state["effect_journal"] is None and
                     broker._STAGING_NAME.fullmatch(staging_name) is not None and
                     staged.st_gid == broker._effect_gid(config), "Pi journal preparation is invalid")
            root = os.fstat(protected_fd)
            journal_state = {**journal_state, "effect_journal": {
                "schema": "aragorn/runtime-effect-journal/v1",
                "authority": "BROKER_RECOVERY_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY", "status": "PENDING",
                "request_digest": request_digest, "observation_digest": observation_digest, **action_digests,
                "payload_size": len(payload), "target_name": target_name,
                "protected_root_device": root.st_dev, "protected_root_inode": root.st_ino,
                "staging_name": staging_name, "staging_device": staged.st_dev, "staging_inode": staged.st_ino}}
            journal_attempted = True
            broker._commit_state(control_fd, config, journal_state)
            # LAST callback action after durable PENDING: the combined protected
            # request/current-state guard. The atomic primitive next calls link.
            final_authority_check()

        def final_authority_check():
            nonlocal journal_state, final_decision, final_observation
            _guard(authority, deadline)
            previous = now
            for _attempt in range(2):
                current = broker._clock_value(lambda: int(time.time()))
                _require(current >= previous, "Pi pre-link clock rolled back")
                checked, observed_digest, verdict, codes = broker._evaluate_snapshot(
                    control_fd, config, request, action_digests, current, minimum_state=journal_state)
                held_claim = grants._load_state(control_fd, grant_config, claim["grant_digest"])
                _require(held_claim["status"] == "CLAIMED" and held_claim["claim"] == claim,
                         "Pi pre-link grant claim changed")
                grants._require_live_grant(grant, current)
                _require(claim["lease"]["issued_at_unix"] <= current < claim["lease"]["expires_at_unix"],
                         "Pi pre-link capability lease expired")
                _require(observed_digest == observation_digest and verdict["verdict"] == "ALLOW" and not codes and
                         checked["effect_journal"] == journal_state["effect_journal"] and any(
                             row["request_digest"] == request_digest and row["observation_digest"] == observation_digest
                             for row in checked["consumed"]), "Pi pre-link authorization changed")
                after = broker._clock_value(lambda: int(time.time()))
                _require(after >= current, "Pi pre-link clock rolled back")
                if after == current:
                    journal_state = checked
                    final_decision, final_observation = verdict, observed_digest
                    break
                previous = after
            else:
                raise broker.RuntimeActionBrokerError("Pi pre-link clock is unstable")
            authority._live()  # Cheap local root/worker PIDFD check after all snapshot I/O.
            _require(time.monotonic() < deadline == authority.deadline,
                     "Pi pre-link original deadline expired")

        def record_applied(staging_name, staged):
            nonlocal journal_state
            _require(journal_state is not None, "Pi effect journal is absent")
            transaction = journal_state["effect_journal"]
            _require(isinstance(transaction, dict) and transaction.get("status") == "PENDING" and
                     transaction.get("staging_name") == staging_name and
                     (transaction.get("staging_device"), transaction.get("staging_inode")) == (staged.st_dev, staged.st_ino),
                     "Pi effect journal changed")
            journal_state = {**journal_state, "effect_journal": {**transaction, "status": "APPLIED"}}
            broker._commit_state(control_fd, config, journal_state)

        if not broker._atomic_create(staging_fd, protected_fd, target_name, payload,
                authorize_link=authorize_link, record_pending=record_pending, record_applied=record_applied):
            return result(final_decision, final_observation, final_reasons)
        effect_committed = True
        _require(journal_state is not None and isinstance(journal_state["effect_journal"], dict) and
                 journal_state["effect_journal"]["status"] == "APPLIED", "Pi effect lacks applied journal")
        broker._recover_effect_journal(control_fd, protected_fd, staging_fd, config)
        return result(final_decision, observation_digest, [], created=True)
    except BaseException as exc:
        if journal_attempted or effect_committed or isinstance(exc, broker.RuntimeActionEffectIndeterminate):
            raise broker.RuntimeActionEffectIndeterminate("Pi journal/effect outcome requires retained recovery") from exc
        if isinstance(exc, broker.RuntimeActionBrokerError):
            raise
        if isinstance(exc, Exception):
            raise broker.RuntimeActionBrokerError("Pi create refused before journal/effect") from exc
        raise
    finally:
        failure = broker._release_lock_and_close(lock_fd, locked, staging_fd, protected_fd, control_fd)
        if failure is not None:
            # Even pre-effect cleanup uncertainty must not discard profile state
            # and turn a possibly published record into a fresh grant.
            raise broker.RuntimeActionEffectIndeterminate("Pi broker cleanup is uncertain") from failure
