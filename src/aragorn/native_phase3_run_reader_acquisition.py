"""Own one transferred reader connection, fresh challenge and durable store."""

import os

from . import native_phase3_run_reader_response as leaf
from .native_phase3_run_reader_store import ReaderStore


class OwnedReaderResponseError(ValueError):
    """Bounded observed bytes survive failures; unavailable values remain None."""

    def __init__(self, original, observed, cleanup_failures=(), retention_failure=None):
        super().__init__("owned reader acquisition refused; preserve observed evidence and permanent claims")
        self.original_failure = original
        self.observed = observed
        self.partial_evidence = observed["evidence_raw"]
        self.cleanup_failures = tuple(cleanup_failures)
        self.retention_failure = retention_failure


def _issue(epoch_raw, expected_epoch_digest, request_digest, sequence_before):
    leaf._pin(expected_epoch_digest)
    leaf._pin(request_digest)
    leaf._uint(sequence_before)
    epoch = leaf._keys(leaf._decode(epoch_raw, 32768), "process clock loss_scope policy deployment_digest")
    leaf._require(leaf._raw_digest(epoch_raw) == expected_epoch_digest, "independent expected epoch pin")
    policy = leaf._keys(epoch["policy"], "timeout_ns max_age_ns")
    leaf._uint(policy["timeout_ns"], 1)
    bindings = {"epoch": expected_epoch_digest, "request": request_digest,
                **{key: leaf._digest(epoch[key]) for key in ("process", "clock", "loss_scope", "policy")}}
    challenge = {"epoch_digest": expected_epoch_digest, "request_digest": request_digest,
                 "boundary": "BEFORE_FIRST_EFFECT", "nonce": "0" * 64,
                 "issued_ns": 0, "deadline_ns": policy["timeout_ns"], "sequence_before": sequence_before}
    # Validate the entire frozen epoch contract before entropy or a clock observation.
    bindings["challenge"] = leaf._digest(challenge)
    leaf._inputs(epoch_raw, leaf._canonical(challenge), bindings, "0" * 64)
    nonce, connection_random = os.urandom(32), os.urandom(32)
    leaf._require(type(nonce) is bytes and len(nonce) == 32 and type(connection_random) is bytes
                  and len(connection_random) == 32 and nonce != connection_random, "fresh reader entropy")
    issued = leaf.clock._stamp()
    challenge.update(nonce=nonce.hex(), issued_ns=issued, deadline_ns=issued + policy["timeout_ns"])
    challenge_raw = leaf._canonical(challenge)
    bindings["challenge"] = leaf._raw_digest(challenge_raw)
    connection_epoch = connection_random.hex()
    leaf._inputs(epoch_raw, challenge_raw, bindings, connection_epoch)
    claim_raw = leaf._canonical({"schema": "aragorn/native-phase3-run-reader-claim/v1",
                                 "connection_epoch": connection_epoch, "challenge": challenge})
    return challenge_raw, bindings, connection_epoch, claim_raw


def acquire_owned_reader_response(connection, *, epoch_raw: bytes, expected_epoch_digest: str,
                                  request_digest: str, sequence_before: int) -> dict:
    """Close the exclusively transferred connection even on refusal or interruption."""
    observed = {key: None for key in ("reader", "challenge_raw", "claim_raw", "bindings", "connection_epoch",
                                       "evidence_raw", "evidence_digest")}
    observed.update(sensor_health_verified=False, acquisition_authenticity_verified=False,
                    effect_authorized=False, run_qualified=False, phase3_qualified=False)
    store, original, retention_failure, cleanup, candidate = None, None, None, [], None

    def retain(raw, *, expected_digest):
        nonlocal retention_failure
        if type(raw) is bytes and len(raw) <= 131072:
            observed["evidence_raw"] = raw
            observed["evidence_digest"] = leaf._raw_digest(raw)
        try:
            return store.retain(raw, expected_digest=expected_digest)
        except BaseException as exc:
            retention_failure = exc
            raise

    try:
        issued = _issue(epoch_raw, expected_epoch_digest, request_digest, sequence_before)
        for key, value in zip(("challenge_raw", "bindings", "connection_epoch", "claim_raw"), issued, strict=True):
            observed[key] = value
        store = ReaderStore(observed["claim_raw"])
        candidate = leaf.acquire_reader_response(
            connection, epoch_raw=epoch_raw, challenge_raw=observed["challenge_raw"],
            bindings=observed["bindings"], connection_epoch=observed["connection_epoch"],
            consume_once=store.consume_once, retain=retain)
        store.final_readback()
    except BaseException as exc:
        original = exc
        if isinstance(exc, leaf.ReaderResponseError):
            partial = exc.partial_evidence
            if type(partial) is bytes and len(partial) <= 131072:
                observed["evidence_raw"] = partial
                observed["evidence_digest"] = leaf._raw_digest(partial)
            retention_failure = exc.retention_failure or retention_failure
    finally:
        if store is not None:
            try:
                store.close()
            except BaseException as exc:
                cleanup.append(exc)
        try:
            connection.close()
        except BaseException as exc:
            cleanup.append(exc)
    if original is not None or cleanup:
        raise OwnedReaderResponseError(original or cleanup[0], observed, cleanup, retention_failure) from (original or cleanup[0])
    observed["reader"] = candidate
    return observed
