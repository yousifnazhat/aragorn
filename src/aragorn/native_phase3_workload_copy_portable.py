"""Retain one independently observed copy; replay only from a separately pinned observation."""
from io import BytesIO

from . import native_phase3_workload_copy_readback_verify as reader
from .cas import CAS
from .native_phase3_http_canary_contract import require
from .oci_worker_protocol import canonical_digest, canonical_json


_LIMIT = 65536


def observe_and_retain(raw, request, boundaries, *, evidence_cas, copy_directory_fd,
                       expected_copy_directory_identity, expected_fixture):
    """Return the observation pin to a separate custodian, never to the task as authority."""
    require(type(evidence_cas) is CAS and evidence_cas.read_only is False, "COPY_PRIVATE_WRITABLE_CAS_REQUIRED")
    copied, observation = reader.observe_copy(
        raw, request, boundaries, copy_directory_fd=copy_directory_fd,
        expected_copy_directory_identity=expected_copy_directory_identity, expected_fixture=expected_fixture,
    )
    # observe_copy returns only after successful guard/descriptor retirement. Publish the index last.
    for data, pin, limit in ((raw, observation["receipt_digest"], _LIMIT),
                             (copied, observation["content_digest"], len(reader._INPUT))):
        evidence_cas.put_expected(BytesIO(data), expected_digest=pin, max_bytes=limit)
    return evidence_cas.put_expected(BytesIO(canonical_json(observation)), expected_digest=canonical_digest(observation),
                                     max_bytes=_LIMIT)


def verify_portable(raw, request, boundaries, *, evidence_cas, expected_observation_digest,
                    expected_copy_directory_identity, expected_fixture):
    """Replay the retained finite observation, not present file custody, cleanup or timing acquisition."""
    require(type(evidence_cas) is CAS and evidence_cas.read_only is True, "COPY_PRIVATE_READ_ONLY_CAS_REQUIRED")
    index = evidence_cas.read(expected_observation_digest, max_bytes=_LIMIT)
    expected = reader.expected_copy_observation(
        raw, request, boundaries, expected_copy_directory_identity=expected_copy_directory_identity,
        expected_fixture=expected_fixture,
    )
    require(index == canonical_json(expected), "COPY_PORTABLE_OBSERVATION_BINDING")
    require(evidence_cas.read(expected["receipt_digest"], max_bytes=_LIMIT) == raw, "COPY_PORTABLE_RECEIPT_BINDING")
    copied = evidence_cas.read(expected["content_digest"], max_bytes=len(reader._INPUT))
    require(copied == reader._INPUT, "COPY_PORTABLE_RETAINED_CONTENT")
    return {"receipt_digest": expected["receipt_digest"], "request_digest": expected["request_digest"],
            "deployment_digest": expected["deployment_digest"], "semantics": {"completed": True}}
