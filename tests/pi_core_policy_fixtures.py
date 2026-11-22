"""Distinct, validator-compatible policies for inert managed bundle checks."""

from io import BytesIO

from aragorn.oci_worker_protocol import canonical_digest, canonical_json


def policy_documents():
    admission = dict(schema="aragorn/policy/v1", id="fixture-admission", version=1,
                     required_analyzers=["inert-scanner"], hard_deny_reason_codes=[], review_severities=["high"])
    runtime = dict(schema="aragorn/runtime-action-policy/v1", id="fixture-runtime", version=1, default="BLOCK",
                   sensor_digest="sha256:" + "1" * 64, revocation_source_digest="sha256:" + "2" * 64, allow=[])
    manifest = dict(schema="aragorn/pi-core-policy-manifest/v1", admission_policy_digest=canonical_digest(admission),
                    runtime_action_policy_digest=canonical_digest(runtime))
    return {canonical_digest(document): document for document in (admission, runtime, manifest)}, manifest


def store_policy_manifest(cas):
    documents, manifest = policy_documents()
    for digest, document in documents.items():
        raw = canonical_json(document)
        cas.put_expected(BytesIO(raw), expected_digest=digest, max_bytes=len(raw))
    return manifest
