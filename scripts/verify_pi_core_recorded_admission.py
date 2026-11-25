"""Managed qualification with independently nominated recorded install/action evidence."""

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.phase3_deployment import build_phase3_deployment_identity
from aragorn.phase3_exit_qualification import Phase3SemanticVerifier, VERIFICATION_SCHEMA, _digest, _pin, _verify_source
from aragorn.pi_core_phase3_qualification import MANIFEST_DIGEST, PROFILE, _document, _require, qualify_pi_core_phase3_exit
from scripts.verify_pi_core_install_action_join import verify_install_action_join


REQUIREMENT = "MP1/ADM-01/exact-admitted-bytes"
_PINS = {"owner_pin", "plan_pin", "context_pin", "manifest_pin", "action_nomination_pin", "deployment_pin"}
# Independent B105 evidence-reader pin. This identifies the reader, not a running guest.
_JOIN = Phase3SemanticVerifier(verify_install_action_join,
    "sha256:e20ba7d79e1f2e6dd94fd6b9569ed895b1aec05716ece827b2197ea5d20c5a47")


def verify_recorded_admission(raw, context, archive):
    _require(type(archive) is CAS and archive.read_only, "read-only evidence archive required")
    _require(context["profile"] == PROFILE and context["requirement_id"] == REQUIREMENT
             and context["gate_manifest_digest"] == MANIFEST_DIGEST
             and _digest(raw) == context["evidence_digest"], "unbound recorded admission evidence")
    doc = _document(raw)
    _require(set(doc) == _PINS | {"schema"} and doc["schema"] == "aragorn/pi-core-recorded-admission-inputs/v1",
             "invalid recorded admission nomination")
    pins = {key: _pin(doc[key]) for key in _PINS}
    # B104 addresses the flat seven bindings; D4 addresses their versioned envelope.
    bindings = _document(archive.read(pins["deployment_pin"], max_bytes=4096))
    _require(canonical_digest(build_phase3_deployment_identity(bindings)) == context["deployment_identity_digest"],
             "recorded admission deployment differs from managed qualification")
    _verify_source(_JOIN)
    verify_install_action_join(archive, **pins)
    _verify_source(_JOIN)
    return dict(schema=VERIFICATION_SCHEMA, bindings=dict(context), status="NOT_TESTED",
                reason_codes=["RECORDED_INSTALL_ACTION_MATCHED", "INDEPENDENT_CONSUMED_CLOSURE_NOT_ESTABLISHED"])


def qualify_with_recorded_admission(*, verifier_source_digest, verifiers, **inputs):
    """Select the bounded reader for ADM-01; never replace a caller's full verifier."""
    _require(type(verifiers) is dict and REQUIREMENT not in verifiers, "ambiguous recorded admission verifier")
    selected = Phase3SemanticVerifier(verify_recorded_admission, _pin(verifier_source_digest))
    return qualify_pi_core_phase3_exit(verifiers=verifiers | {REQUIREMENT: selected}, **inputs)
