"""Compare a pinned install-report/v2 stdout with separately approved inputs in a private read-only CAS.

The owner observed the installed tree. This reader verifies retained source bytes,
not the live filesystem, the transaction preimage, an authorization, or worker consumption.
Never derive the expected owner pin from the submitted report.
"""
import argparse
import json
from pathlib import Path
import re
import sys

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import build_phase3_deployment_identity
from aragorn.pi_core_bundle_install_entry import _plan, _supported_bundle
from aragorn.pi_core_service_source import _inventory
from aragorn import protected_install_context as admission
from aragorn.runtime_action_broker import _parse_canonical_document
from scripts.prepare_pi_core_coordinator_host import host_contract  # trusted checkout, never an archive input


# Independently reviewed first wrapper to emit this finding. A later wrapper
# needs review; a profile pin or a "v2" label alone cannot upgrade v1 code.
WRAPPER = "/opt/aragorn/bin/coordinator.py"
WRAPPER_PIN = "sha256:9466bbe553b557a710a9d7ee2e2164a4fbf0e4f8a1442d4683ea2e8516ab5cfa"
ENTRY = "/opt/aragorn/src/aragorn/pi_core_bundle_install_entry.py"
ENTRY_PIN = "sha256:d74ff1cb8c0b8626ad388eacd6255ad640fa00896b2d86eae2848d533da00564"


def _need(ok, reason):
    if not ok:
        raise ValueError(reason)


def _pin(pin):
    _need(type(pin) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", pin) and int(pin[7:], 16),
          "missing independent content identity")
    return pin


def _document(archive, pin, maximum, *, stdout=False):
    raw = archive.read(_pin(pin), max_bytes=maximum)
    if stdout:
        _need(raw.endswith(b"\n"), "original wrapper stdout LF required")
        raw = raw[:-1]
    return _parse_canonical_document(raw, "protected install readback")


def _custody(owner, profile, profile_pin):
    # _profile validates the original protected profile's pure schema, inventory, paths
    # and limits. It constructs Path values but performs no guest filesystem operation.
    files = {str(p): _pin(row["digest"]) for p, row in host_contract._profile(profile).items()}
    _need(files.get(WRAPPER) == WRAPPER_PIN, "unreviewed wrapper")
    _need(files.get(ENTRY) == ENTRY_PIN, "unreviewed materialization readback entry")
    sources = _inventory({k[1:]: v for k, v in files.items() if k.startswith("/opt/aragorn/src/aragorn/")})
    before, after = owner["host_before"], owner["host_after"]
    _need(canonical_json(before) == canonical_json(after) and type(before) is dict and
          before.keys() == {"schema", "authority", "host_profile_digest", "pid", "python_executable", "files", "phase3_exit_eligible"} and
          type(before["pid"]) is int and 0 < before["pid"] < 1 << 31
          and type(before["files"]) is int and before["files"] == len(files) and
          before["schema"] == "aragorn/pi-core-coordinator-host-observation/v1" and
          before["authority"] == "PINNED_HOST_TCB_ONLY_NOT_CONSUMED_CODE_OR_PHASE3" and
          before["phase3_exit_eligible"] is False and before["host_profile_digest"] == profile_pin and
          before["python_executable"] == profile["python_executable"], "incomplete or mixed host custody")
    initial, final = owner["source_before"], owner["source_after"]
    _need(type(initial) is list and type(final) is list and 0 < len(initial) <= len(final) <= 512
          and initial == final[:len(initial)], "source custody not preserved")
    seen = set()
    for row in final:
        name = row["module"]
        _need(name not in seen and name in sources and set(row) == {"module", "path", "digest"} and
              sources[name][:2] == (row["path"], row["digest"]), "module differs from protected source inventory")
        seen.add(name)
    _need({"aragorn", "aragorn.pi_core_coordinator_entry", "aragorn.pi_core_bundle_install_entry"} <=
          {r["module"] for r in initial}, "missing protected install source")


def _historical_context(context):
    admission._context_document(context, admission._COMMON_FIELDS | {"operation", "expected_active"})
    for key in ("context_id", "decision_digest", "artifact_graph_digest", "analyzer_verifier_digest",
                "artifact_graph_verifier_digest", "manifest_digest", "target_runtime_digest", "runtime_conformance_digest",
                "policy_digest"):
        _pin(context[key])
    receipts = context["analyzer_run_receipt_digests"]
    _need(type(receipts) is list and len(receipts) <= admission._MAX_ANALYZERS, "invalid analyzer receipt count")
    _need(len({_pin(r) for r in receipts}) == len(receipts), "duplicate analyzer receipt")
    for value in admission._context_github_trust_digests(context):
        if value is not None:
            _pin(value)
    admission._positive_integer(context["expires_at_unix"], "historical context expiry")
    destination = admission._exact_object(context["destination"], {"target_name", "root_device", "root_inode"},
                                          "protected install destination")
    admission._non_negative_integer(destination["root_device"], "protected install root device")
    admission._positive_integer(destination["root_inode"], "protected install root inode")
    _need(type(destination["target_name"]) is str and admission._TARGET_NAME.fullmatch(destination["target_name"]),
          "invalid protected install target name")


def verify_installed_bundle_readback(archive, *, owner_pin, plan_pin, context_pin, manifest_pin):
    """All four pins must be selected externally. Supplied guest paths are identifiers only."""
    _need(type(archive) is CAS and archive.read_only is True, "read-only archive required")
    owner = _document(archive, owner_pin, (256 << 10) + 8192, stdout=True)
    _need(owner.keys() == host_contract._public_install(None).keys() | {
        "status", "wrapper_stage", "wrapper_cleanup", "entry_call_attempted"}, "unexpected public install report fields")
    ok = "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED"
    _need(owner["schema"] == "aragorn/pi-core-bundle-install-report/v2" and
          owner["authority"] == "PROTECTED_MATERIALIZATION_ONLY_NOT_ACTIVATION_OR_PHASE3" and
          owner["status"] == owner["entry_status"] == ok and owner["wrapper_stage"] == "POST_CALL_CUSTODY" and
          owner["wrapper_cleanup"] == {"host": "CLOSED", "source_loader": "CLOSED"} and
          owner["entry_failure_stage"] is None and owner["input_cleanup_uncertainty_digest"] == canonical_digest([]) and
          all(owner[k] is True for k in ("entry_call_attempted", "installation_attempted", "owned_destination_closed",
                                          "owned_inputs_closed")) and
          all(owner[k] is False for k in ("phase3_exit_eligible", "managed_call_attempted", "managed_cleanup_complete")) and
          owner["managed_status"] is None and owner["managed_result_digest"] is None and
          owner["publication_state"] == "PUBLISHER_RETURNED" and owner["recovery_digest"] is None,
          "no clean protected post-publication readback")
    _pin(owner["transaction_digest"])  # The public report does not export the private transaction.
    measured = _pin(owner["observed_tree_digest"])
    plan = _document(archive, plan_pin, 64 << 10)
    host_pin = _pin(plan["host_profile_digest"])
    _plan(plan, host_pin)  # Pure validation; never open the guest paths named by this plan.
    _need(owner["plan_digest"] == plan_pin and owner["context_digest"] == plan["context"]["digest"] == context_pin
          and owner["deployment_digest"] == plan["deployment"]["digest"], "plan/context/deployment binding differs")
    _custody(owner, _document(archive, host_pin, 2 << 20), host_pin)
    deployment = _document(archive, plan["deployment"]["digest"], 2 << 20)
    build_phase3_deployment_identity(deployment)
    context = _document(archive, context_pin, 2 << 20)
    _historical_context(context)
    operation = context["operation"]
    _need(context["schema"] == "aragorn/protected-install-context/v2" and context["authority"] == admission._AUTHORITY
          and context["status"] == "active" and operation in ("install", "update") and
          (operation == "update") == (plan["predecessor_cas_root"] is not None) and
          context["target_runtime_digest"] == deployment["runtime_commit_or_image"] and
          context["policy_digest"] == deployment["policy"] and context["runtime_conformance_digest"] == plan["runtime_conformance_digest"]
          and context["manifest_digest"] == manifest_pin, "approved install context differs")
    previous = context["expected_active"]
    if operation == "update":
        _need(type(previous) is dict and previous.keys() == {"context_id", "manifest_digest"} and
              _pin(previous["context_id"]) != _pin(context["context_id"]), "wrong update predecessor")
        _pin(previous["manifest_digest"])
    else:
        _need(previous is None, "fresh install names a predecessor")
    # Same bounded manifest reader as admission: rehashes every original member, reconstructs the tree
    # and applies the supported text-only Pi layout. The publisher's tree digest is not the expected value.
    manifest = _supported_bundle(archive, _pin(manifest_pin))
    _need(measured == manifest["tree_digest"], "reported installed bytes differ from approved retained source tree")
    return dict(schema="aragorn/pi-core-installed-bundle-readback-finding/v1", owner=owner_pin, plan=plan_pin,
                context=context_pin, manifest=manifest_pin, deployment=owner["deployment_digest"], operation=operation,
                observed_tree_digest=measured, verified_retained_members=len(manifest["files"]),
                reported_installed_tree_matches_approved_bytes=True, private_transaction_replayed=False,
                live_filesystem_readback_reperformed=False, decision_or_revocation_replayed=False,
                worker_consumption_verified=False, activation_authorized=False, phase3_exit_eligible=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    for key in ("owner-pin", "plan-pin", "context-pin", "manifest-pin"):
        parser.add_argument("--" + key, required=True)
    args = vars(parser.parse_args(argv))
    try:
        args["archive"] = CAS(args["archive"], read_only=True)
        print(json.dumps(verify_installed_bundle_readback(**args), sort_keys=True))
    except (CASError, OSError, ValueError, RuntimeError, TypeError, KeyError) as exc:
        print(f"Install readback refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
