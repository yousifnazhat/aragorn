"""Replay B111 install stdout and a separately nominated original action; never authorize execution."""
import argparse
import json
from pathlib import Path
import sys

from aragorn.cas import CAS, CASError
from aragorn.decision_receipt import verify_decision_v3
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import build_phase3_deployment_identity
from aragorn.pi_core_action_boundary_verify import _MAX_RECORD
from aragorn.pi_core_bundle_install_entry import _DESTINATION, _plan, _revocations, _supported_bundle
from aragorn.pi_core_bundle_launch import load_pi_core_policy_manifest
from aragorn.pi_core_service_source import _inventory
from aragorn.pi_core_source_observation_verify import _require, _same
from aragorn import protected_install_context as admission
from aragorn.protected_install import _RECORD_AUTHORITY, _version_path
from aragorn.runtime_active_skill_lineage import ACTIVE_RUNTIME_AUTHORITY, ACTIVE_RUNTIME_SCHEMA
from scripts.verify_pi_core_installed_bundle_readback import (
    ENTRY, POLICY_MANIFEST_ENTRY_PIN, POLICY_MANIFEST_HELPER, POLICY_MANIFEST_HELPER_PIN,
    WRAPPER, _document, _historical_context, _need, _pin, host_contract,
)
from scripts.verify_pi_core_retained_action import replay

# B111's signed payload/source catalogs; no profile, wrapper or verifier is selected by stdout.
_HOST = "sha256:5105455ffdb8bc0c0c8e28863230ac7539be0a8d499d31208434b3fa732080c9"
_WRAPPER = "sha256:9b9772bbe638078e4a3439de39020338290d29dfdec1c5104c29516554fb95e0"


def _b111_custody(owner, profile):
    files = {str(p): _pin(row["digest"]) for p, row in host_contract._profile(profile).items()}
    _need(files.get(WRAPPER) == _WRAPPER and files.get(ENTRY) == POLICY_MANIFEST_ENTRY_PIN and
          files.get(POLICY_MANIFEST_HELPER) == POLICY_MANIFEST_HELPER_PIN, "unreviewed B111 install sources")
    sources = _inventory({k[1:]: v for k, v in files.items() if k.startswith("/opt/aragorn/src/aragorn/")})
    before, after = owner["host_before"], owner["host_after"]
    _need(canonical_json(before) == canonical_json(after) and type(before) is dict and
          before.keys() == {"schema", "authority", "host_profile_digest", "pid", "python_executable", "files", "phase3_exit_eligible"} and
          type(before["pid"]) is int and 0 < before["pid"] < 1 << 31
          and type(before["files"]) is int and before["files"] == len(files) and
          before["schema"] == "aragorn/pi-core-coordinator-host-observation/v1" and
          before["authority"] == "PINNED_HOST_TCB_ONLY_NOT_CONSUMED_CODE_OR_PHASE3" and
          before["phase3_exit_eligible"] is False and before["host_profile_digest"] == _HOST and
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
    required = {"aragorn", "aragorn.pi_core_coordinator_entry", "aragorn.pi_core_bundle_install_entry"}
    required.add("aragorn.pi_core_bundle_launch")
    _need(required <= {r["module"] for r in initial}, "missing protected install source")


def verify_b111_install_action_join(archive, *, owner_pin, plan_pin, context_pin, manifest_pin,
                                    action_nomination_pin, deployment_pin, expected_action_receipt_pin):
    """All seven pins are operator selections. No guest path is opened or effect retried."""
    _need(type(archive) is CAS and archive.read_only is True, "read-only B111 archive required")
    deployment_pin = _pin(deployment_pin)
    expected_action_receipt_pin = _pin(expected_action_receipt_pin)
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
    _need(host_pin == _HOST and owner["deployment_digest"] == deployment_pin, "B111 host or deployment differs")
    _b111_custody(owner, _document(archive, _HOST, 2 << 20))
    deployment = _document(archive, deployment_pin, 4096)
    build_phase3_deployment_identity(deployment)
    policy_manifest = load_pi_core_policy_manifest(archive, deployment["policy"])
    policy_pin = policy_manifest["admission_policy_digest"]
    context = _document(archive, context_pin, 2 << 20)
    _historical_context(context)
    operation = context["operation"]
    _need(context["schema"] == "aragorn/protected-install-context/v2" and context["authority"] == admission._AUTHORITY
          and context["status"] == "active" and operation in ("install", "update") and
          (operation == "update") == (plan["predecessor_cas_root"] is not None) and
          context["target_runtime_digest"] == deployment["runtime_commit_or_image"] and
          context["policy_digest"] == policy_pin and context["runtime_conformance_digest"] == plan["runtime_conformance_digest"]
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
    revocations_pin = plan["revocations"]["digest"]
    revoked = _revocations(_document(archive, revocations_pin, 2 << 20))
    _need(context["context_id"] not in revoked, "installed context appears in pinned revocations")
    receipt, gateway = admission._context_github_trust_digests(context)
    decision = verify_decision_v3(archive, context["decision_digest"],
        expected_manifest_digest=manifest_pin, expected_artifact_graph_digest=context["artifact_graph_digest"],
        expected_policy_digest=policy_pin,
        expected_analyzer_run_receipt_digests=context["analyzer_run_receipt_digests"],
        expected_analyzer_verifier_digest=context["analyzer_verifier_digest"],
        expected_artifact_graph_verifier_digest=context["artifact_graph_verifier_digest"],
        expected_quarantine_receipt_digest=receipt, expected_gateway_profile_digest=gateway)
    _need(decision["verdict"] == "ALLOW" and decision["tree_digest"] == measured,
          "retained decision does not allow the reported tree")
    destination = context["destination"]
    version = _version_path(destination["target_name"], context["context_id"], manifest_pin)
    tree = measured
    transaction = dict(schema="aragorn/protected-install-transaction/v1", authority=_RECORD_AUTHORITY,
        context_digest=context_pin, context_id=context["context_id"], operation=context["operation"],
        expected_active=context["expected_active"], manifest_digest=manifest_pin, tree_digest=tree,
        destination=destination, version_path=version)
    # The stdout pin commits to the transaction actually checked on install return.
    transaction_pin = canonical_digest(transaction)
    _require(owner["transaction_digest"] == transaction_pin, "INSTALL_ACTION_TRANSACTION")
    active_pin = canonical_digest(dict(schema=ACTIVE_RUNTIME_SCHEMA, authority=ACTIVE_RUNTIME_AUTHORITY,
                                       transaction=transaction))
    skill_pin = next(row["digest"] for row in manifest["files"] if row["path"] == "SKILL.md")

    action = replay(archive, action_nomination_pin, expected_deployment_digest=deployment_pin)
    _require(action["terminal_records_matched"] is True and
             action["policy_manifest_digest"] == deployment["policy"] and
             action["runtime_action_policy_digest"] == policy_manifest["runtime_action_policy_digest"] and
             action["receipt_digest"] == expected_action_receipt_pin,
             "B111_INSTALL_ACTION_POLICY_OR_TERMINAL_RECEIPT")
    nomination = _document(archive, action_nomination_pin, 256 << 10)
    activation = _document(archive, nomination["activation_digest"], 64 << 10)
    _same([activation[k] for k in ("install_context_digest", "source_manifest_digest", "tree_digest",
                                  "active_skill_digest", "active_record_digest")],
          [context_pin, manifest_pin, tree, skill_pin, active_pin], "INSTALL_ACTION_ACTIVATION_LINEAGE")

    # Replay checked the owner-pinned index chain and the REQUEST_CONTEXT at ordinal two.
    action_owner = _document(archive, action["owner_digest"], _MAX_RECORD)
    reference = action_owner["retained_evidence"]["references"][2]
    _require(reference["kind"] == "REQUEST_CONTEXT", "INSTALL_ACTION_CONTEXT_REFERENCE")
    lineage = _document(archive, reference["digest"], reference["bytes"])["lineage"]
    _same([lineage[k] for k in ("root_device", "root_inode", "target_name", "version_path", "runtime_skill_path")],
          [destination[k] for k in ("root_device", "root_inode", "target_name")] +
          [version, str(_DESTINATION / version / "SKILL.md")], "INSTALL_ACTION_PROTECTED_VERSION")

    return dict(schema="aragorn/pi-core-b111-install-action-join/v1", status="CONSISTENT_RECORDED_B111_INSTALL_AND_ACTION",
        host_profile_digest=_HOST,
        deployment_digest=deployment_pin, context_digest=context_pin, source_manifest_digest=manifest_pin,
        tree_digest=tree, skill_digest=skill_pin, install_transaction_digest=transaction_pin,
        active_record_digest=active_pin, install_owner_digest=owner_pin,
        action_nomination_digest=action_nomination_pin, action_receipt_digest=action["receipt_digest"],
        policy_manifest_digest=deployment["policy"],
        runtime_action_policy_digest=policy_manifest["runtime_action_policy_digest"],
        acquisition_authenticity_verified=False, continuous_filesystem_custody_verified=False,
        worker_consumption_verified=False, effect_verified=False, timing_verified=False, sensor_health_verified=False,
        activation_authorized=False, phase3_exit_eligible=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    for name in ("owner-pin", "plan-pin", "context-pin", "manifest-pin", "action-nomination-pin",
                 "deployment-pin", "expected-action-receipt-pin"):
        parser.add_argument("--" + name, required=True)
    args = vars(parser.parse_args(argv))
    try:
        args["archive"] = CAS(args["archive"], read_only=True)
        finding = verify_b111_install_action_join(**args)
    except (CASError, OSError, ValueError, RuntimeError, KeyError, IndexError, TypeError, OverflowError, StopIteration):
        print("B111 install/action replay refused. Preserve the originals; do not retry.", file=sys.stderr)
        return 2
    print(json.dumps(finding, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
