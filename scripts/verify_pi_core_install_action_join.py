"""Join independently nominated install and action evidence in a read-only CAS."""

import argparse
import json
from pathlib import Path
import sys

from aragorn.artifact_closure import load_retained_manifest
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.pi_core_action_boundary_verify import _MAX_RECORD
from aragorn.pi_core_bundle_install_entry import _DESTINATION
from aragorn.pi_core_source_observation_verify import _require, _same
from aragorn.protected_install import _RECORD_AUTHORITY, _version_path
from aragorn.runtime_active_skill_lineage import ACTIVE_RUNTIME_AUTHORITY, ACTIVE_RUNTIME_SCHEMA
from scripts.verify_pi_core_installed_bundle_readback import _document, _pin, verify_installed_bundle_readback
from scripts.verify_pi_core_retained_action import replay


def verify_install_action_join(archive, *, owner_pin, plan_pin, context_pin, manifest_pin,
                               action_nomination_pin, deployment_pin):
    """Check exact retained correspondence, not worker consumption or physical custody."""
    _require(type(archive) is CAS and archive.read_only is True, "INSTALL_ACTION_READ_ONLY_CAS")
    deployment_pin = _pin(deployment_pin)
    install = verify_installed_bundle_readback(archive, owner_pin=owner_pin, plan_pin=plan_pin,
        context_pin=context_pin, manifest_pin=manifest_pin, replay_admission=True)
    _require(install["schema"] == "aragorn/pi-core-installed-bundle-admission-finding/v2" and
             install["decision_or_revocation_replayed"] is True and install["retained_decision_verdict"] == "ALLOW",
             "INSTALL_ACTION_MANAGED_ADMISSION_REQUIRED")
    _require(install["deployment"] == deployment_pin, "INSTALL_ACTION_DEPLOYMENT")

    context = _document(archive, context_pin, 2 << 20)
    destination = context["destination"]
    version = _version_path(destination["target_name"], context["context_id"], manifest_pin)
    tree = install["observed_tree_digest"]
    transaction = dict(schema="aragorn/protected-install-transaction/v1", authority=_RECORD_AUTHORITY,
        context_digest=context_pin, context_id=context["context_id"], operation=context["operation"],
        expected_active=context["expected_active"], manifest_digest=manifest_pin, tree_digest=tree,
        destination=destination, version_path=version)
    # The stdout pin commits to the transaction actually checked on install return.
    install_owner = _document(archive, owner_pin, (256 << 10) + 8192, stdout=True)
    transaction_pin = canonical_digest(transaction)
    _require(install_owner["transaction_digest"] == transaction_pin, "INSTALL_ACTION_TRANSACTION")
    active_pin = canonical_digest(dict(schema=ACTIVE_RUNTIME_SCHEMA, authority=ACTIVE_RUNTIME_AUTHORITY,
                                       transaction=transaction))
    # The install replay already rehashed the whole bundle. Read only its manifest again.
    manifest = load_retained_manifest(archive, manifest_pin)
    skill_pin = next(row["digest"] for row in manifest["files"] if row["path"] == "SKILL.md")

    action = replay(archive, action_nomination_pin, expected_deployment_digest=deployment_pin)
    _require(action["terminal_records_matched"] is True and
             action["policy_manifest_digest"] == install["policy_manifest_digest"] and
             action["runtime_action_policy_digest"] == install["runtime_action_policy_digest"],
             "INSTALL_ACTION_POLICY_OR_TERMINAL")
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

    return dict(schema="aragorn/pi-core-install-action-join/v1", status="CONSISTENT_RECORDED_INSTALL_AND_ACTION",
        deployment_digest=deployment_pin, context_digest=context_pin, source_manifest_digest=manifest_pin,
        tree_digest=tree, skill_digest=skill_pin, install_transaction_digest=transaction_pin,
        active_record_digest=active_pin, install_owner_digest=owner_pin,
        action_nomination_digest=action_nomination_pin, action_receipt_digest=action["receipt_digest"],
        policy_manifest_digest=install["policy_manifest_digest"],
        runtime_action_policy_digest=install["runtime_action_policy_digest"],
        acquisition_authenticity_verified=False, continuous_filesystem_custody_verified=False,
        worker_consumption_verified=False, effect_verified=False, timing_verified=False, sensor_health_verified=False,
        activation_authorized=False, phase3_exit_eligible=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    for key in ("owner-pin", "plan-pin", "context-pin", "manifest-pin", "action-nomination-pin", "deployment-pin"):
        parser.add_argument("--" + key, required=True)
    args = vars(parser.parse_args(argv))
    try:
        args["archive"] = CAS(args["archive"], read_only=True)
        finding = verify_install_action_join(**args)
    except (CASError, OSError, ValueError, RuntimeError, KeyError, IndexError, TypeError, OverflowError, StopIteration):
        print("Install/action join refused. No evidence was altered and no effect was retried.", file=sys.stderr)
        return 2
    print(json.dumps(finding, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
