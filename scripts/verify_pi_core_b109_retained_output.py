"""Read the private pilot receipt and compare its original observation with B107 records."""
import argparse
import json
from pathlib import Path
import sys

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest
from aragorn import pi_core_pilot_output_custody as custody
from aragorn.pi_core_source_observation_verify import _digest, _document, _pin, _require
from scripts.verify_pi_core_joined_mask_receipts import _separate
from scripts.verify_pi_core_pilot_output import verify_pilot_output


def verify_retained_output(*, store, receipt_directory, attempt_id, expected_activation_id,
                           expected_path_digest, plan_pin, release_pin, deployment_pin, output_pin, receipt_pin,
                           action_archive, action_pin, provider_archive, provider_pin):
    """All nominations come from the caller, never from the submitted records or a directory scan."""
    _require(all(type(a) is CAS and a.read_only is True for a in (action_archive, provider_archive)),
             "RETAINED_PILOT_REQUIRES_READ_ONLY_ARCHIVES")
    # Original action and provider records may share a CAS. Neither that archive
    # nor any ancestor/descendant can be the independent observation store or receipt directory.
    roots = (store, receipt_directory, *dict.fromkeys((action_archive.root, provider_archive.root)))
    identities = _separate(roots)
    for pin in (output_pin, receipt_pin, plan_pin, release_pin, deployment_pin, expected_path_digest, action_pin, provider_pin):
        _pin(pin)
    raw = custody.read_retained(store=store, receipt_directory=receipt_directory, attempt_id=attempt_id,
                                expected_activation_id=expected_activation_id, expected_path_digest=expected_path_digest,
                                deployment_digest=deployment_pin, plan_digest=plan_pin, release_digest=release_pin,
                                observation_digest=output_pin, receipt_digest=receipt_pin)
    original = _document(raw)
    _require(_digest(raw) == output_pin and original["activation_id"] == expected_activation_id and
             canonical_digest(original["path_descriptor"]) == expected_path_digest,
             "RETAINED_PILOT_NOMINATION_DIFFERS")
    # B107 reads this exact digest again from the private read-only CAS. It checks
    # the original action and provider records, not the public result digest or an oracle.
    joined = verify_pilot_output(action_archive, action_pin=action_pin, provider_archive=provider_archive,
                                 provider_pin=provider_pin, deployment_pin=deployment_pin,
                                 output_archive=CAS(store, read_only=True), output_pin=output_pin,
                                 expected_path_digest=expected_path_digest)
    _require(_separate(roots) == identities, "RETAINED_PILOT_ARCHIVE_ROOT_CHANGED")
    return dict(joined, schema="aragorn/pi-core-b109-retained-output-finding/v1",
                status="MATCHED_LOCAL_CUSTODY_AND_RECORDED_PILOT_OUTPUT",
                base_payload_digest=custody.B109_PAYLOAD_DIGEST, base_host_profile_digest=custody.B109_HOST_PROFILE_DIGEST,
                receipt_digest=receipt_pin, plan_digest=plan_pin, release_digest=release_pin, attempt_id=attempt_id,
                local_receipt_matched=True, release_authority_verified=False, installed_identity_verified=False,
                cleanup_verified=False, operational_success_verified=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("store", "receipt-directory", "action-archive", "provider-archive"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("attempt-id", "expected-activation-id", "expected-path-digest", "plan-pin", "release-pin", "deployment-pin",
                 "output-pin", "receipt-pin", "action-pin", "provider-pin"):
        parser.add_argument("--" + name, required=True)
    args = vars(parser.parse_args(argv))
    try:
        for name in ("action_archive", "provider_archive"):
            args[name] = CAS(args[name], read_only=True)
        result = verify_retained_output(**args)
    except (CASError, OSError, RuntimeError, ValueError, KeyError, TypeError, IndexError, OverflowError):
        print("Retained pilot output replay refused. Preserve the originals; do not retry the effect.", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
