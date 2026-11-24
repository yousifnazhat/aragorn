"""Compare a separately nominated fixed-sink observation to original managed pilot records."""
import argparse
from hashlib import sha256
import json
import sys

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.pi_core_action_boundary_verify import _MAX_RECORD
from aragorn.pi_core_source_observation_verify import _document, _fields, _pin, _require, _uint
from aragorn.runtime_action_broker import _request_effect
from aragorn.runtime_action_decision import _RULE_FIELDS
from scripts.verify_pi_core_retained_action import replay


def verify_pilot_output(action_archive, *, action_pin, provider_archive, provider_pin, deployment_pin,
                        output_archive, output_pin, expected_path_digest):
    """Read only; a matching observation is not proof of acquisition, timing or exclusive writer."""
    for archive in (action_archive, provider_archive, output_archive):
        _require(type(archive) is CAS and archive.read_only is True, "PILOT_OUTPUT_READ_ONLY_CAS")
    expected_path_digest = _pin(expected_path_digest)
    observation = _document(output_archive.read(_pin(output_pin), max_bytes=2048))
    _fields(observation, {"schema", "path_descriptor", "activation_id", "before", "after", "file_device",
                          "file_inode", "payload_bytes", "payload_digest", "payload_hex"})
    _require(observation["schema"] == "aragorn/pi-core-pilot-output-observation/v1" and
             (observation["before"], observation["after"]) == ("ABSENT", "PRESENT"), "PILOT_OUTPUT_OBSERVATION")
    path = _fields(observation["path_descriptor"], {"schema", "target_name", "root_device", "root_inode"})
    _require(path["schema"] == "aragorn/runtime-protected-path/v1" and path["target_name"] == "result.json"
             and canonical_digest(path) == expected_path_digest, "PILOT_OUTPUT_NOMINATED_PATH")
    _require(_uint(path["root_inode"], 1) != _uint(observation["file_inode"], 1),
             "PILOT_OUTPUT_DIRECTORY_IS_NOT_FILE")
    _require(_uint(observation["file_device"]) == _uint(path["root_device"]), "PILOT_OUTPUT_DEVICE")
    encoded = observation["payload_hex"]
    _require(type(encoded) is str and len(encoded) == 22, "PILOT_OUTPUT_BYTES")
    captured = bytes.fromhex(encoded)
    _require(encoded == captured.hex() and len(captured) == _uint(observation["payload_bytes"], 11, 11)
             and "sha256:" + sha256(captured).hexdigest() == _pin(observation["payload_digest"]),
             "PILOT_OUTPUT_BYTES")

    result = replay(action_archive, action_pin, expected_deployment_digest=_pin(deployment_pin),
                    provider_archive=provider_archive, provider_nomination_digest=_pin(provider_pin))
    _require(result["recorded_public_pilot_inputs_matched"] is True and
             (result["recorded_verdict"], result["recorded_effect_status"]) == ("ALLOW", "CREATED"),
             "PILOT_OUTPUT_NO_RECORDED_CREATE")
    # replay has already verified this owner, the ordered index and its terminal frame.
    owner = _document(action_archive.read(result["owner_digest"], max_bytes=_MAX_RECORD))
    done_ref, = (r for r in owner["retained_evidence"]["references"] if r["kind"] == "ACTION_DONE")
    done = _document(action_archive.read(done_ref["digest"], max_bytes=done_ref["bytes"]))
    request, target, payload = _request_effect(done["envelope"])
    _require(request["session_id"] == request["run_id"] == observation["activation_id"] and
             request["path_digest"] == expected_path_digest and path["target_name"] == target and
             payload == captured, "PILOT_OUTPUT_ACTION_DIFFERS")
    policy = _document(action_archive.read(result["runtime_action_policy_digest"], max_bytes=1 << 20))
    # Managed replay validated the original policy schema. A provider allow rule
    # alone does not authorize creation of this file under that same policy.
    _require(request["policy_version"] == policy["version"] and
             {k: request[k] for k in _RULE_FIELDS} in policy["allow"], "PILOT_OUTPUT_NO_CREATE_RULE")
    return dict(schema="aragorn/pi-core-pilot-output-finding/v1", status="MATCHED_RECORDED_PILOT_OUTPUT",
                deployment_digest=deployment_pin, action_nomination_digest=action_pin,
                provider_nomination_digest=provider_pin, output_observation_digest=output_pin,
                path_digest=expected_path_digest, payload_digest=observation["payload_digest"],
                activation_digest=done["activation_digest"], worker_request_digest=done["request_digest"],
                recorded_create_rule_matched=True, acquisition_authenticity_verified=False,
                writer_attribution_verified=False, effect_verified=False, phase3_qualified=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("action-archive", "action-pin", "provider-archive", "provider-pin", "deployment-pin",
                "output-archive", "output-pin", "expected-path-digest"):
        parser.add_argument("--" + key, required=True)
    args = vars(parser.parse_args(argv))
    try:
        for key in ("action_archive", "provider_archive", "output_archive"):
            args[key] = CAS(args[key], read_only=True)
        result = verify_pilot_output(**args)
    except (CASError, OSError, RuntimeError, ValueError, KeyError, TypeError, IndexError, OverflowError):
        print("Pilot output replay refused. Preserve originals; do not retry the effect.", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
