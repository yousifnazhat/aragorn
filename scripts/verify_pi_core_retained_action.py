"""Replay one independently nominated completed action from a private, read-only evidence store."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

from aragorn.cas import CAS, CASError
from aragorn.pi_core_action_boundary_verify import _MAX_RECORD, _SOURCE_ARGS
from aragorn.pi_core_action_index_verify import verify_retained_action
from aragorn.pi_core_source_observation_verify import _document, _fields, _pin, _require
from aragorn.runtime_action_worker import _worker_request


def _public_pilot_inputs(activation, worker_request):
    root = Path(__file__).resolve().parents[1] / "benchmark/pi-core-pilot-v1"

    def pinned(name, pin):
        with (root / name).open("rb") as source:
            raw = source.read(4097)
        _require(len(raw) <= 4096 and "sha256:" + sha256(raw).hexdigest() == pin, "PILOT_PUBLIC_INPUT")
        return raw

    review = json.loads(pinned("review.json", "sha256:1afcab1a853579fa6956dcd76d00fa432bb397236ba0853be652fda7f7f64a1e"))
    # The original B95/B97 manifest is path-bound. A different inventory of the same text is not this candidate.
    _require(activation["source_manifest_digest"] == "sha256:e6de9001bdd41e7908d0b9097798d1ab8ae13037c4ad1a7dbceb4cea985ad77f"
             and activation["tree_digest"] == review["tree_digest"]
             and activation["active_skill_digest"] == review["skill_digest"], "PILOT_ACTION_SOURCE")
    request, payload = _worker_request(worker_request)
    _require(request["target_name"] == review["target_name"] and len(payload) == review["expected_payload_bytes"]
             and "sha256:" + sha256(payload).hexdigest() == review["expected_payload_digest"], "PILOT_ACTION_OUTPUT_REQUEST")
    return pinned("candidate/SKILL.md", review["skill_digest"]), pinned("task.txt", review["task_digest"])


def replay(archive, nomination_digest, *, provider_archive=None, provider_nomination_digest=None):
    _require(type(archive) is CAS and archive.read_only is True, "ACTION_REPLAY_READ_ONLY_CAS")
    _require((provider_archive is None) == (provider_nomination_digest is None), "PILOT_BOTH_PROVIDER_INPUTS_REQUIRED")

    def read(pin, limit):
        return archive.read(_pin(pin), max_bytes=limit)

    nomination = _document(read(nomination_digest, 256 << 10))
    _fields(nomination, {"schema", "owner_digest", "index_digest", "configuration_digest", "grant_digest",
                         "activation_digest", "request_digest", "broker_nonce", "deadline_ns",
                         "summary_digest", "selections", "source_expectations"})
    _require(nomination["schema"] == "aragorn/pi-core-retained-action-nomination/v1", "ACTION_REPLAY_NOMINATION")
    sources = dict(_fields(nomination["source_expectations"], _SOURCE_ARGS))
    # In the nomination these three fields name original CAS bytes, not a path or source to execute.
    for field in ("expected_profile_raw", "source_inventory_raw", "loader_inventory_raw"):
        sources[field] = read(sources[field], _MAX_RECORD)
    activation = _document(read(nomination["activation_digest"], 64 << 10))
    worker_request = _document(read(nomination["request_digest"], 1 << 20))
    result = verify_retained_action(evidence_cas=archive, expected_owner_digest=nomination["owner_digest"],
        expected_index_digest=nomination["index_digest"], expected_grant_digest=nomination["grant_digest"],
        expected_configuration_digest=nomination["configuration_digest"],
        expected_activation=activation, expected_request=worker_request,
        expected_broker_nonce=nomination["broker_nonce"], expected_deadline_ns=nomination["deadline_ns"],
        expected_summary_digest=nomination["summary_digest"], selections=nomination["selections"],
        source_expectations=sources)
    if provider_archive is not None:
        from scripts.verify_pi_core_pilot_provider_records import compare_provider_records

        skill, task = _public_pilot_inputs(activation, worker_request)
        match = compare_provider_records(provider_archive, provider_nomination_digest, activation=activation,
                                         worker_request=worker_request, skill_bytes=skill, task_bytes=task)
        result.update(match, provider_nomination_digest=provider_nomination_digest, recorded_public_pilot_inputs_matched=True,
                      provider_peer_authentication_verified=False, provider_delivery_verified=False)
    return {**result, "nomination_digest": nomination_digest}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="existing private read-only CAS")
    parser.add_argument("nomination_digest", help="independently held pin; never select it from the submitted index")
    parser.add_argument("--pilot-provider-archive", help="existing read-only B27 export for the fixed public pilot")
    parser.add_argument("--pilot-provider-nomination", help="independently held provider nomination digest")
    args = parser.parse_args(argv)
    if (args.pilot_provider_archive is None) != (args.pilot_provider_nomination is None):
        parser.error("public pilot replay requires both provider options")
    try:
        result = replay(CAS(args.archive, read_only=True), args.nomination_digest,
                        provider_archive=CAS(args.pilot_provider_archive, read_only=True) if args.pilot_provider_archive is not None else None,
                        provider_nomination_digest=args.pilot_provider_nomination)
    except (CASError, ValueError, OSError, KeyError, IndexError, TypeError, RuntimeError, OverflowError):
        print("Retained action replay refused. Preserve the original records; no effect was retried.", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
