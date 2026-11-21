"""Replay one independently nominated completed action from a private, read-only evidence store."""
import argparse
import json
import sys

from aragorn.cas import CAS, CASError
from aragorn.pi_core_action_boundary_verify import _MAX_RECORD, _SOURCE_ARGS
from aragorn.pi_core_action_index_verify import verify_retained_action
from aragorn.pi_core_source_observation_verify import _document, _fields, _pin, _require


def replay(archive, nomination_digest):
    _require(type(archive) is CAS and archive.read_only is True, "ACTION_REPLAY_READ_ONLY_CAS")

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
    result = verify_retained_action(evidence_cas=archive, expected_owner_digest=nomination["owner_digest"],
        expected_index_digest=nomination["index_digest"], expected_grant_digest=nomination["grant_digest"],
        expected_configuration_digest=nomination["configuration_digest"],
        expected_activation=_document(read(nomination["activation_digest"], 64 << 10)),
        expected_request=_document(read(nomination["request_digest"], 1 << 20)),
        expected_broker_nonce=nomination["broker_nonce"], expected_deadline_ns=nomination["deadline_ns"],
        expected_summary_digest=nomination["summary_digest"], selections=nomination["selections"],
        source_expectations=sources)
    return {**result, "nomination_digest": nomination_digest}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="existing private read-only CAS")
    parser.add_argument("nomination_digest", help="independently held pin; never select it from the submitted index")
    args = parser.parse_args(argv)
    try:
        result = replay(CAS(args.archive, read_only=True), args.nomination_digest)
    except (CASError, ValueError, OSError, KeyError, IndexError, TypeError, RuntimeError, OverflowError):
        print("Retained action replay refused. Preserve the original records; no effect was retried.", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
