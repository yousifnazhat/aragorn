"""Compare independently supplied admission and stopped-worker receipts. No acquisition or writes."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from aragorn.cas import CAS, CASError
from aragorn.pi_core_mask_custody import replay_mask_observation
from aragorn.pi_core_state_admission import _doc, _need, _same, verify_state_archive_v2
from aragorn.pi_core_stopped_mask_capture import _verify_slice


def _separate(roots):
    # Check namespace aliases too, without claiming independent machines or administrators.
    chains = []
    for root in roots:
        _need(isinstance(root, Path) and root.is_absolute() and root != Path("/") and
              root.resolve(strict=True) == root, "expected existing unlinked absolute evidence directory")
        chain = []
        for part in (root, *root.parents):
            info = part.stat()
            chain.append((info.st_dev, info.st_ino))
        _need(all(chain[0] not in other and other[0] not in chain for other in chains), "overlapping evidence roots")
        chains.append(chain)
    return chains


def verify_joined_masks(*, archive, profile_pin, latest_pin, witness_pin, store, receipt_directory,
                        capture_pin, receipt_pin, require_manager_state=False):
    """Validate both original formats, then join their overlapping facts; do not manufacture either witness."""
    _need(type(require_manager_state) is bool, "invalid manager-state requirement")
    _need(type(archive) is CAS and archive.read_only is True, "admission CAS must already be read-only")
    paths = (archive.root, store, receipt_directory)
    roots = _separate(paths)
    admitted = verify_state_archive_v2(archive, profile_pin, latest_pin, witness_pin)
    local = replay_mask_observation(store=store, receipt_directory=receipt_directory,
                                    capture_digest=capture_pin, receipt_digest=receipt_pin)
    binding, view, proof = (json.loads(local[key]) for key in ("bindings", "vantage", "proof"))
    manager_state = _verify_slice(binding, view, proof, local["worker"], local["manager"])
    has_manager_state = binding["schema"] == "aragorn/pi-core-stopped-mask-binding/v2"
    _need(not require_manager_state or has_manager_state, "manager-state evidence required; legacy mask receipt")

    head, capture, outer = (_doc(archive, pin) for pin in (latest_pin, admitted["capture"], witness_pin))
    # Each dereference is content-addressed. The two capture and profile digest *types* differ.
    _same(binding["deployment"], capture["deployment"], "different deployment")
    _same(binding["clock"]["boot_id"], head["boot_id"], "different boot")
    _same(binding["storage"], {"device": capture["mapping"]["device"], "backing_devices":
          capture["mapping"]["backing_devices"], "fs_type": capture["volume"]["fs_type"]}, "different state mapping")
    for role, key in (("pi", "worker"), ("manager", "manager")):
        _same(binding[key], head["subjects"][role], "different subject: " + role)
        pin = "sha256:" + hashlib.sha256(local[key]).hexdigest()
        _same(pin, capture["roles"][role]["mountinfo"], "different raw mountinfo: " + role)
    _same(proof["witness"], outer["proof"], "different mask observation")
    if has_manager_state:
        _need(manager_state is not None, "missing verified manager-state projection")
        source_roots, target_stats = manager_state
        _same(source_roots, capture["source_roots"], "different manager-state source roots")
        _same(target_stats, capture["roles"]["manager"]["targets"], "different manager-state bind targets")

    walk = json.loads(archive.read(capture["pi_exposure"], max_bytes=32 << 20))["walk"]
    _same(walk["root"], view["worker_root"], "different worker root")
    _same(walk["tree"]["/dev"], dict(stat=view["worker_dev"], before=proof["names_before"],
                                     after=proof["names_after"]), "different /dev view")
    # B58 already checked every marked leaf against this exact proof and rejected extra/hidden paths.
    _need(_separate(paths) == roots, "evidence directory changed")
    return {**admitted, "mask_capture_binding": capture_pin, "local_receipt": receipt_pin,
            "manager_state_roots_and_targets_matched": has_manager_state,
            "same_capture_interval_verified": False, "external_freshness_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("archive", "store", "receipt-directory"):
        parser.add_argument("--" + arg, type=Path, required=True)
    for arg in ("profile-pin", "latest-pin", "witness-pin", "capture-pin", "receipt-pin"):
        parser.add_argument("--" + arg, required=True)
    parser.add_argument("--require-manager-state", action="store_true",
                        help="refuse historical mask receipts without measured manager state roots and bind targets")
    args = vars(parser.parse_args(argv))
    try:
        args["archive"] = CAS(args["archive"], read_only=True)
        result = verify_joined_masks(**args)
    except (CASError, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print("Joined mask evidence refused: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
