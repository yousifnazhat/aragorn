"""Read-only comparison of pilot storage evidence; no device access or activation."""
import argparse
import json
import re
import stat
import sys
from uuid import UUID

from .cas import CAS, CASError
from .oci_worker_protocol import canonical_json
from .phase3_exit_gate_manifest import load_phase3_exit_gate_manifest_bytes
from .pi_core_state_exposure import verify_pi_exposure
from .pi_core_state_mounts import ANCHOR, ACTION, PROVIDER, verify_mounts


ROLES = {"manager", "action", "sensor", "provider", "pi"}
PROFILE = "aragorn/pilot-state-profile/v1"
LATEST = "aragorn/pilot-state-independent-head/v1"
CAPTURE = "aragorn/pilot-state-role-capture/v1"
MASK_PROFILE = "aragorn/pilot-state-profile/v2"
MASK_LATEST = "aragorn/pilot-state-independent-head/v2"
MASK_CAPTURE = "aragorn/pilot-state-role-capture/v2"
MASK_WALK = "aragorn/pilot-state-pi-walk/v2"
MASK_WITNESS = "aragorn/pilot-state-independent-masks/v1"


def _need(ok, reason):
    if not ok:
        raise ValueError(reason)


def _keys(obj, fields):
    _need(type(obj) is dict and obj.keys() == set(fields), "missing or unexpected record fields")


def _pin(s):
    _need(type(s) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", s) and int(s[7:], 16), "invalid evidence digest")
    return s


def _uint(n, low=1, high=1 << 64):
    _need(type(n) is int and low <= n < high, "invalid integer identity")
    return n


def _uuid(s):
    _need(type(s) is str and len(s) == 36 and str(UUID(s)) == s and UUID(s).int, "invalid UUID")
    return s


def _dev(s):
    _need(type(s) is str and re.fullmatch(r"[1-9][0-9]{0,3}:(0|[1-9][0-9]{0,6})", s), "invalid block device")
    major, minor = map(int, s.split(":"))
    _need(major < 4096 and minor < 1 << 20, "invalid block device")
    return s


def _doc(cas, pin):
    return load_phase3_exit_gate_manifest_bytes(cas.read(_pin(pin), max_bytes=65536))


def _same(left, right, reason):
    # JSON equality must distinguish false/true from 0/1 at every depth.
    _need(canonical_json(left) == canonical_json(right), reason)


def _volume(volume):
    _keys(volume, ("backing_identity", "encryption_uuid", "filesystem_uuid", "fs_type"))
    _pin(volume["backing_identity"])
    _need(_uuid(volume["encryption_uuid"]) != _uuid(volume["filesystem_uuid"])
          and volume["fs_type"] in ("ext4", "xfs"), "unapproved local filesystem or encryption identity")


def verify_state_archive(cas, profile_pin, latest_pin):
    """Both pins come from independent custody; latest_pin must not be selected by the volume."""
    return _verify_archive(cas, profile_pin, latest_pin, None)


def verify_state_archive_v2(cas, profile_pin, latest_pin, mask_witness_pin):
    """Compare a distinctly pinned independent observer's evidence for the exact stopped gate."""
    return _verify_archive(cas, profile_pin, latest_pin, _pin(mask_witness_pin))


def _verify_archive(cas, profile_pin, latest_pin, mask_pin):
    _need(type(cas) is CAS and cas.read_only is True, "read-only CAS required")
    masked = mask_pin is not None
    schemas = (MASK_PROFILE, MASK_LATEST, MASK_CAPTURE) if masked else (PROFILE, LATEST, CAPTURE)
    p, head = _doc(cas, profile_pin), _doc(cas, latest_pin)
    _keys(p, ("schema", "deployment", "image", "configuration", "volume", "roles"))
    _keys(head, ("schema", "profile", "capture", "boot_id", "attachment", "generation", "state_digest",
                 "unresolved_attempts", "subjects", "worker_root", "admitted_cwd"))
    _need((p["schema"], head["schema"]) == schemas[:2] and head["profile"] == profile_pin,
          "independent head and selected pilot profile differ")
    for k in ("deployment", "image", "configuration"):
        _pin(p[k])
    _volume(p["volume"])
    _uuid(head["boot_id"])
    _uint(head["generation"])
    _pin(head["state_digest"])
    _need(head["unresolved_attempts"] == [], "unresolved attempts at independent head")
    a = head["attachment"]
    _keys(a, ("backing_identity", "writer_deployments", "fence", "mapping"))
    _pin(a["fence"])
    _need(a["backing_identity"] == p["volume"]["backing_identity"] and a["writer_deployments"] == [p["deployment"]],
          "wrong attachment or no exclusive writer")
    c = _doc(cas, head["capture"])
    _keys(c, ("schema", "profile", "deployment", "image", "configuration", "boot_id", "attachment", "volume", "mapping", "generation", "state_digest",
              "unresolved_attempts", "roles", "source_roots", "pi_exposure"))
    _need(c["schema"] == schemas[2] and c["profile"] == profile_pin, "wrong observation profile")
    for k in ("deployment", "image", "configuration"):
        _same(c[k], p[k], "observed deployment does not match profile: " + k)
    for k in ("boot_id", "attachment", "generation", "state_digest", "unresolved_attempts"):
        _same(c[k], head[k], "stale, conflicting or ambiguous observation: " + k)
    _same(c["volume"], p["volume"], "observed backing volume differs from approved identity")
    mapping = c["mapping"]
    _same(mapping, a["mapping"], "observed block mapping disagrees with independent attachment")
    _keys(mapping, ("type", "device", "backing_devices"))
    dev = _dev(mapping["device"])
    backing = mapping["backing_devices"]
    _need(mapping["type"] == "dm-crypt" and type(backing) is list and 1 <= len(backing) <= 16,
          "missing encrypted local block mapping")
    devices = {_dev(d) for d in backing}
    _need(len(devices) == len(backing) and dev not in devices, "ambiguous block device chain")
    for table in (head["subjects"], c["roles"], p["roles"]):
        _keys(table, ROLES)
    source = c["source_roots"]
    _keys(source, (ANCHOR, ACTION, PROVIDER))
    for target, obj in source.items():
        _keys(obj, ("dev", "ino", "uid", "gid", "mode"))
        _uint(obj["ino"])
        _same([obj["dev"], obj["uid"], obj["gid"], obj["mode"]],
              [dev, 0, 0, stat.S_IFDIR | (0o755 if target == ACTION else 0o700)], "wrong backing directory identity or mode")
    _need(len({v["ino"] for v in source.values()}) == len(source), "backing directories alias")
    pids, namespaces, pi_mounts = set(), set(), {}
    mount_details = {"pi": {}, "manager": {}} if masked else {}
    for role in sorted(ROLES):
        ids, subject, obs = p["roles"][role], head["subjects"][role], c["roles"][role]
        _keys(ids, ("uid", "gid"))
        for ident in ids.values():
            _uint(ident, 0 if role == "manager" else 1, 1 << 31)
        if role == "manager":
            _need(ids == {"uid": 0, "gid": 0}, "root manager required")
        fields = ("pid", "start_ticks", "mount_namespace", "uid", "gid")
        if masked and role in mount_details:
            fields += ("user_namespace",)
        _keys(subject, fields)
        if "user_namespace" in fields:
            _uint(subject["user_namespace"])
        pids.add(_uint(subject["pid"], 1, 1 << 31))
        namespaces.add(_uint(subject["mount_namespace"]))
        _uint(subject["start_ticks"])
        _same(ids, {k: subject[k] for k in ids}, "wrong role principal")
        _keys(obs, ("before", "after", "mountinfo", "targets"))
        _same(subject, obs["before"], "wrong process or namespace at opening")
        _same(subject, obs["after"], "process or namespace changed")
        raw = cas.read(_pin(obs["mountinfo"]), max_bytes=1 << 20)
        mounts = verify_mounts(role, raw, device=dev, fs_type=p["volume"]["fs_type"], backing_devices=backing,
                               namespace=pi_mounts if role == "pi" else None, mount_details=mount_details.get(role))
        _keys(obs["targets"], mounts)
        for target, mid in mounts.items():
            _same(obs["targets"][target], {**source[target], "mount_id": mid},
                  "visible path is not the backing directory on the checked mount")
    _need(len(pids) == len(namespaces) == len(ROLES), "role PIDs or namespaces alias")
    _need(all(len({ids[k] for ids in p["roles"].values()}) == len(ROLES) for k in ("uid", "gid")),
          "role users or groups alias")
    pi = head["subjects"]["pi"]
    # The bounded namespace walk can be larger than a 64 KiB control manifest.
    raw = cas.read(_pin(c["pi_exposure"]), max_bytes=32 << 20)
    exposure = json.loads(raw.decode("ascii"))
    _need(canonical_json(exposure) + b"\n" == raw, "noncanonical or duplicate Pi exposure fields")
    context = dict(namespace=pi_mounts, device=dev, backing_devices=backing, pid=pi["pid"],
                   start_ticks=pi["start_ticks"], mount_namespace=pi["mount_namespace"],
                   worker_root=head["worker_root"], admitted_cwd=head["admitted_cwd"])
    if masked:
        from .pi_core_state_exposure import _verify_pi_exposure
        from .pi_core_state_masks import verify_masks

        _keys(exposure, ("schema", "walk"))
        _need(exposure["schema"] == MASK_WALK, "versioned mask walk required")
        witness = _doc(cas, mask_pin)
        joins = dict(schema=MASK_WITNESS, profile=profile_pin, independent_head=latest_pin,
                     capture=head["capture"], pi_exposure=c["pi_exposure"], boot_id=head["boot_id"])
        _keys(witness, (*joins, "proof"))
        _same({k: witness[k] for k in joins}, joins, "independent mask witness belongs to another capture")
        walk = exposure["walk"]
        leaves = verify_masks(walk, witness["proof"], subject=pi, manager_subject=head["subjects"]["manager"],
                              namespace=pi_mounts, device=dev, backing_devices=backing,
                              worker_mounts=mount_details["pi"], manager_mounts=mount_details["manager"])
        _need(witness["proof"]["before"]["probe"]["pid"] not in pids, "mask probe aliases a protected role")
        _verify_pi_exposure(walk, verified_masks=leaves, **context)
    else:
        verify_pi_exposure(exposure, **context)
    return {**({"mask_witness": mask_pin} if masked else {}),
            "status": "consistent-offline-records-only", "profile": profile_pin, "independent_head": latest_pin,
            "capture": head["capture"], "installed_isolation_verified": False, "activation_authorized": False,
            "recovery_authorized": False, "phase3_exit_eligible": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cas", help="existing private, read-only evidence store")
    parser.add_argument("profile", help="out-of-band pin of approved pilot profile")
    parser.add_argument("latest", help="out-of-band pin of latest independently retained witness")
    parser.add_argument("--mask-witness", help="select v2: separately held mask-observer witness digest")
    args = parser.parse_args(argv)
    try:
        cas = CAS(args.cas, read_only=True)
        report = (verify_state_archive(cas, args.profile, args.latest) if args.mask_witness is None else
                  verify_state_archive_v2(cas, args.profile, args.latest, args.mask_witness))
        print(json.dumps(report, sort_keys=True))
    except (CASError, ValueError, OSError, RecursionError) as exc:
        print("State evidence refused: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
