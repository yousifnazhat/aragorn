"""Describe read-only delivery of already approved service configuration, without activation."""

import hashlib
from pathlib import Path
import re

from aragorn import pi_core_confined_launch as launch
from aragorn import pi_core_restricted_profile as fixed
from aragorn import pi_core_service_configuration as service
from aragorn.materialization import _TARGET_NAME
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import _parse_canonical_document
from aragorn.runtime_capability_grant import parse_runtime_capability_grant
from aragorn.runtime_process_profile import runtime_process_profile


ROOT_PATH = "/run/aragorn-pi-config"
# Three bounded canonical role documents plus their fixed enclosing keys.
_MAX_BYTES = len(service.ROLES) * service.entry.MAX_CONFIG + 64
_REFUSE = "invalid protected service configuration"


def _managed_worker(configs, now_unix):
    grant = parse_runtime_capability_grant(canonical_json(configs["action"]["capability_grant"]), now_unix)
    doc = configs["sensor"]["observation_binding"]["runtime_profile"]
    profile = runtime_process_profile(doc)
    unit = profile.cgroup.removeprefix("/system.slice/")
    if (profile.runtime_digest != fixed.RUNTIME_DIGEST or profile.executable_digest != "sha256:" + fixed.NODE_SHA256
            or profile.cgroup != "/system.slice/" + unit or not launch._UNIT.fullmatch(unit)
            or str(profile.skill_path) != doc["skill_path"]):
        raise ValueError(_REFUSE)
    # A context ID, unlike a source manifest digest, cannot be inferred from
    # the grant. Its actual transaction, and the freshness of the unit, are
    # independently established at launch, never by preparing these bytes.
    parts = profile.skill_path.relative_to(launch._ADMITTED / ".aragorn-versions").parts
    if len(parts) != 3 or not _TARGET_NAME.fullmatch(parts[0]) or parts[2] != "SKILL.md":
        raise ValueError(_REFUSE)
    context_id, _, source_manifest = parts[1].partition("-")
    if not re.fullmatch(r"[0-9a-f]{64}", context_id) or "sha256:" + source_manifest != grant["source_manifest_digest"]:
        raise ValueError(_REFUSE)


def layout(config_raw: bytes, expected_digest: str, now_unix: int):
    """Return {relative name: (mode, bytes or None)} and the existing plan section.

    The caller supplies a separately reviewed pin and trusted current time. No
    grant is minted, refreshed, or declared live beyond that instant.
    """
    if (type(config_raw) is not bytes or not 0 < len(config_raw) <= _MAX_BYTES
            or type(expected_digest) is not str or type(now_unix) is not int or now_unix < 0
            or "sha256:" + hashlib.sha256(config_raw).hexdigest() != expected_digest):
        raise ValueError(_REFUSE)
    try:
        docs = _parse_canonical_document(config_raw, "configuration delivery")
        if set(docs) != set(service.ROLES):
            raise ValueError(_REFUSE)
        files = {service.PATHS[role]: canonical_json(docs[role]) for role in service.ROLES}
        manifest = {
            "schema": "aragorn/pi-core-protected-tree/v1", "directories": list(service.DIRECTORIES),
            "files": [{"path": p, "size": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                       "executable": False} for p, raw in sorted(files.items())],
        }
        manifest_digest = canonical_digest(manifest)
        # This is the installed holder's own validator, including
        # validate_service_configurations, all role joins, and every file pin.
        _, configs = service._inputs(manifest, manifest_digest, docs, expected_digest)
        _managed_worker(configs, now_unix)
    except (RuntimeError, ValueError, TypeError):
        # Do not echo untrusted document contents (including duplicate keys).
        raise ValueError(_REFUSE) from None

    root = Path(ROOT_PATH)
    receipt = service._receipt(root / "installed/root", manifest_digest, configs, expected_digest)
    members = {
        "/": (0o700, None), "inputs": (0o700, None),
        "inputs/configurations.json": (0o400, config_raw),
        "inputs/manifest.json": (0o400, canonical_json(manifest)),
        "installed": (0o755, None), "installed/root": (0o755, None),
        "installed/" + service.RECEIPT: (0o444, canonical_json(receipt)),
    }
    members.update({"installed/root/" + d: (0o555, None) for d in service.DIRECTORIES})
    members.update({"installed/root/" + p: (0o444, raw) for p, raw in files.items()})
    section = {
        "deployment_path": str(root / "installed"), "receipt_digest": canonical_digest(receipt),
        "manifest": {"path": str(root / "inputs/manifest.json"), "digest": manifest_digest},
        "configurations": {"path": str(root / "inputs/configurations.json"), "digest": expected_digest},
    }
    return members, section
