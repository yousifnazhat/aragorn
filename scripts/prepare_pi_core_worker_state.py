"""Offline service-state seed, separate from the worker's read-only filesystem view."""
from scripts.build_pi_core_linux import ROOT, regular_bytes, require, sha256


# The reviewed installer creates both leaves absent-only; the worker launch exposes neither.
_SOURCES = {
    "src/aragorn/pi_core_broker_base_provision.py": "aad9d8d915620ff8f939af0d601e5e18cd01c12ee4829dbad09714b300c24401",
    "src/aragorn/pi_core_service_entry.py": "5748b971530b5ae875e7546dd60a5ab02ec435057858667a6b4c33f7afcac980",
    "src/aragorn/pi_core_confined_launch.py": "85dc08e4a116da0f8f644ccfadc9ae1b6b4a00cae4d743742476515d32bf25b7",
}


def state_seed():
    """Return root-owned archive directory modes and a handoff, not mount or installation instructions."""
    for name, digest in _SOURCES.items():
        require(sha256(regular_bytes(ROOT / name, 65536)) == digest, "state seed contract source changed: " + name)
    return {"var": 0o755, "var/lib": 0o755}, {
        "schema": "aragorn/pi-core-offline-service-state-seed/v1",
        "required_absent": ["/var/lib/aragorn-runtime-action", "/var/lib/aragorn-runtime-provider"],
        "installer_source_sha256": dict(_SOURCES),
        "worker_write_policy": "private-tmp-only", "worker_binds": [],
        "mounted": False, "authorized": False,
    }
