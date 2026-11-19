"""Admit exactly the private release digest reviewed for an offline build. No signing, boot or enrollment."""
from pathlib import Path
import re
import subprocess

from scripts import verify_pi_core_host_binding as binding
from scripts.build_pi_core_linux import ROOT, require, sha256
from scripts.pi_core_single_use_release import APPROVALS, parse_release, release_digest
from scripts.prepare_pi_core_host_lifecycle import require_local_custody
from scripts.verify_pi_core_owner_records import _object


PACK = ROOT / "packaging/pi-core"
SEAL = PACK / "immutable-host-b50/build-seal.json"
HELD = {"schema":"aragorn/b50-private-build-seal/v1", "purpose":"prepare-single-use-build-only", "approved":None}
REVIEWED_SOURCES = frozenset(
    [PACK / f"immutable-host-b{batch}" / name for batch, names in (
        (44, ("boot-request.json", "media-output.json")),
        (45, ("host-runner.m", "runner.entitlements.plist", "serial-recorder.h", "serial-recorder.m")),
        (46, ("vm-stop.h", "vm-stop.m")), (47, ("vm-owner.h", "vm-owner.m")),
        (50, ("build-seal.json", "owner-release.json", "owner-runner.m", "single-use.h"))) for name in names] +
    [ROOT / "scripts" / (name + ".py") for name in (
        "build_pi_core_linux", "inspect_pi_core_guest_disk", "pi_core_boot_build_seal", "pi_core_host_evidence_export",
        "pi_core_host_watchdog", "pi_core_single_use_release", "prepare_pi_core_bound_host_runner",
        "prepare_pi_core_guest_disk", "prepare_pi_core_guest_firmware_trust", "prepare_pi_core_host_lifecycle",
        "prepare_pi_core_host_sysroot", "prepare_pi_core_single_use_owner", "prepare_pi_core_vm_owner",
        "verify_pi_core_host_binding", "verify_pi_core_owner_records")])


def _blob(commit, path):
    require(type(commit) is str and re.fullmatch("[0-9a-f]{40}", commit) and
            (path == SEAL or path in REVIEWED_SOURCES), "unexpected source or commit")
    spec = commit + ":" + path.relative_to(ROOT).as_posix()
    def cat(option):
        return subprocess.run(["/usr/bin/git", "--no-replace-objects", "cat-file", option, spec], cwd=ROOT,
                              env={"HOME":str(Path.home()), "PATH":"/usr/bin:/bin", "LC_ALL":"C"},
                              stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=15).stdout
    size = int(cat("-s"))
    require(0 < size <= (8192 if path == SEAL else 1 << 20), "unexpected signed input size")
    raw = cat("blob")
    require(len(raw) == size, "incomplete signed input")
    return raw


def approved_digest(seal_raw):
    require(type(seal_raw) is bytes and 0 < len(seal_raw) <= 8192, "invalid build seal size")
    seal = _object(seal_raw)
    require(seal.keys() == HELD.keys() and seal["schema"] == HELD["schema"] and seal["purpose"] == HELD["purpose"],
            "unrecognized build seal")
    pins = seal["approved"]
    require(type(pins) is dict and pins.keys() == {"release_sha256", *APPROVALS},
            "no reviewed private build or missing approval records")
    require(all(type(v) is str and re.fullmatch("[a-f0-9]{64}",v) and v != "0" * 64 for v in pins.values())
            and len(set(pins.values())) == 4, "invalid or aliased approval digest")
    return pins


def match_private(pins, raw_private):
    release = parse_release(raw_private)
    attempts = release["approved_attempts"]
    require(len(attempts) == 1 and release_digest(release) == pins["release_sha256"] and
            all(attempts[0][key] == pins[key] for key in APPROVALS), "private release differs from signed build seal")
    return release


def reviewed_release(commit, signer, private_path, source_digests):
    # Signer + full commit must be supplied independently by the authorized release custodian.
    # A normal signed code change, including this batch, does not contain a build grant.
    binding.signed_pin(commit, signer)
    raw = _blob(commit, SEAL)
    pins = approved_digest(raw)  # refuse the shipped seal before opening any private path
    require(source_digests.keys() == REVIEWED_SOURCES, "incomplete reviewed build source inventory")
    for path, expected in source_digests.items():
        require(sha256(_blob(commit, path)) == expected, "candidate source differs from reviewed commit: " + path.name)
    require(private_path.is_absolute() and private_path.resolve(strict=True) == private_path, "private release must be canonical")
    require_local_custody(private_path)
    binding.identity(private_path.parent, True)
    return match_private(pins, binding.retained(private_path, 8192)), sha256(raw)
