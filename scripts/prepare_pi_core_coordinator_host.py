"""Check an independently pinned retained host export without executing it.

This is developer-input custody, not installed root protection or proof of the
VM's loader, imports, ABI, or consumed code. No expected pin is discovered here.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
from typing import NamedTuple

_ROOT = Path(__file__).resolve().parents[1]


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host_contract = _module("pi_host_preparation_contract", _ROOT / "packaging/pi-core/coordinator.py")
os_root = _module("pi_host_preparation_elf", _ROOT / "scripts/prepare_pi_core_os_root.py")
_build = os_root._build
_MAX_NATIVE = 256
_MAX_OUTPUT = 2 * 1024 * 1024


class PiCoordinatorHostPreparationError(ValueError):
    pass


class PreparedPiCoordinatorHost(NamedTuple):
    profile_raw: bytes
    preparation_raw: bytes


def _require(condition, reason):
    if not condition:
        raise PiCoordinatorHostPreparationError(reason)


def _identity(info):
    return host_contract._identity(info)


def _root(path):
    _require(isinstance(path, Path), "retained export path required")
    path = path.absolute()
    _require(path != Path("/") and path == path.resolve(strict=True), "unlinked retained export required")
    info = path.lstat()
    _require(stat.S_ISDIR(info.st_mode), "retained export directory required")
    return path


def _inventory(root):
    """Snapshot every supplied name; this is not ambient host discovery."""
    files, directories, objects = {}, {}, set()
    pending = [(root, "")]
    while pending:
        directory, relative = pending.pop()
        info = directory.lstat()
        _require(stat.S_ISDIR(info.st_mode) and directory.resolve(strict=True) == directory,
                 "retained directory is linked or changed")
        directories[relative] = _identity(info)
        _require(len(directories) <= host_contract._MAX_FILES, "retained directory bound")
        with os.scandir(directory) as entries:
            for entry in entries:
                name = relative + "/" + entry.name if relative else entry.name
                host_contract._path("/" + name)
                _require(len(name.split("/")) <= 64, "retained path depth bound")
                metadata = entry.stat(follow_symlinks=False)
                path = root / name
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append((path, name))
                    _require(len(directories) + len(pending) <= host_contract._MAX_FILES,
                             "retained directory bound")
                else:
                    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                             "retained file is linked or special")
                    identity = (metadata.st_dev, metadata.st_ino)
                    _require(identity not in objects, "retained file identity alias")
                    objects.add(identity)
                    _require(0 <= metadata.st_size <= host_contract._MAX_FILE, "retained file byte bound")
                    files[name] = _identity(metadata)
                    _require(len(files) <= host_contract._MAX_FILES, "retained file count bound")
    _require(sum(row[6] for row in files.values()) <= host_contract._MAX_BYTES, "retained total byte bound")
    return files, directories


def _read(root, name, expected, identity):
    path = root / name
    _require(path.resolve(strict=True) == path and _identity(path.lstat()) == identity,
             "retained file changed before read")
    raw = _build.regular_bytes(path, host_contract._MAX_FILE)
    _require(len(raw) == expected["size"] and host_contract._digest(raw) == expected["digest"] and
             path.resolve(strict=True) == path and _identity(path.lstat()) == identity,
             "retained file bytes or identity differ")
    return raw


def _native_inventory(contents, identities, profile):
    python = Path(profile["python_executable"])
    required = {python, *host_contract._TOOLS}
    details, policies = {}, {}
    for path, raw in contents.items():
        shared = path.name.endswith(".so") or ".so." in path.name
        if path not in required and not raw.startswith(b"\x7fELF") and not shared:
            continue
        _require(len(details) < _MAX_NATIVE, "retained native file bound")
        policy = "NONE"
        try:
            value = os_root.elf_dependencies(raw)
        except os_root.OSRootError as error:
            # Only the existing parser's fixed CPython relocation spelling is
            # additionally recognized. This does not resolve runtime searches.
            if path != python or str(error) != "ELF uses unapproved RPATH/RUNPATH/audit/filter loading":
                raise
            value = os_root.elf_dependencies(raw, allowed_rpath=("$ORIGIN/../lib",))
            policy = "$ORIGIN/../lib"
        details[path], policies[str(path)] = value, policy
    _require(required <= details.keys(), "retained native entrypoints absent")
    for path in required:
        _require(identities[str(path)[1:]][2] & stat.S_IXUSR, "retained native entrypoint is not executable")
    edges = []
    for requester, value in sorted(details.items()):
        if value["interpreter"] is not None:
            interpreter = Path(value["interpreter"])
            _require(interpreter in details and identities[str(interpreter)[1:]][2] & stat.S_IXUSR,
                     "retained ELF interpreter is absent or not executable")
            edges.append({"requester": str(requester), "kind": "interpreter", "requested": str(interpreter),
                          "path": str(interpreter), "digest": host_contract._digest(contents[interpreter])})
        for needed in value["needed"]:
            candidates = [path for path, candidate in details.items()
                          if path.name == needed and candidate["soname"] == needed]
            _require(len(candidates) == 1, "missing or ambiguous declared ELF dependency")
            selected = candidates[0]
            edges.append({"requester": str(requester), "kind": "needed", "requested": needed,
                          "path": str(selected), "digest": host_contract._digest(contents[selected])})
    return len(details), sorted(edges, key=lambda row: (row["requester"], row["kind"], row["requested"])), policies


def prepare_pi_coordinator_host_profile(expected_profile_raw, *, expected_profile_digest, retained_root):
    """Return unchanged approved bytes and a candidate-only receipt; write nothing."""
    _require(type(expected_profile_raw) is bytes and 0 < len(expected_profile_raw) <= _MAX_OUTPUT and
             type(expected_profile_digest) is str and host_contract._PIN.fullmatch(expected_profile_digest) and
             host_contract._digest(expected_profile_raw) == expected_profile_digest,
             "independent expected host profile pin required")
    profile = host_contract._document(expected_profile_raw)
    expected = host_contract._profile(profile)
    root = _root(retained_root)
    files, directories = _inventory(root)
    _require(set(files) == {str(path)[1:] for path in expected}, "retained file namespace differs from approved profile")
    for absent in profile["absent_sys_path"]:
        _require(not os.path.lexists(root / absent[1:]), "approved absent Python zip is present")
    contents = {}
    for path, row in expected.items():
        name = str(path)[1:]
        if path.is_relative_to(host_contract._SOURCE_ROOT) or path == host_contract._WRAPPER:
            _require(stat.S_IMODE(files[name][2]) == 0o444, "retained bootstrap source mode differs")
        contents[path] = _read(root, name, row, files[name])
    native_files, edges, policies = _native_inventory(contents, files, profile)
    # Do not adopt replacements or silently correct an independently approved
    # pin. This repeated readback is part of one preparation transaction.
    for path, row in expected.items():
        _require(_read(root, str(path)[1:], row, files[str(path)[1:]]) == contents[path],
                 "retained content changed during preparation")
    _require(_root(root) == root and _inventory(root) == (files, directories),
             "retained namespace or identity changed during preparation")
    receipt = {"schema": "aragorn/pi-core-coordinator-host-preparation/v1",
        "status": "PREPARED_RETAINED_EXPORT_NOT_INSTALLED_OR_EXECUTED",
        "authority": "DEVELOPER_INPUT_CUSTODY_ONLY_NOT_INSTALLED_HOST_OR_CONSUMED_CODE",
        "host_profile_digest": expected_profile_digest, "target": profile["target"],
        "files": len(files), "bytes": sum(row["size"] for row in expected.values()),
        "native_files": native_files, "static_elf_dependencies": edges, "declared_search_policy": policies,
        "executed_target_code": False, "installed_root_protection_verified": False,
        "actual_loader_resolution_verified": False, "phase3_exit_eligible": False}
    receipt_raw = host_contract._canonical(receipt)
    _require(len(receipt_raw) <= _MAX_OUTPUT, "host preparation receipt exceeds bound")
    return PreparedPiCoordinatorHost(expected_profile_raw, receipt_raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--profile-digest", required=True)
    parser.add_argument("--retained-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        prepared = prepare_pi_coordinator_host_profile(_build.regular_bytes(args.profile, _MAX_OUTPUT),
            expected_profile_digest=args.profile_digest, retained_root=args.retained_root)
        report = {"schema": "aragorn/pi-core-coordinator-host-preparation-output/v1",
            "profile": json.loads(prepared.profile_raw), "preparation": json.loads(prepared.preparation_raw)}
        raw = host_contract._canonical(report)
        _require(len(raw) <= 2 * _MAX_OUTPUT, "host preparation output exceeds bound")
    except (ValueError, OSError, KeyError, TypeError, _build.BuildError):
        parser.exit(1, "Pi host preparation refused; no installed-host qualification.\n")
    print(raw.decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
