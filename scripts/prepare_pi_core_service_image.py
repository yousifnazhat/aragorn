"""Prepare one pinned arm64 service image without executing target code.

This is a fixed CPython 3.12 relocation from the retained, reviewed OCI source,
not a package resolver or a service launcher. All selected ELF dependencies must
close statically. Exact local source/wrapper inputs are independently pinned.
Static imports and inventory do not establish dynamic-load completeness, ABI
compatibility, kernel confinement, loaded-code custody or native qualification.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

_SPEC = importlib.util.spec_from_file_location("pi_service_os_helpers", Path(__file__).with_name("prepare_pi_core_os_root.py"))
assert _SPEC and _SPEC.loader
os_root = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(os_root)
_build = os_root._build
canonical, pin = os_root.canonical, os_root.pin
PYTHON_SOURCE = "usr/local/bin/python3.12"
STDLIB_SOURCE = "usr/local/lib/python3.12"
PYTHON = "usr/bin/python3"
STDLIB = "usr/lib/python3.12"
LIBPYTHON = "usr/lib/libpython3.12.so.1.0"
LOADER = "lib/ld-linux-aarch64.so.1"
IMPORT_ROOT = "opt/aragorn/src"
ROLES = {
    "provider": {"module": "aragorn.pi_core_provider_service", "handler": "handle_pi_provider_service",
                 "path": IMPORT_ROOT + "/aragorn/pi_core_provider_service.py"},
    "action": {"module": "aragorn.pi_core_request_service", "handler": "handle_pi_broker_request",
               "path": IMPORT_ROOT + "/aragorn/pi_core_request_service.py"},
    "sensor": {"module": "aragorn.pi_core_request_sensor", "handler": "run_pi_sensor_request",
               "path": IMPORT_ROOT + "/aragorn/pi_core_request_sensor.py"},
}
SOURCE_SEEDS = ("aragorn.pi_core_service_entry", *(row["module"] for row in ROLES.values()))
EXCLUDED_STDLIB = frozenset({"site-packages", "ensurepip", "idlelib", "tkinter", "turtledemo", "test", "tests", "__pycache__"})
# CPython 3.12 Unix builtins/frozen boot modules not represented by a .py/.so.
# The pinned image's config-3.12-aarch64-linux-gnu/config.c explicitly registers
# {"pwd", PyInit_pwd}; its SHA256 is 30d353782cbaf8de2fed2ba82b1040940386e316b7f41604c49f8f3d6f16bb31.
# This is static target availability, never host builtin or target-load proof.
BUILTIN_MODULES = frozenset({"__future__", "builtins", "sys", "posix", "pwd", "errno", "time", "atexit",
    "_abc", "_ast", "_codecs", "_collections", "_functools", "_imp", "_io", "_locale",
    "_operator", "_signal", "_sre", "_stat", "_string", "_symtable", "_thread", "_tracemalloc",
    "_warnings", "_weakref", "gc", "itertools", "marshal"})
MAX_SOURCE_FILE = 4 * 1024 * 1024
MAX_SOURCE_FILES = 512
MAX_SOURCE_BYTES = 32 * 1024 * 1024
UNSUPPORTED_IMPORT_POLICY = {
    "aragorn/benchmark_worker_measurement.py": {
        "verify_worker_measurement": {
            "cryptography.exceptions": ("InvalidSignature",),
            "cryptography.hazmat.primitives.asymmetric.ed25519": ("Ed25519PublicKey",),
        },
        "_cryptography_types": {
            "cryptography.hazmat.primitives.asymmetric.ed25519": ("Ed25519PrivateKey",),
            "cryptography.hazmat.primitives.serialization": ("Encoding", "NoEncryption", "PrivateFormat", "PublicFormat"),
        },
    },
}


class ServiceImageError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ServiceImageError(message)


def _input(root: Path, name: str, expected: str) -> bytes:
    require(type(name) is str and os_root.relative(name) == name and name.endswith(".py"), "invalid source input path")
    require(type(expected) is str and os_root._PIN.fullmatch(expected), "invalid source input digest")
    root = root.absolute()
    require(root == root.resolve(strict=True) and root.is_dir(), "source root must be unlinked")
    path = root / name
    require(path.absolute() == path.resolve(strict=True), "linked source input")
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "source input must be a singly linked regular file")
    raw = _build.regular_bytes(path, MAX_SOURCE_FILE)
    require(pin(raw) == expected, "source input digest differs: " + name)
    return raw


def selected_python_files(tree):
    """Include the fixed non-GUI/non-test stdlib; record every omitted file."""
    selected, omitted = {}, []
    for name, item in sorted(tree.entries.items()):
        if not name.startswith(STDLIB_SOURCE + "/") or item["kind"] == "directory":
            continue
        suffix = name[len(STDLIB_SOURCE) + 1:]
        parts = suffix.split("/")
        reason = None
        native = len(parts) == 2 and parts[0] == "lib-dynload" and suffix.endswith(".so")
        if any(part in EXCLUDED_STDLIB for part in parts) or suffix == "turtle.py":
            reason = "EXCLUDED_GUI_TEST_OR_PACKAGE_INSTALL_TOOLING"
        elif native and (parts[-1].startswith("_tkinter.") or "test" in parts[-1]):
            reason = "EXCLUDED_TK_OR_NATIVE_TEST_EXTENSION"
        elif not suffix.endswith(".py") and not native:
            reason = "EXCLUDED_CACHE_BUILD_METADATA_OR_NON_CODE_RESOURCE"
        if reason:
            omitted.append({"source_path": name, "reason": reason})
            continue
        source, member = tree.file(name)
        require(member["kind"] == "file", "selected Python source is not regular")
        selected[STDLIB + "/" + suffix] = {**member, "mode": 0o555 if native else 0o444, "source_path": source}
    required = ("os.py", "ssl.py", "socket.py", "encodings/__init__.py", "json/__init__.py", "ctypes/__init__.py")
    require(all(STDLIB + "/" + name in selected for name in required), "Python stdlib essentials absent")
    native_names = [Path(name).name for name in selected if name.endswith(".so")]
    require(all(any(name.startswith(prefix + ".") for name in native_names) for prefix in ("_ssl", "_socket", "_ctypes")),
            "Python native essentials absent")
    return selected, omitted


def python_elf_closure(tree, selected):
    """Only Python's exact ORIGIN/../lib is allowed; every other ELF is strict."""
    selected = {name: dict(value) for name, value in selected.items()}
    for destination, source_path in ((PYTHON, PYTHON_SOURCE), (LIBPYTHON, "usr/local/lib/libpython3.12.so.1.0")):
        source, member = tree.file(source_path)
        require(bool(member["mode"] & 0o111), "Python executable/library lacks source executable mode")
        selected[destination] = {**member, "source_path": source, "mode": 0o555}
    queue = [PYTHON, LIBPYTHON, *(name for name in selected if name.startswith(STDLIB + "/lib-dynload/"))]
    seen, edges = set(), []
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        require(len(seen) <= 256, "service ELF closure exceeds bound")
        details = os_root.elf_dependencies(selected[name]["raw"], allowed_rpath=("$ORIGIN/../lib",) if name == PYTHON else ())
        if name == PYTHON:
            require(details["interpreter"] == "/" + LOADER and "libpython3.12.so.1.0" in details["needed"], "unsupported Python entry ELF")
        requests = []
        if details["interpreter"]:
            require(details["interpreter"] == "/" + LOADER, "unexpected service ELF interpreter")
            requests.append(("interpreter", details["interpreter"], LOADER, LOADER))
        for dependency in details["needed"]:
            if dependency == "ld-linux-aarch64.so.1":
                requests.append(("needed", dependency, LOADER, LOADER))
                continue
            if dependency == "libpython3.12.so.1.0":
                require(name == PYTHON, "libpython is only allowed through the pinned Python executable search")
                requests.append(("needed", dependency, LIBPYTHON, "usr/local/lib/libpython3.12.so.1.0"))
                continue
            candidates = []
            for folder in os_root.DEFAULT_LIBRARY_DIRS:
                source_path = folder + "/" + dependency
                resolved = tree.resolve(source_path)
                member = tree.entries.get(resolved)
                if member is not None and member["kind"] == "file":
                    candidates.append((source_path, resolved, member))
            require(candidates, "unresolved service ELF dependency: " + name + " -> " + dependency)
            require(len({pin(member["raw"]) for _, _, member in candidates}) == 1,
                    "ambiguous service ELF library candidates: " + dependency)
            # Fixed multiarch materialization is part of the pinned layout, not
            # ambient ld.so.cache/RPATH/default-host resolution.
            target = "lib/aarch64-linux-gnu/" + dependency
            requests.append(("needed", dependency, target, candidates[0][0]))
        for kind, requested, target, source_path in requests:
            source, member = tree.file(source_path)
            dependency = os_root.elf_dependencies(member["raw"])
            if kind == "needed":
                require(dependency["soname"] == requested, "service library SONAME differs")
            else:
                require(member["mode"] & 0o111, "service loader is not executable")
            if target not in selected:
                selected[target] = {**member, "source_path": source, "mode": 0o555}
                queue.append(target)
            require(selected[target]["raw"] == member["raw"], "conflicting service ELF target")
            edges.append({"requester": name, "kind": kind, "requested": requested, "path": target,
                          "source_path": source, "digest": pin(member["raw"])})
    return selected, edges


def stdlib_modules(selected):
    names = set(BUILTIN_MODULES)
    for name in selected:
        if not name.startswith(STDLIB + "/"):
            continue
        suffix = name[len(STDLIB) + 1:]
        if suffix.startswith("lib-dynload/"):
            names.add(Path(suffix).name.split(".")[0])
        elif suffix.endswith(".py"):
            names.add(suffix.split("/")[0].removesuffix(".py"))
    return names


def _module_path(name, inventory):
    require(re.fullmatch(r"aragorn(?:\.[A-Za-z_][A-Za-z_0-9]*)*", name), "invalid local import")
    base = name.replace(".", "/")
    candidates = [path for path in (base + ".py", base + "/__init__.py") if path in inventory]
    require(len(candidates) == 1, "missing or ambiguous pinned local import: " + name)
    return candidates[0]


def source_closure(source_root, expected, stdlib):
    """Parse all local imports, including lazy functions; never import them."""
    require(type(expected) is dict and 0 < len(expected) <= MAX_SOURCE_FILES, "invalid expected source inventory")
    require(all(type(name) is str and name.startswith("aragorn/") and name.endswith(".py") for name in expected), "invalid source inventory member")
    queue = [*SOURCE_SEEDS, "aragorn"]
    selected, imports, unsupported = {}, set(), []
    while queue:
        module = queue.pop(0)
        path = _module_path(module, expected)
        if path in selected:
            continue
        raw = _input(source_root, path, expected[path])
        require(sum(len(value) for value in selected.values()) + len(raw) <= MAX_SOURCE_BYTES, "source closure exceeds byte bound")
        selected[path] = raw
        try:
            parsed = ast.parse(raw, filename=path, feature_version=(3, 12))
        except (SyntaxError, UnicodeError, ValueError) as exc:
            raise ServiceImageError("source is not Python 3.12 syntax: " + path) from exc
        package = module if path.endswith("/__init__.py") else module.rpartition(".")[0]
        queue.extend(".".join(module.split(".")[:index]) for index in range(1, len(module.split("."))))
        parents = {child: parent for parent in ast.walk(parsed) for child in ast.iter_child_nodes(parent)}

        def unsupported_import(node, name):
            parent = parents.get(node)
            while parent is not None and not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                parent = parents.get(parent)
            function = parent.name if isinstance(parent, ast.FunctionDef) and isinstance(parents.get(parent), ast.Module) else None
            allowed = UNSUPPORTED_IMPORT_POLICY.get(path, {}).get(function, {}).get(name)
            aliases = tuple(alias.name for alias in node.names)
            if (allowed is not None and node.level == 0 and aliases == allowed and
                    all(alias.asname is None for alias in node.names)):
                unsupported.append({"path": path, "function": function, "line": node.lineno,
                                    "module": name, "names": list(aliases), "status": "UNSUPPORTED_BENCHMARK_DSSE_HELPER"})
                return True
            return False

        def add(name):
            if name == "aragorn" or name.startswith("aragorn."):
                queue.append(name)
            else:
                require(name.split(".")[0] in stdlib, "unavailable external import: " + path + " -> " + name)
                imports.add(name)

        dynamic_names = {"__import__"}
        importlib_names = {"importlib"}
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    add(alias.name)
                    if alias.name == "importlib":
                        importlib_names.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    pieces = package.split(".")
                    require(node.level <= len(pieces), "relative import escapes source package")
                    name = ".".join(pieces[:len(pieces) - node.level + 1])
                    if node.module:
                        name += "." + node.module
                else:
                    name = node.module or ""
                if unsupported_import(node, name):
                    continue
                add(name)
                if name == "importlib":
                    dynamic_names.update(alias.asname or alias.name for alias in node.names if alias.name == "import_module")
                if name == "aragorn" or name.startswith("aragorn."):
                    for alias in node.names:
                        candidate = name + "." + alias.name
                        base = candidate.replace(".", "/")
                        if base + ".py" in expected or base + "/__init__.py" in expected:
                            queue.append(candidate)
                        elif node.module is None:
                            raise ServiceImageError("missing pinned sibling import: " + candidate)
        for node in ast.walk(parsed):
            if not isinstance(node, ast.Call):
                continue
            dynamic = isinstance(node.func, ast.Name) and node.func.id in dynamic_names
            dynamic |= isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in importlib_names and node.func.attr in ("import_module", "__import__")
            require(not (isinstance(node.func, ast.Attribute) and node.func.attr in ("spec_from_file_location", "exec_module", "run_module", "run_path")), "dynamic source loading is not supported")
            if dynamic:
                require(node.args and isinstance(node.args[0], ast.Constant) and type(node.args[0].value) is str,
                        "computed dynamic imports are not supported")
                name = node.args[0].value
                if name.startswith("."):
                    require(name.startswith(".") and not name.startswith("..") and len(node.args) == 2 and
                            isinstance(node.args[1], ast.Name) and node.args[1].id == "__package__", "unknown dynamic import package")
                    name = package + name
                add(name)
    require(set(selected) == set(expected), "expected source inventory contains unreachable or extra files")
    return selected, sorted(imports), sorted(unsupported, key=lambda row: (row["path"], row["line"]))


def _wrappers(root, expected):
    require(type(expected) is dict and set(expected) == {role + ".py" for role in ROLES}, "fixed wrapper inventory differs")
    result = {}
    for name, digest in sorted(expected.items()):
        raw = _input(root, name, digest)
        try:
            ast.parse(raw, filename=name, feature_version=(3, 12))
        except (SyntaxError, UnicodeError, ValueError) as exc:
            raise ServiceImageError("wrapper is not Python 3.12 syntax") from exc
        result[name] = raw
    return result


def prepare_service_image(archive: Path, *, source_pin: dict, source_root: Path, wrapper_root: Path,
                          expected_source_inventory: dict, expected_wrapper_inventory: dict, output: Path) -> dict:
    source_pin = json.loads(canonical(source_pin))
    expected_source_inventory = json.loads(canonical(expected_source_inventory))
    expected_wrapper_inventory = json.loads(canonical(expected_wrapper_inventory))
    tree, provenance = os_root.read_source(archive, source_pin)
    selected, omitted = selected_python_files(tree)
    selected, edges = python_elf_closure(tree, selected)
    local, imported_stdlib, unsupported = source_closure(source_root, expected_source_inventory, stdlib_modules(selected))
    wrappers = _wrappers(wrapper_root, expected_wrapper_inventory)
    for name, raw in local.items():
        selected[IMPORT_ROOT + "/" + name] = {"raw": raw, "mode": 0o444, "source_path": "@reviewed-source/" + name}
    for name, raw in wrappers.items():
        selected["opt/aragorn/bin/" + name] = {"raw": raw, "mode": 0o555, "source_path": "@reviewed-wrapper/" + name}
    distro = {name: row for name, row in selected.items() if not row["source_path"].startswith(("usr/local/", "@"))}
    packages, documents = os_root.license_provenance(tree, distro)
    license_path, license_member = tree.file(STDLIB_SOURCE + "/LICENSE.txt")
    documents["licenses/CPython-LICENSE.txt"] = license_member["raw"]
    directories = set()
    for name in selected:
        parts = name.split("/")
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    files = [{"path": name, "size": len(row["raw"]), "digest": pin(row["raw"]), "executable": bool(row["mode"] & 0o111)}
             for name, row in sorted(selected.items())]
    require(len(files) + len(directories) <= 10_000 and sum(row["size"] for row in files) <= 128 * 1024 * 1024,
            "service image exceeds protected installer bounds")
    manifest = {"schema": "aragorn/pi-core-protected-tree/v1", "files": files, "directories": sorted(directories)}
    digests = {row["path"]: row["digest"] for row in files}
    binding = {"schema": "aragorn/pi-core-service-runtime-binding/v2", "target": "linux-arm64-glibc",
        "python": {"path": PYTHON, "digest": digests[PYTHON]}, "import_root": IMPORT_ROOT,
        "stdlib_directory": STDLIB, "loader_path": LOADER,
        "native_extension_paths": sorted(name for name in selected if name.startswith(STDLIB + "/lib-dynload/")),
        "shared_library_paths": sorted(name for name in selected if name == LIBPYTHON or name.startswith("lib/aarch64-linux-gnu/")),
        "source_digests": {IMPORT_ROOT + "/" + name: pin(raw) for name, raw in sorted(local.items())}, "roles": ROLES,
        "wrappers": {role: {"path": "opt/aragorn/bin/" + role + ".py", "digest": pin(wrappers[role + ".py"]),
            "argv": ["/" + PYTHON, "-I", "-S", "-B", "/opt/aragorn/bin/" + role + ".py"]} for role in ROLES}}
    destination = output.absolute()
    require(destination == destination.resolve() and not destination.exists() and not destination.is_symlink(), "service staging destination must be fresh and unlinked")
    destination.mkdir(mode=0o700)
    root = destination / "root"
    root.mkdir(mode=0o755)
    for name in sorted(directories, key=lambda item: (item.count("/"), item)):
        (root / name).mkdir(mode=0o755)
    for row in files:
        target = root / row["path"]
        with target.open("xb") as stream:
            require(stream.write(selected[row["path"]]["raw"]) == row["size"], "short service image write")
        target.chmod(0o555 if row["executable"] else 0o444)
    for name in sorted(directories, key=lambda item: item.count("/"), reverse=True):
        (root / name).chmod(0o555)
    root.chmod(0o755)
    for name, raw in sorted(documents.items()):
        target = destination / "provenance" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            require(stream.write(raw) == len(raw), "short license write")
        target.chmod(0o444)
    provenance_inventory = [{"path": "provenance/" + name, "size": len(raw), "digest": pin(raw)}
                            for name, raw in sorted(documents.items())]
    # Do not declare success when local files changed during archive/assembly
    # processing. The incomplete fresh artifact is retained, never retried.
    for name, raw in local.items():
        require(_input(source_root, name, expected_source_inventory[name]) == raw, "source changed during assembly")
    require(_wrappers(wrapper_root, expected_wrapper_inventory) == wrappers, "wrapper changed during assembly")
    for row in files:
        raw = _build.regular_bytes(root / row["path"], os_root.MAX_FILE)
        require(len(raw) == row["size"] and pin(raw) == row["digest"], "assembled image readback differs")
    for row in provenance_inventory:
        raw = _build.regular_bytes(destination / row["path"], os_root.MAX_FILE)
        require(len(raw) == row["size"] and pin(raw) == row["digest"], "license provenance readback differs")
    receipt = {"schema": "aragorn/pi-core-service-image/v1", "status": "PREPARED_NOT_INSTALLED_OR_EXECUTED",
        "target": "linux-arm64-glibc", **provenance, "source_pin_digest": pin(canonical(source_pin)),
        "manifest_digest": pin(canonical(manifest)), "runtime_binding_digest": pin(canonical(binding)),
        "expected_source_inventory": expected_source_inventory, "expected_wrapper_inventory": expected_wrapper_inventory,
        "elf_dependencies": edges, "python_rpath_policy": "$ORIGIN/../lib", "library_search_directories": list(os_root.DEFAULT_LIBRARY_DIRS),
        "source_mapping": {name: row["source_path"] for name, row in sorted(selected.items())},
        "stdlib_imports": imported_stdlib, "excluded_image_files": omitted,
        "unsupported_import_policy": json.loads(canonical(UNSUPPORTED_IMPORT_POLICY)), "unsupported_import_sites": unsupported,
        "packages": packages, "python_license": {"source_path": license_path, "path": "provenance/licenses/CPython-LICENSE.txt", "digest": pin(license_member["raw"])},
        "provenance_inventory": provenance_inventory,
        "loader_cache_included": False, "ld_preload_included": False, "site_packages_included": False,
        "executed_target_code": False, "native_cleanup_verified": False,
        "qualification": "STATIC_SERVICE_IMAGE_ONLY_NOT_DYNAMIC_LOAD_ABI_OR_PHASE3_QUALIFICATION"}
    for name, value in (("manifest.json", manifest), ("runtime-binding.json", binding), ("service-image-receipt.json", receipt)):
        raw = canonical(value)
        with (destination / name).open("xb") as stream:
            require(stream.write(raw) == len(raw), "short metadata write")
        (destination / name).chmod(0o444)
        require(_build.regular_bytes(destination / name) == raw, "metadata readback differs")
    return receipt
