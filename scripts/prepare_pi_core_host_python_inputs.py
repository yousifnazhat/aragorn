"""Select authenticated Python inputs for the VM host, not an OS or host profile.

No Bookworm loader, libc, systemd tool or service implementation is selected.
The guest's independently approved host profile must still close and validate
the native ABI and installed filesystem. No target code is imported or run.
"""
from pathlib import Path

from scripts import prepare_pi_core_service_image as image
from scripts.prepare_pi_core_restricted_host_sources import _identity

ROOT = Path(__file__).resolve().parents[1]
RELEASE = "packaging/pi-core/service-assembly-inputs-v3.json"
RELEASE_PIN = "sha256:413c7c545353f70447f7cab357d75b920ab98c77bd635eebfab67d544dec5589"
# Git blob contents at the signed dd7bf9c checkpoint. The v3 manifest field
# is instead a hash of canonical JSON (the service preparer's original contract).
SOURCE_RAW_PIN = "sha256:f5d986bbdd24201a76f6de66f223d0bae5e0af77fd12d24b873e4ffc3ba1f350"
# Independent projection of the service-v3 checkpoint's 343bf24835f1... manifest:
# only Python, libpython and the selected stdlib, sorted by absolute path.
PYTHON_ROWS_PIN = "sha256:c7a6433f3b251effdda2130be5a4eb4a9aabc3b97595487e57537fcaea4d9a1b"
PREFIX = "/opt/aragorn-cpython"


def _pinned_bytes(path, expected, limit):
    before = _identity(path)
    raw = image._build.regular_bytes(path, limit)
    image.require(_identity(path) == before and image.pin(raw) == expected,
                  "host Python input differs from pin: " + path.name)
    return raw


def _projection(tree):
    stdlib, _ = image.selected_python_files(tree)
    paths = {target: (image.STDLIB_SOURCE + target[len(image.STDLIB):], entry["mode"])
             for target, entry in stdlib.items()}
    paths[image.PYTHON] = (image.PYTHON_SOURCE, 0o555)
    paths[image.LIBPYTHON] = ("usr/local/lib/libpython3.12.so.1.0", 0o555)
    files, rows = {}, []
    for target, (source, mode) in sorted(paths.items()):
        resolved, member = tree.file(source)
        image.require(resolved == source and not member["mode"] & 0o7022 and
                      (target != image.PYTHON or member["mode"] & 0o100),
                      "unsafe host Python source path or mode: " + source)
        raw = member["raw"]
        fields = {"digest": image.pin(raw), "size": len(raw), "mode": mode}
        # Authenticate historical coordinates; relocate only the selected
        # interpreter/lib pair and its stdlib. Never replace guest OS Python.
        rows.append({"path": "/" + target, **fields})
        if target == image.PYTHON:
            destination = PREFIX + "/bin/python3.12"
        else:
            image.require(target == image.LIBPYTHON or target.startswith(image.STDLIB + "/"),
                          "unexpected host Python destination")
            destination = PREFIX + "/" + target.removeprefix("usr/")
        files[destination] = {**fields, "source_path": source, "raw": raw}
    image.require(image.pin(image.canonical(rows)) == PYTHON_ROWS_PIN,
                  "host Python selection differs from independently pinned rows")
    return files


def prepare_host_python_inputs(root=ROOT):
    """Return absolute destination -> {source_path, raw, digest, size, mode}."""
    root = Path(root).absolute()
    release = image.os_root.document(_pinned_bytes(root / RELEASE, RELEASE_PIN, 1 << 20))
    pin = release["source_pin"]
    source = image.os_root.document(_pinned_bytes(root / pin["path"], SOURCE_RAW_PIN, 1 << 20))
    image.require(image.pin(image.canonical(source)) == pin["digest"], "canonical OCI source differs from pin")
    archive = release["archive"]
    path = root / archive["path"]
    before = _identity(path)
    image.require(path.stat().st_size == archive["bytes"], "host Python archive size differs")
    # Authenticate before parsing; read_source checks the selected OCI layers
    # and reports the digest of the very bytes parsed on its separate open.
    _pinned_bytes(path, "sha256:" + archive["sha256"], archive["bytes"])
    tree, provenance = image.os_root.read_source(path, source)
    image.require(_identity(path) == before and provenance["archive_sha256"] == archive["sha256"] and
                  provenance["archive_bytes"] == archive["bytes"], "host Python archive changed during parsing")
    return _projection(tree)
