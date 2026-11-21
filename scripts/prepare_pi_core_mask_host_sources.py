"""Read the B59 protected coordinator's repository source projection without importing it."""
import ast
from pathlib import Path

from scripts import prepare_pi_core_restricted_host_sources as b37
from scripts.build_pi_core_linux import canonical, regular_bytes, sha256

ROOT = b37.ROOT
REVISION = "241427f8cf1237015b7dba2df214bc843b17ed99"
TREE = "be952dd4fd9eb2e8d7265ea2bf3da883194c9e7c"
ROWS_DIGEST = "sha256:37431489b521277b75969cca3e38b208c905c64e73c3ad7ad735b359a80c08d6"
PROBE_DIGEST = "sha256:aef5d0aebb0c1d98d91da4c627c51b991f902baf2c3005a473bf4fcaaf693725"
_PREFIX = "/opt/aragorn/src/aragorn/"
_PROBE = _PREFIX + "pi_core_mask_probe.py"

# Git blobs in TREE, expanding B37's package, pinned bootstrap, four dispatch
# modules and their in-function imports through the stopped-worker supervisor.
_DELTA = {
    "pi_core_mask_custody": (8541, "017c567ead5352030f6ef794f63848fc695db6fbcd9662213040ed0fcf3c70dc"),
    "pi_core_mask_probe": (9692, "2ff3122526162c3733453231dfed0b65b372bba23448b0b07d7e2939a4ed3841"),
    "pi_core_native_supervisor": (58463, "6eb49831b5a573712960b3ef65db428d0de91b6564f473bf7b5beaa7532c7dce"),
    "pi_core_node_source_observer": (54901, "7eca9a6c0457089c32b3d2bf80a8809db0c820c4cb64cafc2118d64729be8c02"),
    "pi_core_state_admission": (11162, "32e5ee12c941ef49a025976e73ed055481beeaffdf056884e27836537fface9f"),
    "pi_core_state_exposure": (10395, "b40835df1b68d927a043b1abb24f183145502764b5d90dcff639e6154d737522"),
    "pi_core_state_masks": (11373, "1aefbfc248e8f2575230fd3921f8c124ae9f3d49f83021bd7ab8584011e50690"),
    "pi_core_state_mounts": (6397, "34d385bc5cbc1ea70669aefe54b2443a703dd164b9169ac317307362d8ef3ebc"),
    "pi_core_stopped_mask_capture": (14439, "937c8003895c452e28488d589ea5ae9a9cd2a69d358ad037c333b1009077b545"),
    "pi_core_stopped_mask_view": (19487, "2c5f33783b6771f80af6c7b3351af6f0b81f23346390f50baeeeed959c3576eb"),
    "runtime_tetragon_stats_map": (24209, "a1eb5aa65158c268cf8fbd86b54f63a4c886b3bce5f244f862c22ff08f518d2d"),
}


def expected_rows(root=ROOT):
    """Authenticated names and hashes only; does not read selected host source files."""
    rows = {row["path"]: row for row in b37._release(Path(root).absolute())}
    for name, (size, hex_digest) in _DELTA.items():
        path = _PREFIX + name + ".py"
        rows[path] = dict(path=path, size=size, digest="sha256:" + hex_digest)
    ordered = [rows[path] for path in sorted(rows)]
    if "sha256:" + sha256(canonical(ordered)) != ROWS_DIGEST:
        raise ValueError("mask supervisor host row projection differs")
    return ordered


def helper_bytes(raw):
    """Read the exact separately executable -c argument from the approved module as data."""
    size, pin = _DELTA["pi_core_mask_probe"]
    if type(raw) is not bytes or len(raw) != size or sha256(raw) != pin:
        raise ValueError("unapproved mask helper module")
    values = [node.value for node in ast.parse(raw).body if isinstance(node, ast.Assign)
              and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
              and node.targets[0].id == "_PROGRAM"]
    if len(values) != 1 or not isinstance(values[0], ast.Constant) or type(values[0].value) is not str:
        raise ValueError("mask program is not a single fixed source literal")
    program = values[0].value.encode("ascii")
    if "sha256:" + sha256(program) != PROBE_DIGEST:
        raise ValueError("mask helper source differs")
    return program


def prepare_host_sources(root=ROOT):
    """Verify and return the B37-compatible code rows; no VM/profile/activation authority."""
    root = Path(root).absolute()
    rows = expected_rows(root)
    held = {}
    for row in rows:
        dest = row["path"]
        path = root / ("packaging/pi-core/coordinator.py" if dest == b37.WRAPPER
                       else dest.removeprefix("/opt/aragorn/"))
        held[path] = b37._identity(path)
        raw = regular_bytes(path, 4 << 20)
        if len(raw) != row["size"] or "sha256:" + sha256(raw) != row["digest"]:
            raise ValueError("mask host source differs from release: " + dest)
        if dest == _PROBE:
            helper_bytes(raw)
    if any(b37._identity(path) != before for path, before in held.items()):
        raise ValueError("mask host source changed during preparation")
    return rows
