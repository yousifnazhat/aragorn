"""B62 trusted project rows for offline image assembly; never import the projected code."""
import ast
from pathlib import Path

from scripts import prepare_pi_core_mask_host_sources as b60
from scripts.build_pi_core_linux import canonical, regular_bytes, sha256


ROOT, WRAPPER = b60.ROOT, b60.b37.WRAPPER
PREFIX = "/opt/aragorn/src/"
REVISION = "95b8c5f08725beb2bef11667eee87e8c3edaed87"
TREE = "e884e26f937f96b60188634fb69525172128958f"
ROWS_DIGEST = "sha256:e299c0e9c5cb58a872d7547ee8b39220e8838b5b5a16eaad2606f6d4211007a3"
# All four Git blobs are 100644 in TREE. Installed modes come from the image, not the checkout.
_DELTA = {
    WRAPPER: (57506, "baf2854f66c81d8dcd08aa72e287763f278e6392cd963f99b415627835771ea8"),
    b60._PREFIX + "pi_core_mask_capture_entry.py": (12997, "b296dd5e124f607f99eb610830b012632c11458c4b6f904cc437e26731897884"),
    b60._PREFIX + "pi_core_mask_capture_release.py": (9654, "0101ed05eede32e42b7c9ffd9e50dc191a72942f7bfdfb8393784ad319fb6f7f"),
    b60._PREFIX + "pi_core_native_supervisor.py": (58684, "54fd207172ffd5c3a399491055009037c1d543976308a3c61b00369d7aced835"),
}
CHANGED = tuple(sorted(_DELTA))
_LOADER = "aragorn.pi_core_service_source"


def expected_rows(root=ROOT):
    rows = {r["path"]: r for r in b60.expected_rows(root)}
    rows.update({p: dict(path=p, size=s, digest="sha256:" + h) for p, (s, h) in _DELTA.items()})
    ordered = [rows[p] for p in sorted(rows)]
    if "sha256:" + sha256(canonical(ordered)) != ROWS_DIGEST:
        raise ValueError("B62 trusted project projection differs")
    return ordered


def _project_imports(payloads):
    # This fixed wrapper loads its pinned source loader as bytes before dispatch.
    # The only other embedded program is B60's separately pinned stdlib-only helper.
    names = {("wrapper" if path == WRAPPER else path.removeprefix(PREFIX).removesuffix(".py")
              .replace("/", ".").removesuffix(".__init__")): path for path in payloads}
    pending, seen = ["wrapper", "aragorn", _LOADER], set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        if name not in names:
            raise ValueError("missing pinned project import: " + name)
        path = names[name]
        seen.add(name)
        package = name if path.endswith("/__init__.py") else name.rpartition(".")[0]
        for node in ast.walk(ast.parse(payloads[path], filename=path, feature_version=(3, 12))):
            if isinstance(node, ast.Import):
                refs = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level not in (0, 1) or (node.level and not package):
                    raise ValueError("unexpected relative project import: " + path)
                base = ((package + ".") if node.level else "") + (node.module or "")
                base = base.rstrip(".")
                refs = [base]
                refs += [base + "." + a.name for a in node.names if base == "aragorn" or
                         base + "." + a.name in names]
            else:
                continue
            pending.extend(ref for ref in refs if ref == "aragorn" or ref.startswith("aragorn."))
    if len(names) != len(payloads) or seen != set(names):
        raise ValueError("unreachable or ambiguous pinned project source")


def prepare_host_sources(root=ROOT):
    """Return both the reviewed rows and the very bytes read, including the wrapper."""
    root = Path(root).absolute()
    rows = expected_rows(root)
    held, payloads = {}, {}
    for r in rows:
        dest = r["path"]
        path = root / ("packaging/pi-core/coordinator.py" if dest == WRAPPER else dest.removeprefix("/opt/aragorn/"))
        held[path] = b60.b37._identity(path)
        data = regular_bytes(path, 4 << 20)
        if len(data) != r["size"] or "sha256:" + sha256(data) != r["digest"]:
            raise ValueError("B62 trusted source bytes differ: " + dest)
        payloads[dest] = data
    if any(b60.b37._identity(p) != ident for p, ident in held.items()):
        raise ValueError("B62 trusted sources changed during preparation")
    b60.helper_bytes(payloads[b60._PROBE])
    _project_imports(payloads)
    return rows, payloads
