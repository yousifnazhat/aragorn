"""Project B65 service sources from signed inputs; no guest imports or target execution."""
import ast
import json

from scripts import prepare_pi_core_service_image as image
from scripts import prepare_pi_core_mask_host_sources as observer
from scripts.build_pi_core_linux import ROOT, regular_bytes


REVIEW = ROOT / "packaging/pi-core/service-source-successor-b65.json"
REVIEW_PIN = "sha256:cbb15ccbefbd36bed4f96632429a99d2d69922d9080794d3757e4165e7ee5f94"
PRIOR_INPUTS = ROOT / "packaging/pi-core/service-assembly-inputs-v3.json"


def _document(path, pin):
    image.require(path.resolve(strict=True) == path, "linked service source catalog")
    raw = regular_bytes(path, 1 << 20)
    image.require(image.pin(raw) == pin, "service source catalog differs")
    return json.loads(raw)


def _inventory(before, review):
    changes = review["source_changes"]
    image.require(all(before.get(p) != v for p, v in changes.items()), "redundant service source change")
    updated = before | changes
    image.require(image.pin(image.canonical(updated)) == review["source_inventory_digest"],
                  "service source inventory differs")
    return updated


def prepare(prior_manifest_raw):
    """Return relative service-root paths and their verified bytes, not installed identities."""
    r = _document(REVIEW, REVIEW_PIN)
    image.require(type(prior_manifest_raw) is bytes and image.pin(prior_manifest_raw) == r["prior_manifest_digest"],
                  "foreign retained service manifest")
    before = _document(PRIOR_INPUTS, r["prior_assembly_inputs_digest"])
    inventory = _inventory(before["expected_source_inventory"], r)
    stdlib = image.stdlib_modules(row["path"] for row in json.loads(prior_manifest_raw)["files"])
    sources, imports, unsupported = image.source_closure(ROOT / before["source_root"], inventory, stdlib)
    image.require(image.pin(image.canonical(unsupported)) == r["unsupported_import_sites_digest"],
                  "unsupported service imports have changed")
    # The fixed helper is a Python string, not an AST import in the enclosing service source.
    program = observer.helper_bytes(sources["aragorn/pi_core_mask_probe.py"])
    helper_imports = {alias.name for n in ast.walk(ast.parse(program)) if isinstance(n, ast.Import)
                      for alias in n.names}
    image.require(helper_imports <= stdlib, "fixed mask helper lacks target stdlib inputs")
    wrappers = image._wrappers(ROOT / before["wrapper_root"], before["expected_wrapper_inventory"], inventory)
    image.require({n: image.pin(b) for n, b in wrappers.items()} == r["rendered_wrapper_digests"],
                  "rendered service wrappers differ")
    files = {image.IMPORT_ROOT + "/" + n: b for n, b in sources.items()}
    files.update({"opt/aragorn/bin/" + n: b for n, b in wrappers.items()})
    metadata = {k: r[k] for k in ("source_revision", "source_tree", "source_inventory_digest", "rendered_wrapper_digests")}
    metadata.update(source_count=len(sources), imported_stdlib=imports, unsupported_import_sites=unsupported)
    return files, metadata
