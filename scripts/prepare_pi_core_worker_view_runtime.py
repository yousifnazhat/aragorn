"""Stage the B82 gate alongside B36 as an offline candidate, never as a launch receipt."""
import json
from pathlib import Path
import sys

from aragorn import pi_core_restricted_profile as fixed
from scripts import build_pi_core_source_gate as gate
from scripts import prepare_pi_core_restricted_runtime as retained
from scripts import prepare_pi_core_restricted_worker_inventory as inventory


ROOT = retained.ROOT
OUTPUT = retained.BASE / "worker-view-runtime-b83"
PREVIOUS_CHECKPOINT = inventory.RUNTIME
GATE_CHECKPOINT = Path("packaging/pi-core/worker-view-gate-artifact-v3.json")
GATE_CHECKPOINT_SHA = "515b475124cf89500debd15b70b73c6d550936126049e28bd749704241506169"
PREVIOUS_RECEIPT = "sha256:11a2ba77f5161fe554ce57ef001429b4efa50ffab1617e1226e848d67fdbdf6c"
GATE_RECEIPT = "sha256:6e5f9c8d95c639b0e57ac564e4996999ccd149f0d093333e523c9205e73befef"
MEMBER = "observer/source-gate"
SCHEMA = "aragorn/pi-core-worker-view-runtime-candidate/v1"


def _b36(root):
    cp = inventory._document(root / PREVIOUS_CHECKPOINT, inventory.RUNTIME_PIN)
    retained.require(cp["output"] == str(retained.ASSEMBLY) and cp["canonical_receipt_digest"] == PREVIOUS_RECEIPT,
                     "wrong B36 staging input")
    base = root / retained.ASSEMBLY
    docs = {name: inventory._document(base / name, pin) for name, pin in cp["files"].items()}
    manifest = docs["manifest.json"]
    digest = fixed.validate_runtime(docs["build-receipt.json"], manifest, PREVIOUS_RECEIPT)
    outcome = docs["outcome.json"]
    retained.require(digest == cp["runtime_digest"] == outcome["runtime_tree_digest"] == fixed.RUNTIME_DIGEST and
                     outcome["runtime_receipt_sha256"] == cp["files"]["build-receipt.json"] and
                     all(outcome[key] is False for key in ("installed", "target_executed", "phase3_exit_eligible")),
                     "B36 predecessor receipt or evidence boundary differs")
    return inventory._staged_bytes(base / "deployment", ["node", "node/bin", "observer", "pi-core"], manifest["files"])


def _b82(root):
    cp = inventory._document(root / GATE_CHECKPOINT, GATE_CHECKPOINT_SHA)
    retained.require(cp["output"] == str(retained.BASE / "gate-batch-82") and
                     cp["files"]["build-receipt.json"] == GATE_RECEIPT[7:] and
                     cp["runtime_executed"] is False and cp["phase3_exit_eligible"] is False,
                     "wrong B82 gate staging input")
    base = root / cp["output"]
    binary, receipt = (retained.plain(base / name) for name in ("source-gate", "build-receipt.json"))
    retained.require(binary.lstat().st_nlink == receipt.lstat().st_nlink == 1, "multiply linked B82 gate input")
    elf, build = gate.view_gate_input(root, binary, receipt, GATE_RECEIPT)
    retained.require(retained.sha(elf) == build["elf_sha256"] == cp["files"]["source-gate"] and
                     build["source_sha256"] == cp["source_sha256"] and build["toolchain_digest"] == cp["toolchain_digest"]
                     and build["build_command_sha256"] == cp["recipe_sha256"], "B82 bytes or provenance differs")
    return elf, build


def prepare_inputs(root=ROOT):
    """Verify each predecessor in its original contract; never feed B82 to B36's conditional JS finding."""
    root = retained.plain(Path(root))
    elf, build = _b82(root)
    sources = _b36(root)
    previous = fixed.expected_files()
    expected = [dict(row, size=len(elf), digest="sha256:" + build["elf_sha256"]) if row["path"] == MEMBER
                else dict(row) for row in previous]
    retained.require([old["path"] for old, new in zip(previous, expected) if old != new] == [MEMBER]
                     and sources.keys() == {row["path"] for row in previous}, "expected one different gate in four members")
    sources[MEMBER] = elf
    return sources, expected


def assemble(*, root=ROOT):
    root = retained.plain(Path(root))
    work = retained.fresh(root, OUTPUT)
    phase = "input-custody"
    try:
        sources, expected = prepare_inputs(root)
        phase = "four-member-staging"
        manifest = retained.materialize(work / "deployment", sources, expected)
        manifest_sha = retained.record(work / "manifest.json", manifest)
        tree = fixed.digest([dict(path=r["path"], kind="file", bytes=r["size"], sha256=r["digest"][7:])
                             for r in manifest["files"]])
        receipt = dict(schema=SCHEMA, status="STAGED_CANDIDATE_ONLY", replaced_member=MEMBER,
            predecessor_checkpoint_sha256=inventory.RUNTIME_PIN, predecessor_receipt_digest=PREVIOUS_RECEIPT,
            predecessor_runtime_digest=fixed.RUNTIME_DIGEST, gate_checkpoint_sha256=GATE_CHECKPOINT_SHA,
            gate_receipt_digest=GATE_RECEIPT, gate_elf_sha256=next(r["digest"][7:] for r in expected if r["path"] == MEMBER),
            manifest_sha256=manifest_sha, candidate_tree_digest=tree, installed=False, target_executed=False,
            launch_authorized=False, phase3_exit_eligible=False)
        phase = "candidate-receipt"
        retained.record(work / "candidate-receipt.json", receipt)
        return receipt
    except Exception:
        # Preserve the exclusive transaction and any partial bytes; never retry or delete them.
        try:
            retained.record(work / "failure.json", dict(phase=phase, status="INCOMPLETE", launch_authorized=False))
        except OSError:
            pass
        raise


if __name__ == "__main__":
    if sys.argv[1:]:
        raise SystemExit("This preparation takes no path or operation selectors.")
    print(json.dumps(assemble(), sort_keys=True))
