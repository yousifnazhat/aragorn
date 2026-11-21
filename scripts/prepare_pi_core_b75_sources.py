"""Project B74 signed sources against the retained B69 inventory; no guest execution."""
from scripts import prepare_pi_core_b69_sources as prior


REVISION = "80818a521459fb23112f71184cb42fa809f644c9"
TREE = "5a661a00511f4dbd29b85be5de4a8759e2f9cb48"
REVIEW = prior.ROOT / "packaging/pi-core/managed-sources-b75.json"
REVIEW_PIN = "sha256:76b430113937b8a76863c56465679aac7a175f81c409bcb90a5337de651fbc26"


def prepare(host_raw, manifest_raw, binding_raw):
    """Return hosted file bytes, not a claim that a live interpreter loaded them."""
    return prior._prepare(host_raw, manifest_raw, binding_raw, review_path=REVIEW, review_pin=REVIEW_PIN,
                          revision=REVISION, tree=TREE)
