"""Select the connected B108 pilot caller and reader from signed source, without activation."""

from scripts import prepare_pi_core_b69_sources as signed


REVISION = "9db4643f6c40ae18bffc15163d42d80ea57b8458"
TREE = "6ca25b6156210ffec56b896843ab867ff1a663e6"
REVIEW = signed.ROOT / "packaging/pi-core/managed-sources-b109.json"
REVIEW_PIN = "sha256:fc4ba190e1bebf76d1b2fa5c171c5a5763e24c6db9c4a3d90ba500fcdf988ad6"


def prepare(host_raw, manifest_raw, binding_raw):
    """Authenticate B104 inputs and return complete signed host and rendered service sources."""
    return signed._prepare(host_raw, manifest_raw, binding_raw, review_path=REVIEW,
                           review_pin=REVIEW_PIN, revision=REVISION, tree=TREE)
