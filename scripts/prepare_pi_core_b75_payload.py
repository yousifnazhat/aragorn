"""Publish B74 trusted sources in the retained B69 guest layout. No guest or media build."""
from scripts import prepare_pi_core_b69_payload as managed
from scripts import prepare_pi_core_b75_sources as sources


OUT = managed.OUT.parent / "Aragorn-B75-Offline"
# The source reviewer and independent payload reviewer compute separate pins;
# neither a local outcome nor a computed assembly digest can authorize publication.
SPEC = managed._Successor(
    predecessor="b69",
    base=managed.OUT,
    out=OUT,
    base_outcome="fa8ed1160ef21e6a0233a85e534b991f47c731c914d40d49306efdf309419430",
    base_payload="efc1b36a0a033992805cb60cbca14e3bfe5d4f21fb5e58c9d3ee80c0b1bb3a24",
    revision="80818a521459fb23112f71184cb42fa809f644c9",
    tree="5a661a00511f4dbd29b85be5de4a8759e2f9cb48",
    review=managed.ROOT / "packaging/pi-core/managed-payload-b75.json",
    review_sha256="df614590ca54e0186a1b1989fb5e13d2e422976990c3f479af721b418ddfbbf9",
    counts=(1779, 812, 802, 41, 15),  # entries, host files, service files, changed files, added files
)


def prepare():
    return managed._prepare_successor(SPEC, sources.prepare)
