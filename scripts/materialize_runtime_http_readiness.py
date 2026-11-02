"""Finite readiness startup seam over the exact frozen HTTP93 runtime outputs.

The caller supplies destination-keyed installed bytes, not original repository
service bytes. No generated source is imported, installed or executed here.
Full successor profile/measurement/activator identities must be rebuilt together.
"""

import hashlib

SERVICE = "usr/lib/aragorn/aragorn/runtime_action_service_v5.py"
UNIT = "usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service"
INPUTS = {
    SERVICE: (4545, "5850f378989b0327316b8c1cd9605b5aa2aec24cab7eab1ab8ad5493483c60fd"),
    UNIT: (3146, "c668184b6d838b6a9db9f27ac05da349a7dfc39153ff6fb397f42d8f9ca29c2a"),
}
RUNTIME_SOURCE = "src/aragorn/runtime_http_readiness.py"
RUNTIME_DESTINATION = "usr/lib/aragorn/aragorn/runtime_http_readiness.py"
CREDENTIAL = "/etc/aragorn/runtime-http-readiness.json"


class HttpReadinessRenderError(ValueError):
    """Pinned HTTP93 predecessor or unique finite anchor changed."""


def _replace(raw, before, after):
    before, after = before.encode(), after.encode()
    if before == after or raw.count(before) != 1 or after in raw:
        raise HttpReadinessRenderError("HTTP readiness anchor changed")
    value = raw.replace(before, after)
    if value.replace(after, before) != raw:
        raise HttpReadinessRenderError("HTTP readiness replacement not reversible")
    return value


def render(original):
    if type(original) is not dict or not set(INPUTS) <= set(original):
        raise HttpReadinessRenderError("HTTP readiness source inventory changed")
    for name, (size, digest) in INPUTS.items():
        raw = original[name]
        if (
            type(raw) is not bytes
            or len(raw) != size
            or hashlib.sha256(raw).hexdigest() != digest
        ):
            raise HttpReadinessRenderError("HTTP readiness predecessor pin changed")
    service = _replace(
        original[SERVICE],
        "    serve_runtime_action_broker_v5(config)\n",
        "    # Same MainPID, cgroup, namespaces, credentials and service restrictions.\n"
        "    # Startup must fail closed if the root-provisioned one-shot probe fails.\n"
        "    from .runtime_http_readiness import run_startup_readiness\n"
        "    run_startup_readiness()\n"
        "    serve_runtime_action_broker_v5(config)\n",
    )
    unit = _replace(
        original[UNIT],
        "ReadOnlyPaths=/etc/aragorn/runtime-http-fixture.json\n",
        "ReadOnlyPaths=/etc/aragorn/runtime-http-fixture.json\n"
        "ReadOnlyPaths=/etc/aragorn/runtime-http-readiness.json\n",
    )
    return {SERVICE: service, UNIT: unit}
