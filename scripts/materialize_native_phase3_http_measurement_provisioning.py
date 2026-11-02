"""Render a finite HTTP endpoint bridge for frozen native measurement custody.

The renderer returns bytes only. Root provisioning remains absent-only and keeps
partial output on failure; it never activates services or contacts the endpoint.
"""

from __future__ import annotations

import hashlib

SOURCE = "src/aragorn/runtime_native_measurement_provisioning.py"
INPUTS = {
    SOURCE: (
        22666,
        "77dcfa7f8f62704c44bfec769e98737bf3ef585f0c4dcc76829bc22bf18bfa6d",
    ),
}
HTTP_SOURCES = (
    "native_phase3_http_canary_contract.py",
    "runtime_http_action.py",
    "runtime_http_broker.py",
    "runtime_http_ingress.py",
    "runtime_http_capability.py",
    "runtime_action_worker.py",
    "runtime_action_observation_publisher.py",
    "runtime_action_observation_publisher_v2.py",
    "runtime_capability_grant.py",
    "runtime_action_broker_v2.py",
    "runtime_action_broker_v3.py",
    "runtime_native_tool_receipts.py",
    "runtime_worker_ingress_measurement.py",
    "runtime_action_service.py",
)


class NativeHttpMeasurementProvisioningRenderError(ValueError):
    """The frozen provisioner or finite reviewed seam changed."""


def _change(raw, before, after, changes, count=1):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != count or after in raw:
        raise NativeHttpMeasurementProvisioningRenderError(
            "HTTP provisioning anchor changed"
        )
    result = raw.replace(before, after)
    if result.count(after) != count or result.replace(after, before) != raw:
        raise NativeHttpMeasurementProvisioningRenderError(
            "HTTP provisioning reversal changed"
        )
    changes.append((before, after))
    return result


_HTTP_HELPERS = """class _HttpEndpoint:
    def __init__(self, binding, credential, identities, session):
        self.binding = binding
        self.credential = credential
        self.identities = identities
        self.session = session


def _is_http(bound):
    return bound["binding"]["operation_digest"] == canonical_digest(http.operation_descriptor())


def _http_endpoint(bound, identities, policy, held, session):
    _require(session is not None and http.BINDING_PATH.parent == _CREDENTIAL.parent)
    parent = custody._root_directory(http.BINDING_PATH.parent, held)
    credential = custody._hold_file(parent, http.BINDING_PATH.name,
        _ROOT_UID, identities[2], 0o440, 4096, held)
    fixture_binding = http.validate_fixture_binding(
        broker._parse_canonical_document(credential.raw, "HTTP fixture binding"))
    binding = bound["binding"]
    digests = http.action_digests(binding["attempt_id"], fixture_binding)
    _require(credential.raw == canonical_json(fixture_binding)
        and fixture_binding["fixture"]["boot_id"] == binding["boot_id"]
        and http.endpoint_descriptor(fixture_binding) == bound["path_descriptor"]
        and all(binding[key] == value for key, value in digests.items())
        and policy["id"] == "owned-native-receipt-http-canary"
        and policy["default"] == "BLOCK"
        and policy["allow"] == [{"runtime_digest": binding["runtime_digest"],
            "active_skill_digest": binding["active_skill_digest"], **digests}])
    endpoint = _HttpEndpoint(fixture_binding, credential, identities, session)
    _recheck_protected_inputs(bound, endpoint)
    return endpoint


def _recheck_protected_inputs(bound, protected):
    if isinstance(protected, _HttpEndpoint):
        _require(_is_http(bound))
        protected.session.guard()
        _require(response._identities() == protected.identities
            and http_provisioning._accounts() == (protected.identities[0], protected.identities[2])
            and protected.identities[0] != protected.identities[1]
            and (protected.binding["expected_broker_uid"], protected.binding["expected_broker_gid"])
            == (protected.identities[0], protected.identities[2])
            and _boot_id() == bound["binding"]["boot_id"])
        entry = protected.credential
        os.lseek(entry.fd, 0, os.SEEK_SET)
        _require(os.read(entry.fd, len(entry.raw) + 1) == entry.raw)
        custody._recheck([entry])
    else:
        _require(not _is_http(bound))
        custody._absent(protected.fd, bound["path_descriptor"]["target_name"])


"""


def render(original: dict[str, bytes]) -> dict[str, bytes]:
    """Return one replacement, paired with the HTTP native-input validator."""
    if type(original) is not dict or not set(INPUTS) <= set(original):
        raise NativeHttpMeasurementProvisioningRenderError(
            "HTTP provisioning inventory changed"
        )
    raw = original[SOURCE]
    if (
        type(raw) is not bytes
        or (len(raw), hashlib.sha256(raw).hexdigest()) != INPUTS[SOURCE]
    ):
        raise NativeHttpMeasurementProvisioningRenderError(
            "HTTP provisioning source pin changed"
        )
    changes = []
    raw = _change(
        raw,
        "from . import runtime_action_broker as broker\n",
        "from . import runtime_http_action as http\n"
        "from . import runtime_http_provisioning as http_provisioning\n"
        "from .native_phase3_http_fixture import owned_http_fixture\n"
        "from . import runtime_action_broker as broker\n",
        changes,
    )
    raw = _change(
        raw,
        '        "phase3_quantitative_metrics.py",\n',
        '        "phase3_quantitative_metrics.py",\n'
        + "".join(f'        "{name}",\n' for name in HTTP_SOURCES),
        changes,
    )
    raw = _change(
        raw,
        "def _protected_inputs(\n",
        _HTTP_HELPERS + "def _protected_inputs(\n",
        changes,
    )
    raw = _change(
        raw,
        "    bound: dict, identities: tuple, control_fd: int, held: list\n) -> custody._Held:",
        "    bound: dict, identities: tuple, control_fd: int, held: list, *, http_session=None\n) -> custody._Held | _HttpEndpoint:",
        changes,
    )
    raw = _change(
        raw,
        "    runtime_fd = custody._root_directory(_RUNTIME_ROOT, held)\n    protected = _held_directory(\n",
        "    if _is_http(bound):\n        return _http_endpoint(bound, identities, policy, held, http_session)\n"
        "    runtime_fd = custody._root_directory(_RUNTIME_ROOT, held)\n    protected = _held_directory(\n",
        changes,
    )
    raw = _change(
        raw,
        '        input_blobs = dict(bound["input_blobs"])\n',
        '        _require(type(bound["binding_raw"]) is bytes and 0 < len(bound["binding_raw"]) <= 8192)\n'
        '        input_blobs = dict(bound["input_blobs"])\n',
        changes,
    )
    raw = _change(
        raw,
        "        with ExitStack() as stack:\n            stack.enter_context(response._activation_guard())\n",
        "        with ExitStack() as stack:\n"
        '            http_session = (stack.enter_context(owned_http_fixture(bound["path_descriptor"]["fixture"]))\n'
        "                            if _is_http(bound) else None)\n"
        "            stack.enter_context(response._activation_guard())\n",
        changes,
    )
    raw = _change(
        raw,
        "            protected = _protected_inputs(bound, identities, control, held)\n",
        "            protected = _protected_inputs(bound, identities, control, held, http_session=http_session)\n",
        changes,
    )
    raw = _change(
        raw,
        '            custody._absent(protected.fd, bound["path_descriptor"]["target_name"])\n',
        "            _recheck_protected_inputs(bound, protected)\n",
        changes,
        count=2,
    )
    raw = _change(
        raw,
        "            start = len(held)\n",
        "            _recheck_protected_inputs(bound, protected)\n            start = len(held)\n",
        changes,
    )
    raw = _change(
        raw,
        '                "schema": "aragorn/native-measurement-provisioning/v1",\n',
        '                "schema": "aragorn/native-http-measurement-provisioning/v1",\n'
        '                "http_endpoint_bound": isinstance(protected, _HttpEndpoint),\n'
        '                "http_fixture_binding_digest": (canonical_digest(protected.binding)\n'
        "                    if isinstance(protected, _HttpEndpoint) else None),\n",
        changes,
    )
    raw = _change(
        raw,
        '                    "NO_SERVICE_START_STOP_STATE_RESET_OR_EFFECT_RETRY",\n',
        '                    "NO_SERVICE_START_STOP_STATE_RESET_OR_EFFECT_RETRY",\n'
        '                    "HTTP_ENDPOINT_CUSTODY_NOT_REACHABILITY_OR_SENT_EFFECT_EVIDENCE",\n',
        changes,
    )
    restored = raw
    for before, after in reversed(changes):
        restored = restored.replace(after, before)
    if restored != original[SOURCE]:
        raise NativeHttpMeasurementProvisioningRenderError(
            "HTTP provisioning changed unrelated bytes"
        )
    return {SOURCE: raw}
