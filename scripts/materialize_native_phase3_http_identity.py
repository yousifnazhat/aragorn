"""Render the finite HTTP93 installed-identity and retained-process bridge.

Only caller-supplied, exact frozen source bytes are transformed. This module
does not import readers, stage files, inspect processes, or activate services.
The independent process observer has the same four commands and is unchanged.
"""

from __future__ import annotations

import hashlib

IDENTITY = "src/aragorn/native_phase3_common_identity.py"
VERIFIER = "src/aragorn/native_phase3_common_process_verifier.py"
HTTP_FIXTURE_BINDING = "/etc/aragorn/runtime-http-fixture.json"
INPUTS = {
    IDENTITY: (
        20981,
        "46aed5e163e490d7f3261930d956c3c8f3ad7dd1775816a4cdf3efc7f5b780a8",
    ),
    VERIFIER: (
        21812,
        "8be4794672c91772592ddf586ca641f1d1f8d5f67aa51e19b29466379519c302",
    ),
}
HTTP_MEASUREMENT_SOURCES = (
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


class NativeHttpIdentityRenderError(ValueError):
    """A frozen predecessor or reviewed finite anchor changed."""


def _change(raw, before, after, changes, count=1):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != count:
        raise NativeHttpIdentityRenderError("HTTP identity anchor changed")
    result = raw.replace(before, after)
    if result.count(after) != count or result.replace(after, before) != raw:
        raise NativeHttpIdentityRenderError("HTTP identity change is not reversible")
    changes.append((before, after))
    return result


def _function(raw, name, before, after, changes):
    anchor = ("def " + name + "(").encode("ascii")
    if raw.count(anchor) != 1:
        raise NativeHttpIdentityRenderError("HTTP identity function changed")
    start = raw.index(anchor)
    end = raw.find(b"\n\ndef ", start + len(anchor))
    end = len(raw) if end < 0 else end
    section = raw[start:end].decode("ascii")
    if section.count(before) != 1:
        raise NativeHttpIdentityRenderError("HTTP identity function anchor changed")
    return _change(raw, section, section.replace(before, after), changes)


_HTTP_READER_JOINS = """
    # This is protected byte/configuration binding, not HTTP effect evidence.
    from . import runtime_http_action as http

    fixture_binding = http.validate_fixture_binding(
        prior._document(raw[HTTP_FIXTURE_BINDING])
    )
    fixture = fixture_binding["fixture"]
    expected = http.action_digests(binding["attempt_id"], fixture_binding)
    configuration = prior._document(raw[prior._CONFIG])
    _require(
        raw[HTTP_FIXTURE_BINDING] == canonical_json(fixture_binding)
        and fixture["container_id"] == container
        and fixture["boot_id"] == boot
        and (fixture_binding["expected_broker_uid"], fixture_binding["expected_broker_gid"])
        == accounts["broker"]
        and fixture_binding["expected_broker_gid"] == accounts["worker"][1]
        and all(binding[key] == value for key, value in expected.items())
        and configuration["tools"]["alsoAllow"]
        == ["aragorn_runtime_create", "aragorn_runtime_http_canary", "read"],
        "HTTP fixture, action, accounts or gateway tool binding changed",
    )
"""

_HTTP_VERIFIER_JOINS = """
    fixture_binding = joins["http_fixture_binding"]
    _exact(
        fixture_binding,
        {"schema", "fixture", "expected_broker_uid", "expected_broker_gid"},
        "HTTP fixture binding fields changed",
    )
    fixture = fixture_binding["fixture"]
    _exact(
        fixture, {"container_id", "boot_id", "netns_device", "netns_inode"},
        "HTTP fixture identity fields changed",
    )
    _require(
        fixture_binding["schema"] == "aragorn/runtime-http-fixture-binding/v1"
        and all(frozen._integer(fixture_binding[key], 1)
                for key in ("expected_broker_uid", "expected_broker_gid"))
        and fixture_binding["expected_broker_uid"] < 2**31
        and fixture_binding["expected_broker_gid"] < 2**31
        and (fixture_binding["expected_broker_uid"], fixture_binding["expected_broker_gid"])
        == accounts["broker"]
        and fixture_binding["expected_broker_gid"] == accounts["worker"][1]
        and fixture["container_id"] == identity["container_id"]
        and fixture["boot_id"] == identity["boot_id"]
        and frozen._integer(fixture["netns_device"], 0)
        and frozen._integer(fixture["netns_inode"], 1)
        and frozen._digest(canonical_json(fixture_binding)) == pins[HTTP_FIXTURE_BINDING]
        and len(canonical_json(fixture_binding)) == files[HTTP_FIXTURE_BINDING]["bytes"],
        "HTTP protected fixture binding join changed",
    )
    attempt = joins["http_attempt_id"]
    _require(
        type(attempt) is str
        and re.fullmatch(r"p3-lab-a(?:00[1-9]|01[0-9]|02[0-5])", attempt) is not None,
        "HTTP attempt identity changed",
    )
    endpoint = {
        "schema": "aragorn/runtime-http-endpoint/v1",
        "fixture_binding_digest": pins[HTTP_FIXTURE_BINDING],
        "fixture": fixture,
        "host": "127.0.0.1", "port": 47631, "method": "POST",
        "path": "/aragorn-phase3-canary",
    }
    body = ("p3canary-" + attempt).encode("ascii")
    wire = (
        "POST /aragorn-phase3-canary HTTP/1.1\\r\\nHost: 127.0.0.1:47631\\r\\n"
        "Connection: close\\r\\nContent-Type: application/octet-stream\\r\\n"
        f"Content-Length: {len(body)}\\r\\n\\r\\n"
    ).encode("ascii") + body
    http_declared = joins["declared_input_digests_not_cas_readback"]
    _require(
        http_declared["path_digest"] == frozen._digest(canonical_json(endpoint))
        and http_declared["payload_digest"] == frozen._digest(wire),
        "HTTP retained action digest join changed",
    )
"""


def _render(name, original):
    if (
        type(original) is not bytes
        or (len(original), hashlib.sha256(original).hexdigest()) != INPUTS[name]
    ):
        raise NativeHttpIdentityRenderError("HTTP identity predecessor pin changed")
    changes = []
    raw = _change(
        original,
        '"aragorn/native-phase3-common-live-identity/v2"',
        '"aragorn/native-phase3-http-live-identity/v1"',
        changes,
    )
    raw = _change(
        raw,
        '        "phase3_quantitative_metrics.py",\n',
        '        "phase3_quantitative_metrics.py",\n'
        + "".join(f'        "{source}",\n' for source in HTTP_MEASUREMENT_SOURCES),
        changes,
    )
    raw = _change(
        raw,
        'ACTIVATOR = "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh"',
        f'HTTP_FIXTURE_BINDING = "{HTTP_FIXTURE_BINDING}"\n'
        'HTTP_FIXTURE_ROLES = ("worker", "sensor", "broker")\n'
        'ACTIVATOR = "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh"',
        changes,
    )
    predecessor = "prior" if name == IDENTITY else "frozen"
    before = f"""FILE_PATHS = (
    *{predecessor}.FILE_PATHS,
    MEASUREMENT_BINDING,
    *MEASUREMENT_SOURCES.values(),
    ACTIVATOR,
    *WORKER_INGRESS_SOURCES.values(),
)"""
    raw = _change(
        raw,
        before,
        before.replace("FILE_PATHS = (", "FILE_PATHS = tuple(dict.fromkeys((")[:-1]
        + "    HTTP_FIXTURE_BINDING,\n)))",
        changes,
    )
    raw = _change(
        raw,
        "SELECTED_MODULE_UNIT_AND_ACTIVATOR_BYTES_NOT_WHOLE_74_FILE_PROFILE_OR_RUNTIME_TREE",
        "SELECTED_HTTP_MODULE_UNIT_AND_ACTIVATOR_BYTES_NOT_WHOLE_93_FILE_PROFILE_OR_RUNTIME_TREE",
        changes,
    )
    raw = _change(
        raw,
        "complete_installed_74_file_profile",
        "complete_installed_93_file_profile",
        changes,
    )
    raw = _change(
        raw,
        '    "LOADED_CREDENTIAL_BYTES_NOT_APPLICATION_ACK_OR_POLICY_SEMANTICS",',
        '    "LOADED_CREDENTIAL_BYTES_NOT_APPLICATION_ACK_OR_POLICY_SEMANTICS",\n'
        '    "HTTP_FIXTURE_PROCESS_ROOT_BYTES_NOT_APPLICATION_LOAD_OR_NETWORK_NAMESPACE_OBSERVATION",',
        changes,
    )
    if name == IDENTITY:
        raw = _function(
            raw,
            "_joins",
            "raw: dict[str, bytes], boot: str",
            "raw: dict[str, bytes], boot: str, container: str, accounts: dict",
            changes,
        )
        raw = _function(
            raw,
            "_joins",
            "    return {\n        **native,",
            _HTTP_READER_JOINS
            + '    return {\n        **native,\n        "http_fixture_binding": fixture_binding,\n        "http_attempt_id": binding["attempt_id"],',
            changes,
        )
        raw = _function(
            raw,
            "_file_arguments",
            "    runtime = path == prior._ENTRY",
            """    if path == HTTP_FIXTURE_BINDING:
        return {"owner": 0, "owner_gid": accounts["broker"][1],
                "modes": {0o440}, "limit": 4096, "require_read_only": False}
    runtime = path == prior._ENTRY""",
            changes,
        )
        raw = _function(raw, "_file_arguments", "else 4096", "else 8192", changes)
        raw = _function(
            raw,
            "read_native_common_identity",
            "Measure the fixed28 files",
            "Measure the fixed41 HTTP files",
            changes,
        )
        raw = _function(
            raw,
            "_read",
            "        loaded, module_views, worker_module_views, view_reads = {}, {}, {}, []",
            "        loaded, module_views, worker_module_views, view_reads = {}, {}, {}, []\n        http_fixture_views = {}",
            changes,
        )
        raw = _function(raw, "_read", '"limit": 4096', '"limit": 8192', changes)
        raw = _function(
            raw,
            "_read",
            "            for name, source in CREDENTIALS[role].items():",
            """            if role in HTTP_FIXTURE_ROLES:
                http_fixture_views[role] = view(
                    HTTP_FIXTURE_BINDING, HTTP_FIXTURE_BINDING,
                    _file_arguments(HTTP_FIXTURE_BINDING, accounts),
                )
            for name, source in CREDENTIALS[role].items():""",
            changes,
        )
        raw = _function(
            raw,
            "_read",
            "        joins = _joins(raw, boot)",
            "        joins = _joins(raw, boot, container, accounts)",
            changes,
        )
        raw = _function(
            raw,
            "_read",
            '            "worker_module_views": worker_module_views,',
            '            "worker_module_views": worker_module_views,\n            "http_fixture_views": http_fixture_views,',
            changes,
        )
        raw = _function(
            raw,
            "compare_native_common_identity",
            '        "worker_module_views",',
            '        "worker_module_views",\n        "http_fixture_views",',
            changes,
        )
        raw = _function(
            raw,
            "compare_native_common_identity",
            '        and type(before.get("processes")) is dict',
            """        and type(before.get("http_fixture_views")) is dict
        and set(before["http_fixture_views"]) == set(HTTP_FIXTURE_ROLES)
        and type(before.get("processes")) is dict""",
            changes,
        )
    else:
        raw = _change(
            raw,
            'SCHEMA = "aragorn/native-phase3-common-process-verification/v2"',
            'SCHEMA = "aragorn/native-phase3-http-process-verification/v1"',
            changes,
        )
        raw = _function(
            raw,
            "_envelopes",
            '        "worker_module_views",',
            '        "worker_module_views",\n        "http_fixture_views",',
            changes,
        )
        raw = _function(
            raw,
            "_files",
            '"common28 file inventory changed"',
            '"HTTP41 file inventory changed"',
            changes,
        )
        raw = _function(
            raw,
            "_files",
            """        owner = (
            accounts["broker"]""",
            """        owner = (
            (0, accounts["broker"][1])
            if path == HTTP_FIXTURE_BINDING
            else accounts["broker"]""",
            changes,
        )
        raw = _function(
            raw,
            "_files",
            """        modes = (
            {0o400}""",
            """        modes = (
            {0o440}
            if path == HTTP_FIXTURE_BINDING
            else {0o400}""",
            changes,
        )
        raw = _function(
            raw,
            "_files",
            """                4096
                if path == MEASUREMENT_BINDING""",
            """                8192
                if path == MEASUREMENT_BINDING
                else 4096
                if path == HTTP_FIXTURE_BINDING""",
            changes,
        )
        raw = _function(
            raw,
            "_files",
            '    joins = identity["measured_joins"]',
            """    http_views = identity["http_fixture_views"]
    _exact(http_views, set(HTTP_FIXTURE_ROLES), "HTTP fixture process-view inventory changed")
    for view in http_views.values():
        frozen._metadata(view, owners={(0, accounts["broker"][1])}, modes={0o440})
        _require(
            view["bytes"] == files[HTTP_FIXTURE_BINDING]["bytes"]
            and view["digest"] == pins[HTTP_FIXTURE_BINDING],
            "HTTP process-root credential differs from protected source",
        )
    joins = identity["measured_joins"]""",
            changes,
        )
        raw = _function(
            raw,
            "_files",
            '            "configuration_digest",',
            '            "http_fixture_binding",\n            "http_attempt_id",\n            "configuration_digest",',
            changes,
        )
        raw = _function(
            raw,
            "_files",
            '    for name, path in {\n        "configuration_digest":',
            _HTTP_VERIFIER_JOINS
            + '    for name, path in {\n        "configuration_digest":',
            changes,
        )
    restored = raw
    for before, after in reversed(changes):
        restored = restored.replace(after, before)
    if restored != original:
        raise NativeHttpIdentityRenderError("HTTP identity round trip changed")
    return raw


def render(original: dict[str, bytes]) -> dict[str, bytes]:
    """Return two rendered source payloads; caller owns installation and custody."""
    if type(original) is not dict or not set(INPUTS) <= set(original):
        raise NativeHttpIdentityRenderError("HTTP identity source inventory missing")
    return {name: _render(name, original[name]) for name in INPUTS}
