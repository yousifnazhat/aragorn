"""Render HTTP93 preparation and input closure without editing common74 sources.

Only exact reviewed source bytes are transformed. The caller separately composes
the matching HTTP identity reader and measurement planner/verifier successors.
No import of generated code, staging, provisioning or activation occurs here.
"""

from __future__ import annotations

import hashlib

PREPARATION = "src/aragorn/native_phase3_common_preparation.py"
MEASUREMENT_INPUTS = "src/aragorn/runtime_native_measurement_inputs.py"
INPUTS = {
    PREPARATION: (
        30893,
        "428d298ec64f0aab08f08256621f88848260c4736a13d6e0feb1053f114f0b03",
    ),
    MEASUREMENT_INPUTS: (
        7909,
        "bc7d2f356ad40d56cb343375032bc08757130ad9516fae2fc02018b12ccf10da",
    ),
}
STAGED_PROFILE_PIN = (
    65735,
    "sha256:95c8aecc2eb5df094f8d88260971f5b7497d8aed411dc126206dbee08d68e6b5",
)
HTTP_CONFIG_PIN = (
    "sha256:7c9ff65e1e258ae548cd523c8874f8d087313b5ab683aa780d482801fbc6c408"
)
HTTP_FIXTURE = "/etc/aragorn/runtime-http-fixture.json"


class NativeHttpPreparationRenderError(ValueError):
    """The reviewed predecessor or finite preparation boundary changed."""


def _change(raw, before, after, changes):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != 1 or after in raw:
        raise NativeHttpPreparationRenderError("HTTP preparation anchor changed")
    rendered = raw.replace(before, after)
    if rendered.replace(after, before) != raw:
        raise NativeHttpPreparationRenderError(
            "HTTP preparation change is not reversible"
        )
    changes.append((before, after))
    return rendered


def _function(raw, name, before, after, changes):
    marker = ("def " + name + "(").encode("ascii")
    if raw.count(marker) != 1:
        raise NativeHttpPreparationRenderError("HTTP preparation function changed")
    start = raw.index(marker)
    end = raw.find(b"\n\ndef ", start + len(marker))
    end = len(raw) if end == -1 else end
    source = raw[start:end].decode("ascii")
    if source.count(before) != 1:
        raise NativeHttpPreparationRenderError(
            "HTTP preparation function anchor changed"
        )
    return _change(raw, source, source.replace(before, after), changes)


_FIXTURE_HELPER = '''def _http_fixture_writer(inputs):
    """Parse supplied credential bytes only; do not claim root custody or liveness."""
    binding = _http.fixture_binding(old._parse(inputs[HTTP_FIXTURE], 4096))
    _require(binding["expected_broker_gid"] == 997 and binding["expected_broker_uid"] != 997,
             "HTTP fixture differs from fixed runtime group")
    return binding


'''


def _preparation(raw, changes):
    raw = _change(
        raw,
        'STAGED_SCHEMA = "aragorn/runtime-phase3-ingress-staged-profile/v1"\n',
        'STAGED_SCHEMA = "aragorn/runtime-phase3-http-staged-profile/v1"\n',
        changes,
    )
    raw = _change(
        raw,
        '# Derived from the reviewed ingress74 successor report; inert bytes only.\nSTAGED_PROFILE_PIN = (\n    51756,\n    "sha256:0fcd6cb67ac2721122c72ebe6bb6973a1a15f57444a8e8107d618add74677d4e",\n)\n',
        "# Derived from the reviewed HTTP93 successor report; inert bytes only.\n"
        f"STAGED_PROFILE_PIN = {STAGED_PROFILE_PIN!r}\n"
        f"HTTP_CONFIG_PIN = {HTTP_CONFIG_PIN!r}\nHTTP_FIXTURE = {HTTP_FIXTURE!r}\n"
        "PROVISIONING_PATHS = (*old.PROVISIONING_PATHS, HTTP_FIXTURE)\n",
        changes,
    )
    for before, after in (
        (
            'STATIC_SCHEMA = "aragorn/native-common-static-pins/v2"',
            'STATIC_SCHEMA = "aragorn/native-common-static-pins/v3"',
        ),
        (
            'PREPARATION_SCHEMA = "aragorn/native-common-deployment-preparation/v2"',
            'PREPARATION_SCHEMA = "aragorn/native-common-deployment-preparation/v3"',
        ),
        (
            'REQUEST_SCHEMA = "aragorn/native-common-measured-case-request/v2"',
            'REQUEST_SCHEMA = "aragorn/native-common-measured-case-request/v3"',
        ),
        ("STATIC_PATHS = (\n", "STATIC_PATHS = tuple(dict.fromkeys((\n"),
        (
            "    common_identity.ACTIVATOR,\n)\nIMPLEMENTATION_SOURCE_PATHS",
            "    common_identity.ACTIVATOR,\n)))\nIMPLEMENTATION_SOURCE_PATHS",
        ),
        (
            '    "NO_COLLECTION_CREATION_CALLBACK_EXECUTION_OR_ACCEPTANCE_AUTHORITY",\n',
            '    "NO_COLLECTION_CREATION_CALLBACK_EXECUTION_OR_ACCEPTANCE_AUTHORITY",\n'
            '    "HTTP_FIXTURE_BYTES_REQUIRE_SEPARATE_ROOT_CUSTODY_AND_NETWORK_ISOLATION",\n',
        ),
    ):
        raw = _change(raw, before, after, changes)
    raw = _function(
        raw,
        "_stage",
        '        == (74, 96, 30, 16)\n        and value["directories"] == baseline["staged_profile"]["directories"]\n',
        "        == (93, 119, 49, 21)\n"
        '        and value["directories"] == sorted({path.removeprefix("/") for path in baseline["staged_profile"]["directories"]} | {\n'
        '            "opt", "opt/aragorn", "src", "src/benchmark",\n'
        '            "src/benchmark/runtime-action-worker-openclaw-systemd"})\n'
        '        and value["http_paths_staged"] is True\n'
        "        and all(value[key] is False for key in (\n"
        '            "http_fixture_provisioned", "http_runtime_activated", "http_collected"))\n'
        '        and value["measurement_source_names"] == sorted(common_identity.MEASUREMENT_SOURCES)\n'
        '        and len(value["binding_source_pins"]) == 21\n'
        '        and value["gateway_config_digest_required_not_included"] == HTTP_CONFIG_PIN\n',
        changes,
    )
    raw = _function(
        raw,
        "_static",
        "        len(files) == 74\n",
        "        len(files) == 93\n"
        '        and set(stage["binding_source_pins"]) == set(common_identity.MEASUREMENT_SOURCES)\n'
        '        and all(stage["binding_source_pins"][name] == files[path]["digest"]\n'
        "                for name, path in common_identity.MEASUREMENT_SOURCES.items())\n",
        changes,
    )
    for name in ("_provisioning", "_prepare_deployment"):
        raw = _function(
            raw,
            name,
            "set(inputs) == set(old.PROVISIONING_PATHS)",
            "set(inputs) == set(PROVISIONING_PATHS)",
            changes,
        )
    raw = _function(
        raw,
        "_provisioning",
        "hashes[live._CONFIG] == old._CONFIG_PIN",
        "hashes[live._CONFIG] == HTTP_CONFIG_PIN",
        changes,
    )
    raw = _function(
        raw,
        "_provisioning",
        'policy["id"] == "owned-native-receipt-read-create"',
        'policy["id"] == "owned-native-receipt-http-canary"',
        changes,
    )
    raw = _function(
        raw,
        "_provisioning",
        "    return hashes\n",
        "    http_binding = _http_fixture_writer(inputs)\n"
        '    action = policy["allow"][0]\n'
        "    _require(any(all(action[key] == pin for key, pin in _http.action_digests(\n"
        '                 f"p3-lab-a{index:03d}", http_binding).items())\n'
        "                 for index in range(1, 26)),\n"
        '             "HTTP policy action differs from fixed fixture or canary")\n'
        "    return hashes\n",
        changes,
    )
    raw = _change(
        raw,
        "def prepare_native_common_deployment(\n",
        _FIXTURE_HELPER + "def prepare_native_common_deployment(\n",
        changes,
    )
    raw = _function(
        raw,
        "_prepare_deployment",
        "    worker = old._parse(inputs[old.live._WORKER], old._MAX_INPUT)\n",
        "    http_binding = _http_fixture_writer(inputs)\n"
        '    _require(http_binding["fixture"]["container_id"] == container,\n'
        '             "HTTP fixture differs from owned preparation container")\n'
        "    worker = old._parse(inputs[old.live._WORKER], old._MAX_INPUT)\n",
        changes,
    )
    raw = _function(
        raw,
        "_prepare_request",
        '    binding = measured["binding"]\n',
        '    binding = measured["binding"]\n'
        "    http_binding = _http_fixture_writer(inputs)\n"
        '    _require(http_binding["fixture"]["boot_id"] == boot\n'
        '             and http_binding["fixture"]["container_id"] == value["container_id"]\n'
        '             and measured["path_descriptor"] == _http.endpoint_descriptor(http_binding)\n'
        "             and all(binding[key] == pin for key, pin in _http.action_digests(\n"
        '                 binding["attempt_id"], http_binding).items()),\n'
        '             "HTTP measurement differs from supplied fixture binding")\n',
        changes,
    )
    raw = _function(
        raw,
        "_prepare_request",
        "        and len(hashes) == 8\n        and len(expected_files) == 28,\n",
        "        and len(hashes) == 9\n        and len(expected_files) == 41,\n",
        changes,
    )
    return raw


def _measurement_inputs(raw, changes):
    raw = _change(
        raw,
        "read(store, binding_pin, 4096) == binding_raw",
        "read(store, binding_pin, 8192) == binding_raw",
        changes,
    )
    start = "    _require(\n        all(\n            grant[key] == binding[key]\n"
    end = '        "invalid native protected descriptor",\n    )\n'
    if raw.count(start.encode()) != 1 or raw.count(end.encode()) != 1:
        raise NativeHttpPreparationRenderError("HTTP input descriptor boundary changed")
    original = raw[
        raw.index(start.encode()) : raw.index(end.encode()) + len(end)
    ].decode("ascii")
    # The legacy create branch is preserved byte-for-byte under else. HTTP uses
    # the existing independent endpoint contract and the exact scheduled attempt.
    new = """    if binding["operation_digest"] == canonical_digest(_http.operation_descriptor()):
        _require(all(grant[key] == binding[key] for key in (
            "runtime_profile_digest", "sensor_digest", "runtime_digest", "policy_digest",
            "active_skill_digest", "operation_digest")), "HTTP grant differs from binding")
        _require(scheduled["family"] == "EXFILTRATION" and scheduled["negative_control"] is False,
                 "HTTP measurement family changed")
        descriptor = retained._parse(read(store, binding["path_digest"], 4096), 4096)
        _http.validate_plan_descriptor(descriptor, grant,
            {"path": binding["path_digest"], "payload": binding["payload_digest"]},
            binding["attempt_id"], binding["boot_id"])
    else:
""" + "".join(
        "    " + line if line.strip() else line
        for line in original.splitlines(keepends=True)
    )
    return _change(raw, original, new, changes)


def render(original: dict[str, bytes]) -> dict[str, bytes]:
    """Return two exact source replacements, requiring the matching identity stack."""
    if type(original) is not dict or not set(INPUTS) <= set(original):
        raise NativeHttpPreparationRenderError(
            "HTTP preparation source inventory changed"
        )
    outputs = {}
    for name, pin in INPUTS.items():
        raw = original[name]
        if type(raw) is not bytes or (len(raw), hashlib.sha256(raw).hexdigest()) != pin:
            raise NativeHttpPreparationRenderError(
                "HTTP preparation source pin changed"
            )
        changes = []
        raw = _change(
            raw,
            "from __future__ import annotations\n",
            "from __future__ import annotations\n\nfrom . import native_phase3_http_collection_verify as _http\n",
            changes,
        )
        raw = (_preparation if name == PREPARATION else _measurement_inputs)(
            raw, changes
        )
        restored = raw
        for before, after in reversed(changes):
            if restored.count(after) != 1:
                raise NativeHttpPreparationRenderError(
                    "HTTP preparation reverse anchor changed"
                )
            restored = restored.replace(after, before)
        if restored != original[name]:
            raise NativeHttpPreparationRenderError(
                "HTTP preparation changed unrelated bytes"
            )
        outputs[name] = raw
    return outputs
