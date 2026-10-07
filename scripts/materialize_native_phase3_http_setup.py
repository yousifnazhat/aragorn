"""Render the finite HTTP eight-writer setup boundary, never run the fixture.

The frozen setup and its seven-writer interceptor remain unchanged on disk.
The generated successor stops before activation and retains intent/readback
separately. A host controller must still install, invoke, retain and clean up.
"""

from __future__ import annotations

import hashlib

SOURCE = "scripts/runtime_native_common_case_setup.py"
INPUTS = {
    SOURCE: (21422, "d4c7b744da1fe22f76a528223d6c296582a366fbb2ade96f684cf11f1aa409f0"),
}


class NativeHttpSetupRenderError(ValueError):
    """The fixed predecessor or reversible source seam changed."""


def _change(raw, before, after):
    before, after = before.encode(), after.encode()
    if before == after or raw.count(before) != 1 or after in raw:
        raise NativeHttpSetupRenderError("HTTP setup anchor changed")
    changed = raw.replace(before, after)
    if changed.replace(after, before) != raw:
        raise NativeHttpSetupRenderError("HTTP setup replacement not reversible")
    return changed


_OVERRIDES = """def _overrides(stage: dict) -> dict:
    # The caller has already exact-pinned the complete HTTP93 report. Read back
    # every installed runtime file, not merely common74's changed subset.
    rows = stage["files"]
    _require(type(rows) is list and len(rows) == 93, "HTTP93_INVENTORY_REQUIRED")
    result = {}
    for row in rows:
        _require(
            type(row) is dict
            and set(row) == {"path", "source_name", "bytes", "digest", "mode"}
            and type(row["path"]) is str and row["path"].startswith("/")
            and row["path"] not in result
            and row["mode"] in {"0444", "0555", "0644", "0755"}
            and type(row["bytes"]) is int and 0 < row["bytes"] <= _LIMIT,
            "HTTP93_SOURCE_INVENTORY_CHANGED",
        )
        result[row["path"]] = (
            row["bytes"], preparation.old._pin(row["digest"])[7:], int(row["mode"], 8)
        )
    return result


"""


_PARTIAL = """def _http_partial_observation(error):
    value = getattr(error, "http_provisioning_observation", None)
    if value is None:
        return None
    fields = {"schema", "created", "bytes_written", "completed", "binding_digest",
              "cleanup_failed", "activation_performed", "phase3_exit_eligible"}
    if not (type(value) is dict and set(value) == fields
            and value["schema"] == "aragorn/runtime-http-provisioning/v1"
            and (value["created"] is None or type(value["created"]) is bool)
            and (value["bytes_written"] is None or
                 type(value["bytes_written"]) is int and 0 <= value["bytes_written"] <= 4096)
            and all(type(value[key]) is bool for key in (
                "completed", "cleanup_failed", "activation_performed", "phase3_exit_eligible"))
            and value["activation_performed"] is False and value["phase3_exit_eligible"] is False
            and (value["binding_digest"] is None or type(value["binding_digest"]) is str
                 and re.fullmatch(r"sha256:[0-9a-f]{64}", value["binding_digest"]))):
        return {"status": "UNCLASSIFIED_PROVISIONING_OBSERVATION_NOT_EXPORTED"}
    return dict(value)


"""


def render(original):
    """Return one source replacement; inputs are never imported or executed."""
    if type(original) is not dict or not set(INPUTS) <= set(original):
        raise NativeHttpSetupRenderError("HTTP setup source inventory changed")
    raw = original[SOURCE]
    size, digest = INPUTS[SOURCE]
    if (
        type(raw) is not bytes
        or len(raw) != size
        or hashlib.sha256(raw).hexdigest() != digest
    ):
        raise NativeHttpSetupRenderError("HTTP setup predecessor pin changed")
    raw = _change(
        raw, "Prepare one owned common74 fixture", "Prepare one owned HTTP93 fixture"
    )
    raw = _change(
        raw,
        'SCHEMA = "aragorn/native-common-case-setup/v1"',
        'SCHEMA = "aragorn/native-http-case-setup/v1"',
    )
    raw = _change(
        raw,
        'AUTHORITY = "OWNED_SEVEN_WRITER_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY"',
        'AUTHORITY = "OWNED_EIGHT_WRITER_HTTP_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY"',
    )
    raw = _change(
        raw,
        'CAS_ROOT = "/run/aragorn-native-common-setup"',
        'CAS_ROOT = "/run/aragorn-native-http-setup"',
    )
    raw = _change(
        raw,
        "from aragorn.oci_worker_protocol import canonical_json\n",
        "from aragorn.oci_worker_protocol import canonical_json\n"
        "from aragorn import runtime_http_action as http\n"
        "from aragorn.native_phase3_http_canary_contract import validate_fixture, canary_bytes\n"
        "from aragorn.native_phase3_http_fixture import owned_http_fixture\n",
    )
    start = raw.index(b"def _overrides(stage: dict) -> dict:\n")
    end = raw.index(b"def _implementation_readback", start)
    raw = _change(raw, raw[start:end].decode(), _OVERRIDES)
    raw = _change(
        raw,
        "def prepare_common_native_setup(\n",
        _PARTIAL + "def prepare_common_native_setup(\n",
    )
    raw = _change(
        raw,
        "    expected_container_id: str,\n    expected_setup_digest: str,",
        "    expected_container_id: str,\n    expected_setup_digest: str,\n"
        "    expected_http_fixture: dict,\n    http_attempt_id: str,",
    )
    raw = _change(
        raw,
        "Capture the seven fixed provisioning documents during setup, then stop.",
        "Capture eight fixed provisioning documents during HTTP setup, then stop.",
    )
    raw = _change(
        raw,
        '        "writer_readback": None,\n',
        '        "http_writer_intent_digest": None,\n'
        '        "http_provisioning_observation": None,\n        "writer_readback": None,\n',
    )
    raw = _change(
        raw,
        "    native = None\n    cleanup_required = False\n",
        "    native = None\n    http_inputs = {}\n    cleanup_required = False\n",
    )
    raw = _change(
        raw,
        '        phase = "INPUTS"\n',
        '        phase = "INPUTS"\n'
        "        validate_fixture(expected_http_fixture)\n"
        "        canary_bytes(http_attempt_id)\n"
        '        _require(expected_http_fixture["container_id"] == expected_container_id,\n'
        '                 "HTTP_FIXTURE_CONTAINER_CHANGED")\n',
    )
    raw = _change(
        raw,
        '        with patch.object(native, "_STARTUP_CODE", native._STARTUP_CODE | overrides):\n',
        "        with (\n"
        "            owned_http_fixture(expected_http_fixture) as http_held,\n"
        '            patch.object(native, "_STARTUP_CODE", native._STARTUP_CODE | overrides),\n'
        "        ):\n",
    )
    raw = _change(
        raw,
        '                    result["writer_readback"] = _writer_readback(native, inputs)\n',
        "                    _require(set(http_inputs) == {str(http.BINDING_PATH)},\n"
        '                             "HTTP_WRITER_INTENT_MISSING")\n'
        "                    inputs = dict(inputs) | http_inputs\n"
        '                    state["provisioning_file_digests"].update(\n'
        "                        {path: preparation.old._digest(raw) for path, raw in http_inputs.items()}\n"
        "                    )\n"
        "                    http_held.guard()\n"
        '                    result["writer_readback"] = _writer_readback(native, inputs)\n',
    )
    before = """                phase = "SEVEN_WRITER_SETUP"
                try:
                    predecessor._prepare(
                        native, retain_before_activation, state=result["setup_state"]
                    )
"""
    after = """                phase = "EIGHT_WRITER_HTTP_SETUP"
                prepare_native = native._prepare

                def record_http_intent(raw):
                    _require(not http_inputs and type(raw) is bytes,
                             "HTTP_WRITER_INTENT_NOT_ONCE")
                    binding = http.validate_fixture_binding(preparation.old._parse(raw))
                    _require(binding["fixture"] == expected_http_fixture,
                             "HTTP_WRITER_FIXTURE_CHANGED")
                    http_held.guard()
                    http_inputs[str(http.BINDING_PATH)] = raw
                    result["http_writer_intent_digest"] = preparation.old._digest(raw)

                def prepare_http():
                    return prepare_native(
                        expected_http_fixture=expected_http_fixture,
                        http_attempt_id=http_attempt_id,
                        http_binding_writer=record_http_intent,
                    )

                try:
                    with patch.object(native, "_prepare", prepare_http):
                        predecessor._prepare(
                            native, retain_before_activation, state=result["setup_state"]
                        )
"""
    raw = _change(raw, before, after)
    raw = _change(
        raw,
        "                except _PreparedBeforeActivation:\n",
        "                except _PreparedBeforeActivation as completed:\n"
        '                    _require(not getattr(completed, "__notes__", ()),\n'
        '                             "HTTP_WRITER_CONTEXT_CLEANUP_UNCONFIRMED")\n',
    )
    raw = _change(
        raw,
        '    except BaseException as error:\n        result["status"] = "REFUSED"\n',
        '    except BaseException as error:\n        result["status"] = "REFUSED"\n'
        '        result["http_provisioning_observation"] = _http_partial_observation(error)\n',
    )
    raw = _change(
        raw,
        '                        ("INGRESS_ABSENCE_AFTER", _ingress_absent),\n',
        '                        ("HTTP_FIXTURE_AFTER", http_held.guard),\n'
        '                        ("INGRESS_ABSENCE_AFTER", _ingress_absent),\n',
    )
    raw = _change(
        raw,
        "    finally:\n        if cleanup_required:\n",
        "    finally:\n        http_inputs.clear()\n        if cleanup_required:\n",
    )
    raw = _change(
        raw,
        '                result["fixture_stack_cleanup"] = _cleanup(native)\n',
        "                with owned_http_fixture(expected_http_fixture) as cleanup_held:\n"
        "                    cleanup_held.guard()\n"
        '                    result["fixture_stack_cleanup"] = _cleanup(native)\n'
        "                    cleanup_held.guard()\n",
    )
    return {SOURCE: raw}


def compose(original):
    """Compose exactly six helper replacements for the fixed HTTP93 runtime.

    These are installation bytes, not an executable host input bundle. The
    existing common74 host/guest/public-report contract must not consume them.
    An eventual HTTP host controller must bind both signed original sources and
    these rendered outputs before copying or importing any fixture helper.
    """
    from scripts import materialize_native_phase3_http_identity as identity
    from scripts import materialize_native_phase3_http_preparation as preparation
    from scripts import materialize_native_phase3_http_writer as writer

    renderers = (identity, preparation, writer)
    expected = set(INPUTS)
    for component in renderers:
        if expected.intersection(component.INPUTS):
            raise NativeHttpSetupRenderError("HTTP helper source ownership overlaps")
        expected.update(component.INPUTS)
    if type(original) is not dict or set(original) != expected:
        raise NativeHttpSetupRenderError("HTTP helper composition inventory changed")
    result = render(original)
    for component in renderers:
        outputs = component.render(original)
        if set(outputs) != set(component.INPUTS) or set(result).intersection(outputs):
            raise NativeHttpSetupRenderError("HTTP helper output inventory changed")
        result.update(outputs)
    return result
