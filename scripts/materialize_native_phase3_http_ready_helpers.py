"""Compose fixed readiness94 helper successors from the frozen HTTP93 outputs.

Only source bytes are returned. The matching ready94 runtime profile, original
signed sources and generated outputs must be bound by the outer controller.
"""

from __future__ import annotations

import hashlib

from scripts import materialize_native_phase3_http_identity as identity
from scripts import materialize_native_phase3_http_preparation as preparation
from scripts import materialize_native_phase3_http_setup as setup
from scripts import materialize_native_phase3_http_writer as writer
from scripts import (
    materialize_native_phase3_http_measurement_provisioning as measurement,
)

INPUTS = {
    **identity.INPUTS,
    **preparation.INPUTS,
    **setup.INPUTS,
    **writer.INPUTS,
    **measurement.INPUTS,
}
READINESS = "/etc/aragorn/runtime-http-readiness.json"
READINESS_SOURCE = "runtime_http_readiness.py"
STAGED_SCHEMA = "aragorn/runtime-phase3-http-ready-staged-profile/v1"
# Set only from the matching successor's reviewed inert report, never a caller override.
STAGED_PROFILE_PIN = (
    67222,
    "sha256:419aa0d6dffd093dbb20c1533bb79eca70ee8700c2e1741662c303f905360c0a",
)
STAGED_COUNTS = (94, 122, 50, 21)
PREDECESSOR_OUTPUTS = {
    setup.SOURCE: (
        25236,
        "c3c053aaafd1670baeb49e50a5afb5d0d35bc4e8755c3a7224606344ae5284f4",
    ),
    identity.IDENTITY: (
        23702,
        "4f715bddc183347945e0f99a8e58e17c13ef97070af322416fc34805d759bb7d",
    ),
    identity.VERIFIER: (
        25950,
        "5c92dfd4a2691a03e1c2623de3697f1b97bea7372b5dc14e636431cc5b9c93cc",
    ),
    preparation.PREPARATION: (
        33455,
        "dc8435479af95d01d68ec4fa0b66fdf72023e56ba8583e722102dd51fd6f2c29",
    ),
    preparation.MEASUREMENT_INPUTS: (
        8871,
        "8ae5e71a61c9c0869033082bfcdeadb9f3aafffdaf63bad30e14274048ac8ce3",
    ),
    writer.SOURCE: (
        55641,
        "33c44abc4b8d19176e2906822a7274ba0c24769b3ce89a4b35e595f2b2defbe8",
    ),
    measurement.SOURCE: (
        26709,
        "0a570a14231a39fb6d4b8f76b4017e7464f6f9867939842431109dfcfefbf8f5",
    ),
}


class NativeHttpReadyHelpersError(ValueError):
    """A fixed predecessor, generated source or finite seam changed."""


def _change(raw, before, after, changes, count=1):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != count or after in raw:
        raise NativeHttpReadyHelpersError("ready helper anchor changed")
    result = raw.replace(before, after)
    if result.count(after) != count or result.replace(after, before) != raw:
        raise NativeHttpReadyHelpersError("ready helper replacement not reversible")
    changes.append((before, after))
    return result


def _function(raw, name, before, after, changes):
    marker = ("def " + name + "(").encode("ascii")
    if raw.count(marker) != 1:
        raise NativeHttpReadyHelpersError("ready helper function changed")
    start = raw.index(marker)
    end = raw.find(b"\n\ndef ", start + len(marker))
    section = raw[start : len(raw) if end < 0 else end].decode("ascii")
    if section.count(before) != 1:
        raise NativeHttpReadyHelpersError("ready helper function anchor changed")
    return _change(raw, section, section.replace(before, after), changes)


_READINESS_WRITER = """def _readiness_writer(inputs):
    value = old._parse(inputs[HTTP_READINESS], 4096)
    _require(set(value) == {"schema", "readiness_nonce", "fixture_binding_digest", "timeout_ms"}
        and value["schema"] == "aragorn/runtime-http-readiness-input/v1"
        and type(value["readiness_nonce"]) is str
        and re.fullmatch(r"[0-9a-f]{32}", value["readiness_nonce"]) is not None
        and type(value["timeout_ms"]) is int and value["timeout_ms"] == 500
        and value["fixture_binding_digest"] == old._digest(inputs[HTTP_FIXTURE]),
        "readiness input differs from the HTTP fixture or fixed probe")
    return value


"""


def _preparation(raw, changes):
    raw = _change(
        raw,
        'STAGED_SCHEMA = "aragorn/runtime-phase3-http-staged-profile/v1"',
        f'STAGED_SCHEMA = "{STAGED_SCHEMA}"',
        changes,
    )
    raw = _change(
        raw,
        f"STAGED_PROFILE_PIN = {preparation.STAGED_PROFILE_PIN!r}",
        f"STAGED_PROFILE_PIN = {STAGED_PROFILE_PIN!r}",
        changes,
    )
    raw = _change(
        raw,
        "PROVISIONING_PATHS = (*old.PROVISIONING_PATHS, HTTP_FIXTURE)",
        f"HTTP_READINESS = {READINESS!r}\nPROVISIONING_PATHS = (*old.PROVISIONING_PATHS, HTTP_FIXTURE, HTTP_READINESS)",
        changes,
    )
    for old, new in (
        ("native-common-static-pins/v3", "native-common-static-pins/v4"),
        (
            "native-common-deployment-preparation/v3",
            "native-common-deployment-preparation/v4",
        ),
        (
            "native-common-measured-case-request/v3",
            "native-common-measured-case-request/v4",
        ),
    ):
        raw = _change(raw, old, new, changes)
    raw = _change(raw, "== (93, 119, 49, 21)", f"== {STAGED_COUNTS!r}", changes)
    raw = _change(
        raw,
        'and len(value["binding_source_pins"]) == 21',
        'and len(value["binding_source_pins"]) == 22\n        and value["http_readiness_paths_staged"] is True\n        and value["broker_readiness_observed"] is False',
        changes,
    )
    raw = _change(
        raw, "        len(files) == 93\n", "        len(files) == 94\n", changes
    )
    raw = _change(
        raw,
        "def _http_fixture_writer(inputs):\n",
        _READINESS_WRITER + "def _http_fixture_writer(inputs):\n",
        changes,
    )
    raw = _function(
        raw,
        "_provisioning",
        "    return hashes\n",
        "    _readiness_writer(inputs)\n    return hashes\n",
        changes,
    )
    raw = _function(
        raw,
        "prepare_native_common_deployment",
        "    nonce: str,\n",
        "    nonce: str,\n    readiness_nonce: str,\n",
        changes,
    )
    raw = _function(
        raw,
        "prepare_native_common_deployment",
        "            provisioning_inputs,\n",
        "            provisioning_inputs,\n            readiness_nonce,\n",
        changes,
    )
    raw = _function(
        raw,
        "_prepare_deployment",
        "    inputs,\n",
        "    inputs,\n    readiness_nonce,\n",
        changes,
    )
    raw = _function(
        raw,
        "_prepare_deployment",
        "    http_binding = _http_fixture_writer(inputs)\n",
        '    _require(type(readiness_nonce) is str and re.fullmatch(r"[0-9a-f]{32}", readiness_nonce)\n        and _readiness_writer(inputs)["readiness_nonce"] == readiness_nonce,\n        "readiness writer differs from requested nonce")\n    http_binding = _http_fixture_writer(inputs)\n',
        changes,
    )
    raw = _function(
        raw,
        "_prepare_deployment",
        '        "case_id": case_id,',
        '        "readiness_nonce": _readiness_writer(inputs)["readiness_nonce"],\n        "case_id": case_id,',
        changes,
    )
    raw = _function(
        raw,
        "_inspect",
        '        nonce=value["nonce"],',
        '        nonce=value["nonce"],\n        readiness_nonce=value["readiness_nonce"],',
        changes,
    )
    raw = _function(
        raw,
        "_prepare_request",
        "    http_binding = _http_fixture_writer(inputs)\n",
        '    http_binding = _http_fixture_writer(inputs)\n    _require(_readiness_writer(inputs)["readiness_nonce"] == value["readiness_nonce"],\n             "readiness nonce differs from prepared writer input")\n',
        changes,
    )
    raw = _change(
        raw,
        "        and len(hashes) == 9\n        and len(expected_files) == 41,",
        "        and len(hashes) == 10\n        and len(expected_files) == 43,",
        changes,
    )
    raw = _function(
        raw,
        "_prepare_request",
        '        "preparation_digest": expected,',
        '        "preparation_digest": expected,\n        "readiness_nonce": value["readiness_nonce"],',
        changes,
    )
    return raw


_IDENTITY_READINESS = """
    readiness = prior._document(raw[HTTP_READINESS_BINDING])
    _require(set(readiness) == {"schema", "readiness_nonce", "fixture_binding_digest", "timeout_ms"}
        and readiness["schema"] == "aragorn/runtime-http-readiness-input/v1"
        and type(readiness["readiness_nonce"]) is str
        and re.fullmatch(r"[0-9a-f]{32}", readiness["readiness_nonce"]) is not None
        and type(readiness["timeout_ms"]) is int and readiness["timeout_ms"] == 500
        and readiness["fixture_binding_digest"] == prior._digest(raw[HTTP_FIXTURE_BINDING])
        and raw[HTTP_READINESS_BINDING] == canonical_json(readiness),
        "readiness input differs from protected HTTP fixture")
"""

_VERIFIER_READINESS = """
    readiness = joins["http_readiness_input"]
    _exact(readiness, {"schema", "readiness_nonce", "fixture_binding_digest", "timeout_ms"},
        "readiness input fields changed")
    _require(readiness["schema"] == "aragorn/runtime-http-readiness-input/v1"
        and type(readiness["readiness_nonce"]) is str
        and re.fullmatch(r"[0-9a-f]{32}", readiness["readiness_nonce"]) is not None
        and type(readiness["timeout_ms"]) is int and readiness["timeout_ms"] == 500
        and readiness["fixture_binding_digest"] == pins[HTTP_FIXTURE_BINDING]
        and frozen._digest(canonical_json(readiness)) == pins[HTTP_READINESS_BINDING]
        and len(canonical_json(readiness)) == files[HTTP_READINESS_BINDING]["bytes"],
        "readiness protected input join changed")
"""


def _identity(raw, changes, *, verifier):
    raw = _change(
        raw,
        '        "runtime_http_action.py",\n',
        '        "runtime_http_action.py",\n        "runtime_http_readiness.py",\n',
        changes,
    )
    raw = _change(
        raw,
        'HTTP_FIXTURE_ROLES = ("worker", "sensor", "broker")',
        f'HTTP_READINESS_BINDING = {READINESS!r}\nHTTP_FIXTURE_ROLES = ("worker", "sensor", "broker")',
        changes,
    )
    raw = _change(
        raw,
        "    HTTP_FIXTURE_BINDING,\n)))",
        "    HTTP_FIXTURE_BINDING,\n    HTTP_READINESS_BINDING,\n)))",
        changes,
    )
    raw = _change(
        raw,
        "aragorn/native-phase3-http-live-identity/v1",
        "aragorn/native-phase3-http-live-identity/v2",
        changes,
    )
    raw = _change(raw, "WHOLE_93_FILE_PROFILE", "WHOLE_94_FILE_PROFILE", changes)
    raw = _change(
        raw,
        "complete_installed_93_file_profile",
        "complete_installed_94_file_profile",
        changes,
    )
    if not verifier:
        raw = _function(
            raw,
            "_file_arguments",
            "if path == HTTP_FIXTURE_BINDING:",
            "if path in (HTTP_FIXTURE_BINDING, HTTP_READINESS_BINDING):",
            changes,
        )
        raw = _function(
            raw,
            "_joins",
            "    return {\n        **native,",
            _IDENTITY_READINESS
            + '    return {\n        **native,\n        "http_readiness_input": readiness,',
            changes,
        )
        raw = _change(
            raw,
            "Measure the fixed41 HTTP files",
            "Measure the fixed43 HTTP readiness files",
            changes,
        )
        raw = _function(
            raw,
            "_read",
            "        http_fixture_views = {}",
            "        http_fixture_views = {}\n        http_readiness_views = {}",
            changes,
        )
        raw = _function(
            raw,
            "_read",
            '            if role == "broker":\n                module_views = {',
            '            if role == "broker":\n                http_readiness_views[role] = view(HTTP_READINESS_BINDING, HTTP_READINESS_BINDING,\n                    _file_arguments(HTTP_READINESS_BINDING, accounts))\n                module_views = {',
            changes,
        )
        raw = _function(
            raw,
            "_read",
            '            "http_fixture_views": http_fixture_views,',
            '            "http_fixture_views": http_fixture_views,\n            "http_readiness_views": http_readiness_views,',
            changes,
        )
        raw = _function(
            raw,
            "compare_native_common_identity",
            '        "http_fixture_views",',
            '        "http_fixture_views",\n        "http_readiness_views",',
            changes,
        )
        raw = _function(
            raw,
            "compare_native_common_identity",
            '        and type(before.get("http_fixture_views")) is dict',
            '        and type(before.get("http_readiness_views")) is dict\n        and set(before["http_readiness_views"]) == {"broker"}\n        and type(before.get("http_fixture_views")) is dict',
            changes,
        )
    else:
        raw = _change(
            raw,
            "aragorn/native-phase3-http-process-verification/v1",
            "aragorn/native-phase3-http-process-verification/v2",
            changes,
        )
        raw = _function(
            raw,
            "_envelopes",
            '        "http_fixture_views",',
            '        "http_fixture_views",\n        "http_readiness_views",',
            changes,
        )
        raw = _function(
            raw,
            "_files",
            "HTTP41 file inventory changed",
            "HTTP43 file inventory changed",
            changes,
        )
        # Three ownership/mode/size expressions use this same exact condition.
        raw = _change(
            raw,
            "if path == HTTP_FIXTURE_BINDING\n",
            "if path in (HTTP_FIXTURE_BINDING, HTTP_READINESS_BINDING)\n",
            changes,
            count=3,
        )
        raw = _function(
            raw,
            "_files",
            '    http_views = identity["http_fixture_views"]',
            """    ready_views = identity["http_readiness_views"]
    _exact(ready_views, {"broker"}, "readiness process-view inventory changed")
    view = frozen._metadata(ready_views["broker"], owners={(0, accounts["broker"][1])}, modes={0o440})
    _require(view["bytes"] == files[HTTP_READINESS_BINDING]["bytes"]
        and view["digest"] == pins[HTTP_READINESS_BINDING], "readiness process-root bytes changed")
    http_views = identity["http_fixture_views"]""",
            changes,
        )
        raw = _function(
            raw,
            "_files",
            '            "http_fixture_binding",',
            '            "http_readiness_input",\n            "http_fixture_binding",',
            changes,
        )
        raw = _function(
            raw,
            "_files",
            '    fixture_binding = joins["http_fixture_binding"]',
            _VERIFIER_READINESS + '    fixture_binding = joins["http_fixture_binding"]',
            changes,
        )
    return raw


_PARTIAL = """def _readiness_partial_observation(error):
    value = getattr(error, "readiness_provisioning_observation", None)
    if value is None:
        value = getattr(error, "http_readiness_publication", None)
    if value is None:
        report = getattr(error, "http_readiness_provisioning", None)
        if type(report) is dict:
            value = report.get("publication")
    if value is None:
        return None
    if not (type(value) is dict and set(value) == {"path", "created", "bytes_written", "completed", "cleanup_failed"}
        and value["path"] == str(readiness.CREDENTIAL)
        and (value["created"] is None or type(value["created"]) is bool)
        and (value["bytes_written"] is None or type(value["bytes_written"]) is int and 0 <= value["bytes_written"] <= 4096)
        and type(value["completed"]) is bool and type(value["cleanup_failed"]) is bool):
        return {"status": "UNCLASSIFIED_READINESS_PROVISIONING_NOT_EXPORTED"}
    return dict(value)


"""


def _setup(raw, changes):
    raw = _change(raw, "HTTP93", "HTTP94", changes, count=4)
    raw = _change(raw, "len(rows) == 93", "len(rows) == 94", changes)
    raw = _change(
        raw,
        'SCHEMA = "aragorn/native-http-case-setup/v1"',
        'SCHEMA = "aragorn/native-http-case-setup/v2"',
        changes,
    )
    raw = _change(
        raw,
        "OWNED_EIGHT_WRITER_HTTP_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY",
        "OWNED_NINE_WRITER_HTTP_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY",
        changes,
    )
    raw = _change(
        raw,
        "from aragorn import runtime_http_action as http\n",
        "from aragorn import runtime_http_action as http\nfrom aragorn import runtime_http_readiness as readiness\n",
        changes,
    )
    raw = _change(
        raw,
        "    expected_http_fixture: dict,\n    http_attempt_id: str,",
        "    expected_http_fixture: dict,\n    http_attempt_id: str,\n    readiness_nonce: str,",
        changes,
    )
    raw = _change(
        raw,
        "Capture eight fixed provisioning documents during HTTP setup",
        "Capture nine fixed provisioning documents during HTTP readiness setup",
        changes,
    )
    raw = _change(
        raw,
        "def prepare_common_native_setup(\n",
        _PARTIAL + "def prepare_common_native_setup(\n",
        changes,
    )
    raw = _change(
        raw,
        '        "http_writer_intent_digest": None,',
        '        "readiness_nonce": readiness_nonce,\n        "readiness_writer_intent_digest": None,\n        "readiness_provisioning_observation": None,\n        "http_writer_intent_digest": None,',
        changes,
    )
    raw = _change(
        raw,
        '            "nonce": nonce,\n',
        '            "nonce": nonce,\n            "readiness_nonce": readiness_nonce,\n',
        changes,
    )
    raw = _change(
        raw,
        "        canary_bytes(http_attempt_id)\n",
        '        canary_bytes(http_attempt_id)\n        _require(type(readiness_nonce) is str and re.fullmatch(r"[0-9a-f]{32}", readiness_nonce),\n                 "READINESS_NONCE_REFUSED")\n',
        changes,
    )
    raw = _change(
        raw,
        "set(http_inputs) == {str(http.BINDING_PATH)}",
        "set(http_inputs) == {str(http.BINDING_PATH), str(readiness.CREDENTIAL)}",
        changes,
    )
    raw = _change(
        raw,
        'phase = "EIGHT_WRITER_HTTP_SETUP"',
        'phase = "NINE_WRITER_HTTP_SETUP"',
        changes,
    )
    raw = _change(
        raw,
        "                def prepare_http():\n",
        """                def record_readiness_intent(raw):
                    _require(set(http_inputs) == {str(http.BINDING_PATH)} and type(raw) is bytes,
                             "READINESS_WRITER_INTENT_NOT_ONCE")
                    binding = http.validate_fixture_binding(preparation.old._parse(http_inputs[str(http.BINDING_PATH)]))
                    expected = readiness.build_readiness_input(fixture_binding=binding, readiness_nonce=readiness_nonce)
                    _require(canonical_json(expected) == raw, "READINESS_WRITER_INTENT_CHANGED")
                    http_held.guard()
                    http_inputs[str(readiness.CREDENTIAL)] = raw
                    result["readiness_writer_intent_digest"] = preparation.old._digest(raw)

                def prepare_http():
""",
        changes,
    )
    raw = _change(
        raw,
        "                        http_binding_writer=record_http_intent,\n",
        "                        http_binding_writer=record_http_intent,\n                        readiness_nonce=readiness_nonce,\n                        readiness_binding_writer=record_readiness_intent,\n",
        changes,
    )
    raw = _change(
        raw,
        '        result["http_provisioning_observation"] = _http_partial_observation(error)\n',
        '        result["http_provisioning_observation"] = _http_partial_observation(error)\n        result["readiness_provisioning_observation"] = _readiness_partial_observation(error)\n',
        changes,
    )
    return raw


def _writer(raw, changes):
    raw = _change(
        raw,
        "def _prepare(*, expected_http_fixture, http_attempt_id, http_binding_writer):",
        "def _prepare(*, expected_http_fixture, http_attempt_id, http_binding_writer, readiness_nonce, readiness_binding_writer):",
        changes,
    )
    raw = _change(
        raw,
        "    from aragorn import runtime_http_provisioning as _http_provision\n",
        "    from aragorn import runtime_http_provisioning as _http_provision\n    from aragorn import runtime_http_readiness as _http_ready\n",
        changes,
    )
    raw = _change(
        raw,
        '    _expect(callable(http_binding_writer), "HTTP binding writer callback required")',
        '    _expect(callable(http_binding_writer) and callable(readiness_binding_writer), "HTTP readiness writer callbacks required")',
        changes,
    )
    raw = _change(
        raw,
        '    expected = binding["fixture"]\n',
        '    expected = binding["fixture"]\n    readiness_input = _http_ready.build_readiness_input(fixture_binding=binding, readiness_nonce=readiness_nonce)\n    readiness_raw = canonical_json(readiness_input)\n',
        changes,
    )
    raw = _change(
        raw,
        "        observation = None\n",
        "        observation = readiness_observation = None\n        readiness_metadata = None\n",
        changes,
    )
    raw = _change(
        raw,
        "                not os.path.lexists(_http.BINDING_PATH)\n",
        "                not os.path.lexists(_http.BINDING_PATH)\n                and not any(os.path.lexists(path) for path in (_http_ready.CREDENTIAL, _http_ready.CLAIM, _http_ready.RESULT))\n",
        changes,
    )
    raw = _change(
        raw,
        "            def guard():\n",
        """            # The ninth writer intent precedes the distinct absent-only write.
            readiness_binding_writer(readiness_raw)
            held.guard()
            readiness_observation = _http_ready.provision_readiness_input(
                expected_fixture=expected, readiness_nonce=readiness_nonce)
            publication = readiness_observation["publication"]
            _expect(readiness_observation["request_digest"] == canonical_digest(readiness_input)
                and readiness_observation["completed"] is True
                and publication["created"] is True and publication["completed"] is True
                and publication["cleanup_failed"] is False
                and readiness_observation["activation_performed"] is False,
                "readiness credential publication changed")
            readiness_read, readiness_metadata = _http_ready._read_owned(_http_ready.CREDENTIAL,
                uid=0, gid=binding["expected_broker_gid"], mode=0o440)
            _expect(readiness_read == readiness_raw, "readiness credential differs from writer")

            def guard():
""",
        changes,
    )
    raw = _change(
        raw,
        "                _http_provision._stopped()\n\n            def gateway_reader(path):",
        '                _expect(_http_ready._read_owned(_http_ready.CREDENTIAL,\n                    uid=0, gid=binding["expected_broker_gid"], mode=0o440)\n                    == (readiness_raw, readiness_metadata), "readiness credential changed during setup")\n                _http_provision._stopped()\n\n            def gateway_reader(path):',
        changes,
    )
    raw = _change(
        raw,
        '            if observation is not None and not hasattr(error, "http_provisioning_observation"):',
        '            if readiness_observation is not None:\n                error.readiness_provisioning_observation = readiness_observation["publication"]\n            if observation is not None and not hasattr(error, "http_provisioning_observation"):',
        changes,
    )
    raw = _change(
        raw,
        '        if hasattr(primary, "http_provisioning_observation"):',
        '        for attribute in ("readiness_provisioning_observation", "http_readiness_provisioning", "http_readiness_publication"):\n            if hasattr(primary, attribute):\n                setattr(error, attribute, getattr(primary, attribute))\n        if hasattr(primary, "http_provisioning_observation"):',
        changes,
    )
    return raw


def _measurement(raw, changes):
    raw = _change(
        raw,
        '        "runtime_http_action.py",\n',
        '        "runtime_http_action.py",\n        "runtime_http_readiness.py",\n',
        changes,
    )
    raw = _change(
        raw,
        "from . import runtime_http_action as http\n",
        "from . import runtime_http_action as http\nfrom . import runtime_http_readiness as readiness\n",
        changes,
    )
    raw = _change(
        raw,
        '    "profile-receipt.json",\n',
        '    "profile-receipt.json",\n    "http-readiness-used.json",\n    "http-readiness-result.json",\n',
        changes,
    )
    raw = _change(
        raw,
        "        self.session = session\n",
        "        self.session = session\n        self.readiness_credential = None\n",
        changes,
    )
    raw = _change(
        raw,
        "    endpoint = _HttpEndpoint(fixture_binding, credential, identities, session)\n",
        """    _require(readiness.CREDENTIAL.parent == _CREDENTIAL.parent)
    ready = custody._hold_file(parent, readiness.CREDENTIAL.name,
        _ROOT_UID, identities[2], 0o440, 4096, held)
    readiness._input(ready.raw, fixture_binding)
    endpoint = _HttpEndpoint(fixture_binding, credential, identities, session)
    endpoint.readiness_credential = ready
""",
        changes,
    )
    raw = _change(
        raw,
        "        custody._recheck([entry])\n    else:\n",
        """        custody._recheck([entry])
        ready = protected.readiness_credential
        _require(ready is not None)
        os.lseek(ready.fd, 0, os.SEEK_SET)
        _require(os.read(ready.fd, len(ready.raw) + 1) == ready.raw)
        custody._recheck([ready])
    else:
""",
        changes,
    )
    return raw


def render(original: dict[str, bytes]) -> dict[str, bytes]:
    """Return seven exact-pinned ready94 helper replacements; never execute them."""
    if (
        type(original) is not dict
        or set(original) != set(INPUTS)
        or STAGED_PROFILE_PIN is None
        or STAGED_COUNTS is None
        or set(PREDECESSOR_OUTPUTS) != set(INPUTS)
    ):
        raise NativeHttpReadyHelpersError(
            "ready helper input or reviewed stage inventory missing"
        )
    for name, pin in INPUTS.items():
        raw = original[name]
        if type(raw) is not bytes or (len(raw), hashlib.sha256(raw).hexdigest()) != pin:
            raise NativeHttpReadyHelpersError("ready helper original source changed")
    predecessors = setup.compose(
        {name: original[name] for name in INPUTS if name != measurement.SOURCE}
    ) | measurement.render(original)
    outputs = {}
    for name, raw in predecessors.items():
        if (len(raw), hashlib.sha256(raw).hexdigest()) != PREDECESSOR_OUTPUTS[name]:
            raise NativeHttpReadyHelpersError(
                "ready helper generated predecessor changed"
            )
        changes = []
        if name == preparation.PREPARATION:
            result = _preparation(raw, changes)
        elif name in (identity.IDENTITY, identity.VERIFIER):
            result = _identity(raw, changes, verifier=name == identity.VERIFIER)
        elif name == setup.SOURCE:
            result = _setup(raw, changes)
        elif name == writer.SOURCE:
            result = _writer(raw, changes)
        elif name == measurement.SOURCE:
            result = _measurement(raw, changes)
        else:
            result = raw  # Existing HTTP native-input validator consumes matching22-source verifier.
        restored = result
        for before, after in reversed(changes):
            restored = restored.replace(after, before)
        if restored != raw:
            raise NativeHttpReadyHelpersError("ready helper modified unrelated bytes")
        outputs[name] = result
    return outputs


compose = render
