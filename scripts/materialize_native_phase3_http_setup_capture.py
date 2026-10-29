"""Finite HTTP93 setup-only host, guest, and public replay source successor.

Rendering never imports generated code. Original signed sources and installation
bytes are distinct inventories; only the checked-in finite launcher evaluates
reviewed generated modules after its signed-tree check. No attempt is captured.
"""

from __future__ import annotations

import hashlib

HOST = "scripts/capture_native_phase3_common_setup.py"
GUEST = "scripts/runtime_native_common_setup_capture.py"
CONSUMER = "src/aragorn/native_phase3_common_setup_capture.py"
LAUNCHER = "scripts/capture_native_phase3_http_setup.py"
SELF = "scripts/materialize_native_phase3_http_setup_capture.py"
INPUTS = {
    HOST: (29151, "d03f72b016e40a0b9062e8256dfef079f40a213c0724f8e01c207fdff1a31c23"),
    GUEST: (15499, "1185e83bdbd7996c8efac584fd34f171fcebe3242fef9e61f577ec3cdc4cacc5"),
    CONSUMER: (
        43304,
        "093f3fbf3769898a563cb7a689f5aad6707e986b867c92949b92311027b13e31",
    ),
}
RENDERER_SOURCES = (
    SELF,
    "scripts/materialize_native_phase3_http_setup.py",
    "scripts/materialize_native_phase3_http_identity.py",
    "scripts/materialize_native_phase3_http_preparation.py",
    "scripts/materialize_native_phase3_http_writer.py",
    "scripts/materialize_runtime_http_collection.py",
)
GENERATED_SOURCES = (
    HOST,
    GUEST,
    CONSUMER,
    "scripts/runtime_native_common_case_setup.py",
    "scripts/runtime_native_receipt_systemd_check.py",
    "src/aragorn/native_phase3_common_identity.py",
    "src/aragorn/native_phase3_common_process_verifier.py",
    "src/aragorn/native_phase3_common_preparation.py",
    "src/aragorn/runtime_native_measurement_inputs.py",
    "src/aragorn/runtime_broker_measurement_plan.py",
    "src/aragorn/runtime_broker_decision_measurement_verify.py",
    "src/aragorn/runtime_broker_effective_receipt_verify.py",
)
STAGE_OWNED = {
    "src/aragorn/phase3_deployment.py": "/usr/lib/aragorn/aragorn/phase3_deployment.py",
    "src/aragorn/runtime_broker_decision_measurement_verify.py": "/usr/lib/aragorn/aragorn/runtime_broker_decision_measurement_verify.py",
}


class NativeHttpSetupCaptureRenderError(ValueError):
    """A fixed source or reversible extension boundary changed."""


def _change(raw, before, after, changes, count=1):
    before, after = before.encode(), after.encode()
    if before == after or raw.count(before) != count:
        raise NativeHttpSetupCaptureRenderError("HTTP setup-capture anchor changed")
    result = raw.replace(before, after)
    if result.count(after) != count or result.replace(after, before) != raw:
        raise NativeHttpSetupCaptureRenderError(
            "HTTP setup-capture change not reversible"
        )
    changes.append((before, after))
    return result


def _function(raw, name, before, after, changes):
    marker = ("def " + name + "(").encode()
    if raw.count(marker) != 1:
        raise NativeHttpSetupCaptureRenderError("HTTP setup-capture function changed")
    start = raw.index(marker)
    end = raw.find(b"\n\ndef ", start + len(marker))
    end = len(raw) if end < 0 else end
    section = raw[start:end].decode()
    if section.count(before) != 1:
        raise NativeHttpSetupCaptureRenderError(
            "HTTP setup-capture function anchor changed"
        )
    return _change(raw, section, section.replace(before, after), changes)


_SOURCE_HELPERS = '''
def _generated_sources(source_raws, generated_source_raws, stage):
    """Validate output custody, not signed-tree membership or execution."""
    _require(type(generated_source_raws) is dict
             and set(generated_source_raws) == set(GENERATED_SOURCES),
             "generated HTTP source inventory changed")
    for name, raw in generated_source_raws.items():
        _require(name in source_raws and type(raw) is bytes
                 and 0 < len(raw) <= MAX_PUBLIC_BLOB and raw != source_raws[name],
                 "generated HTTP source bytes changed")
        raw.decode("utf-8")
    by_source = {row["source_name"]: row for row in stage["files"]}
    for name in STAGE_GENERATED_SOURCES:
        row, raw = by_source[name], generated_source_raws[name]
        _require(row["bytes"] == len(raw) and row["digest"] == _digest(raw),
                 "generated helper differs from HTTP93-owned runtime")
    return source_raws | generated_source_raws


def helper_records(bound, source_rows):
    """Keep source Git identity distinct from installed output digest and size."""
    result = {}
    for name, target in FIXTURE_HELPERS.items():
        original, installed = bound["source_raws"][name], bound["installed_source_raws"][name]
        origin = source_rows[name]
        blob = hashlib.sha1(b"blob " + str(len(original)).encode() + b"\\0" + original).hexdigest()
        _require(set(origin) == {"path", "mode", "blob", "bytes", "digest"}
                 and origin == {"path": name, "mode": "100644", "blob": blob,
                                "bytes": len(original), "digest": _digest(original)},
                 "helper original signed-tree row changed")
        result[name] = {"source_origin": dict(origin), "bytes": len(installed),
                        "digest": _digest(installed), "installed_path": target,
                        "installed_mode": "0444",
                        "generated": name in GENERATED_SOURCES}
    return result


'''

_HTTP_FIXTURE_READER = """def _observe_http_fixture(container):
    # Caller identity comes from the exact newly-owned container, never bundle
    # supplied namespace numbers. Setup separately holds/rechecks its descriptors.
    from aragorn.native_phase3_http_canary_contract import validate_fixture
    from aragorn.native_phase3_http_fixture import owned_http_fixture
    setup.predecessor._environment(container, (0, 0))
    boot = _IDENTITY.process._read_virtual_file(
        __import__("pathlib").Path("/proc/sys/kernel/random/boot_id"), 64
    ).decode("ascii")
    _require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\\n", boot),
             "HTTP_BOOT_OBSERVATION_REFUSED")
    namespace = os.stat("/proc/self/ns/net")
    fixture = {"container_id": container, "boot_id": boot.strip(),
               "netns_device": namespace.st_dev, "netns_inode": namespace.st_ino}
    validate_fixture(fixture)
    with owned_http_fixture(fixture) as held:
        held.guard()
    return fixture


"""

_COPY_HELPERS = """                generated_root = Path(temporary).resolve() / "helpers"
                generated_root.mkdir(mode=0o700)
                for index, (path, target) in enumerate(_FILES.items()):
                    local = generated_root / str(index)
                    raw = bound["installed_source_raws"][path]
                    _API._write_output(local, raw)
                    local.chmod(0o444)
                    pins._read_fixed(local, (len(raw), _API._digest(raw)))
                    native.existing._docker("cp", str(local), container + ":" + target)
                    pins._read_fixed(local, (len(raw), _API._digest(raw)))
"""

_HANDOFF = """def _http_handoff_program():
    # Exact finite adaptation of the old held-directory/file custody handoff.
    raw = native._HEALTH_VERIFY
    changes = (
        ("len(directories)!=16", "len(directories)!=21"),
        ("len(set(directories))!=16", "len(set(directories))!=21"),
        (" if v['installed_path'].startswith('/usr/')", ""),
    )
    for before, after in changes:
        _require(raw.count(before) == 1, "HTTP directory handoff anchor changed")
        raw = raw.replace(before, after)
    return raw


"""


def _contract(raw, changes):
    for before, after, count in (
        ("native-common-setup", "native-http-setup", 6),
        (
            "OWNED_COMMON_SETUP_CAPTURE_NOT_ACTIVATION_OR_QUALIFICATION",
            "OWNED_HTTP_SETUP_CAPTURE_NOT_ACTIVATION_OR_QUALIFICATION",
            1,
        ),
        ("Raw seven-writer", "Raw eight-writer", 1),
        (
            "SEVEN_WRITER_DIGEST_AND_METADATA_JOINS_NOT_PRIVATE_WRITER_SEMANTIC_REPLAY",
            "EIGHT_WRITER_DIGEST_AND_METADATA_JOINS_NOT_PRIVATE_WRITER_SEMANTIC_REPLAY",
            1,
        ),
        (
            "scripts/stage_runtime_phase3_ingress_profile.py",
            "scripts/stage_runtime_phase3_http_profile.py",
            1,
        ),
    ):
        raw = _change(raw, before, after, changes, count)
    raw = _change(
        raw,
        "SOURCE_PATHS = tuple(sorted(set(FIXTURE_HELPERS) | {HOST_SOURCE, STAGER_SOURCE}))",
        f"GENERATED_SOURCES = {GENERATED_SOURCES!r}\n"
        f"RENDERER_SOURCES = {RENDERER_SOURCES!r}\nLAUNCHER_SOURCE = {LAUNCHER!r}\n"
        'STAGE_GENERATED_SOURCES = ("src/aragorn/runtime_broker_measurement_plan.py",\n'
        '    "src/aragorn/runtime_broker_decision_measurement_verify.py",\n'
        '    "src/aragorn/runtime_broker_effective_receipt_verify.py")\n'
        f"_STAGE_OWNED = {STAGE_OWNED!r}\n"
        "FIXTURE_HELPERS = {name: path for name, path in FIXTURE_HELPERS.items() if name not in _STAGE_OWNED}\n"
        "SOURCE_PATHS = tuple(sorted(set(FIXTURE_HELPERS) | set(GENERATED_SOURCES) | set(RENDERER_SOURCES)\n"
        "    | {HOST_SOURCE, STAGER_SOURCE, LAUNCHER_SOURCE}))",
        changes,
    )
    raw = _change(
        raw,
        '    "RETAINED_PUBLIC_REPORT_JOINS_NOT_SIGNATURE_EXECUTION_OR_LOADED_CODE_ATTESTATION",',
        '    "RETAINED_PUBLIC_REPORT_JOINS_NOT_SIGNATURE_EXECUTION_OR_LOADED_CODE_ATTESTATION",\n'
        '    "GENERATED_OUTPUT_PINS_NOT_SIGNED_GIT_BLOBS_OR_INDEPENDENT_RENDERER_EXECUTION_PROOF",\n'
        '    "HTTP_GUEST_FIXTURE_IDENTITY_NOT_INDEPENDENT_PRIVATE_CREDENTIAL_OR_KERNEL_ATTESTATION",',
        changes,
    )
    raw = _change(
        raw,
        "def prepare_common_setup_inputs(\n",
        _SOURCE_HELPERS + "def prepare_common_setup_inputs(\n",
        changes,
    )
    raw = _function(
        raw,
        "prepare_common_setup_inputs",
        "    case_id,\n",
        "    case_id,\n    http_attempt_id,\n    generated_source_raws,\n",
        changes,
    )
    raw = _function(
        raw,
        "prepare_common_setup_inputs",
        "        preparation.admission._source(source_record_raw)",
        "        _require(type(http_attempt_id) is str and re.fullmatch(\n"
        '            r"p3-lab-a(?:00[1-9]|01[0-9]|02[0-5])", http_attempt_id), "invalid HTTP attempt")\n'
        "        preparation.admission._source(source_record_raw)",
        changes,
    )
    raw = _function(
        raw,
        "prepare_common_setup_inputs",
        "        _require(\n            type(implementation_source_raws) is dict",
        "        installed = _generated_sources(source_raws, generated_source_raws, stage)\n"
        "        _require(\n            type(implementation_source_raws) is dict",
        changes,
    )
    raw = _change(
        raw,
        "                source_raws[path] == raw",
        "                installed[path] == raw",
        changes,
        2,
    )
    raw = _function(
        raw,
        "prepare_common_setup_inputs",
        '            "case_id": case_id,',
        '            "case_id": case_id,\n            "http_attempt_id": http_attempt_id,\n            "generated_sources": {path: text(generated_source_raws[path]) for path in GENERATED_SOURCES},',
        changes,
    )
    raw = _function(
        raw,
        "inspect_common_setup_inputs",
        "        arguments = {",
        '        generated = {path: raw.encode("utf-8") for path, raw in value["generated_sources"].items()}\n'
        "        installed = sources | generated\n        arguments = {",
        changes,
    )
    raw = _function(
        raw,
        "inspect_common_setup_inputs",
        "                path: sources[path] for path in IMPLEMENTATION_PATHS",
        "                path: installed[path] for path in IMPLEMENTATION_PATHS",
        changes,
    )
    raw = _function(
        raw,
        "inspect_common_setup_inputs",
        "            **arguments,\n",
        '            **arguments,\n            http_attempt_id=value["http_attempt_id"],\n            generated_source_raws=generated,\n',
        changes,
    )
    for arg, key in (
        ("setup", "SETUP_SOURCE"),
        ("wrapper", "WRAPPER_SOURCE"),
        ("host", "HOST_SOURCE"),
    ):
        raw = _function(
            raw,
            "inspect_common_setup_inputs",
            f"{arg}_source_raw=sources[{key}]",
            f"{arg}_source_raw=installed[{key}]",
            changes,
        )
    raw = _function(
        raw,
        "inspect_common_setup_inputs",
        '{"expected_setup_digest": _digest(sources[SETUP_SOURCE])}',
        '{"expected_setup_digest": _digest(installed[SETUP_SOURCE])}',
        changes,
    )
    raw = _function(
        raw,
        "inspect_common_setup_inputs",
        '            "source_raws": sources,',
        '            "source_raws": sources,\n            "generated_source_raws": generated,\n'
        '            "installed_source_raws": installed,\n            "http_attempt_id": value["http_attempt_id"],',
        changes,
    )
    raw = _function(
        raw,
        "_public_preparation",
        "preparation.old.PROVISIONING_PATHS",
        "preparation.PROVISIONING_PATHS",
        changes,
    )
    raw = _function(
        raw,
        "_public_preparation",
        "preparation.old._CONFIG_PIN",
        "preparation.HTTP_CONFIG_PIN",
        changes,
    )
    raw = _function(
        raw,
        "_setup_readbacks",
        'sources = bound["source_raws"]',
        'sources = bound["installed_source_raws"]',
        changes,
    )
    raw = _function(
        raw,
        "_setup_readbacks",
        "        _OVERRIDE_PATHS\n",
        '        row["path"] for row in stage["files"]\n',
        changes,
    )
    raw = _function(
        raw,
        "_setup_readbacks",
        "        live._metadata(record, owners={owner}, modes={0o400})",
        "        if path == preparation.HTTP_FIXTURE:\n"
        "            owner = (0, 997)\n"
        "        live._metadata(record, owners={owner}, modes={0o440} if path == preparation.HTTP_FIXTURE else {0o400})",
        changes,
    )
    raw = _function(
        raw,
        "_setup_readbacks",
        '    _require(\n        canonical_json(setup["setup_state"])',
        '    _require(setup["http_writer_intent_digest"] == pins[preparation.HTTP_FIXTURE]\n'
        '             and setup["http_provisioning_observation"] is None,\n'
        '             "HTTP writer intent or successful provisioning status changed")\n'
        '    _require(\n        canonical_json(setup["setup_state"])',
        changes,
    )
    # Replace only copied-helper record validation; all owned fixture and cleanup
    # validation below the following container anchor is preserved byte-for-byte.
    marker = "    for path, target in fixture_helpers.items():\n"
    start = raw.index(marker.encode(), raw.index(b"def _outer("))
    end = raw.index(b"    container, item, cleanup = (\n", start)
    old = raw[start:end].decode()
    new = """    expected_helpers = helper_records(bound, {
        name: row["source_origin"] for name, row in helpers.items()
    })
    _require(canonical_json(helpers) == canonical_json(expected_helpers),
             "copied original/rendered helper binding changed")
"""
    raw = _change(raw, old, new, changes)
    raw = _function(
        raw,
        "verify_native_common_setup_capture",
        '            "controller_sources",',
        '            "http_fixture",\n            "controller_sources",',
        changes,
    )
    raw = _function(
        raw,
        "verify_native_common_setup_capture",
        "        _false(guest)\n",
        "        _false(guest)\n"
        "        from .native_phase3_http_canary_contract import validate_fixture\n"
        '        validate_fixture(guest["http_fixture"])\n'
        '        _require(guest["http_fixture"]["container_id"] == capture["fixture_container"],\n'
        '                 "HTTP guest fixture differs from owned host identity")\n',
        changes,
    )
    raw = _function(
        raw,
        "verify_native_common_setup_capture",
        '            "writer_readback",',
        '            "http_writer_intent_digest",\n            "http_provisioning_observation",\n            "writer_readback",',
        changes,
    )
    raw = _function(
        raw,
        "verify_native_common_setup_capture",
        '"aragorn/native-common-case-setup/v1"',
        '"aragorn/native-http-case-setup/v1"',
        changes,
    )
    raw = _function(
        raw,
        "verify_native_common_setup_capture",
        "OWNED_SEVEN_WRITER_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY",
        "OWNED_EIGHT_WRITER_HTTP_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY",
        changes,
    )
    raw = _function(
        raw,
        "verify_native_common_setup_capture",
        '_digest(bound["source_raws"][SETUP_SOURCE])',
        '_digest(bound["installed_source_raws"][SETUP_SOURCE])',
        changes,
    )
    raw = _function(
        raw,
        "verify_native_common_setup_capture",
        '"writer_digest_count": 7,',
        '"writer_digest_count": 8,\n            "generated_sources_recomputed": False,',
        changes,
    )
    return raw


def _guest(raw, changes):
    raw = _change(raw, "native-common-setup", "native-http-setup", changes, 4)
    raw = _change(
        raw,
        "def _run(container: str, expected_bundle_digest: str) -> dict:\n",
        _HTTP_FIXTURE_READER
        + "def _run(container: str, expected_bundle_digest: str) -> dict:\n",
        changes,
    )
    raw = _function(
        raw,
        "_run",
        '        "controller_sources": {},',
        '        "http_fixture": None,\n        "controller_sources": {},',
        changes,
    )
    raw = _change(
        raw,
        'source, inspected["source_raws"][source]',
        'source, inspected["installed_source_raws"][source]',
        changes,
        2,
    )
    raw = _function(
        raw,
        "_run",
        '        phase = "SETUP"\n',
        '        phase = "HTTP_FIXTURE"\n'
        '        result["http_fixture"] = _observe_http_fixture(container)\n'
        '        phase = "SETUP"\n',
        changes,
    )
    raw = _function(
        raw,
        "_run",
        '            expected_container_id=container, **inspected["setup_arguments"]',
        "            expected_container_id=container,\n"
        '            expected_http_fixture=result["http_fixture"],\n'
        '            http_attempt_id=inspected["http_attempt_id"],\n'
        '            **inspected["setup_arguments"]',
        changes,
    )
    return raw


def _host(raw, changes):
    raw = _change(
        raw,
        "from scripts import stage_runtime_phase3_ingress_profile as profile",
        "from scripts import stage_runtime_phase3_http_profile as profile\nfrom scripts import materialize_native_phase3_http_setup_capture as http_sources",
        changes,
    )
    raw = _change(
        raw,
        '_STAGE_OWNED = {\n    "src/aragorn/phase3_deployment.py": "/usr/lib/aragorn/aragorn/phase3_deployment.py",\n}',
        f"_STAGE_OWNED = {STAGE_OWNED!r}",
        changes,
    )
    raw = _change(
        raw,
        "    admission._FILES.get(source) != target for source, target in _STAGE_OWNED.items()",
        "    admission._FILES.get(source) not in (None, target) for source, target in _STAGE_OWNED.items()",
        changes,
    )
    raw = _change(
        raw,
        "_SOURCE_PATHS = tuple(sorted(set(_FILES) | {_HOST, _STAGER}))",
        "_FILES = {name: path for name, path in _FILES.items() if name not in _STAGE_OWNED}\n"
        "_SOURCE_PATHS = contract.SOURCE_PATHS",
        changes,
    )
    raw = _change(
        raw,
        "scripts/stage_runtime_phase3_ingress_profile.py",
        "scripts/stage_runtime_phase3_http_profile.py",
        changes,
    )
    raw = _change(
        raw,
        "stage_runtime_phase3_ingress_profile(",
        "stage_runtime_phase3_http_profile(",
        changes,
        2,
    )
    raw = _change(raw, "native-common-setup", "native-http-setup", changes, 4)
    raw = _change(
        raw,
        "OWNED_COMMON_SETUP_CAPTURE_NOT_ACTIVATION_OR_QUALIFICATION",
        "OWNED_HTTP_SETUP_CAPTURE_NOT_ACTIVATION_OR_QUALIFICATION",
        changes,
    )
    raw = _function(
        raw,
        "_source_guard",
        "    return source\n",
        '    _require(http_sources.compose(bound["source_raws"]) == bound["generated_source_raws"],\n'
        '             "HTTP generated source derivation changed")\n    return source\n',
        changes,
    )
    raw = _function(
        raw, "_prepare", "nonce: str)", "nonce: str, http_attempt_id: str)", changes
    )
    raw = _function(
        raw,
        "_prepare",
        "    with TemporaryDirectory(",
        "    generated = http_sources.compose(source_raws)\n    installed = source_raws | generated\n    with TemporaryDirectory(",
        changes,
    )
    raw = _function(
        raw,
        "_prepare",
        "            case_id=case_id,",
        "            case_id=case_id,\n            http_attempt_id=http_attempt_id,\n            generated_source_raws=generated,",
        changes,
    )
    raw = _function(
        raw, "_prepare", "path: source_raws[path]", "path: installed[path]", changes
    )
    for key in ("_SETUP", "_GUEST", "_HOST"):
        raw = _function(
            raw, "_prepare", f"source_raws[{key}]", f"installed[{key}]", changes
        )
    raw = _function(
        raw, "_stage_guard", "(74, 96, 30, 16)", "(93, 119, 49, 21)", changes
    )
    raw = _function(
        raw,
        "_stage_guard",
        "len(destinations) == 74",
        "len(destinations) == 93",
        changes,
    )
    raw = _function(
        raw,
        "_guest_output",
        '            "controller_sources",',
        '            "http_fixture",\n            "controller_sources",',
        changes,
    )
    raw = _change(
        raw,
        "def _capture(store: CAS, input_pin: str) -> dict:\n",
        _HANDOFF + "def _capture(store: CAS, input_pin: str) -> dict:\n",
        changes,
    )
    start = raw.index(b"    helpers = {\n", raw.index(b"def _capture("))
    end = raw.index(b"    parent = ", start)
    raw = _change(
        raw,
        raw[start:end].decode(),
        "    helpers = contract.helper_records(bound, {\n"
        '        path: _API._tree_file(source["commit"], Path(path)) for path in _FILES\n'
        "    })\n",
        changes,
    )
    raw = _function(
        raw,
        "_capture",
        "            original, replacements = profile._verified_payloads()",
        "            original, replacements, _ = profile._verified_payloads()",
        changes,
    )
    before = """                for path, target in _FILES.items():
                    native.existing._docker(
                        "cp", str(_ROOT / path), container + ":" + target
                    )
"""
    raw = _change(raw, before, _COPY_HELPERS, changes)
    raw = _function(
        raw,
        "_capture",
        "                    native._HEALTH_VERIFY,",
        "                    _http_handoff_program(),",
        changes,
    )
    raw = _function(
        raw,
        "_capture",
        'json.dumps(stage["directories"])',
        'json.dumps(["/" + path for path in stage["directories"]])',
        changes,
    )
    raw = _function(
        raw,
        "main",
        '            command.add_argument("--nonce", required=True)',
        '            command.add_argument("--nonce", required=True)\n            command.add_argument("--http-attempt-id", required=True)',
        changes,
    )
    raw = _function(
        raw,
        "main",
        "_prepare(store, args.case_id, args.nonce)",
        "_prepare(store, args.case_id, args.nonce, args.http_attempt_id)",
        changes,
    )
    return raw


def render(original):
    """Return the fixed three source-keyed replacements, with no evaluation."""
    if type(original) is not dict or not set(INPUTS) <= set(original):
        raise NativeHttpSetupCaptureRenderError("HTTP capture source inventory missing")
    outputs = {}
    for name, pin in INPUTS.items():
        source = original[name]
        if (
            type(source) is not bytes
            or (len(source), hashlib.sha256(source).hexdigest()) != pin
        ):
            raise NativeHttpSetupCaptureRenderError(
                "HTTP capture predecessor pin changed"
            )
        changes = []
        raw = {HOST: _host, GUEST: _guest, CONSUMER: _contract}[name](source, changes)
        recovered = raw
        for before, after in reversed(changes):
            recovered = recovered.replace(after, before)
        if recovered != source:
            raise NativeHttpSetupCaptureRenderError(
                "HTTP capture source round trip changed"
            )
        outputs[name] = raw
    return outputs


def compose(original):
    """Twelve exact outputs: six setup helpers, three capture, three stage-owned."""
    from scripts import materialize_native_phase3_http_setup as setup
    from scripts import materialize_native_phase3_http_identity as identity
    from scripts import materialize_native_phase3_http_preparation as preparation
    from scripts import materialize_native_phase3_http_writer as writer
    from scripts import materialize_runtime_http_collection as collection

    expected = (
        set(setup.INPUTS)
        | set(identity.INPUTS)
        | set(preparation.INPUTS)
        | set(writer.INPUTS)
    )
    outputs = setup.compose({name: original[name] for name in expected})
    for component in (collection.render(original), render(original)):
        if set(outputs).intersection(component):
            raise NativeHttpSetupCaptureRenderError("HTTP source composition overlap")
        outputs.update(component)
    if set(outputs) != set(GENERATED_SOURCES):
        raise NativeHttpSetupCaptureRenderError("HTTP generated inventory changed")
    return outputs
