"""Finite ready94 nested setup bundle for the combined HTTP attempt launcher.

The retained HTTP93 controller supplies source custody and fixture lifecycle.
Only its profile, nine-writer nonce and installed-source bindings change here.
Rendering returns bytes; it neither evaluates them nor starts a fixture.
"""

from scripts import materialize_native_phase3_http_setup_capture as prior
from scripts import materialize_native_phase3_http_ready_helpers as helpers
from scripts import materialize_runtime_http_collection as collection
from scripts import materialize_native_phase3_http_attempt as attempt_guest

HOST, GUEST, CONSUMER = prior.HOST, prior.GUEST, prior.CONSUMER
SELF = "scripts/materialize_native_phase3_http_ready_setup_capture.py"
LAUNCHER = "scripts/capture_native_phase3_http_attempt.py"
STAGER = "scripts/stage_runtime_phase3_http_ready_profile.py"
STAGE_OWNED = dict(prior.STAGE_OWNED)
RENDERER_SOURCES = (
    *prior.RENDERER_SOURCES,
    SELF,
    "scripts/materialize_native_phase3_http_ready_helpers.py",
    "scripts/materialize_native_phase3_http_measurement_provisioning.py",
    "scripts/materialize_native_phase3_http_attempt.py",
)
GENERATED_SOURCES = (*prior.GENERATED_SOURCES, helpers.measurement.SOURCE)
INPUTS = prior.INPUTS | helpers.INPUTS | collection.INPUTS
_change, _function = prior._change, prior._function


def _contract(raw, changes):
    raw = _change(raw, "native-http-setup", "native-http-ready-setup", changes, 6)
    raw = _change(
        raw,
        "OWNED_HTTP_SETUP_CAPTURE_NOT_ACTIVATION_OR_QUALIFICATION",
        "OWNED_HTTP_READY_SETUP_CAPTURE_NOT_ACTIVATION_OR_QUALIFICATION",
        changes,
    )
    raw = _change(raw, "Raw eight-writer", "Raw nine-writer", changes)
    raw = _change(
        raw,
        "EIGHT_WRITER_DIGEST_AND_METADATA_JOINS_NOT_PRIVATE_WRITER_SEMANTIC_REPLAY",
        "NINE_WRITER_DIGEST_AND_METADATA_JOINS_NOT_PRIVATE_WRITER_SEMANTIC_REPLAY",
        changes,
    )
    for before, after in (
        (
            f"GENERATED_SOURCES = {prior.GENERATED_SOURCES!r}",
            f"GENERATED_SOURCES = {GENERATED_SOURCES!r}",
        ),
        (
            f"RENDERER_SOURCES = {prior.RENDERER_SOURCES!r}",
            f"RENDERER_SOURCES = {RENDERER_SOURCES!r}",
        ),
        (f"LAUNCHER_SOURCE = {prior.LAUNCHER!r}", f"LAUNCHER_SOURCE = {LAUNCHER!r}"),
        ("scripts/stage_runtime_phase3_http_profile.py", STAGER),
        ("HTTP93-owned runtime", "HTTP94-owned runtime"),
    ):
        raw = _change(raw, before, after, changes)
    raw = _function(
        raw,
        "helper_records",
        "def helper_records(bound, source_rows):",
        "def helper_records(bound, source_rows, *, fixture_helpers=None):",
        changes,
    )
    raw = _function(
        raw,
        "helper_records",
        "    result = {}\n",
        "    fixture_helpers = FIXTURE_HELPERS if fixture_helpers is None else fixture_helpers\n    result = {}\n",
        changes,
    )
    raw = _function(
        raw,
        "helper_records",
        "FIXTURE_HELPERS.items()",
        "fixture_helpers.items()",
        changes,
    )
    raw = _function(
        raw,
        "helper_records",
        '"generated": name in GENERATED_SOURCES',
        '"generated": name in bound["generated_source_raws"]',
        changes,
    )
    raw = _function(
        raw,
        "_outer",
        '        name: row["source_origin"] for name, row in helpers.items()\n    })',
        '        name: row["source_origin"] for name, row in helpers.items()\n    }, fixture_helpers=fixture_helpers)',
        changes,
    )
    raw = _function(
        raw,
        "prepare_common_setup_inputs",
        "    http_attempt_id,\n",
        "    http_attempt_id,\n    readiness_nonce,\n",
        changes,
    )
    raw = _function(
        raw,
        "prepare_common_setup_inputs",
        "        preparation.admission._source(source_record_raw)",
        '        _require(type(readiness_nonce) is str and re.fullmatch(r"[0-9a-f]{32}", readiness_nonce),\n'
        '                 "invalid readiness nonce")\n        preparation.admission._source(source_record_raw)',
        changes,
    )
    raw = _function(
        raw,
        "prepare_common_setup_inputs",
        '            "http_attempt_id": http_attempt_id,',
        '            "http_attempt_id": http_attempt_id,\n            "readiness_nonce": readiness_nonce,',
        changes,
    )
    raw = _function(
        raw,
        "inspect_common_setup_inputs",
        '            "nonce": value["nonce"],',
        '            "nonce": value["nonce"],\n            "readiness_nonce": value["readiness_nonce"],',
        changes,
    )
    raw = _function(
        raw,
        "inspect_common_setup_inputs",
        '            "installed_source_raws": installed,',
        '            "installed_source_raws": installed,\n            "readiness_nonce": value["readiness_nonce"],',
        changes,
    )
    raw = _function(
        raw,
        "_public_preparation",
        '        "nonce": args["nonce"],',
        '        "nonce": args["nonce"],\n        "readiness_nonce": args["readiness_nonce"],',
        changes,
    )
    raw = _function(
        raw,
        "_setup_readbacks",
        "if path == preparation.HTTP_FIXTURE:",
        "if path in (preparation.HTTP_FIXTURE, preparation.HTTP_READINESS):",
        changes,
    )
    raw = _function(
        raw,
        "_setup_readbacks",
        "if path == preparation.HTTP_FIXTURE else {0o400}",
        "if path in (preparation.HTTP_FIXTURE, preparation.HTTP_READINESS) else {0o400}",
        changes,
    )
    raw = _function(
        raw,
        "_setup_readbacks",
        '    _require(setup["http_writer_intent_digest"] == pins[preparation.HTTP_FIXTURE]',
        '    _require(setup["readiness_nonce"] == bound["setup_arguments"]["readiness_nonce"]\n'
        '             and setup["readiness_writer_intent_digest"] == pins[preparation.HTTP_READINESS]\n'
        '             and setup["readiness_provisioning_observation"] is None,\n'
        '             "readiness writer intent or successful provisioning status changed")\n'
        '    _require(setup["http_writer_intent_digest"] == pins[preparation.HTTP_FIXTURE]',
        changes,
    )
    raw = _function(
        raw,
        "verify_native_common_setup_capture",
        '            "http_writer_intent_digest",',
        '            "readiness_nonce",\n            "readiness_writer_intent_digest",\n'
        '            "readiness_provisioning_observation",\n            "http_writer_intent_digest",',
        changes,
    )
    raw = _function(
        raw,
        "verify_native_common_setup_capture",
        '"aragorn/native-http-case-setup/v1"',
        '"aragorn/native-http-case-setup/v2"',
        changes,
    )
    raw = _function(
        raw,
        "verify_native_common_setup_capture",
        "OWNED_EIGHT_WRITER_HTTP_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY",
        "OWNED_NINE_WRITER_HTTP_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY",
        changes,
    )
    return _function(
        raw,
        "verify_native_common_setup_capture",
        '"writer_digest_count": 8,',
        '"writer_digest_count": 9,',
        changes,
    )


def _host(raw, changes):
    for before, after, count in (
        ("native-http-setup", "native-http-ready-setup", 4),
        (
            "OWNED_HTTP_SETUP_CAPTURE_NOT_ACTIVATION_OR_QUALIFICATION",
            "OWNED_HTTP_READY_SETUP_CAPTURE_NOT_ACTIVATION_OR_QUALIFICATION",
            1,
        ),
        (
            "stage_runtime_phase3_http_profile",
            "stage_runtime_phase3_http_ready_profile",
            4,
        ),
        (
            "materialize_native_phase3_http_setup_capture as http_sources",
            "materialize_native_phase3_http_ready_setup_capture as http_sources",
            1,
        ),
    ):
        raw = _change(raw, before, after, changes, count)
    raw = _function(
        raw,
        "_prepare",
        "http_attempt_id: str)",
        "http_attempt_id: str, readiness_nonce: str)",
        changes,
    )
    raw = _function(
        raw,
        "_prepare",
        "            http_attempt_id=http_attempt_id,",
        "            http_attempt_id=http_attempt_id,\n            readiness_nonce=readiness_nonce,",
        changes,
    )
    raw = _function(
        raw, "_stage_guard", "(93, 119, 49, 21)", repr(helpers.STAGED_COUNTS), changes
    )
    raw = _function(
        raw,
        "_stage_guard",
        "len(destinations) == 93",
        "len(destinations) == 94",
        changes,
    )
    raw = _function(
        raw,
        "main",
        '            command.add_argument("--http-attempt-id", required=True)',
        '            command.add_argument("--http-attempt-id", required=True)\n'
        '            command.add_argument("--readiness-nonce", required=True)',
        changes,
    )
    return _function(
        raw,
        "main",
        "_prepare(store, args.case_id, args.nonce, args.http_attempt_id)",
        "_prepare(store, args.case_id, args.nonce, args.http_attempt_id, args.readiness_nonce)",
        changes,
    )


def render(original):
    """Return three fixed capture replacements without importing their output."""
    outputs = {}
    for name, raw in prior.render(original).items():
        changes = []
        if name == HOST:
            output = _host(raw, changes)
        elif name == CONSUMER:
            output = _contract(raw, changes)
        else:
            output = _change(
                raw, "native-http-setup", "native-http-ready-setup", changes, 4
            )
        restored = output
        for before, after in reversed(changes):
            restored = restored.replace(after, before)
        if restored != raw:
            raise prior.NativeHttpSetupCaptureRenderError(
                "ready setup reversal changed"
            )
        outputs[name] = output
    return outputs


def compose(original):
    """Seven ready helpers, three capture outputs and three stage-owned verifiers."""
    outputs = helpers.render({name: original[name] for name in helpers.INPUTS})
    outputs[helpers.writer.SOURCE] = attempt_guest.render_writer(
        outputs[helpers.writer.SOURCE]
    )
    stage = collection.render(original)
    for name in (collection.PLAN, collection.PRIOR):
        changes = []
        stage[name] = _change(
            stage[name],
            "_SOURCES = {\n",
            '_SOURCES = {\n    "runtime_http_readiness.py",\n',
            changes,
        )
    for component in (stage, render(original)):
        if set(outputs).intersection(component):
            raise prior.NativeHttpSetupCaptureRenderError("ready setup output overlap")
        outputs.update(component)
    if set(outputs) != set(GENERATED_SOURCES):
        raise prior.NativeHttpSetupCaptureRenderError(
            "ready setup output inventory changed"
        )
    return outputs
