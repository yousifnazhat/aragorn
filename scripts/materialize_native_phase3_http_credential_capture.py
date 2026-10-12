"""Finite credential-view HTTP94 setup and attempt capture source successor.

Original signed bytes, the retained public stage receipt and generated helper
bytes remain separate. Rendering never evaluates its output or stages a tree.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from scripts import materialize_native_phase3_http_attempt_capture as prior
from scripts import materialize_native_phase3_http_ready_setup_capture as setup
from scripts import materialize_native_phase3_http_credential_helpers as helpers

HOST, INPUT = prior.HOST, prior.INPUT
SELF = "scripts/materialize_native_phase3_http_credential_capture.py"
LAUNCHER = "scripts/capture_native_phase3_http_credential_attempt.py"
STAGER = "scripts/stage_runtime_phase3_http_credential_profile.py"
REPORT = helpers.REPORT
PRIVATE_STAGED_SOURCES = (
    "src/aragorn/runtime_http_action.py",
    "src/aragorn/runtime_http_provisioning.py",
    "src/aragorn/runtime_http_readiness.py",
    *prior.PRIVATE_STAGED_SOURCES,
)
_ROOT = Path(__file__).resolve().parents[1]


def generated_paths():
    """Preserve the existing full generated installation inventory."""
    return prior.generated_paths()


def renderer_paths():
    return tuple(sorted(set(prior.renderer_paths()) | {SELF, LAUNCHER,
        "scripts/materialize_native_phase3_http_credential_helpers.py"}))


def source_paths():
    """One exact signed-source closure for both nested and outer bundles."""
    receipt = helpers.report((_ROOT / REPORT).read_bytes())
    return tuple(sorted(set(prior.source_paths())
        | {row["name"] for row in receipt["source_inputs"]}
        | set(PRIVATE_STAGED_SOURCES)
        | {SELF, LAUNCHER, STAGER, REPORT,
           "scripts/materialize_native_phase3_http_credential_helpers.py"}))


def _checked_original(original):
    if type(original) is not dict or set(original) != set(source_paths()):
        raise ValueError("HTTP credential capture signed source inventory changed")
    if any(type(raw) is not bytes or not raw for raw in original.values()):
        raise ValueError("HTTP credential capture source bytes changed")
    receipt = helpers.report(original[REPORT])
    for row in receipt["source_inputs"]:
        raw = original[row["name"]]
        if (len(raw), "sha256:" + hashlib.sha256(raw).hexdigest()) != (
                row["bytes"], row["digest"]):
            raise ValueError("HTTP credential capture public source pin changed")
    return receipt


def _change(raw, before, after, count=1):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != count:
        raise ValueError("HTTP credential capture anchor changed: " + before[:100].decode())
    result = raw.replace(before, after)
    if result.replace(after, before) != raw:
        raise ValueError("HTTP credential capture reversal changed")
    return result


def _function(raw, name, before, after, count=1):
    marker = ("def " + name + "(").encode("ascii")
    if raw.count(marker) != 1:
        raise ValueError("HTTP credential capture function changed")
    start = raw.index(marker)
    end = raw.find(b"\n\ndef ", start + len(marker))
    section = raw[start:len(raw) if end < 0 else end]
    changed = _change(section, before, after, count)
    return _change(raw, section.decode("ascii"), changed.decode("ascii"))


def _prepare_receipt(raw):
    """Replace only offline setup preparation's former redundant staging."""
    start = b'    with TemporaryDirectory(prefix="aragorn-common-setup-prepare-") as temporary:\n'
    end = b'    raw, pin = built["bundle_raw"], built["bundle_digest"]\n'
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise ValueError("HTTP credential setup preparation section changed")
    left, right = raw.index(start), raw.index(end)
    old = raw[left:right]
    prefix = start + (
        "        stage = profile.stage_runtime_phase3_http_credential_profile(\n"
        '            Path(temporary).resolve() / "stage"\n'
        "        )\n"
        "        stage_raw = canonical_json(stage)\n"
    ).encode("ascii")
    if not old.startswith(prefix):
        raise ValueError("HTTP credential setup preparation staging anchor changed")
    body = old[len(prefix):].splitlines(keepends=True)
    if any(line.strip() and not line.startswith(b"        ") for line in body):
        raise ValueError("HTTP credential setup preparation indentation changed")
    changed = (f"    stage_raw = source_raws[{REPORT!r}]\n"
        "    stage = json.loads(stage_raw)\n").encode("ascii")
    changed += b"".join(line[4:] if line.strip() else line for line in body)
    return _change(raw, old.decode("ascii"), changed.decode("ascii"))


def _setup_host(raw):
    raw = _change(raw,
        "materialize_native_phase3_http_ready_setup_capture as http_sources",
        "materialize_native_phase3_http_credential_capture as http_sources")
    raw = _change(raw, "stage_runtime_phase3_http_ready_profile",
        "stage_runtime_phase3_http_credential_profile", 4)
    raw = _change(raw, "http_sources.compose(", "http_sources.compose_setup(", 2)
    raw = _function(raw, "_stage_guard", repr(helpers.prior.STAGED_COUNTS),
        repr(helpers.STAGED_COUNTS))
    return _prepare_receipt(raw)


def _setup_consumer(raw):
    raw = _change(raw, f"RENDERER_SOURCES = {setup.RENDERER_SOURCES!r}",
        f"RENDERER_SOURCES = {renderer_paths()!r}")
    raw = _change(raw, f"LAUNCHER_SOURCE = {setup.LAUNCHER!r}",
        f"LAUNCHER_SOURCE = {LAUNCHER!r}")
    raw = _change(raw, setup.STAGER, STAGER)
    raw = _change(raw,
        "SOURCE_PATHS = tuple(sorted(set(FIXTURE_HELPERS) | set(GENERATED_SOURCES) | set(RENDERER_SOURCES)\n"
        "    | {HOST_SOURCE, STAGER_SOURCE, LAUNCHER_SOURCE}))",
        f"SOURCE_PATHS = {source_paths()!r}")
    return _change(raw, "aragorn/native-http-case-setup/v2",
        "aragorn/native-http-case-setup/v3")


def _attempt_host(raw):
    raw = _change(raw,
        "materialize_native_phase3_http_attempt_capture as http_sources",
        "materialize_native_phase3_http_credential_capture as http_sources")
    return _change(raw, "stage_runtime_phase3_http_ready_profile(output)",
        "stage_runtime_phase3_http_credential_profile(output)")


def _transform(outputs, original, *, nested):
    expected = set(setup.GENERATED_SOURCES if nested else generated_paths())
    if set(outputs) != expected or not set(helpers.INPUTS) <= expected:
        raise ValueError("HTTP credential capture generated inventory changed")
    result = dict(outputs)
    result.update(helpers._transform(
        {name: result[name] for name in helpers.INPUTS}, original[REPORT]))
    result[setup.HOST] = _setup_host(result[setup.HOST])
    result[setup.CONSUMER] = _setup_consumer(result[setup.CONSUMER])
    if not nested:
        result[HOST] = _attempt_host(result[HOST])
        result[INPUT] = _change(result[INPUT],
            f"SOURCE_PATHS = {prior.source_paths()!r}",
            f"SOURCE_PATHS = {source_paths()!r}")
        for name in ("scripts/runtime_native_common_attempt_plan.py",
                "scripts/runtime_native_common_measurement_handoff.py"):
            result[name] = _change(result[name],
                "aragorn/native-common-deployment-preparation/v4",
                "aragorn/native-common-deployment-preparation/v5")
    if set(result) != expected:
        raise ValueError("HTTP credential capture output inventory changed")
    return result


def compose_setup(original):
    """Thirteen nested setup outputs over the same full signed-source closure."""
    _checked_original(original)
    return _transform(setup.compose(original), original, nested=True)


def compose(original):
    """Full attempt outputs; no generated module evaluation or staging."""
    _checked_original(original)
    return _transform(prior.compose(original), original, nested=False)
