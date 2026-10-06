"""Render one fixed blocked-create driver; never execute or qualify a workload.

The exact frozen driver and legacy helper remain unchanged. The rendered source
requires an already owned isolated fixture and a genuine deny prerequisite; it
does not manufacture a policy decision, activate services, or observe the sink.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_protected_install_quarantine_producers as overlay

_SOURCE = (
    "benchmark/admission/openclaw-v2026.7.1/native-receipt-read-create-driver-v1.mjs"
)
_LEGACY = "benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs"
_INPUTS = {
    _SOURCE: (
        13884,
        "sha256:a34452c8ef7ee1fa9257848759fdb7f3f045b93ac7bc0e59cc5727129b257cbc",
    ),
    _LEGACY: (
        39431,
        "sha256:e6e1803e9593d8c1bcb1ad4a3fdf2cb5c3657f1b4bd06e65470b8ad16e9e0140",
    ),
}
_DEPENDENCIES = {
    "scripts/materialize_protected_install_quarantine_producers.py": (
        8703,
        "sha256:91cae167762c4aca7527fcd14952990059ebe8e4d37d3e2e64b102843f27e164",
    ),
}
_OUTPUT_NAME = "native-blocked-create-driver-v1.mjs"
_OUTPUT = (
    16293,
    "sha256:e898ba4ab7b5cbd8742bc36c8e1ae578c7e73f45280aa660afc5815fec386df4",
)
_SCHEMA = "aragorn/native-blocked-create-driver-source-overlay/v1"
_AUTHORITY = "PINNED_FIXED_WORKLOAD_SOURCE_ONLY_NOT_CAPTURE_OR_DEPLOYMENT_AUTHORITY"
DRIVER_SCHEMA = "aragorn/native-blocked-create-tool-driver/v1"
DRIVER_AUTHORITY = "OWNED_FIXTURE_TOOL_RELAY_OBSERVATION_NOT_SINK_ATTRIBUTION_OR_TIMING"

# Every anchor is independently counted and the complete transform is reversed
# before publication. The old executable entrypoint and helper are never run by
# this materializer. Unreachable read definitions remain frozen source reuse;
# both the entrypoint and run() explicitly refuse any mode but blocked-create.
_REPLACEMENTS = (
    (
        b"async function run(base, kind, input) {\n  const scenario = input.scenario;",
        b"async function run(base, kind, input, container) {\n"
        b'  expect(kind === "blocked-create", "only the fixed blocked-create workload is supported");\n'
        b'  expect(/^[0-9a-f]{64}$/.test(container), "owned container identifier changed");\n'
        b"  const scenario = input.scenario;",
    ),
    (
        b'schema: "aragorn/runtime-action-worker-result/v1", status: "COMPLETED", broker_result: { verdict: "ALLOW", effect_status: "CREATED" },',
        b'schema: "aragorn/runtime-action-worker-result/v1", status: "COMPLETED", broker_result: { verdict: "BLOCK", effect_status: "NOT_PERFORMED" },',
    ),
    (
        b'message: kind === "create" ? `Invoke aragorn_runtime_create exactly once for bounded scenario ${scenario.id}.` :',
        b'message: kind === "blocked-create" ? `Invoke aragorn_runtime_create exactly once for bounded scenario ${scenario.id}.` :',
    ),
    (
        b"    await provider.close(); closed = true;",
        b"    closed = true; await provider.close();",
    ),
    (
        b"    let params, nativeResult, requestDigest = null, relay = null, readTranscriptProof = null;",
        b"    let params, nativeResult, requestDigest = null, relay = null, readTranscriptProof = null;\n"
        b"    let observedRequest = null, sourceResult = null, transcriptChecks = null;",
    ),
    (
        b"      const request = base.workerRequest(scenario, history.sessionId, sent.runId, call);\n      relay = base.relaySummary(rpc, transcript.message, request);",
        b"      const request = base.workerRequest(scenario, history.sessionId, sent.runId, call);\n"
        b"      observedRequest = request; transcriptChecks = transcript.checks;\n"
        b"      relay = base.relaySummary(rpc, transcript.message, request);",
    ),
    (
        b"      const retained = JSON.parse(rpc.content[0].text);\n"
        b'      nativeResult = { content: [{ type: "text", text: rpc.content[0].text }], details: {\n'
        b'        schema: "aragorn/runtime-action-worker-openclaw-details/v1", status: "completed", source_result: retained.result,\n'
        b"      } };",
        b"      const retained = JSON.parse(rpc.content[0].text);\n"
        b"      sourceResult = retained.result;\n"
        b'      expect(transcript.message.details.status === "blocked", "native blocked details changed");\n'
        b'      nativeResult = { content: [{ type: "text", text: rpc.content[0].text }],\n'
        b"        details: structuredClone(transcript.message.details) };",
    ),
    (
        b'      schema: "aragorn/native-receipt-tool-driver/v1", status: "OBSERVED", tool_name: tool,',
        b'      schema: "aragorn/native-blocked-create-tool-driver/v1",\n'
        b'      authority: "OWNED_FIXTURE_TOOL_RELAY_OBSERVATION_NOT_SINK_ATTRIBUTION_OR_TIMING",\n'
        b'      status: "OBSERVED", container_id: container, tool_name: tool,',
    ),
    (
        b"      native_projection: { params: projection(params), result: projection(nativeResult) },",
        b"      native_projection: { params: projection(params), result: projection(nativeResult) },\n"
        b"      native_callback: { params_json: JSON.stringify(params), result_json: JSON.stringify(nativeResult) },\n"
        b"      worker_request: retainedDocument(base, observedRequest), source_result: retainedDocument(base, sourceResult),\n"
        b"      transcript_checks: transcriptChecks,\n"
        b"      sink_observed: false, attribution_verified: false, elapsed_time_derived: false,",
    ),
    (
        b"async function main() {\n"
        b'  expect(process.argv.length === 5 && ["read", "create"].includes(process.argv[2]), "usage: native-receipt-driver read|create INPUT OUTPUT");',
        b"function ownedFixture(container) {\n"
        b'  expect(typeof container === "string" && /^[0-9a-f]{64}$/.test(container), "owned container identifier changed");\n'
        b'  const path = "/proc/1/cgroup";\n'
        b"  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);\n"
        b"  try {\n"
        b"    const before = fstatSync(fd);\n"
        b"    expect(before.isFile() && before.uid === 0 && before.gid === 0 && before.nlink === 1 &&\n"
        b'      (before.mode & 0o7777) === 0o444, "owned fixture cgroup custody changed");\n'
        b"    const buffer = Buffer.alloc(1025);\n"
        b"    let count = 0;\n"
        b"    while (count < buffer.length) {\n"
        b"      const size = readSync(fd, buffer, count, buffer.length - count, null);\n"
        b"      if (!size) break;\n"
        b"      count += size;\n"
        b"    }\n"
        b"    const after = fstatSync(fd), named = lstatSync(path);\n"
        b'    for (const key of ["dev", "ino", "mode", "uid", "gid", "nlink"]) {\n'
        b'      expect(before[key] === after[key] && after[key] === named[key], "owned fixture cgroup identity changed");\n'
        b"    }\n"
        b"    expect(count > 0 && count <= 1024 && buffer.subarray(0, count).equals(\n"
        b'      Buffer.from(`0::/docker/${container}/init.scope\\n`, "ascii")), "exact owned fixture required");\n'
        b"  } finally { closeSync(fd); }\n"
        b"}\n\n"
        b"function retainedDocument(base, document) {\n"
        b'  const raw = Buffer.from(base.canonicalJson(document), "ascii");\n'
        b'  expect(document !== null && raw.length > 0 && raw.length <= 65536, "retained native document exceeded bound");\n'
        b"  return { document, bytes: raw.length, digest: sha(raw) };\n"
        b"}\n\n"
        b"async function main() {\n"
        b'  expect(process.argv.length === 6 && process.argv[2] === "blocked-create", "usage: native-blocked-create-driver blocked-create CONTAINER INPUT OUTPUT");',
    ),
    (
        b'  expect(process.platform === "linux" && process.geteuid() === 0 && process.version === "v24.16.0", "owned Linux fixture required");\n  const base = await legacyHelpers();',
        b'  expect(process.platform === "linux" && process.geteuid() === 0 && process.version === "v24.16.0", "owned Linux fixture required");\n'
        b"  ownedFixture(process.argv[3]);\n"
        b"  const base = await legacyHelpers();",
    ),
    (
        b"  const input = base.readInput(process.argv[3]);\n"
        b"  const result = await run(base, process.argv[2], input);\n"
        b"  base.publish(process.argv[4], result);",
        b"  const input = base.readInput(process.argv[4]);\n"
        b"  const result = await run(base, process.argv[2], input, process.argv[3]);\n"
        b"  base.publish(process.argv[5], result);",
    ),
    (
        b'main().catch(() => { process.stderr.write("native receipt fixture driver refused\\n"); process.exitCode = 1; });',
        b'main().catch(() => { process.stderr.write("native blocked-create fixture driver refused\\n"); process.exitCode = 1; });',
    ),
)


class NativeBlockedCreateDriverError(ValueError):
    """A pinned source, exact transformation or absent publication changed."""


def _transform(native_raw: bytes, legacy_raw: bytes) -> bytes:
    for name, raw in ((_SOURCE, native_raw), (_LEGACY, legacy_raw)):
        if type(raw) is not bytes or (len(raw), overlay._digest(raw)) != _INPUTS[name]:
            raise NativeBlockedCreateDriverError("fixed driver source changed")
    original = native_raw
    for before, after in _REPLACEMENTS:
        if native_raw.count(before) != 1:
            raise NativeBlockedCreateDriverError("blocked driver anchor changed")
        native_raw = native_raw.replace(before, after)
    restored = native_raw
    for before, after in reversed(_REPLACEMENTS):
        if restored.count(after) != 1:
            raise NativeBlockedCreateDriverError("blocked driver inverse changed")
        restored = restored.replace(after, before)
    if restored != original:
        raise NativeBlockedCreateDriverError("blocked driver is not reversible")
    return native_raw


def _verified_source() -> bytes:
    for name, pin in _DEPENDENCIES.items():
        overlay._read_pinned(name, *pin, root=_ROOT)
    raw = _transform(
        *(
            overlay._read_pinned(name, *_INPUTS[name], root=_ROOT)
            for name in (_SOURCE, _LEGACY)
        )
    )
    if (len(raw), overlay._digest(raw)) != _OUTPUT:
        raise NativeBlockedCreateDriverError("blocked driver output pin changed")
    return raw


def materialize_runtime_native_blocked_create_driver(output: Path) -> dict:
    """Publish a fixed source artifact, not a captured workload or effect proof."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise NativeBlockedCreateDriverError("output must be absolute and absent")
        raw = _verified_source()
        overlay._write_overlay(output, {_OUTPUT_NAME: raw}, ())
        if _verified_source() != raw:
            raise NativeBlockedCreateDriverError(
                "driver source changed after publication"
            )
        return {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "files": [
                {
                    "name": _OUTPUT_NAME,
                    "bytes": len(raw),
                    "digest": _OUTPUT[1],
                    "mode": "0444",
                }
            ],
            "source_inputs": [
                {"name": name, "bytes": pin[0], "digest": pin[1]}
                for name, pin in _INPUTS.items()
            ],
            "required_checkout_dependencies_not_included": [
                {"name": name, "bytes": pin[0], "digest": pin[1]}
                for name, pin in _DEPENDENCIES.items()
            ],
            "driver_schema": DRIVER_SCHEMA,
            "driver_authority": DRIVER_AUTHORITY,
            "standalone_executable": False,
            "capture_performed": False,
            "production_activation_eligible": False,
            "sink_observed": False,
            "attribution_verified": False,
            "elapsed_time_derived": False,
            "run_eligible": False,
            "phase3_eligible": False,
            "limitations": [
                "REQUIRES_EXACT_OWNED_NETWORK_ISOLATED_FIXTURE_AND_CALLER_GUARDS",
                "REQUIRES_REAL_SAME_ACTION_DENIAL_PREREQUISITE_NOT_CREATED_BY_DRIVER",
                "FIXED_TARGET_AND_PAYLOAD_ONE_CHAT_SEND_NO_ACTION_RETRY",
                "REQUEST_RECONSTRUCTION_BOUND_BY_RESULT_DIGEST_NOT_WORKER_WIRE_CAPTURE",
                "NATIVE_CALLBACK_JSON_IS_SOURCE_DERIVED_NOT_ACK_WIRE_CAPTURE",
                "REQUIRES_INDEPENDENT_RECEIPT_SINK_ATTRIBUTION_AND_COMMON_CLOCK_JOINS",
                "NO_TIMING_RUN_ADMISSION_OR_PHASE3_QUALIFICATION",
            ],
        }
    except (OSError, TypeError, ValueError) as exc:
        raise NativeBlockedCreateDriverError(
            "cannot materialize blocked-create driver"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    report = materialize_runtime_native_blocked_create_driver(
        parser.parse_args().output
    )
    print(json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
