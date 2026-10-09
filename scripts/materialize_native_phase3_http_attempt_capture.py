"""Finite HTTP94 input/host assembly over the retained common capture lifecycle.

Original signed sources and generated installation bytes remain separate. This
renderer never starts a VM, installs a service or evaluates generated Python.
"""

from __future__ import annotations

import hashlib

HOST = "scripts/capture_native_phase3_common_attempt.py"
INPUT = "src/aragorn/native_phase3_common_attempt_inputs.py"
SELF = "scripts/materialize_native_phase3_http_attempt_capture.py"
LAUNCHER = "scripts/capture_native_phase3_http_attempt.py"
INPUTS = {
    HOST: (46033, "9f0d59428aa692c193c180c37285a1ce52d458d473ebbb54fa698c2aa912cf05"),
    INPUT: (12772, "dd834dd99d70ed6f0d12477f6c3cf9588a9970b760a1c8e32cb5db41950cfc42"),
}
HTTP_MODULES = (
    "native_phase3_http_collection",
    "native_phase3_http_collection_verify",
    "native_phase3_http_broker_ready_capture",
    "native_phase3_http_readiness_verify",
    "native_phase3_http_fixture",
    "native_phase3_http_sink",
)
# Host-only semantic replay dependencies, in their import order. These bytes
# belong to the pinned HTTP94 stage, not to the generated fixture helper set.
PRIVATE_STAGED_SOURCES = (
    "src/aragorn/runtime_http_capability.py",
    "src/aragorn/runtime_action_broker_v2.py",
    "src/aragorn/runtime_capability_grant.py",
    "src/aragorn/runtime_action_broker_v3.py",
    "src/aragorn/runtime_action_broker_v4.py",
    "src/aragorn/native_phase3_http_collection_verify.py",
)
STAGE_OWNED = {
    "src/aragorn/runtime_broker_measurement_plan.py",
    "src/aragorn/runtime_broker_effective_receipt_verify.py",
    "src/aragorn/runtime_worker_ingress_verify.py",
    "src/aragorn/native_phase3_clock_domain_verify.py",
    "src/aragorn/native_phase3_http_collection.py",
    "src/aragorn/native_phase3_http_collection_verify.py",
    "src/aragorn/native_phase3_http_fixture.py",
    "src/aragorn/native_phase3_http_sink.py",
}


def _change(raw, before, after, count=1):
    before, after = before.encode(), after.encode()
    if before == after or raw.count(before) != count:
        raise ValueError("HTTP host/input anchor changed: " + before[:100].decode())
    return raw.replace(before, after)


def _section(raw, start, end, replacement):
    left, right = start.encode(), end.encode()
    if raw.count(left) != 1 or raw.count(right) != 1:
        raise ValueError("HTTP host/input section changed")
    return _change(raw, raw[raw.index(left) : raw.index(right)].decode(), replacement)


def components():
    from scripts import materialize_native_phase3_http_ready_setup_capture as setup
    from scripts import materialize_native_phase3_http_attempt as guest
    from scripts import materialize_native_phase3_http_attempt_evidence as evidence
    from scripts import materialize_native_phase3_http_attempt_plan as plan

    return setup, guest, evidence, plan


def generated_paths():
    setup, guest, evidence, plan = components()
    return tuple(
        sorted(
            set(setup.GENERATED_SOURCES)
            | set(guest.INPUTS)
            | set(evidence.INPUTS)
            | set(plan.INPUTS)
            | set(INPUTS)
        )
    )


def renderer_paths():
    setup, _, _, _ = components()
    return tuple(
        sorted(
            set(setup.RENDERER_SOURCES)
            | {
                SELF,
                LAUNCHER,
                "scripts/materialize_native_phase3_http_attempt.py",
                "scripts/materialize_native_phase3_http_attempt_evidence.py",
                "scripts/materialize_native_phase3_http_attempt_plan.py",
            }
        )
    )


def source_paths():
    from aragorn import native_phase3_common_attempt_inputs as old
    from aragorn import native_phase3_common_setup_capture as old_setup
    from aragorn.native_phase3_http_collection import DRIVER_INPUTS

    setup, _, _, _ = components()
    return tuple(
        sorted(
            set(old.SOURCE_PATHS)
            | set(old_setup.SOURCE_PATHS)
            | set(generated_paths())
            | set(renderer_paths())
            | set(DRIVER_INPUTS)
            | set(setup.STAGE_OWNED)
            | set(PRIVATE_STAGED_SOURCES)
            | {"src/aragorn/" + name + ".py" for name in HTTP_MODULES}
            | {"scripts/stage_runtime_phase3_http_ready_profile.py"}
        )
    )


def _inputs(raw, original):
    from aragorn.native_phase3_http_collection import (
        DRIVER_INPUTS,
        DRIVER_PATH,
        render_native_http_driver,
    )

    driver = render_native_http_driver(original)
    report = {
        "schema": "aragorn/native-http-staged-driver/v1",
        "path": DRIVER_PATH,
        "mode": "0444",
        "bytes": len(driver),
        "digest": "sha256:" + hashlib.sha256(driver).hexdigest(),
        "stage_owned": True,
    }
    raw = _change(
        raw,
        'BUNDLE_SCHEMA = "aragorn/native-common-attempt-inputs/v1"',
        'BUNDLE_SCHEMA = "aragorn/native-http-attempt-inputs/v1"',
    )
    raw = _section(
        raw,
        "DRIVER_MATERIALIZER_SOURCE = (\n",
        "_SCRIPT_NAMES = (\n",
        f"DRIVER_SOURCE_PATHS = {tuple(DRIVER_INPUTS)!r}\nGENERATED_FILES = {{}}\nHTTP_DRIVER_REPORT = {report!r}\n\n",
    )
    raw = _change(
        raw,
        '    "native_phase3_common_attempt_inputs",\n',
        '    "native_phase3_common_attempt_inputs",\n'
        + "".join(f'    "{name}",\n' for name in HTTP_MODULES),
    )
    raw = _change(
        raw,
        "FIXTURE_HELPERS = base.FIXTURE_HELPERS | EXTRA_HELPERS",
        f"EXTRA_HELPERS = {{name: path for name, path in EXTRA_HELPERS.items() if name not in {tuple(sorted(STAGE_OWNED))!r}}}\n"
        "FIXTURE_HELPERS = base.FIXTURE_HELPERS | EXTRA_HELPERS",
    )
    raw = _section(
        raw,
        "EXTRA_SOURCE_PATHS = tuple(\n",
        "# A data-only mirror",
        f"SOURCE_PATHS = {source_paths()!r}\n"
        "EXTRA_SOURCE_PATHS = tuple(sorted(set(SOURCE_PATHS) - set(base.SOURCE_PATHS)))\n"
        f"GENERATED_SOURCES = {generated_paths()!r}\n\n",
    )
    raw = _change(
        raw,
        '    "/opt/aragorn/runtime_native_common_attempt.py",\n',
        '    "/opt/aragorn/runtime_native_common_attempt.py",\n'
        '    "/opt/aragorn/runtime-native-receipt-systemd-check.py",\n'
        + "".join(
            f'    "/usr/lib/aragorn/aragorn/{name}.py",\n' for name in HTTP_MODULES
        )
        + f'    "{DRIVER_PATH}",\n',
    )
    raw = _change(
        raw, "    source_raws,\n", "    source_raws,\n    generated_source_raws,\n"
    )
    raw = _change(
        raw,
        '        retained = dict(base_bound["input_blobs"])\n',
        "        _require(type(generated_source_raws) is dict\n"
        '            and set(generated_source_raws) == set(GENERATED_SOURCES), "generated source inventory changed")\n'
        '        _require(all(generated_source_raws[name] == value for name, value in base_bound["generated_source_raws"].items()),\n'
        '                 "nested generated source differs")\n'
        "        installed = sources | generated_source_raws\n"
        '        retained = dict(base_bound["input_blobs"])\n'
        "        generated_texts = {}\n"
        "        for name, value in generated_source_raws.items():\n"
        "            _require(name in sources and type(value) is bytes and 0 < len(value) <= MAX_SOURCE,\n"
        '                     "generated source bound changed")\n'
        '            generated_texts[name] = value.decode("utf-8")\n'
        "            retained[_digest(value)] = value\n",
    )
    raw = _change(
        raw,
        "        target_sources = {target: source for source, target in FIXTURE_HELPERS.items()}\n",
        "        target_sources = {target: source for source, target in FIXTURE_HELPERS.items()}\n"
        '        stage_pins = {row["path"]: row["digest"] for row in stage["files"]}\n',
    )
    raw = _change(
        raw,
        "            set(ATTEMPT_SOURCE_PATHS) <= set(target_sources),",
        "            set(ATTEMPT_SOURCE_PATHS) <= set(target_sources) | set(stage_pins),",
    )
    raw = _change(
        raw,
        "        bundle = {\n",
        '        driver_row = next(row for row in stage["files"] if row["path"] == HTTP_DRIVER_REPORT["path"])\n'
        '        _require(all(driver_row[key] == HTTP_DRIVER_REPORT[key] for key in ("path", "mode", "bytes", "digest")),\n'
        '                 "HTTP staged driver differs")\n'
        "        bundle = {\n",
    )
    raw = _change(
        raw,
        '            "sources": texts,\n',
        '            "sources": texts,\n            "generated_sources": generated_texts,\n',
    )
    raw = _change(
        raw,
        "        return {\n",
        '        common["http_attempt_id"] = base_bound["http_attempt_id"]\n'
        '        _require(common["http_attempt_id"] == plan["selected_attempt_id"], "selected HTTP attempt changed")\n'
        "        return {\n",
    )
    raw = _change(
        raw,
        '            "source_raws": sources,\n',
        '            "source_raws": sources,\n            "installed_source_raws": installed,\n'
        '            "generated_source_raws": generated_source_raws,\n',
    )
    raw = _change(
        raw,
        "                path: _digest(sources[target_sources[path]])\n",
        "                path: stage_pins[path] if path in stage_pins\n"
        "                else _digest(installed[target_sources[path]])\n",
    )
    raw = _change(
        raw,
        '            plan_arguments=value["plan_arguments"],\n',
        '            plan_arguments=value["plan_arguments"],\n'
        '            generated_source_raws={name: value.encode("utf-8") for name, value in value["generated_sources"].items()},\n',
    )
    return raw


def _host(raw):
    raw = _change(
        raw,
        "from scripts import materialize_runtime_native_blocked_create_driver as driver",
        "from scripts import materialize_native_phase3_http_attempt_capture as http_sources",
    )
    raw = _change(
        raw,
        '"aragorn/native-common-attempt-capture/v1"',
        '"aragorn/native-http-attempt-capture/v1"',
    )
    raw = _change(
        raw,
        '_DRIVER_PATH = "/opt/aragorn/native-blocked-create-driver-v1.mjs"',
        '_DRIVER_PATH = inputs.HTTP_DRIVER_REPORT["path"]',
    )
    raw = _change(
        raw,
        "list(_FILES.values()) + list(_ALIASES) + [_DRIVER_PATH]",
        "list(_FILES.values()) + list(_ALIASES)",
    )
    raw = _change(
        raw,
        "    return source\n",
        '    _require(http_sources.compose(bound["source_raws"]) == bound["generated_source_raws"],\n'
        '             "HTTP source derivation changed")\n    return source\n',
    )
    raw = _change(
        raw,
        "        source_raws=sources,\n",
        "        source_raws=sources,\n"
        '        generated_source_raws=http_sources.compose(base_bound["source_raws"] | sources),\n',
    )
    raw = _section(raw, "def _driver(output: Path)", "def _seal_program()", "")
    raw = _section(
        raw,
        "    helpers = {\n",
        "    parent = native.existing.campaign.current_v3_parent_identity()",
        "    helpers = base.contract.helper_records(bound, {\n"
        '        path: _API._tree_file(source["commit"], Path(path)) for path in _FILES\n'
        "    }, fixture_helpers=_FILES)\n"
        "    aliases = {target: dict(helpers[path], installed_path=target) for target, path in _ALIASES.items()}\n",
    )
    raw = _change(
        raw,
        "stage_runtime_phase3_ingress_profile(output)",
        "stage_runtime_phase3_http_ready_profile(output)",
    )
    raw = _change(
        raw,
        "original, replacements = profile._verified_payloads()",
        "original, replacements, _ = profile._verified_payloads()",
    )
    raw = _section(
        raw,
        "            generated, driver_path, driver_metadata = _driver(\n",
        "            payloads = {\n",
        '            result["generated_driver"] = dict(inputs.HTTP_DRIVER_REPORT)\n',
    )
    raw = _section(
        raw,
        "                for path, target in _FILES.items():\n",
        '                native.existing._docker("start", container)\n',
        '                generated_root = Path(directory).resolve() / "helpers"\n'
        "                generated_root.mkdir(mode=0o700)\n"
        "                for index, (target, path) in enumerate(\n"
        "                        [(target, path) for path, target in _FILES.items()] + list(_ALIASES.items())):\n"
        "                    local = generated_root / str(index)\n"
        '                    content = bound["installed_source_raws"][path]\n'
        "                    _API._write_output(local, content)\n                    local.chmod(0o444)\n"
        "                    pins._read_fixed(local, (len(content), _API._digest(content)))\n"
        '                    native.existing._docker("cp", str(local), container + ":" + target)\n'
        "                    pins._read_fixed(local, (len(content), _API._digest(content)))\n",
    )
    raw = _change(
        raw,
        "                    native._HEALTH_VERIFY,",
        "                    base._http_handoff_program(),",
    )
    raw = _change(
        raw,
        "payloads | helpers | aliases | {_DRIVER_PATH: driver_metadata}",
        "payloads | helpers | aliases",
    )
    raw = _change(
        raw,
        'json.dumps(stage["directories"])',
        'json.dumps(["/" + path for path in stage["directories"]])',
    )
    raw = _change(
        raw,
        '            "expected_sink_accounts",\n',
        '            "expected_sink_accounts",\n            "expected_http_sink_identity",\n            "expected_readiness_sink_identity",\n',
    )
    return raw


def render(original):
    outputs = {}
    for name, pin in INPUTS.items():
        raw = original[name]
        if type(raw) is not bytes or (len(raw), hashlib.sha256(raw).hexdigest()) != pin:
            raise ValueError("HTTP host/input predecessor changed")
        outputs[name] = _host(raw) if name == HOST else _inputs(raw, original)
    return outputs


def compose(original):
    setup, guest, evidence, plan = components()
    result = setup.compose(original)
    for extra in (
        guest.render(original),
        evidence.render(original),
        plan.render(original),
        render(original),
    ):
        if set(result).intersection(extra):
            raise ValueError("HTTP capture generated source overlap")
        result.update(extra)
    if set(result) != set(generated_paths()):
        raise ValueError("HTTP capture generated inventory changed")
    return result
