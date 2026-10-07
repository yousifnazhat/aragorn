"""Compose the fixed HTTP worker/sensor/capability successor in an inert DESTDIR.

Frozen create implementations and evidence remain unchanged. Only this successor
admits the finite lab HTTP schema. Staging is neither activation nor a live test.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from scripts import stage_runtime_phase3_ingress_profile as predecessor
from scripts import materialize_runtime_http_ingress as ingress
from scripts import materialize_runtime_http_capability as capability
from scripts import materialize_runtime_http_collection as collection
from aragorn import native_phase3_http_collection as native_collection

base = predecessor.base
_PARENT = "scripts/stage_runtime_phase3_ingress_profile.py"
_ACTIVATOR = predecessor._ACTIVATOR
_CAP_ACTIVATOR = "packaging/activate-runtime-capability-host.sh"
_BROKER_UNIT = (
    "packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service"
)
_WORKER_UNIT = "packaging/systemd/aragorn-runtime-action-worker.service"
_MEASUREMENT = "src/aragorn/runtime_broker_decision_measurement.py"
_CREDENTIAL_READER = "src/aragorn/runtime_action_service.py"
_MEASUREMENT_SERVICE = "src/aragorn/runtime_action_service_v5.py"
_CREDENTIAL = "/etc/aragorn/runtime-http-fixture.json"
_SCHEMA = "aragorn/runtime-phase3-http-staged-profile/v1"
# Filled from the reviewed new source set before the first selected stage run.
_SOURCE_PINS = {
    "benchmark/admission/openclaw-v2026.7.1/native-receipt-read-create-driver-v1.mjs": (
        13884,
        "sha256:a34452c8ef7ee1fa9257848759fdb7f3f045b93ac7bc0e59cc5727129b257cbc",
    ),
    "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json": (
        2160,
        "sha256:2855474d8b709654fb8902c0dc69ec1f0a3a378518ec23bfb12c1eb9630824ab",
    ),
    "benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs": (
        39431,
        "sha256:e6e1803e9593d8c1bcb1ad4a3fdf2cb5c3657f1b4bd06e65470b8ad16e9e0140",
    ),
    "scripts/materialize_runtime_http_capability.py": (
        9421,
        "sha256:64fdf59445c7a5ff76abedc0638f97b640e06b3bc4d7c03c2bf83b032804f56e",
    ),
    "scripts/materialize_runtime_http_collection.py": (
        5345,
        "sha256:978cdd411f1b3f883310e7a5a5eb904443d24337c5d7392ef769075c71b743d7",
    ),
    "scripts/materialize_runtime_http_ingress.py": (
        18318,
        "sha256:a49b2200ddb7a4f902d0e536a382a2a2b438cb144a52765dba6e57b07ff5fe0a",
    ),
    "scripts/stage_runtime_phase3_ingress_profile.py": (
        15371,
        "sha256:758f650169d286bfff133c591444e8416c4abce70def1b74050f712475473022",
    ),
    "src/aragorn/native_phase3_clock_domain_verify.py": (
        8800,
        "sha256:939d47e99874e13a375280eea6586d1537d5a09d6e1585453c1d13c49ce89361",
    ),
    "src/aragorn/native_phase3_http_canary.py": (
        6422,
        "sha256:4249256e60654e649b8beb435815f9ad5e3ed3da14ef3aeed5372aa7f9925d43",
    ),
    "src/aragorn/native_phase3_http_canary_contract.py": (
        9776,
        "sha256:bcdd7b92d3ddaddb4ab38ce5cabcdbd68c7f87c79a6251f81c1bb225313946c2",
    ),
    "src/aragorn/native_phase3_http_collection.py": (
        31523,
        "sha256:b5f76a060d635ff15b0022aa794055a2861dc7cb6e9172ead0a548c12bd51e86",
    ),
    "src/aragorn/native_phase3_http_collection_verify.py": (
        40268,
        "sha256:d19c8042dac3d84e3f9d0cd86442093755767d74a6e368346a7311a9af53e03a",
    ),
    "src/aragorn/native_phase3_http_fixture.py": (
        5848,
        "sha256:49c2d801c4e27dca73336042a76e1c47daf8532cbb4553a0c318410dcb246d64",
    ),
    "src/aragorn/native_phase3_http_sink.py": (
        10254,
        "sha256:06e81234b1576f484cf3a9ab39a6db6d48bc6e74d249106da3628200dd4c1a5b",
    ),
    "src/aragorn/runtime_broker_decision_measurement_verify.py": (
        21956,
        "sha256:0354718223c4f65d2d92908817a0ac29dc3f6e5fcc873933eee8afa65672860f",
    ),
    "src/aragorn/runtime_broker_effective_receipt_verify.py": (
        16027,
        "sha256:a8441ec4098d119677b29b3644f5040d6301b29e2c600ca090f90417c1399cfa",
    ),
    "src/aragorn/runtime_broker_measurement_plan.py": (
        13206,
        "sha256:5789d265c779ad4d5674d7dabe0cd65a289274da6663369d5d17a8557fa78c30",
    ),
    "src/aragorn/runtime_http_action.py": (
        21866,
        "sha256:823ffdcaf114bdc8bcd7ca43009f67d6bf46969d4a27856e104ceedc979b0ac5",
    ),
    "src/aragorn/runtime_http_broker.py": (
        18373,
        "sha256:fff489d9a315d53c79bd44f6266465788e55876d2e14e363d84713857f0b9d50",
    ),
    "src/aragorn/runtime_http_capability.py": (
        13577,
        "sha256:3ec5d0b7d213a0ebaf24f06c6ef94d405ba38b187ec4d1be0d1d5e1391d5391e",
    ),
    "src/aragorn/runtime_http_ingress.py": (
        7919,
        "sha256:394b02ce5e8497d754db449d54157a58ad1df2893463e28baf4b471fcc41faea",
    ),
    "src/aragorn/runtime_http_provisioning.py": (
        6369,
        "sha256:d02ee8fb3f535ab4c3925f26bed134cb319548c63ab7d9056fec3415bc37b6bc",
    ),
    "src/aragorn/runtime_worker_ingress_verify.py": (
        18483,
        "sha256:e99f84c0f412b2b2fdec5cca17e438cb6108d85eb3026a528b7b72d8fe8c7252",
    ),
}
_RUNTIME_HELPERS = (
    "src/aragorn/native_phase3_http_canary_contract.py",
    "src/aragorn/native_phase3_http_fixture.py",
    "src/aragorn/native_phase3_http_sink.py",
    "src/aragorn/native_phase3_http_canary.py",
    "src/aragorn/runtime_http_action.py",
    "src/aragorn/runtime_http_broker.py",
    "src/aragorn/runtime_http_ingress.py",
    "src/aragorn/runtime_http_capability.py",
    "src/aragorn/runtime_http_provisioning.py",
    "src/aragorn/native_phase3_http_collection.py",
    "src/aragorn/native_phase3_http_collection_verify.py",
    "src/aragorn/runtime_worker_ingress_verify.py",
    "src/aragorn/native_phase3_clock_domain_verify.py",
    "src/aragorn/runtime_broker_measurement_plan.py",
    "src/aragorn/runtime_broker_decision_measurement_verify.py",
    "src/aragorn/runtime_broker_effective_receipt_verify.py",
    ingress.GATEWAY_CONFIG,
    native_collection.NATIVE_SOURCE,
    native_collection.LEGACY_SOURCE,
)
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
_ACTIVATION_GUARD = b"""# No host networking: require the exact stopped owned loopback fixture.
require_unit_value "$broker_unit" PrivateNetwork no
require_unit_value "$broker_unit" RestrictAddressFamilies "AF_INET AF_NETLINK AF_UNIX"
case "$(unit_property "$broker_unit" IPAddressDeny)" in
    "0.0.0.0/0 ::/0"|"::/0 0.0.0.0/0") ;;
    *) fail_activation "HTTP broker effective IP deny inventory changed" ;;
esac
require_unit_value "$broker_unit" IPAddressAllow "127.0.0.1/32"
if ! /usr/bin/python3.12 -I -S -B -c 'import sys; sys.path.insert(0,"/usr/lib/aragorn"); from aragorn.runtime_http_provisioning import validate_activation_fixture; validate_activation_fixture()'
then
    fail_activation "HTTP fixture credential or isolation guard refused"
fi
"""
_EARLY_GUARD = b"""# Refuse outside the stopped owned fixture before locks, traps or service writes.
if ! /usr/bin/python3.12 -I -S -B -c 'import sys; sys.path.insert(0,"/usr/lib/aragorn"); from aragorn.runtime_http_provisioning import validate_activation_fixture; validate_activation_fixture()'
then
    echo "HTTP owned stopped fixture required before activation" >&2
    exit 1
fi
"""


class Phase3HttpStageError(ValueError):
    """The finite common successor cannot preserve its source/custody boundary."""


def _replace(raw, before, after):
    if raw.count(before) != 1 or before == after or after in raw:
        raise Phase3HttpStageError("HTTP source anchor changed")
    changed = raw.replace(before, after)
    if changed.replace(after, before) != raw:
        raise Phase3HttpStageError("HTTP replacement is not reversible")
    return changed


def _destination(name):
    if name == ingress.GATEWAY_CONFIG:
        return "opt/aragorn/runtime-http-gateway-template.json", 0o444
    if name == native_collection.NATIVE_SOURCE:
        return native_collection.DRIVER_PATH.lstrip("/"), 0o444
    if name == native_collection.LEGACY_SOURCE:
        return native_collection.LEGACY_PATH.lstrip("/"), 0o555
    if name.startswith("scripts/runtime_native_http_"):
        return "opt/aragorn/" + Path(name).name, 0o444
    return predecessor._destination(name)


def _unit(raw, *, broker):
    condition = b"ConditionPathExists=" + _CREDENTIAL.encode() + b"\n"
    raw = _replace(raw, b"[Service]\n", condition + b"\n[Service]\n")
    raw = _replace(
        raw,
        b"ProtectSystem=strict\n",
        b"ProtectSystem=strict\nReadOnlyPaths=" + _CREDENTIAL.encode() + b"\n",
    )
    if broker:
        raw = _replace(raw, b"PrivateNetwork=yes\n", b"PrivateNetwork=no\n")
        # libc if_nameindex uses a read-only route-netlink inventory. All
        # capabilities remain empty; only the exact loopback fixture is accepted.
        raw = _replace(
            raw,
            b"RestrictAddressFamilies=AF_UNIX\n",
            b"RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\n",
        )
        raw = _replace(
            raw,
            b"IPAddressDeny=any\n",
            b"IPAddressDeny=any\nIPAddressAllow=127.0.0.1/32\n",
        )
    return raw


def extend_measurement_sources(raw):
    addition = b"".join(
        b'    "' + name.encode() + b'",\n' for name in HTTP_MEASUREMENT_SOURCES
    )
    return _replace(raw, b"_SOURCES = {\n", b"_SOURCES = {\n" + addition)


def _replace_pins(raw, old, new):
    """Replace only hashes of known installed sources named in this activator."""
    for name in sorted(set(old) & set(new)):
        if old[name] == new[name]:
            continue
        before = base.overlay._digest(old[name])[7:].encode()
        after = base.overlay._digest(new[name])[7:].encode()
        count = raw.count(before)
        if count:
            if count > 4 or after in raw:
                raise Phase3HttpStageError("HTTP activator pin multiplicity changed")
            changed = raw.replace(before, after)
            if changed.replace(after, before) != raw:
                raise Phase3HttpStageError("HTTP activator pin inverse changed")
            raw = changed
    return raw


def _verified_payloads():
    if predecessor._ROOT != _ROOT or not _SOURCE_PINS:
        raise Phase3HttpStageError("HTTP source closure missing")
    inputs = {
        name: base.overlay._read_pinned(name, *pin, root=_ROOT)
        for name, pin in _SOURCE_PINS.items()
    }
    inherited, overrides = predecessor._verified_payloads()
    original = inherited | overrides
    if len(original) != 74:
        raise Phase3HttpStageError("HTTP predecessor inventory changed")
    old = {source: raw for source, _, raw in original.values()}
    if len(old) != len(original):
        raise Phase3HttpStageError("HTTP predecessor duplicate source")
    rendered = dict(old)
    touched = set()
    for renderer in (ingress, capability):
        changed = renderer.render(dict(old))
        if not changed or set(changed) & touched or not set(changed) <= set(old):
            raise Phase3HttpStageError("HTTP renderer ownership changed")
        rendered.update(changed)
        touched.update(changed)
    for name in _RUNTIME_HELPERS:
        if name in rendered:
            raise Phase3HttpStageError("HTTP helper already exists")
        rendered[name] = inputs[name]
    if collection.HTTP_MEASUREMENT_SOURCES != HTTP_MEASUREMENT_SOURCES:
        raise Phase3HttpStageError("HTTP measurement inventory disagreement")
    collected = collection.render({**old, **inputs})
    if set(collected) & touched or set(collected) != set(collection.INPUTS):
        raise Phase3HttpStageError("HTTP collector ownership changed")
    rendered.update(collected)
    template = ingress.render_gateway_configuration(inputs[ingress.GATEWAY_CONFIG])
    canonical = json.dumps(
        json.loads(template),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if template != canonical + b"\n":
        raise Phase3HttpStageError("HTTP gateway template encoding changed")
    # The fresh protected writer and worker preflight require canonical bytes,
    # unlike the source template whose final newline is retained in its input pin.
    rendered[ingress.GATEWAY_CONFIG] = canonical
    rendered[native_collection.NATIVE_SOURCE] = (
        native_collection.render_native_http_driver(inputs)
    )
    rendered[_BROKER_UNIT] = _unit(old[_BROKER_UNIT], broker=True)
    rendered[_WORKER_UNIT] = _unit(old[_WORKER_UNIT], broker=False)
    rendered[_MEASUREMENT] = extend_measurement_sources(old[_MEASUREMENT])
    reader = _replace(
        old[_CREDENTIAL_READER],
        b"    label: str,\n) -> bytes:\n",
        b"    label: str,\n    max_bytes: int = _MAX_CREDENTIAL_BYTES,\n) -> bytes:\n"
        b'    if type(max_bytes) is not int or max_bytes not in {_MAX_CREDENTIAL_BYTES, 8192} or (max_bytes != _MAX_CREDENTIAL_BYTES and label != "decision measurement binding"):\n'
        b'        raise RuntimeActionServiceError("credential size boundary refused")\n',
    )
    for before, after in (
        (b"before.st_size > _MAX_CREDENTIAL_BYTES", b"before.st_size > max_bytes"),
        (
            b"os.read(descriptor, _MAX_CREDENTIAL_BYTES + 1)",
            b"os.read(descriptor, max_bytes + 1)",
        ),
        (b"len(raw) > _MAX_CREDENTIAL_BYTES", b"len(raw) > max_bytes"),
    ):
        reader = _replace(reader, before, after)
    rendered[_CREDENTIAL_READER] = reader
    rendered[_MEASUREMENT_SERVICE] = _replace(
        old[_MEASUREMENT_SERVICE],
        b'_read_credential_bytes(measurement_path, broker_uid, label="decision measurement binding")',
        b'_read_credential_bytes(measurement_path, broker_uid, label="decision measurement binding", max_bytes=8192)',
    )
    rendered[_MEASUREMENT] = _replace(
        rendered[_MEASUREMENT],
        b"_require(_PLAN is None and type(raw) is bytes and 0 < len(raw) <= 4096)",
        b"_require(_PLAN is None and type(raw) is bytes and 0 < len(raw) <= 8192)",
    )
    rendered[_MEASUREMENT] = _replace(
        rendered[_MEASUREMENT],
        b'if result.get("effect_status") == "CREATED":',
        b'if result.get("effect_status") in {"CREATED", "SENT"}:',
    )
    rendered[_MEASUREMENT] = _replace(
        rendered[_MEASUREMENT],
        b'profiled = {**legacy, "schema": "aragorn/runtime-observed-create-submission/v2", "runtime_attribution": attribution}',
        b'profiled = {**legacy, "schema": ("aragorn/runtime-observed-http-submission/v2" if legacy.get("schema") == "aragorn/runtime-observed-http-submission/v1" else "aragorn/runtime-observed-create-submission/v2"), "runtime_attribution": attribution}',
    )
    # The subordinate activator is pinned by the worker activator, so update it first.
    rendered[_CAP_ACTIVATOR] = _replace_pins(old[_CAP_ACTIVATOR], old, rendered)
    activator = _replace_pins(old[_ACTIVATOR], old, rendered)
    activator = _replace(
        activator,
        b"require_root_secret /etc/aragorn/runtime-broker-decision-measurement.json 4096\n",
        b"require_root_secret /etc/aragorn/runtime-broker-decision-measurement.json 8192\n",
    )
    activator = _replace(
        activator,
        b"export PATH LANG LC_ALL TZ\n",
        b"export PATH LANG LC_ALL TZ\n\n" + _EARLY_GUARD,
    )
    activator = _replace(
        activator,
        base.activation._CONFIG_DIGEST.encode(),
        base.overlay._digest(rendered[ingress.GATEWAY_CONFIG])[7:].encode(),
    )
    additions = []
    for name in sorted(set(rendered) - set(old)):
        destination, mode = _destination(name)
        additions.append(
            f"{mode:o} {base.overlay._digest(rendered[name])[7:]} /{destination}\n".encode()
        )
    activator = _replace(activator, b"\nEOF\n", b"\n" + b"".join(additions) + b"EOF\n")
    activator = _replace(
        activator,
        predecessor._ACTIVATION_ANCHOR,
        _ACTIVATION_GUARD + predecessor._ACTIVATION_ANCHOR,
    )
    rendered[_ACTIVATOR] = activator
    replacements = {
        _destination(name)[0]: (name, _destination(name)[1], raw)
        for name, raw in rendered.items()
        if old.get(name) != raw
    }
    return original, replacements, inputs


def stage_runtime_phase3_http_profile(output):
    """Install exact successor bytes only under one fresh caller-owned DESTDIR."""
    if (
        not isinstance(output, Path)
        or not output.is_absolute()
        or output.exists()
        or output.is_symlink()
    ):
        raise Phase3HttpStageError("HTTP DESTDIR must be absolute and absent")
    custody = base._parent_custody(output.parent)
    original, replacements, inputs = _verified_payloads()
    report = predecessor.stage_runtime_phase3_ingress_profile(output)
    base._audit_tree(output, original)
    final = original | replacements
    for directory in sorted(
        base._directories(final) - base._directories(original),
        key=lambda x: (x.count("/"), x),
    ):
        (output / directory).mkdir(mode=0o755)
    base._apply_overrides(output, replacements)
    base._audit_tree(output, final)
    if (
        _verified_payloads() != (original, replacements, inputs)
        or base._parent_custody(output.parent) != custody
    ):
        raise Phase3HttpStageError("HTTP staging custody changed")
    sources = {
        row["name"]: (row["bytes"], row["digest"]) for row in report["source_inputs"]
    }
    for name, pin in _SOURCE_PINS.items():
        if name in sources and sources[name] != pin:
            raise Phase3HttpStageError("HTTP conflicting source pin")
        sources[name] = pin
    return {
        **report,
        "schema": _SCHEMA,
        "http_paths_staged": True,
        "http_fixture_provisioned": False,
        "http_runtime_activated": False,
        "http_collected": False,
        "gateway_config_digest_required_not_included": base.overlay._digest(
            final[_destination(ingress.GATEWAY_CONFIG)[0]][2]
        ),
        "http_gateway_template": "/" + _destination(ingress.GATEWAY_CONFIG)[0],
        "measurement_source_names": sorted(
            set(report["binding_source_pins"]) | set(HTTP_MEASUREMENT_SOURCES)
        ),
        "binding_source_pins": {
            name: base.overlay._digest(final[_destination("src/aragorn/" + name)[0]][2])
            for name in set(report["binding_source_pins"])
            | set(HTTP_MEASUREMENT_SOURCES)
        },
        "files": [
            {
                "path": "/" + path,
                "source_name": name,
                "mode": f"{mode:04o}",
                "bytes": len(raw),
                "digest": base.overlay._digest(raw),
            }
            for path, (name, mode, raw) in sorted(final.items())
        ],
        "source_inputs": [
            {"name": name, "bytes": pin[0], "digest": pin[1]}
            for name, pin in sorted(sources.items())
        ],
        "directories": sorted(base._directories(final)),
        "new_dependencies": [
            {"name": name, "bytes": len(raw), "digest": base.overlay._digest(raw)}
            for name, _, raw in sorted(final.values())
            if name not in {v[0] for v in original.values()}
            or name in {row["name"] for row in report["new_dependencies"]}
        ],
        "missing_inputs": report["missing_inputs"]
        + [
            "exact owned network-none fixture and absent-only HTTP credential provisioning before activation",
            "new installed identity/clock joins, broker-restricted readiness, real HTTP collection and independent sink replay",
            "no live qualification or final acceptance from staging or inert checks",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    report = stage_runtime_phase3_http_profile(parser.parse_args().output)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
