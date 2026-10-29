"""Render one opt-in measured broker successor without changing frozen sources."""

from __future__ import annotations

import itertools
from pathlib import Path

from scripts import stage_runtime_native_startup_profile as predecessor

_ROOT = Path(__file__).resolve().parents[1]
base = predecessor.base
_CORE = "src/aragorn/runtime_action_broker.py"
_GRANT = "src/aragorn/runtime_action_broker_v4.py"
_SERVICE = "src/aragorn/runtime_action_service_v5.py"
_UNIT = "packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service"
_BASE_ACTIVATOR = "packaging/activate-runtime-capability-host.sh"
_ACTIVATOR = predecessor._ACTIVATOR
_HELPER = "src/aragorn/runtime_broker_decision_measurement.py"
_PARENT = "scripts/stage_runtime_native_startup_profile.py"
_PARENT_PIN = (
    8299,
    "sha256:5da4968e024cdff144d445dfd694ea8b7697f6af871b34fc1e13e71391364d16",
)
_INPUTS = {
    _CORE: (
        79641,
        "sha256:94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21",
    ),
    _GRANT: (
        45748,
        "sha256:ab7d08105229ee3dd58f8dca5c20156d5e260e2b79f0ed2b4c08693c3cf6174a",
    ),
    _SERVICE: (
        4146,
        "sha256:a3e829d2e60f26dd91cbb14967ddf2a747414ce8f125b4f207dbce7a5e1e86c7",
    ),
    _UNIT: (
        2725,
        "sha256:e0273dbeb4ed40a203193a52eb6146f81ecbc6abca605fa0bfff69774676b2db",
    ),
    _BASE_ACTIVATOR: (
        12420,
        "sha256:b4ad162940d842e93ede73143f607cff4c612716334b66430d71b885f398984c",
    ),
    _ACTIVATOR: (
        41003,
        "sha256:14ffb65763714aea3ee7f5c3e2acb476888d4c71020cd6e86c32ed8740cb349b",
    ),
}
# Exact output and helper pins are frozen after the focused source review.
_ADDED = {
    _HELPER: (
        19164,
        "sha256:cb374ad8d1b7dc591fa554ab0590e8c39eb3ac287589ce26da67b4d5fc0e454e",
    ),
    "src/aragorn/phase3_deployment.py": (
        3882,
        "sha256:d4f4ce6e43dd59b85b84db88c502e8cb8b5180a38a9ecdb2ab58ef1e3033a9dd",
    ),
    "src/aragorn/phase3_quantitative_metrics.py": (
        25613,
        "sha256:09b3c3848ba7700efbb468f614b40a71e472ddbf116643fb280a564bdb50af2e",
    ),
}
_OUTPUTS = {
    _CORE: (
        80206,
        "sha256:b02b809c58a96957ccb539ad7d15fa34fe3e960c828a329fe7f3956e6ebf8354",
    ),
    _GRANT: (
        46172,
        "sha256:1d464c22cd90c34ea5e3748b3cabbbed0966883a0e70e6950d785a314fdeb411",
    ),
    _SERVICE: (
        4529,
        "sha256:d7582ba0aee9ab920764f640095fc870b735ac92fce4147b35cffafc2819eb1e",
    ),
    _UNIT: (
        2987,
        "sha256:861b5e2b982cdc457358dcaa1b0334a049cc739917cdecf0ffb1d89eaf1d706a",
    ),
    _BASE_ACTIVATOR: (
        14154,
        "sha256:649c601aef6f465c22541dc6442563af0da9a1ee3afc3b0646af5f27b799b9f9",
    ),
    _ACTIVATOR: (
        41455,
        "sha256:5b25d6f98e91392d119f1959fbb2f4c36800c619b2d1b3f6a37964db43261951",
    ),
}


class BrokerDecisionMeasurementRenderError(ValueError):
    """The exact successor cannot preserve its frozen predecessor."""


def _replace(raw: bytes, before: str, after: str) -> bytes:
    old, new = before.encode("ascii"), after.encode("ascii")
    if raw.count(old) != 1 or new == old:
        raise BrokerDecisionMeasurementRenderError("measurement source anchor changed")
    rendered = raw.replace(old, new)
    if rendered.count(new) != 1 or rendered.replace(new, old) != raw:
        raise BrokerDecisionMeasurementRenderError(
            "measurement replacement is not reversible"
        )
    return rendered


def _render(name: str, raw: bytes) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != _INPUTS.get(name):
        raise BrokerDecisionMeasurementRenderError(
            "measurement predecessor pin changed"
        )
    if name in {_CORE, _GRANT, _SERVICE}:
        raw = _replace(
            raw,
            "from __future__ import annotations\n",
            "from __future__ import annotations\n\nfrom . import runtime_broker_decision_measurement as _measurement\n",
        )
    if name == _CORE:
        raw = _replace(
            raw,
            '        ):\n            return _result(\n                request_digest=request_digest,\n                observation_digest=observation_digest,\n                target_name=target_name,\n                verdict="BLOCK",\n                reason_codes=["BROKER_REPLAY_BLOCKED"],',
            '        ):\n            _measurement.final_decision(request_digest, observation_digest, None, False, ["BROKER_REPLAY_BLOCKED"])\n            return _result(\n                request_digest=request_digest,\n                observation_digest=observation_digest,\n                target_name=target_name,\n                verdict="BLOCK",\n                reason_codes=["BROKER_REPLAY_BLOCKED"],',
        )
        raw = _replace(
            raw,
            '        if decision["verdict"] != "ALLOW" or broker_reasons:\n            return _result(',
            '        if decision["verdict"] != "ALLOW" or broker_reasons:\n            _measurement.final_decision(request_digest, observation_digest, decision, False, broker_reasons or decision["reason_codes"])\n            return _result(',
        )
        raw = _replace(
            raw,
            "        def record_pending(\n",
            "        def measured_authorize_link() -> bool:\n            allowed = authorize_link()\n            _measurement.final_decision(request_digest, final_observation_digest, final_decision, allowed, final_reasons)\n            return allowed\n\n        def record_pending(\n",
        )
        raw = _replace(
            raw,
            "            authorize_link=authorize_link,\n",
            "            authorize_link=measured_authorize_link,\n",
        )
    elif name == _GRANT:
        start = raw.index(b"def mediate_granted_profiled_runtime_create(\n")
        end = raw.index(b"\n\ndef recover_runtime_capability_grant(\n", start)
        original = raw[start:end].decode("ascii")
        head, tail = original.split("    claim = _build_claim(\n", 1)
        tail = "    claim = _build_claim(\n" + tail
        tail = tail.replace(
            "    return result\n",
            "    _measurement.retain(measurement, config, claim, result, deadline_monotonic)\n    return result\n",
        )
        replacement = (
            head
            + "    measurement = _measurement.begin(config, grant, legacy, attribution, submission_digest, lease, deadline_monotonic)\n    try:\n"
            + "".join(
                "    " + line if line.strip() else line
                for line in tail.splitlines(keepends=True)
            )
            + "    finally:\n        _measurement.close(measurement)\n"
        )
        raw = _replace(raw, original, replacement)
    elif name == _SERVICE:
        for before, after in (
            ("if len(arguments) != 2:", "if len(arguments) != 3:"),
            (
                '"RUNTIME_BINDING_CREDENTIAL CAPABILITY_GRANT_CREDENTIAL",',
                '"RUNTIME_BINDING_CREDENTIAL CAPABILITY_GRANT_CREDENTIAL MEASUREMENT_CREDENTIAL",',
            ),
            (
                "_run(Path(arguments[0]), Path(arguments[1]))",
                "_run(Path(arguments[0]), Path(arguments[1]), Path(arguments[2]))",
            ),
            (
                "def _run(runtime_binding_path: Path, capability_grant_path: Path) -> None:",
                "def _run(runtime_binding_path: Path, capability_grant_path: Path, measurement_path: Path) -> None:",
            ),
            (
                "    state = initialize_runtime_capability_grant(grant_broker)\n",
                '    measurement_path = _credential_path(measurement_path, broker_uid, credential_name="decision-measurement-binding")\n    _measurement.configure(_read_credential_bytes(measurement_path, broker_uid, label="decision measurement binding"), broker_uid)\n    state = initialize_runtime_capability_grant(grant_broker)\n',
            ),
        ):
            raw = _replace(raw, before, after)
    elif name == _UNIT:
        raw = _replace(
            raw,
            "LoadCredential=capability-grant:/etc/aragorn/runtime-capability-grant.json\n",
            "LoadCredential=capability-grant:/etc/aragorn/runtime-capability-grant.json\nLoadCredential=decision-measurement-binding:/etc/aragorn/runtime-broker-decision-measurement.json\nBindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/aragorn-broker-boot-id\n",
        )
        raw = _replace(
            raw,
            " %d/runtime-binding %d/capability-grant\n",
            " %d/runtime-binding %d/capability-grant %d/decision-measurement-binding\n",
        )
        raw = _replace(
            raw,
            "InaccessiblePaths=/etc/aragorn/runtime-action-runtime.json /etc/aragorn/runtime-capability-grant.json\n",
            "InaccessiblePaths=/etc/aragorn/runtime-action-runtime.json /etc/aragorn/runtime-capability-grant.json /etc/aragorn/runtime-broker-decision-measurement.json\n",
        )
    elif name == _BASE_ACTIVATOR:
        raw = _replace(
            raw,
            'service-v5.py %d/runtime-binding %d/capability-grant"',
            'service-v5.py %d/runtime-binding %d/capability-grant %d/decision-measurement-binding"',
        )
        raw = _replace(
            raw,
            'service-v5.py /run/credentials/$new_broker/runtime-binding /run/credentials/$new_broker/capability-grant"',
            'service-v5.py /run/credentials/$new_broker/runtime-binding /run/credentials/$new_broker/capability-grant /run/credentials/$new_broker/decision-measurement-binding"',
        )
        old = """    case "$verified_credentials" in
        "$verified_expected_credentials"|"$verified_reverse_credentials")
            ;;
        *)
            fail_activation "effective LoadCredential is unsafe for $verified_unit"
            ;;
    esac
"""
        values = (
            '\\"runtime-binding\\" \\"/etc/aragorn/runtime-action-runtime.json\\"',
            '\\"capability-grant\\" \\"/etc/aragorn/runtime-capability-grant.json\\"',
            '\\"decision-measurement-binding\\" \\"/etc/aragorn/runtime-broker-decision-measurement.json\\"',
        )
        cases = "|".join(
            '"a(ss) 3 ' + " ".join(order) + '"'
            for order in itertools.permutations(values)
        )
        new = (
            '    if [ "$verified_unit" = "$new_broker" ]; then\n        case "$verified_credentials" in\n            '
            + cases
            + ') ;;\n            *) fail_activation "measurement credential inventory changed" ;;\n        esac\n    else\n'
            + "".join("    " + line for line in old.splitlines(keepends=True))
            + "    fi\n"
        )
        raw = _replace(raw, old, new)
    else:
        raise BrokerDecisionMeasurementRenderError("unsupported measured source")
    return raw


def _render_activator(raw: bytes, replacements: dict) -> bytes:
    if (len(raw), base.overlay._digest(raw)) != _INPUTS[_ACTIVATOR]:
        raise BrokerDecisionMeasurementRenderError("native activator pin changed")
    for name, original_pin in _INPUTS.items():
        if name == _ACTIVATOR:
            continue
        destination, _ = predecessor._destination(name)
        old = original_pin[1][7:]
        new = base.overlay._digest(replacements[destination][2])[7:]
        raw = _replace(raw, old, new)
    raw = _replace(
        raw,
        "require_root_secret /etc/aragorn/runtime-native-tool-genesis.json 4096\n",
        "require_root_secret /etc/aragorn/runtime-native-tool-genesis.json 4096\nrequire_root_secret /etc/aragorn/runtime-broker-decision-measurement.json 4096\n",
    )
    lines = "".join(
        f"{predecessor._destination(name)[1]:o} {pin[1][7:]} /{predecessor._destination(name)[0]}\n"
        for name, pin in sorted(_ADDED.items())
    )
    return _replace(raw, "\nEOF\n", "\n" + lines + "EOF\n")


def _verified_payloads():
    base.overlay._read_pinned(_PARENT, *_PARENT_PIN, root=_ROOT)
    inherited, overrides = predecessor._verified_payloads()
    original = inherited | overrides
    replacements = {}
    for name in _INPUTS.keys() - {_ACTIVATOR}:
        destination, mode = predecessor._destination(name)
        replacements[destination] = (
            name,
            mode,
            _render(name, original[destination][2]),
        )
    for name, pin in _ADDED.items():
        destination, mode = predecessor._destination(name)
        if destination in original:
            raise BrokerDecisionMeasurementRenderError(
                "new measurement dependency overlaps predecessor"
            )
        replacements[destination] = (
            name,
            mode,
            base.overlay._read_pinned(name, *pin, root=_ROOT),
        )
    destination, mode = predecessor._destination(_ACTIVATOR)
    replacements[destination] = (
        _ACTIVATOR,
        mode,
        _render_activator(original[destination][2], replacements),
    )
    actual = {
        name: (len(raw), base.overlay._digest(raw))
        for name, _, raw in replacements.values()
        if name in _INPUTS
    }
    if actual != _OUTPUTS or len(original) != 70 or len(original | replacements) != 73:
        raise BrokerDecisionMeasurementRenderError(
            "measured successor output inventory changed"
        )
    return original, replacements
