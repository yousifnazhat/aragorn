"""Check fixed archive replacement semantics without execution authority."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from itertools import pairwise
from typing import Any

from . import admission_openclaw_final_v3_config_entry_subfixture as commands
from . import admission_openclaw_final_v3_curator_restore_subfixture as checks
from . import admission_protected_final_combined_v3_archive_replacement as old
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_ROUTE = old._ROUTE
_ACTION = "archive-source-force-replacement"
_PARSE = old.current.base.legacy._parse_time
_CONTROL = "/tmp/aragorn-final-archive-control/workspace/skills/template-skill"
_ORIGIN_MAX_SPAN_MS = 60_000


def verify_openclaw_final_v3_archive_replacement_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute exact route predicates from actual, non-authoritative identities."""
    try:
        old.semantics.base._verify_scalar_types(document)
        old.current._verify_no_positive_eligibility(document)
        action = document["action"]
        after = action["observations"]
        # These two CLI responses intentionally are not JSON. Validate their exact
        # wrappers separately, then reuse the shared record checker everywhere.
        unparsed = {name: after[name] for name in ("source_install", "discovery_after")}
        for value in unparsed.values():
            _require(
                set(value) == {"command", "response"}
                and value["response"] == {"parsed": False, "value": None},
                "unparsed command wrapper",
            )
        checks._verify_records(
            {
                **document,
                "action": {
                    **action,
                    "observations": {
                        **after,
                        **{
                            name: list(value.values())
                            for name, value in unparsed.items()
                        },
                    },
                },
            }
        )
        _verify_document(document)
        digest = canonical_digest(document)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 archive replacement semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-archive-replacement-semantic-compatibility/v1",
        "assurance": "ARCHIVE_REPLACEMENT_SEMANTIC_COMPATIBILITY_ONLY_NOT_EXECUTION_CAPTURE_FRESHNESS_INDEPENDENCE_PASS_OR_CAMPAIGN_AUTHORITY",
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": old._PROBE_BUNDLE[0]["digest"],
            "input_document_canonical_digest": digest,
        },
        "decision": {
            "status": "ARCHIVE_REPLACEMENT_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
            **{key: False for key in old.contract._ELIGIBILITY_KEYS},
        },
        "route_semantics": {
            "expected_action_id": _ACTION,
            "semantic_target_route": _ROUTE,
            "transition_predicates_verified": True,
            "native_independent_route_execution_verified": False,
            "pass_authority": False,
            "shared_capture_independence_verified": False,
        },
        "limitations": [
            "NO_CAPTURE_EXECUTION_FRESHNESS_DESTRUCTION_OR_INDEPENDENCE_VERIFIED",
            "FRESH_INPUT_SOURCE_VOLUMES_AND_PROCESS_IDENTITY_REQUIRE_OUTER_CAPTURE_JOIN",
            "FIXED_INERT_144_BYTE_SOURCE_AND_TEMPLATE_SKILL_ONLY",
            "CONTROL_ORIGIN_DIGEST_BOUND_RECONSTRUCTION_NOT_SEPARATELY_CAPTURED_BYTES",
            "CONTROL_ORIGIN_TIMESTAMP_SEARCH_CAPPED_AT_60000_MS_ABOVE_30000_MS_PROBE_TIMEOUT",
            "SOURCE_INSTALL_WORKSPACE_RESIDUE_ALLOWED_WITH_EXACT_CATALOG_REJECTION",
            "NO_GLOBAL_NO_WRITE_MODEL_SUCCESS_CLEANUP_ROLLBACK_OR_GENERAL_REPLACEMENT_CLAIM",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(f"V3 archive replacement {label} changed")


def _verify_document(document: Mapping[str, Any]) -> None:
    action = document["action"]
    before, after = action["prerequisites"], action["observations"]
    _require(
        type(document) is dict
        and set(document)
        == {
            "action",
            "assurance",
            "implementation_digest",
            "protected_boundary",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        and document["schema"]
        == "aragorn/openclaw-protected-archive-replacement-observation/v1"
        and document["assurance"]
        == "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        and document["implementation_digest"] == old._PROBE_BUNDLE[0]["digest"]
        and document["route"]
        == {
            "action_id": _ACTION,
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        and re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is not None
        and document["runtime_binding"]
        == {
            "commit": old.contract._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": old.contract._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": old.current._RUNTIME_TREE["tree_digest"],
            "version": old.contract._OPENCLAW["version"],
        }
        and set(action)
        == {
            "commands",
            "execution_error",
            "id",
            "observations",
            "prerequisites",
            "reason_codes",
            "status",
        }
        and action["id"] == _ACTION
        and action["status"] == "OBSERVED"
        and action["execution_error"] is None
        and action["reason_codes"] == []
        and set(before)
        == {
            "discovery",
            "gateway_process",
            "openclaw",
            "positive_control",
            "ready",
            "reason_codes",
            "runtime_tree",
            "source",
            "system_info",
            "target_before",
            "version",
        }
        and set(after)
        == {
            "boundary_after",
            "discovery_after",
            "gateway_after",
            "runtime_tree_after",
            "source_after",
            "source_install",
            "staging_after",
            "staging_before",
            "target_after",
            "upload_begin",
            "upload_install",
        }
        and before["ready"] is True
        and before["reason_codes"] == []
        and after["staging_before"] == after["staging_after"] == []
        and before["runtime_tree"] == old.current._RUNTIME_TREE
        and all(
            checks._same(left, right)
            for left, right in (
                (before["source"], after["source_after"]),
                (before["target_before"], after["target_after"]),
                (before["runtime_tree"], after["runtime_tree_after"]),
                (before["gateway_process"], after["gateway_after"]),
            )
        ),
        "document identity and stability",
    )
    _verify_boundary(document["protected_boundary"])
    old.semantics._verify_boundary_delta(
        document["protected_boundary"], after["boundary_after"]
    )
    _verify_fixture(before["source"], source=True)
    _verify_fixture(before["target_before"], source=False)
    _require(
        before["source"]["root"]["device"]
        == document["protected_boundary"]["inputs"]["source"]["entry"]["device"]
        and before["openclaw"]["device"]
        == document["protected_boundary"]["runtime"]["entry"]["device"],
        "source and runtime mount device joins",
    )
    gateway = before["gateway_process"]
    old.semantics._verify_gateway_process(gateway, gateway["hostname"])
    _require(
        re.fullmatch(r"[0-9a-f]{12}", gateway["hostname"]) is not None
        and re.fullmatch(r"[1-9][0-9]*", gateway["start_time_ticks"]) is not None
        and gateway["pid"] > 1,
        "gateway identity",
    )
    old.semantics.base._verify_openclaw(before["openclaw"])
    checks._verify_system(before["system_info"], gateway)
    old.semantics.base._verify_version(before["version"])
    old.semantics.base._verify_discovery(before["discovery"])
    old.semantics._verify_upload_denial(
        after["upload_begin"], method="skills.upload.begin"
    )
    old.semantics._verify_upload_denial(
        after["upload_install"], method="skills.install"
    )
    old.semantics._verify_source_install(after["source_install"])
    old.semantics._verify_catalog_rejection(after["discovery_after"])
    _verify_commands(action, document["recorded_at"])
    _verify_positive_control(before["positive_control"])


def _directory(value, path, uid, gid, mode, entries, nlink) -> None:
    _require(
        value["type"] == "directory"
        and value["path"] == path
        and (
            value["uid"],
            value["gid"],
            value["mode"],
            value["entries"],
            value["nlink"],
        )
        == (uid, gid, mode, entries, nlink),
        "directory custody",
    )


def _file(value, path, uid, gid, mode, size, digest) -> None:
    _require(
        value["type"] == "file"
        and value["path"] == path
        and (
            value["uid"],
            value["gid"],
            value["mode"],
            value["size"],
            value["digest"],
            value["nlink"],
        )
        == (uid, gid, mode, size, digest, 1),
        "file contents and custody",
    )


def _verify_boundary(boundary: Mapping[str, Any]) -> None:
    config, inputs = boundary["configuration"], boundary["inputs"]
    _require(
        set(boundary)
        == {
            "configuration",
            "effective_identity",
            "inputs",
            "ready",
            "roots",
            "runtime",
        }
        and boundary["ready"] is True
        and checks._same(
            boundary["effective_identity"], {"gid": 992, "groups": [992], "uid": 992}
        )
        and set(config) == {"canonical_digest", "file", "mount", "ready"}
        and set(inputs) == {"probe", "source"}
        and set(boundary["roots"]) == set(checks._ROOTS),
        "protected boundary shape",
    )
    old.v3_contract._verify_config(config)
    checks._verify_mount(
        config["mount"],
        path="/run/credentials/aragorn-agent-gateway.service",
        source="/",
    )
    _directory(
        config["mount"]["entry"],
        config["mount"]["path"],
        992,
        0,
        "500",
        ["openclaw-config"],
        2,
    )
    _require(
        config["file"]["device"] == config["mount"]["entry"]["device"],
        "credential device join",
    )
    checks._verify_mount(
        boundary["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{old._RUNTIME_VOLUME}/_data",
    )
    _directory(boundary["runtime"]["entry"], "/runtime", 0, 0, "755", ["bin", "lib"], 4)
    for name, path, gid, mode, entries in (
        ("probe", "/route-input", 0, "555", [_ACTION]),
        ("source", "/sources", 992, "750", ["replacement"]),
    ):
        mount = inputs[name]
        source = mount["records"][0]["root"]
        _require(
            re.fullmatch(r"/docker/volumes/[a-zA-Z0-9][a-zA-Z0-9_.-]*/_data", source)
            is not None,
            "input volume",
        )
        checks._verify_mount(mount, path=path, source=source)
        _directory(mount["entry"], path, 0, gid, mode, entries, 3)
    _require(
        len(
            {
                inputs["probe"]["records"][0]["root"],
                inputs["source"]["records"][0]["root"],
                boundary["runtime"]["records"][0]["root"],
            }
        )
        == 3,
        "input and runtime volume separation",
    )
    for name, path in checks._ROOTS.items():
        value = boundary["roots"][name]
        _require(
            set(value) == {"observation", "ready", "writable"}
            and value["ready"] is True
            and value["writable"] is True,
            "protected root",
        )
        _directory(value["observation"], path, 992, 992, "700", [], 2)


def _tree_devices(value: Mapping[str, Any]) -> None:
    records = [value["root"], *value["entries"]]
    _require(
        all(item["device"] == value["root"]["device"] for item in records)
        and len({item["inode"] for item in records}) == len(records),
        "tree device and inode identities",
    )


def _verify_fixture(value: Mapping[str, Any], *, source: bool) -> None:
    _require(len(value["entries"]) == 1, "fixture inventory")
    _directory(
        value["root"],
        "/sources/replacement" if source else old.semantics._TARGET_ROOT,
        0,
        992 if source else 0,
        "750" if source else "555",
        ["SKILL.md"],
        2,
    )
    _file(
        value["entries"][0],
        "SKILL.md",
        0,
        992 if source else 0,
        "440" if source else "444",
        144 if source else old.current._SOURCES["skill"]["bytes"],
        old.semantics._SOURCE_DIGEST
        if source
        else old.current._SOURCES["skill"]["digest"],
    )
    _tree_devices(value)


def _verify_commands(action: Mapping[str, Any], recorded_at: str) -> None:
    before, after = action["prerequisites"], action["observations"]
    values = action["commands"]
    expected = [
        before["version"],
        before["system_info"]["command"],
        before["positive_control"]["install"],
        before["discovery"]["command"],
        after["upload_begin"]["command"],
        after["upload_install"]["command"],
        after["source_install"]["command"],
        after["discovery_after"]["command"],
    ]
    _require(
        checks._same(values, expected)
        and len(values) == 8
        and len({value["pid"] for value in values}) == 8
        and before["gateway_process"]["pid"] not in {value["pid"] for value in values}
        and all(
            set(value) == commands._COMMAND_KEYS
            and type(value["pid"]) is int
            and value["pid"] > 1
            and all(
                type(value[key]) is int
                for key in ("exit_code", "stdout_bytes", "stderr_bytes")
            )
            and value["error"] is None
            and value["signal"] is None
            and old.semantics.base._command_output_is_exact(value)
            and _PARSE(value["started_at"]) <= _PARSE(value["completed_at"])
            for value in values
        )
        and all(
            _PARSE(left["completed_at"]) <= _PARSE(right["started_at"])
            for left, right in pairwise(values)
        )
        and _PARSE(values[-1]["completed_at"]) <= _PARSE(recorded_at),
        "eight command bindings and chronology",
    )


def _epoch_ms(value: str) -> int:
    delta = _PARSE(value) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    _require(delta.microseconds % 1000 == 0, "millisecond timestamp precision")
    return (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000


def _origin_bytes(installed_at: int) -> bytes:
    # Exact 7fa98d8 source-install.ts writer via infra/json-files.ts writeJson.
    value = {
        "version": 1,
        "source": "path",
        "spec": "/sources/replacement",
        "slug": "template-skill",
        "installedAt": installed_at,
    }
    return (json.dumps(value, indent=2) + "\n").encode()


def _verify_positive_control(value: Mapping[str, Any]) -> None:
    target, install = value["target_after"], value["install"]
    entries = {item["path"]: item for item in target["entries"]}
    _require(
        set(value)
        == {"configuration_digest", "install", "ready", "target_after", "target_before"}
        and value["ready"] is True
        and value["configuration_digest"]
        == "sha256:9b584ae1e25f46b4708aa135fe896f67358ef0229f4263d42dbf4a60af343d87"
        and value["target_before"] == {"exists": False, "path": _CONTROL}
        and install["argv"] == old.semantics._INSTALL_ARGV
        and old.semantics.base._command_succeeded_clean(install)
        and install["stdout_excerpt"]
        == f"Installing to {_CONTROL}…\nInstalled template-skill from path -> {_CONTROL}\n"
        and [item["path"] for item in target["entries"]]
        == [".openclaw", "SKILL.md", ".openclaw/source-origin.json"],
        "isolated source install control",
    )
    _directory(target["root"], _CONTROL, 992, 992, "700", [".openclaw", "SKILL.md"], 3)
    _directory(
        entries[".openclaw"], ".openclaw", 992, 992, "755", ["source-origin.json"], 2
    )
    _file(
        entries["SKILL.md"],
        "SKILL.md",
        992,
        992,
        "440",
        144,
        old.semantics._SOURCE_DIGEST,
    )
    origin = entries[".openclaw/source-origin.json"]
    _file(
        origin, ".openclaw/source-origin.json", 992, 992, "600", 133, origin["digest"]
    )
    _tree_devices(target)
    start, stop = _epoch_ms(install["started_at"]), _epoch_ms(install["completed_at"])
    _require(
        0 <= stop - start <= _ORIGIN_MAX_SPAN_MS, "bounded origin timestamp interval"
    )
    for ms in range(start, stop + 1):
        raw = _origin_bytes(ms)
        if len(raw) == origin["size"] and old._digest(raw) == origin["digest"]:
            return
    _require(False, "digest-bound origin fields and install timestamp")
