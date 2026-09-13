"""Fresh-identity compatibility for the fixed inert plugin force-reinstall denial."""

from __future__ import annotations

import json
import re
from functools import cache
from itertools import pairwise
from typing import Any

from . import admission_openclaw_final_v3_config_entry_subfixture as commands
from . import admission_openclaw_final_v3_curator_restore_subfixture as checks
from . import admission_protected_final_combined_v3_plugin_force_reinstall as old
from .admission_evidence import AdmissionEvidenceError
from .oci_worker_protocol import canonical_digest

_FILE_KEYS = {
    "device",
    "digest",
    "digest_error",
    "exists",
    "gid",
    "inode",
    "mode",
    "nlink",
    "path",
    "size",
    "type",
    "uid",
}
_DIRECTORY_KEYS = _FILE_KEYS - {"digest", "digest_error"}
_ACTION = "plugin-force-reinstall"


def _require(value: bool, label: str) -> None:
    if not value:
        raise AdmissionEvidenceError("V3 plugin-force " + label + " changed")


@cache
def _reference_bytes() -> bytes:
    # This independently authenticated immutable template is not a fresh capture.
    old._verify_dependencies()
    return old._verify_retained_evidence()


def _reference() -> dict[str, Any]:
    return json.loads(_reference_bytes())["route_observation"]["document"]


def _records(value: Any) -> None:
    if type(value) is dict:
        if value.get("type") in {"file", "directory"}:
            is_file = value["type"] == "file"
            _require(
                set(value) == (_FILE_KEYS if is_file else _DIRECTORY_KEYS)
                and value["exists"] is True
                and all(
                    type(value[k]) is int and value[k] > 0
                    for k in ("device", "inode", "nlink")
                )
                and all(
                    type(value[k]) is int and value[k] >= 0
                    for k in ("uid", "gid", "size")
                )
                and type(value["path"]) is str
                and bool(value["path"])
                and type(value["mode"]) is str
                and re.fullmatch(r"[0-7]{3}", value["mode"]) is not None,
                "file custody",
            )
            if is_file:
                _require(
                    value["digest_error"] is None
                    and type(value["digest"]) is str
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"])
                    is not None,
                    "file digest",
                )
        if "tree_digest" in value:
            _require(
                set(value) == {"entries", "ready", "root", "tree_digest"}
                and value["ready"] is True
                and type(value["entries"]) is list
                and value["tree_digest"] == canonical_digest(value["entries"]),
                "tree digest",
            )
        for item in value.values():
            _records(item)
    elif type(value) is list:
        for item in value:
            _records(item)


def _content(value: Any) -> Any:
    """Project only validated filesystem identities, never static route facts."""
    if type(value) is dict:
        omit = set()
        if value.get("type") in {"file", "directory"}:
            omit = {"device", "inode"}
            if value["type"] == "directory":
                omit.update({"size", "nlink"})
        if "tree_digest" in value:
            omit.add("tree_digest")
        return {key: _content(item) for key, item in value.items() if key not in omit}
    if type(value) is list:
        return [_content(item) for item in value]
    return value


def _aliases(boundary: dict[str, Any]) -> None:
    records: dict[str, dict[str, Any]] = {}
    identities: dict[tuple[int, int], dict[str, Any]] = {}

    def bind(path: str, item: dict[str, Any]) -> None:
        bound = {**item, "path": path}
        _require(
            path not in records or checks._same(records[path], bound),
            "filesystem alias",
        )
        records[path] = bound

    def walk(value: Any) -> None:
        if type(value) is dict:
            if value.get("type") == "file":
                identity = value["device"], value["inode"]
                intrinsic = {key: item for key, item in value.items() if key != "path"}
                # A bind mount may give one inode multiple logical paths, but
                # that inode cannot have conflicting metadata or content.
                _require(
                    identity not in identities
                    or checks._same(identities[identity], intrinsic),
                    "file identity consistency",
                )
                identities[identity] = intrinsic
            if "tree_digest" in value:
                root = value["root"]
                bind(root["path"], root)
                for item in value["entries"]:
                    _require(item["device"] == root["device"], "tree device")
                    bind(root["path"] + "/" + item["path"], item)
            for item in value.values():
                walk(item)
        elif type(value) is list:
            for item in value:
                walk(item)

    walk(boundary)


def _boundary(value: dict[str, Any], reference: dict[str, Any]) -> None:
    _records(value)
    _aliases(value)
    gateway = value["gateway_process"]
    _require(
        type(gateway["pid"]) is int
        and gateway["pid"] > 0
        and type(gateway["start_time_ticks"]) is str
        and re.fullmatch(r"[1-9][0-9]*", gateway["start_time_ticks"]) is not None,
        "gateway identity",
    )
    mount = value["route_input_mount"]["records"][0]
    _require(
        type(mount["root"]) is str
        and re.fullmatch(
            r"/docker/volumes/aragorn-phase3-final-combined-v3-plugin-force-reinstall-route-input-[1-9][0-9]*/_data",
            mount["root"],
        )
        is not None
        and type(mount["source"]) is str
        and re.fullmatch(r"/dev/[A-Za-z0-9_./-]+", mount["source"]) is not None,
        "input mount identity",
    )
    projected = {
        **value,
        "gateway_process": {
            **gateway,
            "pid": reference["gateway_process"]["pid"],
            "start_time_ticks": reference["gateway_process"]["start_time_ticks"],
        },
        "route_input_mount": {
            **value["route_input_mount"],
            "records": [
                {
                    **mount,
                    "root": reference["route_input_mount"]["records"][0]["root"],
                    "source": reference["route_input_mount"]["records"][0]["source"],
                },
                *value["route_input_mount"]["records"][1:],
            ],
        },
    }
    _require(
        checks._same(
            _content({k: v for k, v in projected.items() if k != "state_store"}),
            _content({k: v for k, v in reference.items() if k != "state_store"}),
        ),
        "protected static boundary",
    )
    old._verify_policy_and_target(value)


def _state(
    before: dict[str, Any], after: dict[str, Any], reference: dict[str, Any]
) -> None:
    _require(
        checks._same(before["root"], after["root"])
        and checks._same(_content(before["root"]), _content(reference["root"])),
        "SQLite root",
    )
    names = ["openclaw.sqlite", "openclaw.sqlite-shm", "openclaw.sqlite-wal"]
    _require(
        [item["path"] for item in before["entries"]] == names
        and [item["path"] for item in after["entries"]] == names,
        "SQLite inventory",
    )
    for prior, later, expected in zip(
        before["entries"], after["entries"], reference["entries"], strict=True
    ):
        stable = {k: v for k, v in prior.items() if k not in {"digest", "size"}}
        _require(
            checks._same(
                stable, {k: v for k, v in later.items() if k not in {"digest", "size"}}
            )
            and checks._same(
                _content(stable),
                _content(
                    {k: v for k, v in expected.items() if k not in {"digest", "size"}}
                ),
            ),
            "SQLite custody",
        )
    db, shm, wal = before["entries"]
    db_after, shm_after, wal_after = after["entries"]
    _require(
        checks._same(db, db_after)
        and db["size"] == 4096
        and db["digest"] == reference["entries"][0]["digest"]
        and shm["size"] == shm_after["size"] == 32768
        and shm["digest"] != shm_after["digest"]
        and wal["digest"] != wal_after["digest"]
        and 32 < wal["size"] < wal_after["size"]
        and all((item["size"] - 32) % 4120 == 0 for item in (wal, wal_after)),
        "reported SQLite delta",
    )


def verify_openclaw_final_v3_plugin_force_semantic_compatibility(
    document: dict[str, Any],
) -> dict[str, Any]:
    """Verify the inert denial contract; never establish capture or qualification."""
    try:
        old.parent.parent._verify_scalar_types(document)
        old.parent.config._verify_no_positive_eligibility(document)
        reference = _reference()
        action, expected = document["action"], reference["action"]
        _require(
            type(document) is dict
            and set(document) == set(reference)
            and checks._same(
                {
                    k: v
                    for k, v in document.items()
                    if k not in {"action", "recorded_at", "run_nonce"}
                },
                {
                    k: v
                    for k, v in reference.items()
                    if k not in {"action", "recorded_at", "run_nonce"}
                },
            )
            and type(document["run_nonce"]) is str
            and re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is not None,
            "document contract",
        )
        before, after = action["prerequisites"], action["observations"]
        _require(
            set(action) == set(expected)
            and set(before) == set(expected["prerequisites"])
            and set(after) == set(expected["observations"])
            and checks._same(
                {
                    k: v
                    for k, v in action.items()
                    if k not in {"commands", "prerequisites", "observations"}
                },
                {
                    k: v
                    for k, v in expected.items()
                    if k not in {"commands", "prerequisites", "observations"}
                },
            ),
            "action contract",
        )
        prior, later = before["boundary_before"], after["boundary_after"]
        for boundary in (prior, later):
            _boundary(boundary, expected["prerequisites"]["boundary_before"])
        _require(
            checks._same(
                {k: v for k, v in prior.items() if k != "state_store"},
                {k: v for k, v in later.items() if k != "state_store"},
            ),
            "boundary stability",
        )
        _state(
            prior["state_store"],
            later["state_store"],
            expected["prerequisites"]["boundary_before"]["state_store"],
        )
        for name in ("post_write_containment", "state_invariants"):
            _require(
                checks._same(after[name], expected["observations"][name]),
                "containment claims",
            )
        old._verify_nonforce_commands(before, after)
        for side, suffix in ((before, "before"), (after, "after")):
            for name in ("plugin", "skills_status"):
                _require(
                    checks._same(
                        side[f"{name}_{suffix}"]["response"],
                        expected["prerequisites"][f"{name}_before"]["response"],
                    ),
                    "plugin/catalog response",
                )
            system = side[f"system_info_{suffix}"]
            hostname = system["response"]["value"]["hostname"]
            _require(
                type(hostname) is str
                and re.fullmatch(r"[0-9a-f]{12}", hostname) is not None,
                "hostname",
            )
            checks._verify_system(
                system, {**prior["gateway_process"], "hostname": hostname}
            )
        systems = [
            side[f"system_info_{suffix}"]["response"]["value"]
            for side, suffix in ((before, "before"), (after, "after"))
        ]
        stable = (
            "machineName",
            "hostname",
            "platform",
            "release",
            "arch",
            "pid",
            "port",
            "nodeVersion",
        )
        _require(
            checks._same(
                {k: systems[0][k] for k in stable}, {k: systems[1][k] for k in stable}
            )
            and systems[0]["uptimeMs"] < systems[1]["uptimeMs"],
            "system stability",
        )
        force = after["native_force_reinstall"]
        _require(
            checks._same(
                {k: v for k, v in force.items() if k != "command"},
                {
                    k: v
                    for k, v in expected["observations"][
                        "native_force_reinstall"
                    ].items()
                    if k != "command"
                },
            ),
            "force predicates",
        )
        command = force["command"]
        _require(
            checks._same(
                {
                    k: v
                    for k, v in command.items()
                    if k not in {"pid", "started_at", "completed_at"}
                },
                {
                    k: v
                    for k, v in expected["observations"]["native_force_reinstall"][
                        "command"
                    ].items()
                    if k not in {"pid", "started_at", "completed_at"}
                },
            ),
            "exact native policy denial",
        )
        aliases = [
            before["version"],
            before["system_info_before"]["command"],
            before["skills_status_before"]["command"],
            before["plugin_before"]["command"],
            command,
            after["plugin_after"]["command"],
            after["skills_status_after"]["command"],
            after["system_info_after"]["command"],
        ]
        _require(
            checks._same(action["commands"], aliases)
            and len({item["pid"] for item in aliases}) == 8
            and prior["gateway_process"]["pid"] not in {item["pid"] for item in aliases}
            and all(
                set(item) == commands._COMMAND_KEYS
                and type(item["pid"]) is int
                and item["pid"] > 0
                and old._time(item["started_at"]) <= old._time(item["completed_at"])
                for item in aliases
            )
            and all(
                old._time(left["completed_at"]) <= old._time(right["started_at"])
                for left, right in pairwise(aliases)
            )
            and old._time(aliases[-1]["completed_at"])
            <= old._time(document["recorded_at"]),
            "command joins/chronology",
        )
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
            f"invalid V3 plugin-force semantics: {exc}"
        ) from exc
    return {
        "schema": "aragorn/openclaw-final-v3-plugin-force-semantic-compatibility/v1",
        "assurance": "SEMANTIC_COMPATIBILITY_ONLY_NOT_FRESH_CAPTURE_PASS_OR_QUALIFICATION",
        "bindings": {
            "target_case_id": old._ROUTE,
            "input_document_canonical_digest": canonical_digest(document),
            "expected_probe_digest": old._SOURCE_ARTIFACTS["force_probe"]["digest"],
            "signed_reference_digest": old._EVIDENCE["digest"],
        },
        "decision": {
            "status": "PLUGIN_FORCE_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
            **{key: False for key in old.contract._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "FIXED_INERT_BASELINE_AND_CANDIDATE_PLUGIN_ONLY",
            "SIGNED_STATIC_TEMPLATE_NOT_RETAINED_DYNAMIC_IDENTITY_PINS",
            "EXACT_TRUNCATED_PLUGIN_OUTPUT_AND_PARSED_RESPONSE_SEPARATELY_BOUND",
            "SQLITE_DIGEST_METADATA_DELTA_ONLY_NOT_RAW_BYTES_OR_LOGICAL_EQUIVALENCE",
            "FRESH_IMAGE_SOURCE_VOLUME_AND_PROCESS_REQUIRE_OUTER_CAPTURE_JOINS",
            "NO_GLOBAL_NO_WRITE_CAUSALITY_MODEL_SUCCESS_OR_RELEASE_AUTHORITY",
        ],
    }
