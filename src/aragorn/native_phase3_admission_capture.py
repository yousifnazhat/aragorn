"""Read-only replay of the two-case native admission successor.

This consumes the successor's own envelope, never a relabelled predecessor.
Caller-pinned CAS closure, reported process/credential joins, branch semantics
and cleanup are recomputed. It does not attest source execution, signatures,
preactivation timing, whole-database equality, performance or qualification.
No controller/probe imports, subprocesses, service operations or CAS writes.
"""

from __future__ import annotations

import json
import re
import stat

from . import native_phase3_admission_case as case
from . import native_phase3_admission_direct_write as direct
from . import native_phase3_live_identity as reader
from . import native_phase3_plugin_update_binding as reported
from . import native_phase3_plugin_update_live_binding as live
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-admission-capture-replay/v1"
AUTHORITY = "RETAINED_SUCCESSOR_REPORT_JOINS_NOT_EXECUTION_ATTESTATION_OR_QUALIFICATION"
CAPTURE_SCHEMA = "aragorn/native-admission-case-capture/v1"
CAPTURE_AUTHORITY = (
    "OWNED_SUCCESSOR_CASE_CAPTURE_NOT_INDEPENDENT_ROUTE_OR_PHASE3_QUALIFICATION"
)
GUEST_SCHEMA = "aragorn/native-admission-case-guest/v1"
GUEST_AUTHORITY = (
    "GUEST_LOCAL_PREACTIVATION_NATIVE_ADMISSION_CASE_NOT_HOST_ACK_OR_QUALIFICATION"
)
FALSE_FLAGS = case._FALSE_FLAGS
LIMITATIONS = (
    "CALLER_PINNED_RETAINED_RECORDS_NOT_FRESH_EXECUTION",
    "SOURCE_CONTENT_JOINS_NOT_SIGNATURE_OR_EXECUTION_ATTESTATION",
    "REPORTED_PREACTIVATION_ORDER_NOT_INDEPENDENT_HOST_ACK_OR_TIMING_PROOF",
    "SELECTED_PROTECTED_BOUNDARIES_NOT_ALL_SIDE_EFFECTS_OR_WHOLE_DATABASE_EQUALITY",
    "INHERITED_INPUT_RESTORATION_METADATA_ONLY_NOT_CONTENT_HASHES",
    "TWO_FIXED_CASES_NOT_COMPLETE_ADMISSION_OR_RUN_INVENTORY",
    "NO_PERFORMANCE_OR_PHASE3_QUALIFICATION",
)
_digest = case._digest


class NativeAdmissionCaptureError(ValueError):
    """Retained successor records cannot support bounded replay."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeAdmissionCaptureError(message)


def _false(value: dict) -> None:
    _require(
        all(value.get(key) is False for key in FALSE_FLAGS), "proof ceiling changed"
    )


def _same_raw(value: dict, raw: bytes, message: str) -> None:
    _require(canonical_json(value) == raw, message)


def _cleanup(capture: dict) -> None:
    cleanup, container = capture["cleanup"], capture["fixture_container"]
    name, owner = cleanup["name"], cleanup["owner"]
    _require(
        type(owner) is str
        and re.fullmatch(r"[0-9a-f]{64}", owner) is not None
        and name == "aragorn-native-admission-" + owner[:16]
        and cleanup["removed_id"] == container
        and cleanup["image"] == reported._IMAGE,
        "owned successor cleanup identity changed",
    )
    listing = ["container", "ls", "--all", "--no-trunc", "--filter"]
    by_name = [*listing, "name=^/" + name + "$", "--format", "{{.ID}}"]
    expected = [
        by_name,
        ["container", "inspect", container],
        ["container", "rm", "--force", container],
        ["info", "--format", "{{.ServerVersion}}"],
        by_name,
        [*listing, "id=" + container, "--format", "{{.ID}}"],
    ]
    commands = cleanup["commands"]
    _require(len(commands) == len(expected), "cleanup command inventory changed")
    for command, argv in zip(commands, expected, strict=True):
        _require(
            command["argv"] == reported._DOCKER + argv
            and type(command["exit_code"]) is int
            and command["exit_code"] == 0,
            "cleanup command changed",
        )
    _require(
        commands[0]["stdout"] == commands[2]["stdout"] == container + "\n"
        and commands[4]["stdout"] == commands[5]["stdout"] == "",
        "owned removal not observed",
    )
    inspected = json.loads(
        commands[1]["stdout"],
        object_pairs_hook=reported._pairs,
        parse_constant=reported._constant,
    )
    _require(type(inspected) is list and len(inspected) == 1, "cleanup inspect changed")
    item = inspected[0]
    _require(
        item["Id"] == container
        and item["Image"] == reported._IMAGE
        and item["Name"] == "/" + name
        and item["Config"]["Labels"]["dev.aragorn.snapshot-owner"] == owner
        and item["Config"]["Labels"]["dev.aragorn.source-commit"]
        == capture["source"]["commit"],
        "cleanup ownership differs",
    )
    states = capture["guest"]["fixture_stack_cleanup"]
    _require(set(states) == set(live._UNITS.values()), "cleanup units changed")
    for unit, state in states.items():
        _require(
            state["Id"] == unit
            and state["ActiveState"] == "inactive"
            and state["MainPID"] == state["ControlPID"] == "0",
            "guest service cleanup unconfirmed",
        )


def _outer(capture: dict, bound: dict) -> None:
    intent, retained = bound["intent"], bound["retained"]
    _same_raw(
        capture["source"],
        retained[intent["source_record_digest"]],
        "source record changed",
    )
    _same_raw(
        capture["staged_profile"],
        retained[intent["staged_profile_digest"]],
        "stage changed",
    )
    _require(
        capture["source"]["commit"] == intent["source_commit"], "source commit changed"
    )
    _require(
        capture["build_observation"]["digest"] == reported._BUILD
        and capture["build_observation"]["bytes"] == 40591,
        "build record changed",
    )
    container, item = capture["fixture_container"], capture["container_inspect"]
    _require(
        type(container) is str and re.fullmatch(r"[0-9a-f]{64}", container) is not None,
        "container identity malformed",
    )
    cleanup = capture["cleanup"]
    _require(
        item["Id"] == container
        and item["Name"] == "/" + cleanup["name"]
        and item["Image"]
        == item["Config"]["Image"]
        == capture["fixture_image"]["Id"]
        == reported._IMAGE
        and item["Config"]["Labels"]["dev.aragorn.snapshot-owner"] == cleanup["owner"]
        and item["Config"]["Labels"]["dev.aragorn.source-commit"]
        == intent["source_commit"],
        "owned fixture identity differs",
    )
    expected = {
        "NetworkMode": "none",
        "Privileged": True,
        "CgroupnsMode": "host",
        "Binds": ["/sys/fs/cgroup:/sys/fs/cgroup:rw"],
        "Mounts": [
            {
                "Type": "volume",
                "Source": reported._VOLUME,
                "Target": "/runtime",
                "ReadOnly": True,
            }
        ],
        "Tmpfs": {
            path: "rw,nosuid,nodev,noexec,mode=755" for path in ("/run", "/run/lock")
        },
        "SecurityOpt": ["label=disable"],
        "IpcMode": "private",
        "UsernsMode": "",
        "Runtime": "runc",
    }
    _require(
        canonical_json({key: item["HostConfig"][key] for key in expected})
        == canonical_json(expected),
        "fixture isolation changed",
    )
    mounts = {row["Destination"]: row for row in item["Mounts"]}
    _require(
        len(mounts) == len(item["Mounts"]) == 2
        and set(mounts) == {"/runtime", "/sys/fs/cgroup"}
        and mounts["/runtime"]["Type"] == "volume"
        and mounts["/runtime"]["Name"] == reported._VOLUME
        and mounts["/runtime"]["RW"] is False
        and mounts["/sys/fs/cgroup"]["Type"] == "bind"
        and mounts["/sys/fs/cgroup"]["Source"] == "/sys/fs/cgroup"
        and mounts["/sys/fs/cgroup"]["RW"] is True,
        "fixture mounts changed",
    )
    before, after = capture["parent_before"], capture["parent_after"]
    _require(
        before["image_inspect"] == after["image_inspect"]
        and before["volume_inspect"] == after["volume_inspect"]
        and before["content"]["runtime_tree_before"]
        == after["content"]["runtime_tree_after"]
        and {
            k: v["content_base64"]
            for k, v in before["content"]["contract_files"].items()
        }
        == {
            k: v["content_base64"]
            for k, v in after["content"]["contract_files"].items()
        },
        "frozen parent changed",
    )
    layers = before["image_inspect"]["RootFS"]["Layers"]
    image = capture["fixture_image"]
    _require(
        image["RootFS"]["Type"] == "layers"
        and image["RootFS"]["Layers"][: len(layers)] == layers
        and len(image["RootFS"]["Layers"]) > len(layers),
        "fixture parent layers changed",
    )
    for side in ("runtime_before", "runtime_after"):
        runtime = capture[side]
        _require(
            runtime["content"]["runtime_tree_before"]
            == runtime["content"]["runtime_tree_after"]
            == reported._RUNTIME
            and runtime["volume_inspect"]["Name"] == reported._VOLUME
            and runtime["running_users_before"] == runtime["running_users_after"] == [],
            "runtime snapshot changed",
        )
        mount = runtime["content"]["mount"]
        _require(
            mount["path"] == "/runtime"
            and mount["error"] is None
            and mount["read_only"] is True
            and len(mount["records"]) == 1
            and mount["records"][0]["root"]
            == f"/docker/volumes/{reported._VOLUME}/_data"
            and "ro" in mount["records"][0]["mount_options"]
            and "rw" not in mount["records"][0]["mount_options"],
            "runtime mount not read-only",
        )
    _require(
        capture["runtime_before"]["volume_inspect"]
        == capture["runtime_after"]["volume_inspect"],
        "runtime volume custody changed",
    )
    # Join installed successor code to the caller-held source closure. The
    # host's signed-checkout guard is separate; this does not verify signatures.
    helpers = capture["fixture_helpers"]
    for field in (
        "controller_source_digests",
        "live_source_digests",
        "case_source_digests",
    ):
        for path, pin in intent[field].items():
            if path.startswith("scripts/capture_") or path.endswith(
                "native_phase3_admission_capture.py"
            ):
                continue  # host-only, retained in the deployment closure
            record = helpers[path]
            target = (
                "/opt/aragorn/" + path.rsplit("/", 1)[1]
                if path.startswith("scripts/")
                else "/usr/lib/aragorn/aragorn/" + path.rsplit("/", 1)[1]
            )
            _require(
                record["path"] == path
                and record["mode"] == "100644"
                and record["digest"] == pin
                and record["bytes"] == len(retained[pin])
                and record["installed_path"] == target
                and record["installed_mode"] == "0444",
                "installed successor helper binding changed",
            )
    _cleanup(capture)


def _files(snapshot: dict, envelope: dict, capture: dict, accounts: dict) -> None:
    files, observation = snapshot["files"], capture["guest"]
    setup, pins = observation["setup"], envelope["expected_file_digests"]
    _require(
        type(files) is dict and set(files) == set(live.FILE_PATHS),
        "measured file inventory changed",
    )
    for path, record in files.items():
        owner = (
            accounts["broker"]
            if path == live._POLICY
            else (1000, 1000)
            if path == live._ENTRY
            else (0, 0)
        )
        live._metadata(
            record,
            owners={owner},
            modes={0o400}
            if path in live.DYNAMIC_PATHS
            else {0o755}
            if path == live._ENTRY
            else {0o644, 0o755},
        )
        _require(
            record["digest"] == pins[path],
            "measured file differs from preactivation pin",
        )
    profile = {item["path"]: item for item in capture["staged_profile"]["files"]}
    for path in live._PROFILE_PATHS:
        record = files[path]
        _require(
            record == observation["installed_sources"][path]
            and record["digest"] == profile[path]["digest"]
            and record["bytes"] == profile[path]["bytes"]
            and stat.S_IMODE(record["identity"][2]) == int(profile[path]["mode"], 8),
            "selected live code/unit bytes do not join staged and installed profile",
        )
    entry = capture["staged_profile"]["required_runtime_not_included"]
    _require(
        entry["entrypoint"] == live._ENTRY
        and files[live._ENTRY]["bytes"] == entry["entrypoint_bytes"] == 23463
        and files[live._ENTRY]["digest"]
        == entry["entrypoint_digest"]
        == "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
        and files[live._PYTHON]["digest"]
        == setup["runtime_profile"]["executable_digest"],
        "runtime entrypoint or Python profile join changed",
    )
    documents = {
        live._WORKER: setup["worker_binding"],
        live._POLICY: setup["policy"],
        live._GRANT: setup["grant"],
        live._GENESIS: setup["empty_store"]["genesis"],
        live._RUNTIME: {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": setup["runtime_digest"],
            "runtime_profile_digest": _digest(canonical_json(setup["runtime_profile"])),
        },
        live._OBSERVATION: {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": setup["policy"]["sensor_digest"],
            "runtime_profile": setup["runtime_profile"],
        },
    }
    worker, policy, grant, genesis = (
        setup["worker_binding"],
        setup["policy"],
        setup["grant"],
        setup["empty_store"]["genesis"],
    )
    policy_digest = _digest(canonical_json(policy))
    _require(
        worker["schema"] == "aragorn/runtime-action-worker-binding/v1"
        and policy["schema"] == "aragorn/runtime-action-policy/v1"
        and grant["schema"] == "aragorn/runtime-capability-grant/v1"
        and genesis["schema"] == "aragorn/native-tool-receipt-genesis/v1"
        and worker["runtime_digest"]
        == grant["runtime_digest"]
        == genesis["runtime_digest"]
        == setup["runtime_profile"]["runtime_digest"]
        == setup["runtime_digest"]
        and worker["policy_digest"]
        == grant["policy_digest"]
        == genesis["policy_digest"]
        == policy_digest
        and type(policy["version"]) is int
        and all(
            type(document["policy_version"]) is int
            and document["policy_version"] == policy["version"]
            for document in (worker, grant, genesis)
        )
        and grant["runtime_profile_digest"]
        == documents[live._RUNTIME]["runtime_profile_digest"]
        and grant["sensor_digest"] == policy["sensor_digest"]
        and worker["active_skill_digest"]
        == grant["active_skill_digest"]
        == setup["skill_digest"]
        and [genesis["worker_uid"], genesis["worker_gid"]] == list(accounts["worker"])
        and setup["runtime_profile"]["cgroup"]
        == snapshot["processes"]["worker"]["cgroup"],
        "measured worker, grant, genesis, policy and process bindings disagree",
    )
    for path, document in documents.items():
        raw = canonical_json(document)
        _require(
            files[path]["digest"] == _digest(raw) and files[path]["bytes"] == len(raw),
            "provisioned bytes do not join original setup",
        )
    _require(
        files[live._CONFIG]["digest"] == setup["configuration_digest"]
        and snapshot["measured_joins"]
        == {
            "configuration_digest": setup["configuration_digest"],
            "worker_binding_digest": _digest(canonical_json(setup["worker_binding"])),
            "policy_digest": _digest(canonical_json(setup["policy"])),
            "declared_runtime_digest_not_whole_tree_measurement": setup[
                "runtime_digest"
            ],
        },
        "measured binding document joins changed",
    )
    loaded = snapshot["loaded_process_views"]
    _require(
        type(loaded) is dict and set(loaded) == set(live._UNITS),
        "loaded process-view inventory changed",
    )
    for role, credentials in live._CREDENTIALS.items():
        views = loaded[role]
        _require(
            type(views) is dict and set(views) == {*credentials, "code_view"},
            "loaded credential inventory changed",
        )
        uid, gid = accounts[role]
        for name, source in credentials.items():
            view = live._metadata(
                views[name], owners={(0, 0), (uid, 0), (uid, gid)}, modes={0o400, 0o440}
            )
            _require(
                (view["identity"][3] == 0 or stat.S_IMODE(view["identity"][2]) == 0o400)
                and view["bytes"] == files[source]["bytes"]
                and view["digest"] == files[source]["digest"],
                "loaded credential differs from measured provisioned source",
            )
        code = (
            live._ENTRY
            if role == "gateway"
            else live._WORKER_CODE
            if role == "worker"
            else live._SHIMS[role]
        )
        view = live._metadata(
            views["code_view"],
            owners={(1000, 1000)} if role == "gateway" else {(0, 0)},
            modes={0o755} if role == "gateway" else {0o644, 0o755},
        )
        _require(
            view["bytes"] == files[code]["bytes"]
            and view["digest"] == files[code]["digest"],
            "process code view differs from measured source",
        )
    # The fixed runtime volume is not root-owned. The original consumer already
    # checks its fixed volume root and read-only mount options on both sides;
    # join that reported custody to the selected source and service-view file.
    # This is not proof of whole-tree ownership or independently attested mounts.
    for side in ("runtime_before", "runtime_after"):
        mount = capture[side]["content"]["mount"]
        entry = mount["entry"]
        _require(
            mount["path"] == mount["records"][0]["mount_point"] == "/runtime"
            and mount["read_only"] is True
            and entry["path"] == "/runtime"
            and entry["exists"] is True
            and entry["type"] == "directory"
            and int(entry["mode"], 8) == 0o755
            and [entry["uid"], entry["gid"]]
            == files[live._ENTRY]["identity"][3:5]
            == loaded["gateway"]["code_view"]["identity"][3:5]
            == [1000, 1000],
            "runtime mount custody differs from entrypoint or gateway view",
        )


def _live(capture: dict, bound: dict) -> None:
    guest, intent = capture["guest"], bound["intent"]
    value = guest["live_identity"]
    _require(
        value["pins_frozen_before_activation"] is True
        and type(value["activation_count"]) is int
        and value["activation_count"] == 1
        and type(value["invocation_count"]) is int
        and value["invocation_count"] == 1,
        "single activation/invocation changed",
    )
    timing = value["boundaries_monotonic_ns"]
    _require(
        set(timing) == set(live._BOUNDARIES)
        and all(
            type(timing[key]) is int and timing[key] > 0 for key in live._BOUNDARIES
        )
        and all(
            timing[a] <= timing[b]
            for a, b in zip(live._BOUNDARIES, live._BOUNDARIES[1:])
        ),
        "reported boundary chronology changed",
    )
    expected = bound["static"]["file_digests"] | value["provisioning_file_digests"]
    _require(
        value["expected_file_digests"] == expected
        and set(expected) == set(live.FILE_PATHS),
        "expected measured file inventory changed",
    )
    before, after = value["before"], value["after"]
    comparison = reader.compare_native_live_identity(before, after)
    _require(
        value["comparison"] == comparison
        and before["container_id"] == capture["fixture_container"],
        "live comparison or fixture identity changed",
    )
    boot = before["boot_id"]
    _require(
        type(boot) is str
        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)
        is not None
        and boot.replace("-", "") == guest["boot_id"] == guest["boot_id_after"]
        and guest["processes"] == guest["processes_after"]
        and guest["installed_sources"] == guest["installed_sources_after"],
        "process, boot or installed source epoch changed",
    )
    accounts = live._processes(before, guest, capture["fixture_container"])
    live._aliases(before)
    _files(before, value, capture, accounts)
    setup, post = guest["setup"], guest["post_observation"]
    artifacts = {
        key: json.loads(raw)["identity"] for key, raw in bound["artifacts"].items()
    }
    _require(
        setup["configuration_digest"]
        == artifacts["configuration"]["configuration_digest"]
        and setup["worker_binding"] == artifacts["worker"]["binding"]
        and _digest(canonical_json(setup["policy"]))
        == artifacts["policy"]["policy_digest"]
        and setup["runtime_digest"] == reported._RUNTIME["tree_digest"],
        "setup differs from common deployment artifacts",
    )
    admission = setup["admission_observation"]
    expected_post = {
        "LIVE_IDENTITY_AFTER": after,
        "LIVE_IDENTITY_COMPARISON": comparison,
        "PROCESSES_AFTER": guest["processes_after"],
        "BOOT_ID_AFTER": guest["boot_id_after"],
        "INSTALLED_SOURCES_AFTER": guest["installed_sources_after"],
        "LEAF_SOURCES_AFTER": admission["leaf_sources"],
        "INSTALLED_SKILL_AFTER": admission["installed"],
        "RECEIPT_STORE_AFTER": setup["empty_store"],
        "STARTUP_BUDGET_AFTER": admission["startup_task_budget_after"],
    }
    _require(
        all(post[key] == item for key, item in expected_post.items())
        and admission["empty_receipt_store_after"] == setup["empty_store"]
        and admission["installed"]["denial"] is None
        and admission["protected_effects_unchanged"] is True
        and type(post["PROTECTED_EFFECTS_AFTER"]) is dict
        and admission["cgroup_prerequisites"]["status"] == "READY",
        "post-observation inventory or reported startup prerequisites changed",
    )
    # The initial general effect snapshot is not retained by this dispatcher;
    # no independent all-effects equality claim is made from the boolean above.
    leaf_paths = {
        "scripts/runtime_native_admission_direct_write.py": direct.PROBE,
        "src/aragorn/native_phase3_admission_direct_write.py": direct.VERIFIER,
    }
    _require(
        set(admission["leaf_sources"]) == set(leaf_paths.values()),
        "leaf source inventory changed",
    )
    for source, installed in leaf_paths.items():
        item = admission["leaf_sources"][installed]
        pin = intent["case_source_digests"][source]
        _require(
            item == {"bytes": len(bound["retained"][pin]), "digest": pin},
            "leaf source bytes changed",
        )


def _direct(guest: dict, intent: dict) -> dict:
    _require(guest["plugin_update"] is None, "unexpected plugin invocation")
    leaf = guest["leaf"]
    document, execution = leaf["document"], leaf["execution"]
    raw = canonical_json(document)
    pins = intent["case_source_digests"]
    snapshot = guest["live_identity"]
    gateway = snapshot["before"]["processes"]["gateway"]
    result = direct.verify_native_admission_direct_write(
        raw,
        expected_raw_digest=_digest(raw),
        expected_container=guest["fixture_container"],
        expected_gateway_pid=gateway["pid"],
        expected_admitted_digest=guest["setup"]["skill_digest"],
        expected_probe_digest=pins["scripts/runtime_native_admission_direct_write.py"],
        expected_verifier_digest=pins[
            "src/aragorn/native_phase3_admission_direct_write.py"
        ],
    )
    argv = execution["argv"]
    _require(
        type(argv) is list
        and len(argv) == 26
        and re.fullmatch(r"--mount=/proc/self/fd/[0-9]+", argv[1]) is not None,
        "direct leaf mount descriptor changed",
    )
    expected = [
        "/usr/bin/nsenter",
        argv[1],
        "--",
        "/usr/bin/setpriv",
        "--reuid=992",
        "--regid=992",
        "--groups=992",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        direct.PROBE,
        "--container",
        guest["fixture_container"],
        "--gateway-pid",
        str(gateway["pid"]),
        "--admitted-digest",
        guest["setup"]["skill_digest"],
        "--probe-digest",
        pins["scripts/runtime_native_admission_direct_write.py"],
        "--verifier-digest",
        pins["src/aragorn/native_phase3_admission_direct_write.py"],
    ]
    _require(
        argv == expected
        and type(execution["exit_code"]) is int
        and execution["exit_code"] == 0
        and execution["stdout"] == (raw + b"\n").decode("ascii")
        and execution["stdout_bytes"] == len(raw) + 1
        and execution["stdout_digest"] == _digest(raw + b"\n")
        and execution["stderr_bytes"] == 0
        and execution["effective_identity"] == {"uid": 992, "gid": 992, "groups": [992]}
        and execution["environment_names"]
        == ["LANG", "LC_ALL", "NO_COLOR", "OPENCLAW_GATEWAY_TOKEN", "PATH"],
        "direct leaf execution binding changed",
    )
    for side in ("before", "after"):
        observed = document[side]
        process = snapshot[side]["processes"]["gateway"]
        subject = observed["gateway"]
        _require(
            subject["pid"] == process["pid"]
            and subject["start_time_ticks"] == process["start_time_ticks"]
            and subject["cgroup"] == "0::" + process["cgroup"] + "\n"
            and subject["mount_namespace"] == process["mount_namespace"]["inode"]
            and subject["uid"] == process["uids"]
            and subject["gid"] == process["gids"],
            "direct leaf process does not join root readback",
        )
        credential = snapshot[side]["loaded_process_views"]["gateway"][
            "openclaw-config"
        ]
        _require(
            observed["config"]["read_only"] is True
            and {
                key: observed["config"][key] for key in ("identity", "bytes", "digest")
            }
            == credential,
            "direct leaf credential does not join root readback",
        )
    claimed = leaf["verification"]
    _require(
        {
            key: item
            for key, item in claimed.items()
            if key != "native_live_identity_joins"
        }
        == result,
        "retained direct replay differs from recomputation",
    )
    _false(claimed["native_live_identity_joins"])
    return {
        "case_id": intent["case_id"],
        "status": "BOUNDED_DIRECT_WRITE_JOINS_VERIFIED",
    }


def _bundle_records(records: dict, root: str, manifest: dict) -> None:
    package = root + "/plugin-package-skill-replacement"
    directories = {
        root,
        package,
        *(
            package + "/" + name
            for name in ("adapter", "baseline-source", "candidate-source")
        ),
    }
    files = {package + "/" + item["name"]: item for item in manifest["files"]}
    _require(
        set(records) == directories | files.keys(), "plugin input inventory changed"
    )
    for path, record in records.items():
        if path in directories:
            identity = record["identity"]
            _require(
                set(record) == {"identity"}
                and type(identity) is list
                and len(identity) == 9
                and all(type(n) is int and n >= 0 for n in identity)
                and stat.S_ISDIR(identity[2])
                and stat.S_IMODE(identity[2]) == 0o555
                and identity[3:5] == [0, 0],
                "plugin input directory custody changed",
            )
        else:
            live._metadata(record, owners={(0, 0)}, modes={0o444})
            _require(
                (record["bytes"], record["digest"])
                == (files[path]["bytes"], files[path]["digest"]),
                "plugin input file bytes changed",
            )


def _plugin(capture: dict, baseline: dict) -> dict:
    guest, plugin = capture["guest"], capture["guest"]["plugin_update"]
    _require(guest["leaf"] is None, "unexpected direct leaf invocation")
    invocation = plugin["invocation"]
    document = invocation["document"]
    original = baseline["observation"]["plugin_update"]["document"]
    for key in (
        "schema",
        "authority",
        "status",
        "branch",
        "route_id",
        "limitations",
        "decision",
        "implementation_digest",
        "helper_binding",
        "native_version_binding",
        "native_update_source_binding",
    ):
        _require(
            canonical_json(document[key]) == canonical_json(original[key]),
            "fixed plugin document binding changed: " + key,
        )
    _require(
        document["route_qualified"] is False
        and document["inventory_route_coverage"] is False,
        "plugin proof ceiling changed",
    )
    _require(
        document["plugin_update_lifecycle_executed"] is True,
        "plugin lifecycle was not executed",
    )
    observation = {
        "plugin_update": invocation,
        "processes": guest["processes"],
        "setup": guest["setup"],
        "empty_receipt_store_after": guest["setup"]["admission_observation"][
            "empty_receipt_store_after"
        ],
    }
    # These existing pure primitives consume actual records, not old envelopes.
    reported._commands(document, observation)
    reported._protected(document, observation)
    _require(
        capture["plugin_input_bundle"] == baseline["input_bundle"]
        and capture["source"]["plugin_fixture_sources"]
        == baseline["source"]["plugin_fixture_sources"]
        and plugin["baseline"] == baseline["observation"]["baseline"],
        "fixed plugin input or baseline seed changed",
    )
    _bundle_records(
        plugin["staged_input_bundle"],
        "/opt/aragorn/native-plugin-update-input",
        capture["plugin_input_bundle"],
    )
    _bundle_records(
        plugin["input_bundle"], "/route-input", capture["plugin_input_bundle"]
    )
    _require(
        {
            path.replace(
                "/route-input", "/opt/aragorn/native-plugin-update-input", 1
            ): item
            for path, item in plugin["input_bundle"].items()
        }
        == plugin["staged_input_bundle"],
        "mounted plugin input does not alias the staged custody records",
    )
    helpers = {}
    source_files = {row["path"]: row for row in capture["source"]["files"]}
    _require(
        len(source_files) == len(capture["source"]["files"]),
        "duplicate source file records",
    )
    # Exact unchanged helper source pins come from the retained baseline recorder.
    for path, size in (
        ("/opt/aragorn/runtime_native_plugin_update_check.py", 11677),
        ("/opt/aragorn/runtime_native_plugin_package_check.py", 24331),
    ):
        source_path = "scripts/" + path.rsplit("/", 1)[1]
        baseline_helper = baseline["fixture_helpers"][source_path]
        _require(
            capture["fixture_helpers"][source_path] == baseline_helper
            and source_files[source_path]
            == {
                key: value
                for key, value in baseline_helper.items()
                if key not in {"installed_path", "installed_mode"}
            },
            "plugin copied helper or source record differs from fixed input",
        )
        helpers[path] = {"bytes": size, "digest": baseline_helper["digest"]}
        _require(size == baseline_helper["bytes"], "fixed helper size changed")
    _require(
        plugin["installed_sources"] == plugin["installed_sources_after"] == helpers,
        "plugin installed helper readback changed",
    )
    mount = plugin["input_mount"]
    _require(
        plugin["input_mount_source"] == "/opt/aragorn/native-plugin-update-input"
        and mount["mountpoint"] == "/route-input"
        and type(mount["mount_id"]) is str
        and mount["mount_id"].isdigit()
        and {"ro", "nosuid", "nodev", "noexec"} <= set(mount["options"])
        and "rw" not in mount["options"],
        "plugin mount custody changed",
    )
    post = guest["post_observation"]
    for key, value in (
        ("PLUGIN_UPDATE_SOURCES_AFTER", helpers),
        ("PLUGIN_INPUT_BUNDLE_AFTER", plugin["input_bundle"]),
        ("PLUGIN_STAGED_INPUT_BUNDLE_AFTER", plugin["staged_input_bundle"]),
        ("PLUGIN_INPUT_MOUNT_AFTER", mount),
    ):
        _require(post[key] == value, "plugin post-readback changed")
    restoration = plugin["inherited_input_restoration"]
    _require(
        plugin["input_mount_removed"] is True
        and plugin["inherited_input_restored"] is True
        and restoration["authority"]
        == "BOUNDED_METADATA_AND_INVENTORY_ONLY_NOT_CONTENT_HASHES"
        and type(restoration["before"]) is dict
        and 0 < len(restoration["before"]) <= 256
        and "." in restoration["before"]
        and restoration["before"] == restoration["after"],
        "plugin cleanup restoration unconfirmed",
    )
    for side in ("before", "after"):
        process = guest["live_identity"][side]["processes"]["gateway"]
        observed_process = document["action"][side]["boundary"]["gateway_process"]
        _require(
            observed_process["pid"] == process["pid"]
            and observed_process["start_time_ticks"] == str(process["start_time_ticks"])
            and observed_process["cmdline"] == process["argv"]
            and observed_process["effective_capabilities"] == "0000000000000000"
            and observed_process["no_new_privileges"] == "1"
            and observed_process["seccomp"] == "2",
            "plugin gateway epoch or hardening differs from root readback",
        )
        credential = guest["live_identity"][side]["loaded_process_views"]["gateway"][
            "openclaw-config"
        ]
        observed = document["action"][side]["boundary"]["config"]["file"]
        ident = credential["identity"]
        _require(
            observed["digest"] == credential["digest"]
            and observed["size"] == credential["bytes"]
            and observed["device"] == ident[0]
            and observed["inode"] == ident[1]
            and int(observed["mode"], 8) == stat.S_IMODE(ident[2])
            and [observed["uid"], observed["gid"], observed["nlink"]] == ident[3:6],
            "plugin credential differs from root readback",
        )
    return {
        "case_id": case.UPDATE_CASE,
        "status": "BOUNDED_PLUGIN_UPDATE_JOINS_VERIFIED",
    }


def verify_native_admission_capture(
    raw: bytes,
    *,
    expected_capture_digest: str,
    expected_intent_digest: str,
    evidence_cas: CAS,
) -> dict:
    """Recompute bounded joins without writes, probe imports or live operations."""
    try:
        _require(
            type(evidence_cas) is CAS and evidence_cas.read_only is True,
            "read-only CAS required",
        )
        _require(
            _digest(raw) == case._pin(expected_capture_digest),
            "capture differs from caller pin",
        )
        capture = reported._parse(raw, newline=True, limit=4 * 1024 * 1024)
        _require(
            evidence_cas.read(expected_capture_digest, max_bytes=len(raw)) == raw,
            "capture not retained",
        )
        intent_raw = evidence_cas.read(
            case._pin(expected_intent_digest), max_bytes=case._MAX_DOCUMENT
        )
        bound = case._inputs(intent_raw, expected_intent_digest, evidence_cas)
        intent, guest = bound["intent"], capture["guest"]
        for value, schema, authority in (
            (capture, CAPTURE_SCHEMA, CAPTURE_AUTHORITY),
            (guest, GUEST_SCHEMA, GUEST_AUTHORITY),
        ):
            _require(
                value["schema"] == schema
                and value["authority"] == authority
                and value["status"] == "OBSERVED"
                and value["refusal"] is None
                and value["postcondition_failures"] == []
                and value["intent_digest"] == expected_intent_digest
                and value["case_id"] == intent["case_id"],
                "successor envelope changed",
            )
            _false(value)
        _require(
            capture["independent_capture_replay_complete"] is False
            and capture["fixture_creation_attempted"] is True
            and guest["branch"] == intent["branch"]
            and guest["fixture_container"] == capture["fixture_container"]
            and guest["static_pin_manifest_digest"]
            == intent["static_pin_manifest_digest"],
            "case or fixture linkage changed",
        )
        bundle = canonical_json(
            {
                "schema": "aragorn/native-admission-case-inputs/v1",
                "intent_digest": expected_intent_digest,
                "blobs": {
                    pin: value.decode("utf-8")
                    for pin, value in bound["retained"].items()
                },
            }
        )
        _require(
            guest["input_bundle_digest"] == _digest(bundle),
            "guest input bundle differs from retained closure",
        )
        prepared = guest["prepared_case"]
        request = {
            **case.old._request(
                intent,
                expected_intent_digest,
                guest["live_identity"]["provisioning_file_digests"],
            ),
            "schema": case.REQUEST_SCHEMA,
            "staged_profile_digest": intent["staged_profile_digest"],
        }
        request_raw = canonical_json(request)
        request_pin = _digest(request_raw)
        _same_raw(
            prepared["request"],
            request_raw,
            "reported request is not exact canonical commitment",
        )
        _require(
            prepared["request"] == request
            and prepared["request_digest"] == request_pin
            and prepared["local_pre_activation_readback"] is True
            and prepared["host_ack_received"] is False
            and prepared["authority"] == GUEST_AUTHORITY
            and evidence_cas.read(request_pin, max_bytes=16384) == request_raw,
            "preactivation request closure changed",
        )
        _false(prepared)
        _outer(capture, bound)
        _live(capture, bound)
        if intent["case_id"] == case.DIRECT_WRITE_CASE:
            _require(capture["plugin_input_bundle"] is None, "unexpected plugin bundle")
            branch = _direct(guest, intent)
        else:
            baseline = reported._parse(
                bound["retained"][case.old._BASELINE_DIGEST], newline=True
            )
            branch = _plugin(capture, baseline)
        case.old._closure(
            evidence_cas,
            bound["retained"]
            | {request_pin: request_raw, expected_capture_digest: raw},
        )
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "status": "BOUNDED_CAPTURE_REPLAY_VERIFIED",
            "capture_digest": expected_capture_digest,
            "intent_digest": expected_intent_digest,
            "request_digest": request_pin,
            "deployment_digest": intent["deployment_digest"],
            "case_adapter_digest": intent["case_adapter_digest"],
            "case_id": intent["case_id"],
            "branch": branch,
            "independent_capture_replay_complete": True,
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(FALSE_FLAGS, False),
        }
    except NativeAdmissionCaptureError:
        raise
    except (
        CASError,
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        OSError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise NativeAdmissionCaptureError(
            "native admission capture replay refused"
        ) from exc
