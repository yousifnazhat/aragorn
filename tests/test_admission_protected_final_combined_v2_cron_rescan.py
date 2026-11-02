from __future__ import annotations

import base64
import hashlib
import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import admission_protected_final_combined_v2_cron_rescan as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-cron-rescan-"
    "route-coverage-v1-2026-08-22.json"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _store(*raw_values: bytes) -> tuple[TemporaryDirectory[str], CAS]:
    temporary = TemporaryDirectory()
    store = CAS(temporary.name)
    for raw in raw_values:
        store.put_expected(
            BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw)
        )
    return temporary, store


def _repin(
    changed: dict[str, object],
) -> tuple[bytes, dict[str, object], dict[str, object], str]:
    document = changed["route_observation"]["document"]
    canonical_json = (
        subject.parent.parent.legacy.parent.oci_worker_protocol.canonical_json
    )
    nested_canonical = canonical_json(document)
    nested = nested_canonical + b"\n"
    changed["route_observation"]["raw"] = {
        "base64": base64.b64encode(nested).decode(),
        "bytes": len(nested),
        "canonical_digest": _digest(nested_canonical),
        "digest": _digest(nested),
        "raw_is_canonical_json_lf": True,
    }
    outer_canonical = canonical_json(changed)
    raw = outer_canonical + b"\n"
    return (
        raw,
        {
            **subject._EVIDENCE,
            "bytes": len(raw),
            "canonical_bytes": len(outer_canonical),
            "canonical_digest": _digest(outer_canonical),
            "digest": _digest(raw),
        },
        {
            "bytes": len(nested),
            "canonical_digest": _digest(nested_canonical),
            "digest": _digest(nested),
        },
        _digest(canonical_json(document["action"])),
    )


class FinalCombinedV2CronRescanTests(unittest.TestCase):
    def test_exact_three_route_passes_and_terminal_mutation_fails_closed(self) -> None:
        parent_raw = [
            (_ROOT / identity["path"]).read_bytes()
            for identity in (
                subject.parent.parent._EVIDENCE,
                subject.parent._EVIDENCE,
            )
        ]
        cron_raw = (_ROOT / subject._EVIDENCE["path"]).read_bytes()
        temporary, store = _store(*parent_raw, cron_raw)
        self.addCleanup(temporary.cleanup)
        result = subject.verify_openclaw_final_combined_v2_cron_rescan(
            evidence_cas=store
        )
        statuses = {
            route["id"]: route["status"] for route in result["profile"]["routes"]
        }
        self.assertEqual(result["profile"]["counts"], {"PASS": 3, "NOT_TESTED": 18})
        self.assertEqual(
            {route for route, status in statuses.items() if status == "PASS"},
            subject._PASS_ROUTES,
        )
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.parent.parent.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(
            _RECEIPT.read_bytes(),
            subject.parent.parent.legacy.parent.oci_worker_protocol.canonical_json(
                result
            )
            + b"\n",
        )

        changed = deepcopy(json.loads(cron_raw))
        changed["route_observation"]["document"]["action"]["observations"][
            "terminal_result"
        ]["model"] = "gpt-4"
        changed_raw, evidence_identity, route_identity, action_digest = _repin(changed)
        changed_temporary, changed_store = _store(*parent_raw, changed_raw)
        self.addCleanup(changed_temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", evidence_identity),
            patch.object(subject, "_ROUTE_RAW", route_identity),
            patch.object(subject, "_ACTION_DIGEST", action_digest),
            patch.object(
                subject, "_verify_retained_evidence", return_value=changed_raw
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v2_cron_rescan(
                evidence_cas=changed_store
            )

    def test_coordinated_custody_mutations_fail_closed(self) -> None:
        parent_raw = [
            (_ROOT / identity["path"]).read_bytes()
            for identity in (
                subject.parent.parent._EVIDENCE,
                subject.parent._EVIDENCE,
            )
        ]
        cron_raw = (_ROOT / subject._EVIDENCE["path"]).read_bytes()
        canonical_json = (
            subject.parent.parent.legacy.parent.oci_worker_protocol.canonical_json
        )

        def rejects(
            changed: dict[str, object],
            *,
            host_config_digest: str | None = None,
            static_digests: dict[str, str] | None = None,
        ) -> None:
            changed_raw, evidence_identity, route_identity, action_digest = _repin(
                changed
            )
            temporary, store = _store(*parent_raw, changed_raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", evidence_identity),
                patch.object(subject, "_ROUTE_RAW", route_identity),
                patch.object(subject, "_ACTION_DIGEST", action_digest),
                patch.object(
                    subject,
                    "_HOST_CONFIG_DIGEST",
                    subject._HOST_CONFIG_DIGEST
                    if host_config_digest is None
                    else host_config_digest,
                ),
                patch.object(
                    subject,
                    "_STATIC_DIGESTS",
                    subject._STATIC_DIGESTS
                    if static_digests is None
                    else static_digests,
                ),
                patch.object(
                    subject, "_verify_retained_evidence", return_value=changed_raw
                ),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v2_cron_rescan(
                    evidence_cas=store
                )

        def repin_snapshot_store(after: dict[str, object]) -> None:
            snapshot = after["snapshot"]
            canonical_store = canonical_json(snapshot["store_document"])
            raw_store = canonical_store + b"\n"
            snapshot["entry_digest"] = _digest(
                canonical_json(snapshot["entry_document"])
            )
            snapshot["store_raw"] = {
                "base64": base64.b64encode(raw_store).decode(),
                "bytes": len(raw_store),
                "digest": _digest(raw_store),
            }
            snapshot["store"]["bytes"] = len(raw_store)
            snapshot["store"]["digest"] = _digest(raw_store)
            snapshot["store_document_bytes"] = len(canonical_store)
            snapshot["store_document_digest"] = _digest(canonical_store)
            after["session_store_after"]["size"] = len(raw_store)
            after["session_store_after"]["digest"] = _digest(raw_store)

        def repin_raw_snapshot_store(
            after: dict[str, object], raw_document: dict[str, object]
        ) -> None:
            snapshot = after["snapshot"]
            canonical_store = canonical_json(raw_document)
            raw_store = canonical_store + b"\n"
            snapshot["store_raw"] = {
                "base64": base64.b64encode(raw_store).decode(),
                "bytes": len(raw_store),
                "digest": _digest(raw_store),
            }
            snapshot["store"]["bytes"] = len(raw_store)
            snapshot["store"]["digest"] = _digest(raw_store)
            snapshot["store_document_bytes"] = len(canonical_store)
            snapshot["store_document_digest"] = _digest(canonical_store)
            after["session_store_after"]["size"] = len(raw_store)
            after["session_store_after"]["digest"] = _digest(raw_store)

        changed = deepcopy(json.loads(cron_raw))
        changed["route_observation"]["document"]["decision"] = {"edr_eligible": True}
        rejects(changed)

        for path in (
            ("limitations",),
            ("composition", "limitations"),
            ("composition", "action", "limitations"),
        ):
            changed = deepcopy(json.loads(cron_raw))
            value = changed
            for key in path[:-1]:
                value = value[key]
            value[path[-1]] = ["PUBLIC_RELEASE_AUTHORITY"]
            rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["route_observation"]["execution"]["edr_eligible"] = False
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["decision"]["route_pass_count"] = False
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["composition"]["decision"][
            "p3_7c_activation_action_observed"
        ] = 1
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["composition"]["action"]["decision"][
            "available_to_expired_observed"
        ] = 1
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["composition"]["action"]["secret_checks"][
            "gateway_environment_bytes_retained"
        ] = 0
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["source_artifacts"]["collector"]["bytes"] = 9473.0
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        collector = changed["source_artifacts"]["collector"]
        collector["path"] = "/tmp/forged.py"
        collector["stat"]["uid"] = 997
        collector["stat"]["mode"] = "0777"
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["source_artifacts"]["probe_bundle"][0]["bytes"] = 35318.0
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["route_observation"]["document"]["action"]["observations"][
            "session_store_after"
        ]["release_eligible"] = True
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["composition"]["action"]["cases"]["coherent_consumed"]["checks"][
            "release_eligible"
        ] = True
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        action["prerequisites"]["system_info_before"]["edr_eligible"] = False
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        terminal = action["observations"]["terminal_result"]
        poll_terminal = action["observations"]["run"]["terminal_poll"]["response"][
            "value"
        ]["entries"][0]
        terminal["edr_eligible"] = False
        poll_terminal["edr_eligible"] = False
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        action["commands"][3], action["commands"][4] = (
            action["commands"][4],
            action["commands"][3],
        )
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        inventories = (
            changed["route_observation"]["document"]["action"]["prerequisites"][
                "cron_inventory_before"
            ],
            changed["route_observation"]["document"]["action"]["observations"][
                "cron_inventory_after_add"
            ],
            changed["route_observation"]["document"]["action"]["observations"][
                "cron_inventory_after_remove"
            ],
        )
        for inventory in inventories:
            inode = inventory["store"]["database"]["inode"]
            inventory["store"]["shared_memory"]["inode"] = inode
            inventory["store"]["write_ahead_log"]["inode"] = inode
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        inventories = (
            changed["route_observation"]["document"]["action"]["prerequisites"][
                "cron_inventory_before"
            ],
            changed["route_observation"]["document"]["action"]["observations"][
                "cron_inventory_after_add"
            ],
            changed["route_observation"]["document"]["action"]["observations"][
                "cron_inventory_after_remove"
            ],
        )
        for inventory in inventories:
            inventory["store"]["database"]["mtime_ns"] = "9999999999999999999"
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        inventories = (
            changed["route_observation"]["document"]["action"]["prerequisites"][
                "cron_inventory_before"
            ],
            changed["route_observation"]["document"]["action"]["observations"][
                "cron_inventory_after_add"
            ],
            changed["route_observation"]["document"]["action"]["observations"][
                "cron_inventory_after_remove"
            ],
        )
        for index, inventory in enumerate(inventories, start=1):
            for name in ("shared_memory", "write_ahead_log"):
                inventory["store"][name]["mtime_ns"] = str(index)
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        inventories = (
            changed["route_observation"]["document"]["action"]["prerequisites"][
                "cron_inventory_before"
            ],
            changed["route_observation"]["document"]["action"]["observations"][
                "cron_inventory_after_add"
            ],
            changed["route_observation"]["document"]["action"]["observations"][
                "cron_inventory_after_remove"
            ],
        )
        reused_digest = inventories[0]["store"]["write_ahead_log"]["digest"]
        for inventory in inventories:
            inventory["store"]["database"]["digest"] = reused_digest
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        after = action["observations"]
        snapshot = after["snapshot"]
        coherent = "agent:main:aragorn-worker-coherent"
        snapshot["store_document"][coherent]["status"] = "forged"
        repin_snapshot_store(after)
        rejects(changed)

        for field, replacement in (("systemSent", 1), ("updatedAt", 1787382021199.0)):
            changed = deepcopy(json.loads(cron_raw))
            action = changed["route_observation"]["document"]["action"]
            after = action["observations"]
            snapshot = after["snapshot"]
            raw_document = json.loads(
                base64.b64decode(snapshot["store_raw"]["base64"])
            )
            raw_document[snapshot["base_session_key"]][field] = replacement
            repin_raw_snapshot_store(after, raw_document)
            rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        after = action["observations"]
        snapshot = after["snapshot"]
        base_session_key = snapshot["base_session_key"]
        snapshot["snapshot"]["metadata"]["promptFormatVersion"] = True
        snapshot["snapshot"]["metadata_digest"] = _digest(
            canonical_json(snapshot["snapshot"]["metadata"])
        )
        snapshot["entry_document"]["skillsSnapshot"]["promptFormatVersion"] = True
        snapshot["entry_document"]["skillsSnapshot"]["promptRef"]["version"] = True
        snapshot["blob"]["prompt_ref"]["version"] = True
        snapshot["store_document"][base_session_key] = deepcopy(
            snapshot["entry_document"]
        )
        repin_snapshot_store(after)
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        after = action["observations"]
        snapshot = after["snapshot"]
        base_session_key = snapshot["base_session_key"]
        future_version = 9_999_999_999_999
        snapshot["snapshot"]["metadata"]["version"] = future_version
        snapshot["snapshot"]["metadata_digest"] = _digest(
            canonical_json(snapshot["snapshot"]["metadata"])
        )
        snapshot["entry_document"]["skillsSnapshot"]["version"] = future_version
        snapshot["store_document"][base_session_key] = deepcopy(
            snapshot["entry_document"]
        )
        repin_snapshot_store(after)
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        after = action["observations"]
        snapshot = after["snapshot"]
        base_session_key = snapshot["base_session_key"]
        snapshot["snapshot"]["metadata"]["version"] = -1
        snapshot["snapshot"]["metadata_digest"] = _digest(
            canonical_json(snapshot["snapshot"]["metadata"])
        )
        snapshot["entry_document"]["skillsSnapshot"]["version"] = -1
        snapshot["store_document"][base_session_key] = deepcopy(
            snapshot["entry_document"]
        )
        repin_snapshot_store(after)
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        snapshot = changed["route_observation"]["document"]["action"]["observations"][
            "snapshot"
        ]
        snapshot["blob"]["inode"] = snapshot["store"]["inode"]
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["session_store_after"]["device"] = -1
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        replacement_inode = observations["snapshot"]["store"]["inode"] + 1
        observations["snapshot"]["store"]["inode"] = replacement_inode
        observations["session_store_after"]["inode"] = replacement_inode
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        database_inode = action["prerequisites"]["cron_inventory_before"]["store"][
            "database"
        ]["inode"]
        action["observations"]["snapshot"]["blob"]["inode"] = database_inode
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        host_config = changed["composition"]["action"]["harness"]["document"][
            "host_config"
        ]
        host_config["network_mode"] = "bridge"
        rejects(changed, host_config_digest=_digest(canonical_json(host_config)))

        changed = deepcopy(json.loads(cron_raw))
        changed["composition"]["action"]["harness"]["document"][
            "capture_disposition"
        ] = "PUBLIC_RELEASE_AUTHORITY"
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["composition"]["action"]["harness"]["document"][
            "route_input_mount"
        ]["rw"] = 0
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["composition"]["action"]["cases"]["coherent_consumed"]["status"] = (
            "PUBLIC_RELEASE_AUTHORIZED"
        )
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        action["observations"]["job"]["edr_eligible"] = False
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        action["observations"]["session_state_before_forced_run"]["store"]["path"] = (
            "/forged/sessions.json"
        )
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        action["observations"]["session_state_before_forced_run"]["store"][
            "mtime_ns"
        ] = "9999999999999999999"
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        request = action["observations"]["run"]["request"]
        request["response"]["value"]["enqueued"] = 1
        stdout = request["command"]["stdout_excerpt"].replace(
            '"enqueued": true', '"enqueued": 1'
        )
        request["command"]["stdout_excerpt"] = stdout
        request["command"]["stdout_bytes"] = len(stdout.encode())
        request["command"]["stdout_digest"] = _digest(stdout.encode())
        action["commands"][5] = deepcopy(request["command"])
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        cleanup = action["observations"]["cleanup"]
        cleanup["response"]["value"]["removed"] = 1
        stdout = cleanup["command"]["stdout_excerpt"].replace(
            '"removed": true', '"removed": 1'
        )
        cleanup["command"]["stdout_excerpt"] = stdout
        cleanup["command"]["stdout_bytes"] = len(stdout.encode())
        cleanup["command"]["stdout_digest"] = _digest(stdout.encode())
        action["commands"][7] = deepcopy(cleanup["command"])
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        inventory = action["prerequisites"]["cron_inventory_before"]["list"]
        inventory["response"]["value"]["hasMore"] = 0
        stdout = inventory["command"]["stdout_excerpt"].replace(
            '"hasMore": false', '"hasMore": 0'
        )
        inventory["command"]["stdout_excerpt"] = stdout
        inventory["command"]["stdout_bytes"] = len(stdout.encode())
        inventory["command"]["stdout_digest"] = _digest(stdout.encode())
        action["commands"][2] = deepcopy(inventory["command"])
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["route_observation"]["execution"]["stderr"]["bytes"] = False
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        action["prerequisites"]["system_info_before"]["command"]["pid"] = -1
        action["commands"][1]["pid"] = -1
        rejects(changed)

        for field in ("pid", "port"):
            changed = deepcopy(json.loads(cron_raw))
            action = changed["route_observation"]["document"]["action"]
            for index, call in (
                (1, action["prerequisites"]["system_info_before"]),
                (9, action["observations"]["system_info_after"]),
            ):
                old = call["response"]["value"][field]
                call["response"]["value"][field] = float(old)
                stdout = call["command"]["stdout_excerpt"].replace(
                    f'"{field}": {old}', f'"{field}": {old}.0'
                )
                call["command"]["stdout_excerpt"] = stdout
                call["command"]["stdout_bytes"] = len(stdout.encode())
                call["command"]["stdout_digest"] = _digest(stdout.encode())
                action["commands"][index] = deepcopy(call["command"])
            rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        call = action["observations"]["system_info_after"]
        old_uptime = call["response"]["value"]["uptimeMs"]
        call["response"]["value"]["uptimeMs"] = 1
        stdout = call["command"]["stdout_excerpt"].replace(
            f'"uptimeMs": {old_uptime}', '"uptimeMs": 1'
        )
        call["command"]["stdout_excerpt"] = stdout
        call["command"]["stdout_bytes"] = len(stdout.encode())
        call["command"]["stdout_digest"] = _digest(stdout.encode())
        action["commands"][9] = deepcopy(call["command"])
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["effective_identity"]["uid"] = 992.0
        static_digests = {
            **subject._STATIC_DIGESTS,
            "boundary": _digest(
                canonical_json(action["prerequisites"]["boundary_before"])
            ),
        }
        rejects(changed, static_digests=static_digests)

        changed = deepcopy(json.loads(cron_raw))
        service = "aragorn-agent-gateway.service"
        for stack in (
            changed["route_observation"]["stack_before"],
            changed["composition"]["action"]["boundaries"],
        ):
            stack["gateway_listener"]["fd_owners"] = []
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        service = "aragorn-agent-gateway.service"
        for stack in (
            changed["route_observation"]["stack_before"],
            changed["composition"]["action"]["boundaries"],
        ):
            stack["units"][service]["FragmentDigest"] = "sha256:" + "0" * 64
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        service = "aragorn-agent-gateway.service"
        for stack in (
            changed["route_observation"]["stack_before"],
            changed["composition"]["action"]["boundaries"],
        ):
            stack["units"][service]["ActiveState"] = "inactive"
            stack["service_state"]["units"][service]["properties"]["ActiveState"] = (
                "inactive"
            )
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        service = "aragorn-runtime-action-worker.service"
        for stack in (
            changed["route_observation"]["stack_before"],
            changed["composition"]["action"]["boundaries"],
        ):
            stack["processes"][service]["no_new_privileges"] = True
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        service = "aragorn-runtime-action-worker.service"
        for stack in (
            changed["route_observation"]["stack_before"],
            changed["composition"]["action"]["boundaries"],
        ):
            stack["processes"][service]["pid"] = float(
                stack["processes"][service]["pid"]
            )
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        service = "aragorn-runtime-action-worker.service"
        for stack in (
            changed["route_observation"]["stack_before"],
            changed["composition"]["action"]["boundaries"],
        ):
            stack["processes"][service]["cmdline"] = ["forged-worker"]
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        changed["route_observation"]["execution"]["exit_code"] = False
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        service = "aragorn-agent-gateway.service"
        for stack in (
            changed["route_observation"]["stack_before"],
            changed["composition"]["action"]["boundaries"],
        ):
            stack["service_state"]["units"][service]["cgroup_members"] = ["1"]
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        for name in ("prerequisites", "observations"):
            key = (
                "gateway_process_before"
                if name == "prerequisites"
                else "gateway_process_after"
            )
            action[name][key]["start_time_ticks"] = "1"
        for stack in (
            changed["route_observation"]["stack_before"],
            changed["composition"]["action"]["boundaries"],
        ):
            stack["processes"][service]["start_time_ticks"] = "1"
        static_digests = {
            **subject._STATIC_DIGESTS,
            "gateway": _digest(
                canonical_json(action["prerequisites"]["gateway_process_before"])
            ),
        }
        rejects(changed, static_digests=static_digests)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        action["prerequisites"]["module_files_before"] = {}
        action["observations"]["module_files_after"] = {}
        static_digests = {
            **subject._STATIC_DIGESTS,
            "modules": _digest(canonical_json({})),
        }
        rejects(changed, static_digests=static_digests)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        for key in ("module_files_before", "module_files_after"):
            action["prerequisites" if key == "module_files_before" else "observations"][
                key
            ]["cron"]["expected"]["digest"] = "sha256:" + "0" * 64
            action["prerequisites" if key == "module_files_before" else "observations"][
                key
            ]["cron"]["observed"]["digest"] = "sha256:" + "0" * 64
        static_digests = {
            **subject._STATIC_DIGESTS,
            "modules": _digest(
                canonical_json(action["prerequisites"]["module_files_before"])
            ),
        }
        rejects(changed, static_digests=static_digests)

        changed = deepcopy(json.loads(cron_raw))
        observation = changed["route_observation"]
        completed_at = observation["execution"]["completed_at"]
        for stack in (
            observation["stack_before"],
            changed["composition"]["action"]["boundaries"],
        ):
            stack["service_state"]["units"][service]["command"]["completed_at"] = (
                completed_at
            )
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        after = changed["route_observation"]["document"]["action"]["observations"]
        after["run"]["poll_count"] = True
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        after = changed["route_observation"]["document"]["action"]["observations"]
        terminal = after["terminal_result"]
        poll = after["run"]["terminal_poll"]
        old_run_at = terminal["runAtMs"]
        terminal["runAtMs"] = old_run_at + 1
        poll["response"]["value"]["entries"][0]["runAtMs"] = old_run_at + 1
        stdout = poll["command"]["stdout_excerpt"].replace(
            f'"runAtMs": {old_run_at}', f'"runAtMs": {old_run_at + 1}'
        )
        poll["command"]["stdout_excerpt"] = stdout
        poll["command"]["stdout_bytes"] = len(stdout.encode())
        poll["command"]["stdout_digest"] = _digest(stdout.encode())
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        after = action["observations"]
        terminal = after["terminal_result"]
        polls = (after["run"]["terminal_poll"], after["run"]["polls"][0])
        old_duration = terminal["durationMs"]
        terminal["durationMs"] = False
        for poll in polls:
            poll["response"]["value"]["entries"][0]["durationMs"] = False
            stdout = poll["command"]["stdout_excerpt"].replace(
                f'"durationMs": {old_duration}', '"durationMs": false'
            )
            poll["command"]["stdout_excerpt"] = stdout
            poll["command"]["stdout_bytes"] = len(stdout.encode())
            poll["command"]["stdout_digest"] = _digest(stdout.encode())
        action["commands"][6] = deepcopy(polls[0]["command"])
        rejects(changed)

        changed = deepcopy(json.loads(cron_raw))
        action = changed["route_observation"]["document"]["action"]
        after = action["observations"]
        terminal = after["terminal_result"]
        polls = (after["run"]["terminal_poll"], after["run"]["polls"][0])
        old_duration = terminal["durationMs"]
        terminal["durationMs"] = 999_999_999_999
        for poll in polls:
            poll["response"]["value"]["entries"][0]["durationMs"] = (
                terminal["durationMs"]
            )
            stdout = poll["command"]["stdout_excerpt"].replace(
                f'"durationMs": {old_duration}',
                f'"durationMs": {terminal["durationMs"]}',
            )
            poll["command"]["stdout_excerpt"] = stdout
            poll["command"]["stdout_bytes"] = len(stdout.encode())
            poll["command"]["stdout_digest"] = _digest(stdout.encode())
        action["commands"][6] = deepcopy(polls[0]["command"])
        rejects(changed)

        config_changed = deepcopy(json.loads(cron_raw))
        action = config_changed["route_observation"]["document"]["action"]
        for config in (
            action["prerequisites"]["config_before"],
            action["prerequisites"]["boundary_before"]["configuration"],
            action["observations"]["config_after"],
            action["observations"]["boundary_after"]["configuration"],
        ):
            config["document"]["tools"]["fs"]["workspaceOnly"] = False
        changed_raw, evidence_identity, route_identity, action_digest = _repin(
            config_changed
        )
        canonical_json = (
            subject.parent.parent.legacy.parent.oci_worker_protocol.canonical_json
        )
        static_digests = {
            **subject._STATIC_DIGESTS,
            "boundary": _digest(
                canonical_json(action["prerequisites"]["boundary_before"])
            ),
            "config": _digest(canonical_json(action["prerequisites"]["config_before"])),
        }
        changed_temporary, changed_store = _store(*parent_raw, changed_raw)
        self.addCleanup(changed_temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", evidence_identity),
            patch.object(subject, "_ROUTE_RAW", route_identity),
            patch.object(subject, "_ACTION_DIGEST", action_digest),
            patch.object(subject, "_STATIC_DIGESTS", static_digests),
            patch.object(
                subject, "_verify_retained_evidence", return_value=changed_raw
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v2_cron_rescan(
                evidence_cas=changed_store
            )


if __name__ == "__main__":
    unittest.main()
