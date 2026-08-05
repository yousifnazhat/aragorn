from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn import runtime_action_openclaw_revocation_evidence as verifier

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "runtime-action-openclaw-live-revocation-p3-3d-2026-08-05.json"
)


def _redigest(wrapper: dict) -> None:
    wrapper["digest"] = canonical_digest(wrapper["document"])


def _redigest_stdout(wrapper: dict) -> None:
    raw = canonical_json(wrapper["evidence"]) + b"\n"
    wrapper["stdout_bytes"] = len(raw)
    wrapper["stdout_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()


def _redigest_provider_record(record: dict) -> None:
    raw = canonical_json(record["body"])
    record["body_raw"] = raw.decode("ascii")
    record["body_bytes"] = len(raw)
    record["body_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    record["response_digest"] = "sha256:" + hashlib.sha256(
        canonical_json(record["response"])
    ).hexdigest()


class RuntimeActionOpenClawRevocationEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        raw = _EVIDENCE.read_bytes()
        cls.raw_digest = hashlib.sha256(raw).hexdigest()
        cls.document = json.loads(raw)
        cls.digest = canonical_digest(cls.document)

    def test_retained_evidence_verifies(self) -> None:
        self.assertEqual(
            self.raw_digest,
            "d75155cd6a9584350c7f015df7256b0147edb1484ae42e3213e9668d2289b6f1",
        )
        verifier.verify_runtime_action_openclaw_revocation_evidence(self.document)

    def test_explicit_digest_is_required_before_retained_pin(self) -> None:
        with (
            patch.object(verifier, "_EVIDENCE_DIGEST", None),
            self.assertRaisesRegex(
                AdmissionEvidenceError,
                "explicit retained evidence digest",
            ),
        ):
            verifier.verify_runtime_action_openclaw_revocation_evidence(
                self.document
            )

    def test_authority_and_scenario_mutations_are_rejected(self) -> None:
        mutations = []

        promoted = deepcopy(self.document)
        promoted["decision"]["run_02_eligible"] = True
        mutations.append(("authority", promoted))

        extra = deepcopy(self.document)
        extra["decision"]["release_gate_eligible"] = False
        mutations.append(("extra-authority", extra))

        missing = deepcopy(self.document)
        missing["scenarios"].pop("openclaw_sensor_unavailable")
        mutations.append(("scenario-set", missing))

        reason = deepcopy(self.document)
        result = reason["scenarios"]["openclaw_revoked_block"]["openclaw"][
            "evidence"
        ]["scenario"]["proof"]["retained_tool_result"]["result"]
        result["reason_codes"].append("MEDIATOR_UNHEALTHY")
        mutations.append(("sole-reason", reason))

        duplicate = deepcopy(self.document)
        duplicate["inputs"]["actions"]["revoked"] = duplicate["inputs"][
            "actions"
        ]["allow"]
        mutations.append(("distinct-action", duplicate))

        for label, document in mutations:
            with self.subTest(label), self.assertRaises(AdmissionEvidenceError):
                verifier.verify_runtime_action_openclaw_revocation_evidence(
                    document,
                    expected_digest=canonical_digest(document),
                )

    def test_revocation_transition_mutations_are_rejected(self) -> None:
        mutations = []

        digest = deepcopy(self.document)
        digest["revocation_transition"]["publication"]["revocations"][
            "skill_digests"
        ] = []
        mutations.append(("revoked-digest", digest))

        generation = deepcopy(self.document)
        generation["revocation_transition"]["publication"]["revocations"][
            "generation"
        ] += 1
        mutations.append(("generation", generation))

        staging = deepcopy(self.document)
        staging["revocation_transition"]["after_publication"][
            "staging_entries"
        ].append("unexpected")
        mutations.append(("staging", staging))

        target = deepcopy(self.document)
        target["revocation_transition"]["after_denial"]["target"][
            "lexists"
        ] = True
        mutations.append(("target", target))

        target_path = deepcopy(self.document)
        target_path["revocation_transition"]["after_publication"]["target"][
            "path"
        ] += ".changed"
        mutations.append(("target-path", target_path))

        journal = deepcopy(self.document)
        state = journal["scenarios"]["openclaw_revoked_block"][
            "control_after"
        ]["state"]
        state["document"]["effect_journal"] = {}
        _redigest(state)
        mutations.append(("journal", journal))

        sequence = deepcopy(self.document)
        observation = sequence["revocation_transition"]["after_denial"][
            "controls"
        ]["observation"]
        observation["document"]["sequence"] += 1
        _redigest(observation)
        mutations.append(("sequence", sequence))

        unhealthy = deepcopy(self.document)
        health = unhealthy["scenarios"]["openclaw_revoked_block"][
            "control_after"
        ]["health"]
        health["document"]["status"] = "unhealthy"
        _redigest(health)
        mutations.append(("unhealthy", unhealthy))

        publication_digest = deepcopy(self.document)
        publication = publication_digest["revocation_transition"]
        publication["publication"]["revocations"]["expires_at_unix"] += 1
        published = publication["after_publication"]["controls"]["revocations"]
        published["document"] = publication["publication"]["revocations"]
        _redigest(published)
        mutations.append(("publication-digest", publication_digest))

        floor = deepcopy(self.document)
        floor["scenarios"]["openclaw_revoked_block"]["openclaw"]["evidence"][
            "scenario"
        ]["proof"]["retained_tool_result"]["result"]["decision"][
            "minimum_revocation_generation"
        ] -= 1
        mutations.append(("decision-floor", floor))

        publisher = deepcopy(self.document)
        publisher["revocation_transition"]["publication"]["process"]["groups"] = []
        mutations.append(("publication-process", publisher))

        publisher_pid = deepcopy(self.document)
        publisher_pid["revocation_transition"]["publication"]["process"]["pid"] = (
            publisher_pid["deployment"]["processes"]["broker"]["pid"]
        )
        mutations.append(("publication-process-pid", publisher_pid))

        state_authority = deepcopy(self.document)
        for state in (
            state_authority["scenarios"]["openclaw_revoked_block"]["control_after"][
                "state"
            ],
            state_authority["revocation_transition"]["after_denial"]["controls"][
                "state"
            ],
        ):
            state["document"]["authority"] = "FORGED"
            _redigest(state)
        mutations.append(("denied-state-authority", state_authority))

        health_jump = deepcopy(self.document)
        for health in (
            health_jump["scenarios"]["openclaw_revoked_block"]["control_after"][
                "health"
            ],
            health_jump["revocation_transition"]["after_denial"]["controls"][
                "health"
            ],
        ):
            health["document"]["epoch"] += 1
            _redigest(health)
        for state in (
            health_jump["scenarios"]["openclaw_revoked_block"]["control_after"][
                "state"
            ],
            health_jump["revocation_transition"]["after_denial"]["controls"][
                "state"
            ],
        ):
            state["document"]["minimum_mediator_health_epoch"] += 1
            _redigest(state)
        mutations.append(("denied-health-floor-jump", health_jump))

        early_send = deepcopy(self.document)
        early_send["scenarios"]["openclaw_revoked_block"]["openclaw"][
            "evidence"
        ]["turn"]["send"]["command"]["started_at"] = "1970-01-01T00:00:00Z"
        _redigest_stdout(
            early_send["scenarios"]["openclaw_revoked_block"]["openclaw"]
        )
        mutations.append(("pre-publication-chat-send", early_send))

        early_provider = deepcopy(self.document)
        wrapper = early_provider["scenarios"]["openclaw_revoked_block"][
            "openclaw"
        ]
        records = wrapper["evidence"]["provider"]["records"]
        records[0]["received_at"] = "1970-01-01T00:00:00Z"
        records[1]["received_at"] = "1970-01-01T00:00:01Z"
        _redigest_stdout(wrapper)
        mutations.append(("pre-publication-provider", early_provider))

        for label, document in mutations:
            with self.subTest(label), self.assertRaises(AdmissionEvidenceError):
                verifier.verify_runtime_action_openclaw_revocation_evidence(
                    document,
                    expected_digest=canonical_digest(document),
                )

    def test_lineage_service_and_peer_mutations_are_rejected(self) -> None:
        mutations = []

        parent = deepcopy(self.document)
        parent["lineage"]["retained_p3c"]["canonical_digest"] = (
            "sha256:" + "0" * 64
        )
        mutations.append(("parent", parent))

        derivation = deepcopy(self.document)
        derivation["lineage"]["derivations"][0]["transformations"][0][
            "count"
        ] = 0
        mutations.append(("derivation", derivation))

        process = deepcopy(self.document)
        process["deployment_after_revocation"]["processes"]["sensor"][
            "start_time_ticks"
        ] = "1"
        mutations.append(("process", process))

        socket = deepcopy(self.document)
        socket["deployment_after_revocation"]["sockets"]["frontend"][
            "inode"
        ] += 1
        mutations.append(("socket", socket))

        peer = deepcopy(self.document)
        peer["peer_trace"]["sensor"]["peer_credentials"][-1]["uid"] += 1
        mutations.append(("peer", peer))

        harness = deepcopy(self.document)
        harness["harness"]["document"]["parent_image_id"] = "sha256:" + "1" * 64
        _redigest(harness["harness"])
        mutations.append(("harness", harness))

        harness_key = deepcopy(self.document)
        harness_key["harness"]["document"]["unexpected"] = False
        _redigest(harness_key["harness"])
        mutations.append(("harness-key", harness_key))

        host_network = deepcopy(self.document)
        host_network["harness"]["document"]["host_config"][
            "network_mode"
        ] = "bridge"
        _redigest(host_network["harness"])
        mutations.append(("host-network", host_network))

        runtime_mount = deepcopy(self.document)
        runtime_mount["harness"]["document"]["openclaw_runtime_mount"][
            "rw"
        ] = True
        _redigest(runtime_mount["harness"])
        mutations.append(("runtime-mount", runtime_mount))

        groups = deepcopy(self.document)
        for deployment in ("deployment", "deployment_after_revocation"):
            groups[deployment]["processes"]["broker"]["groups"] = [
                groups["identities"]["runtime_gid"]
            ]
        mutations.append(("service-groups", groups))

        for label, document in mutations:
            with self.subTest(label), self.assertRaises(AdmissionEvidenceError):
                verifier.verify_runtime_action_openclaw_revocation_evidence(
                    document,
                    expected_digest=canonical_digest(document),
                )

    def test_effect_proof_mutations_are_rejected(self) -> None:
        mutations = []

        target = deepcopy(self.document)
        target["scenarios"]["openclaw_allowed_create"]["target"]["digest"] = (
            target["inputs"]["actions"]["revoked"]["payload_digest"]
        )
        mutations.append(("allow-target", target))

        refresh = deepcopy(self.document)
        refresh["scenarios"]["openclaw_revoked_block"]["openclaw"][
            "control_refreshes"
        ].append(
            refresh["scenarios"]["openclaw_allowed_create"]["openclaw"][
                "control_refreshes"
            ][0]
        )
        mutations.append(("revoked-refresh", refresh))

        absent = deepcopy(self.document)
        absent["scenarios"]["openclaw_revoked_block"]["openclaw"]["evidence"][
            "turn"
        ]["target_after"]["exists"] = True
        mutations.append(("revoked-target", absent))

        for scenario in ("openclaw_allowed_create", "openclaw_revoked_block"):
            checks = deepcopy(self.document)
            checks["scenarios"][scenario]["openclaw"]["evidence"]["scenario"][
                "proof"
            ]["checks"]["target_effect_matches_result"] = False
            mutations.append((f"{scenario}-check", checks))

        for label, document in mutations:
            with self.subTest(label), self.assertRaises(AdmissionEvidenceError):
                verifier.verify_runtime_action_openclaw_revocation_evidence(
                    document,
                    expected_digest=canonical_digest(document),
                )

    def test_retained_context_mutations_are_rejected(self) -> None:
        mutations = []

        direct = deepcopy(self.document)
        direct["scenarios"]["runtime_direct_write"]["result"] = {
            "blocked": False,
            "errno": None,
            "error": None,
        }
        mutations.append(("direct-write-result", direct))

        sensor_target = deepcopy(self.document)
        sensor_target["scenarios"]["openclaw_sensor_unavailable"][
            "target_exists"
        ] = True
        mutations.append(("sensor-target", sensor_target))

        sensor_control = deepcopy(self.document)
        sensor_control["scenarios"]["openclaw_sensor_unavailable"][
            "control_after"
        ]["state"] = "sha256:" + "0" * 64
        mutations.append(("sensor-control", sensor_control))

        for label, document in mutations:
            with self.subTest(label), self.assertRaises(AdmissionEvidenceError):
                verifier.verify_runtime_action_openclaw_revocation_evidence(
                    document,
                    expected_digest=canonical_digest(document),
                )

    def test_fresh_composition_mutations_are_rejected(self) -> None:
        mutations = []

        command = deepcopy(self.document)
        command["scenarios"]["openclaw_allowed_create"]["openclaw"]["command"][
            1
        ] = "--reuid=0"
        mutations.append(("wrapper-command", command))

        stdout = deepcopy(self.document)
        stdout["scenarios"]["openclaw_allowed_create"]["openclaw"][
            "stdout_digest"
        ] = "sha256:" + "0" * 64
        mutations.append(("wrapper-stdout", stdout))

        configuration = deepcopy(self.document)
        wrapper = configuration["scenarios"]["openclaw_allowed_create"]["openclaw"]
        wrapper["evidence"]["configuration"]["digest"] = "sha256:" + "0" * 64
        _redigest_stdout(wrapper)
        mutations.append(("configuration-digest", configuration))

        provider = deepcopy(self.document)
        wrapper = provider["scenarios"]["openclaw_allowed_create"]["openclaw"]
        wrapper["evidence"]["provider"]["errors"].append("unexpected")
        _redigest_stdout(wrapper)
        mutations.append(("provider-error", provider))

        runtime = deepcopy(self.document)
        wrapper = runtime["scenarios"]["openclaw_allowed_create"]["openclaw"]
        wrapper["evidence"]["runtime"]["tree"]["file_count"] -= 1
        _redigest_stdout(wrapper)
        mutations.append(("runtime-tree", runtime))

        plugin = deepcopy(self.document)
        wrapper = plugin["scenarios"]["openclaw_allowed_create"]["openclaw"]
        wrapper["evidence"]["plugin"]["expected_tree_digest"] = (
            "sha256:" + "0" * 64
        )
        _redigest_stdout(wrapper)
        mutations.append(("plugin-pin", plugin))

        turn = deepcopy(self.document)
        wrapper = turn["scenarios"]["openclaw_revoked_block"]["openclaw"]
        wrapper["evidence"]["turn"]["target_after"]["path"] += ".changed"
        _redigest_stdout(wrapper)
        mutations.append(("turn-target", turn))

        result_target = deepcopy(self.document)
        wrapper = result_target["scenarios"]["openclaw_revoked_block"]["openclaw"]
        proof = wrapper["evidence"]["scenario"]["proof"]
        proof["retained_tool_result"]["result"]["target_name"] = "other.txt"
        raw = canonical_json(proof["retained_tool_result"])
        proof["tool_result"]["content"][0]["text"] = raw.decode("ascii")
        proof["retained_tool_result_digest"] = (
            "sha256:" + hashlib.sha256(raw).hexdigest()
        )
        _redigest_stdout(wrapper)
        mutations.append(("result-target", result_target))

        artifact = deepcopy(self.document)
        artifact["artifacts"][0]["installed_digest"] = "sha256:" + "0" * 64
        mutations.append(("artifact-binding", artifact))

        artifact_mode = deepcopy(self.document)
        artifact_mode["artifacts"][0]["installed_stat"]["mode"] = "0666"
        mutations.append(("artifact-mode", artifact_mode))

        artifact_missing = deepcopy(self.document)
        artifact_missing["artifacts"].pop()
        mutations.append(("artifact-closure", artifact_missing))

        status = deepcopy(self.document)
        status["scenarios"]["runtime_direct_write"]["status"] = "FAIL"
        mutations.append(("retained-status", status))

        service = deepcopy(self.document)
        for deployment in ("deployment", "deployment_after_revocation"):
            service[deployment]["processes"]["broker"]["cmdline"][-1] += ".changed"
        mutations.append(("service-command", service))

        published_policy = deepcopy(self.document)
        policy = published_policy["revocation_transition"]["after_publication"][
            "controls"
        ]["policy"]
        policy["document"]["id"] += "-changed"
        _redigest(policy)
        mutations.append(("publication-only-delta", published_policy))

        publication_health = deepcopy(self.document)
        publication_health["revocation_transition"]["publication"]["health"][
            "epoch"
        ] += 1
        mutations.append(("publication-health", publication_health))

        for label, document in mutations:
            with self.subTest(label), self.assertRaises(AdmissionEvidenceError):
                verifier.verify_runtime_action_openclaw_revocation_evidence(
                    document,
                    expected_digest=canonical_digest(document),
                )

    def test_adversarial_openclaw_lineage_mutations_are_rejected(self) -> None:
        mutations = []

        history = deepcopy(self.document)
        wrapper = history["scenarios"]["openclaw_allowed_create"]["openclaw"]
        wrapper["evidence"]["turn"]["history"]["response"]["messages"].pop()
        _redigest_stdout(wrapper)
        mutations.append(("history-message", history))

        provider_tools = deepcopy(self.document)
        wrapper = provider_tools["scenarios"]["openclaw_allowed_create"][
            "openclaw"
        ]
        record = wrapper["evidence"]["provider"]["records"][0]
        record["body"].pop("tools")
        _redigest_provider_record(record)
        _redigest_stdout(wrapper)
        mutations.append(("provider-tools", provider_tools))

        provider_call = deepcopy(self.document)
        wrapper = provider_call["scenarios"]["openclaw_allowed_create"]["openclaw"]
        record = wrapper["evidence"]["provider"]["records"][0]
        record["response"][0]["choices"][0]["delta"].pop("tool_calls")
        _redigest_provider_record(record)
        _redigest_stdout(wrapper)
        mutations.append(("provider-tool-call", provider_call))

        proof_id = deepcopy(self.document)
        wrapper = proof_id["scenarios"]["openclaw_revoked_block"]["openclaw"]
        wrapper["evidence"]["scenario"]["proof"]["tool_result"][
            "toolCallId"
        ] = "disconnected"
        _redigest_stdout(wrapper)
        mutations.append(("proof-tool-result-id", proof_id))

        authority = deepcopy(self.document)
        wrapper = authority["scenarios"]["openclaw_revoked_block"]["openclaw"]
        evidence = wrapper["evidence"]
        proof = evidence["scenario"]["proof"]
        proof["retained_tool_result"]["result"]["authority"] = "FORGED_AUTHORITY"
        raw = canonical_json(proof["retained_tool_result"])
        proof["tool_result"]["content"][0]["text"] = raw.decode("ascii")
        proof["retained_tool_result_digest"] = (
            "sha256:" + hashlib.sha256(raw).hexdigest()
        )
        evidence["turn"]["history"]["response"]["messages"][2] = deepcopy(
            proof["tool_result"]
        )
        record = evidence["provider"]["records"][1]
        for message in record["body"]["messages"]:
            if message.get("role") == "tool":
                message["content"] = raw.decode("ascii")
        _redigest_provider_record(record)
        _redigest_stdout(wrapper)
        mutations.append(("broker-result-authority", authority))

        send = deepcopy(self.document)
        wrapper = send["scenarios"]["openclaw_allowed_create"]["openclaw"]
        wrapper["evidence"]["turn"]["send"]["command"]["argv"][-1] = "{}"
        _redigest_stdout(wrapper)
        mutations.append(("send-argv", send))

        spawned = deepcopy(self.document)
        wrapper = spawned["scenarios"]["openclaw_allowed_create"]["openclaw"]
        gateway = wrapper["evidence"]["gateway"]
        gateway["spawned_pid"] += 1
        gateway["system_info"]["pid"] = gateway["spawned_pid"]
        _redigest_stdout(wrapper)
        mutations.append(("gateway-spawned-pid", spawned))

        shutdown = deepcopy(self.document)
        wrapper = shutdown["scenarios"]["openclaw_allowed_create"]["openclaw"]
        wrapper["evidence"]["gateway"]["shutdown"]["pid"] += 1
        _redigest_stdout(wrapper)
        mutations.append(("gateway-shutdown-pid", shutdown))

        plugin_file = deepcopy(self.document)
        wrapper = plugin_file["scenarios"]["openclaw_allowed_create"]["openclaw"]
        wrapper["evidence"]["plugin"]["snapshot"]["files"][0]["digest"] = (
            "sha256:" + "0" * 64
        )
        _redigest_stdout(wrapper)
        mutations.append(("plugin-file-digest", plugin_file))

        root_owner = deepcopy(self.document)
        wrapper = root_owner["scenarios"]["openclaw_allowed_create"]["openclaw"]
        for when in ("target_before", "target_after"):
            wrapper["evidence"]["turn"][when]["root"]["uid"] = root_owner[
                "identities"
            ]["attacker_uid"]
        _redigest_stdout(wrapper)
        mutations.append(("protected-root-owner", root_owner))

        outer_path = deepcopy(self.document)
        outer_path["scenarios"]["openclaw_allowed_create"]["target"]["path"] = (
            "/tmp/openclaw-allowed.txt"
        )
        mutations.append(("outer-target-path", outer_path))

        child_id = deepcopy(self.document)
        harness = child_id["harness"]["document"]
        harness["image_id"] = harness["run_image_reference"] = "child-image"
        harness["image_lineage"]["child"]["id"] = "child-image"
        _redigest(child_id["harness"])
        mutations.append(("child-image-id", child_id))

        for label, document in mutations:
            with self.subTest(label), self.assertRaises(AdmissionEvidenceError):
                verifier.verify_runtime_action_openclaw_revocation_evidence(
                    document,
                    expected_digest=canonical_digest(document),
                )


if __name__ == "__main__":
    unittest.main()
