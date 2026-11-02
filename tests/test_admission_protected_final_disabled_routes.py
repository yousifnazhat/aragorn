from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import admission_protected_final_disabled_routes as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_PATHS = {
    "composition": _ROOT
    / "benchmark/evidence/runtime-action-worker-final-combined-systemd-"
    "composition-p3-final-2026-08-13.json",
    "configuration": _ROOT / "benchmark/admission/openclaw-v2026.7.1/"
    "protected-final-combined-config-v1.json",
    "profile": _ROOT / "benchmark/admission/openclaw-v2026.7.1/"
    "protected-final-combined-profile-v1.json",
    "runtime_lock": _ROOT / "benchmark/admission/openclaw-v2026.7.1/"
    "protected-final-combined-runtime-v1.lock.json",
    "skill": _ROOT / "benchmark/runtime-action-worker-final-combined-systemd/SKILL.md",
    "plugin_index": _ROOT / "packaging/openclaw/aragorn-runtime-action-worker/index.js",
    "plugin_manifest": _ROOT
    / "packaging/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json",
    "plugin_package": _ROOT
    / "packaging/openclaw/aragorn-runtime-action-worker/package.json",
}


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _put_all(store: CAS, retained: dict[str, bytes]) -> None:
    for raw in retained.values():
        store.put_expected(
            BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw)
        )


def _repin(identities: dict[str, dict[str, object]], name: str, raw: bytes) -> None:
    identity = identities[name]
    identity["bytes"] = len(raw)
    identity["digest"] = _digest(raw)
    if "canonical_digest" in identity:
        document = json.loads(raw)
        canonical = subject.oci_worker_protocol.canonical_json(document)
        identity["canonical_bytes"] = len(canonical)
        identity["canonical_digest"] = _digest(canonical)


class FinalDisabledRouteTests(unittest.TestCase):
    def test_five_static_passes_and_hostile_inputs_fail_closed(self) -> None:
        retained = {name: path.read_bytes() for name, path in _PATHS.items()}
        self.assertEqual(
            {name: _digest(raw) for name, raw in retained.items()},
            {name: value["digest"] for name, value in subject._SOURCES.items()},
        )

        with TemporaryDirectory() as temporary:
            store = CAS(temporary)
            _put_all(store, retained)
            first = subject.verify_openclaw_final_disabled_routes(evidence_cas=store)
            self.assertEqual(
                first,
                subject.verify_openclaw_final_disabled_routes(evidence_cas=store),
            )
            self.assertEqual(
                subject.oci_worker_protocol.canonical_digest(first),
                "sha256:62dc1f68469422e5cc8ae8116fe8f6a9fef02f57256a39a0b3981541e50c8790",
            )
            self.assertEqual(first["profile"]["counts"], {"PASS": 5, "NOT_TESTED": 16})
            self.assertEqual(
                {
                    item["id"]
                    for item in first["profile"]["routes"]
                    if item["status"] == "PASS"
                },
                subject._PASS_ROUTES,
            )
            self.assertEqual(
                {item["status"] for item in first["profile"]["routes"]},
                {"PASS", "NOT_TESTED"},
            )
            self.assertEqual(
                first["route_semantics"],
                {
                    "pass_basis": "GATE_OR_DENY_UNDER_ADM-02",
                    "transitions_dynamically_exercised": False,
                },
            )
            self.assertEqual(
                set(first["decision"]), {"status", *subject._ELIGIBILITY_KEYS}
            )
            self.assertTrue(
                all(
                    first["decision"][key] is False for key in subject._ELIGIBILITY_KEYS
                )
            )

        for omitted in retained:
            with self.subTest(omitted_cas=omitted), TemporaryDirectory() as temporary:
                store = CAS(temporary)
                _put_all(
                    store,
                    {name: raw for name, raw in retained.items() if name != omitted},
                )
                with self.assertRaises(AdmissionEvidenceError):
                    subject.verify_openclaw_final_disabled_routes(evidence_cas=store)

        changed = dict(retained)
        composition = json.loads(changed["composition"])
        config = json.loads(changed["configuration"])
        profile = json.loads(changed["profile"])
        runtime_lock = json.loads(changed["runtime_lock"])
        config["skills"]["load"]["watch"] = True
        profile["controls"]["skill_watch"] = "enabled"
        runtime_lock["deployment_bindings"]["skill_source"]["watch"] = True
        composition["action"]["artifacts"]["final_combined"]["config"]["document"] = (
            config
        )
        composition["action"]["inputs"]["gateway_config"] = config
        composition["action"]["artifacts"]["final_combined"]["runtime_lock"][
            "document"
        ] = runtime_lock
        for location in (
            composition["profile"]["before"],
            composition["profile"]["after"],
            composition["action"]["artifacts"]["final_combined"]["profile"],
        ):
            location["document"] = profile
        for name, document in (
            ("composition", composition),
            ("configuration", config),
            ("profile", profile),
            ("runtime_lock", runtime_lock),
        ):
            changed[name] = subject.oci_worker_protocol.canonical_json(document) + b"\n"
        identities = deepcopy(subject._SOURCES)
        for name in ("composition", "configuration", "profile", "runtime_lock"):
            _repin(identities, name, changed[name])
        with (
            TemporaryDirectory() as temporary,
            patch.object(subject, "_SOURCES", identities),
        ):
            store = CAS(temporary)
            _put_all(store, changed)
            with self.assertRaisesRegex(AdmissionEvidenceError, "watch boundary"):
                subject.verify_openclaw_final_disabled_routes(evidence_cas=store)

        with (
            TemporaryDirectory() as temporary,
            patch.object(subject.cas, "__file__", __file__),
        ):
            store = CAS(temporary)
            _put_all(store, retained)
            with self.assertRaisesRegex(AdmissionEvidenceError, "dependency"):
                subject.verify_openclaw_final_disabled_routes(evidence_cas=store)

    def test_gateway_containment_envelope_rejects_repinned_changes(self) -> None:
        retained = {name: path.read_bytes() for name, path in _PATHS.items()}
        cases = {
            "user": ("units", {"User": "root"}),
            "group": ("units", {"Group": "root"}),
            "ambient capabilities": (
                "units",
                {"AmbientCapabilities": "cap_dac_override cap_sys_admin"},
            ),
            "capability bounding set": (
                "units",
                {"CapabilityBoundingSet": "cap_dac_override cap_sys_admin"},
            ),
            "new privileges": ("units", {"NoNewPrivileges": "no"}),
            "shared mounts": ("units", {"PrivateMounts": "no"}),
            "writable system": ("units", {"ProtectSystem": "full"}),
            "writable root": ("units", {"ReadWritePaths": "/"}),
            "missing inaccessible paths": ("units", {"InaccessiblePaths": ""}),
            "extra unit leaf": ("units", {"UnexpectedOverride": "yes"}),
            "effective capabilities": (
                "processes",
                {"capabilities_effective": "0000000000200002"},
            ),
            "effective new privileges": ("processes", {"no_new_privileges": 0}),
            "coordinated composition repin": (
                "units",
                {
                    "User": "root",
                    "Group": "root",
                    "AmbientCapabilities": "cap_dac_override cap_sys_admin",
                    "CapabilityBoundingSet": "cap_dac_override cap_sys_admin",
                    "NoNewPrivileges": "no",
                    "PrivateMounts": "no",
                },
            ),
        }
        for label, (section, changes) in cases.items():
            with self.subTest(label=label), TemporaryDirectory() as temporary:
                changed = dict(retained)
                composition = json.loads(changed["composition"])
                composition["action"]["boundaries"][section][
                    "aragorn-agent-gateway.service"
                ].update(changes)
                changed["composition"] = (
                    subject.oci_worker_protocol.canonical_json(composition) + b"\n"
                )
                identities = deepcopy(subject._SOURCES)
                _repin(identities, "composition", changed["composition"])
                store = CAS(temporary)
                _put_all(store, changed)
                with (
                    patch.object(subject, "_SOURCES", identities),
                    self.assertRaisesRegex(
                        AdmissionEvidenceError, "composition profile or runtime join"
                    ),
                ):
                    subject.verify_openclaw_final_disabled_routes(evidence_cas=store)

    def test_sibling_service_boundaries_reject_repinned_changes(self) -> None:
        retained = {name: path.read_bytes() for name, path in _PATHS.items()}
        original = json.loads(retained["composition"])
        boundaries = original["action"]["boundaries"]
        siblings = set(boundaries["units"]) - {"aragorn-agent-gateway.service"}
        self.assertEqual(
            siblings, set(boundaries["processes"]) - {"aragorn-agent-gateway.service"}
        )

        for service in sorted(siblings):
            for section, key, value in (
                ("units", "NoNewPrivileges", "no"),
                ("processes", "no_new_privileges", 0),
            ):
                with (
                    self.subTest(service=service, section=section),
                    TemporaryDirectory() as temporary,
                ):
                    changed = dict(retained)
                    composition = deepcopy(original)
                    composition["action"]["boundaries"][section][service][key] = value
                    changed["composition"] = (
                        subject.oci_worker_protocol.canonical_json(composition) + b"\n"
                    )
                    identities = deepcopy(subject._SOURCES)
                    _repin(identities, "composition", changed["composition"])
                    store = CAS(temporary)
                    _put_all(store, changed)
                    with (
                        patch.object(subject, "_SOURCES", identities),
                        self.assertRaisesRegex(
                            AdmissionEvidenceError,
                            "composition profile or runtime join",
                        ),
                    ):
                        subject.verify_openclaw_final_disabled_routes(
                            evidence_cas=store
                        )

    def test_dependency_paths_reject_same_bytes_at_another_path(self) -> None:
        modules = {
            "admission_evidence": subject.admission_evidence,
            "cas": subject.cas,
            "oci_worker_protocol": subject.oci_worker_protocol,
        }
        for name, module in modules.items():
            with self.subTest(module=name), TemporaryDirectory() as temporary:
                duplicate = Path(temporary) / f"{name}.py"
                duplicate.write_bytes(Path(module.__file__).read_bytes())
                with (
                    patch.object(module, "__file__", str(duplicate)),
                    self.assertRaisesRegex(AdmissionEvidenceError, "dependency"),
                ):
                    subject._verify_dependencies()

    def test_plugin_source_commit_rejects_coordinated_repins(self) -> None:
        retained = {name: path.read_bytes() for name, path in _PATHS.items()}
        changed = dict(retained)
        runtime_lock = json.loads(changed["runtime_lock"])
        runtime_lock["deployment_bindings"]["aragorn_plugin"]["source"]["commit"] = (
            "0" * 40
        )
        changed["runtime_lock"] = (
            subject.oci_worker_protocol.canonical_json(runtime_lock) + b"\n"
        )
        identities = deepcopy(subject._SOURCES)
        _repin(identities, "runtime_lock", changed["runtime_lock"])

        composition = json.loads(changed["composition"])
        embedded = composition["action"]["artifacts"]["final_combined"]["runtime_lock"]
        embedded["document"] = runtime_lock
        embedded["file"]["canonical_bytes"] = identities["runtime_lock"][
            "canonical_bytes"
        ]
        embedded["file"]["canonical_digest"] = identities["runtime_lock"][
            "canonical_digest"
        ]
        source = embedded["file"]["source"]
        source["bytes"] = source["stat"]["size"] = identities["runtime_lock"]["bytes"]
        source["digest"] = identities["runtime_lock"]["digest"]
        changed["composition"] = (
            subject.oci_worker_protocol.canonical_json(composition) + b"\n"
        )
        _repin(identities, "composition", changed["composition"])

        with (
            TemporaryDirectory() as temporary,
            patch.object(subject, "_SOURCES", identities),
        ):
            store = CAS(temporary)
            _put_all(store, changed)
            with self.assertRaisesRegex(AdmissionEvidenceError, "source.*lock"):
                subject.verify_openclaw_final_disabled_routes(evidence_cas=store)

    def test_plugin_file_type_rejects_coordinated_composition_repin(self) -> None:
        retained = {name: path.read_bytes() for name, path in _PATHS.items()}
        changed = dict(retained)
        composition = json.loads(changed["composition"])
        composition["action"]["artifacts"]["final_combined"]["plugin"]["index.js"][
            "stat"
        ]["type"] = "symlink"
        changed["composition"] = (
            subject.oci_worker_protocol.canonical_json(composition) + b"\n"
        )
        identities = deepcopy(subject._SOURCES)
        _repin(identities, "composition", changed["composition"])

        with (
            TemporaryDirectory() as temporary,
            patch.object(subject, "_SOURCES", identities),
        ):
            store = CAS(temporary)
            _put_all(store, changed)
            with self.assertRaisesRegex(
                AdmissionEvidenceError, "plugin index.js changed"
            ):
                subject.verify_openclaw_final_disabled_routes(evidence_cas=store)

    def test_retained_file_missing_path_rejects_composition_repin(self) -> None:
        retained = {name: path.read_bytes() for name, path in _PATHS.items()}
        changed = dict(retained)
        composition = json.loads(changed["composition"])
        del composition["action"]["harness"]["file"]["path"]
        changed["composition"] = (
            subject.oci_worker_protocol.canonical_json(composition) + b"\n"
        )
        identities = deepcopy(subject._SOURCES)
        _repin(identities, "composition", changed["composition"])

        with (
            TemporaryDirectory() as temporary,
            patch.object(subject, "_SOURCES", identities),
        ):
            store = CAS(temporary)
            _put_all(store, changed)
            with self.assertRaisesRegex(AdmissionEvidenceError, "retained shape"):
                subject.verify_openclaw_final_disabled_routes(evidence_cas=store)


if __name__ == "__main__":
    unittest.main()
