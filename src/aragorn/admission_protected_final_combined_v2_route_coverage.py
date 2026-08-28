"""Compose eleven current-contract V2 qualifications from nine captures."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v2_archive_replacement as archive
from . import (
    admission_protected_final_combined_v2_catalog_fixed_fresh_session_reset as fresh,
)
from . import (
    admission_protected_final_combined_v2_chat_session_snapshot_consumer_catalog_fixed as chat,
)
from . import admission_protected_final_combined_v2_config_activation as config
from . import admission_protected_final_combined_v2_curator_restore as curator
from . import admission_protected_final_combined_v2_plugin_enable as plugin_enable
from . import (
    admission_protected_final_combined_v2_cron_rescan_catalog_fixed as cron,
)
from . import (
    admission_protected_final_combined_v2_prompt_rebuild_catalog_fixed as prompt,
)
from . import (
    admission_protected_final_combined_v2_session_snapshot_consumer_catalog_fixed as session,
)
from . import (
    admission_protected_final_combined_v2_workshop_invalidation as workshop_reload,
)
from . import (
    admission_protected_final_combined_v2_workshop_proposal_apply as workshop,
)
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS
from .oci_worker_protocol import canonical_digest

_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_ELIGIBILITY_KEYS = config.base.legacy.parent._ELIGIBILITY_KEYS
_SHARED_BINDINGS = ("configuration", "profile", "runtime_lock", "skill", "runtime")
_VERIFIER_PATH = "src/aragorn/admission_protected_final_combined_v2_route_coverage.py"
_EXPECTED_SHARED_BINDINGS = {
    "configuration": {
        "bytes": 1_881,
        "canonical_bytes": 1_880,
        "canonical_digest": (
            "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
        ),
        "digest": (
            "sha256:d145feb4e935e6f86c7e2bfdeefcaec5fa4ebf8f044ffa472bd7589b03bf4fe8"
        ),
    },
    "profile": {
        "bytes": 4_951,
        "canonical_bytes": 4_950,
        "canonical_digest": (
            "sha256:a20ab2dd6572ada5fac086bc818495a6e6079f55f6fcbae397687c7b19eac59e"
        ),
        "digest": (
            "sha256:615928c74bb467ed1422aa19c0ca3266fec21e6a9b195ff32e7e2fae86f966fc"
        ),
    },
    "runtime_lock": {
        "bytes": 6_742,
        "canonical_bytes": 6_741,
        "canonical_digest": (
            "sha256:95f6088dfe227e27e136c7a1fb79688e0afa0ea3ac543137d7089d0a79f2eff9"
        ),
        "digest": (
            "sha256:4832dc99c016bd8c0f6d97133dbb7d3681d4ad18c1c225c94f10a51d6df839c1"
        ),
    },
    "skill": {
        "bytes": 140,
        "digest": (
            "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
        ),
    },
    "runtime": {
        "entrypoint_digest": (
            "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
        ),
        "runtime_digest": (
            "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154"
        ),
        "runtime_volume": "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1",
        "version_output": "OpenClaw 2026.7.1 (7fa98d8)",
    },
}
_EXPECTED_RUNTIME = {
    "commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
    "name": "openclaw-protected-final-combined-v2",
    "source_parent_commit": "805a4b152b0cee271ee78ad5608c15a4f8d1624b",
    "source_tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
    "upstream_base_commit": "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
    "version": "2026.7.1",
}
_ROUTES = (
    "ADM-02/update/archive-source-force-replacement",
    "ADM-02/update/clawhub-tracked-replacement",
    "ADM-02/update/config-entry-activation",
    "ADM-02/update/core-updater-plugin-replacement",
    "ADM-02/update/curator-restore-activation",
    "ADM-02/update/plugin-enable-activation",
    "ADM-02/update/plugin-force-reinstall",
    "ADM-02/update/plugin-package-skill-replacement",
    "ADM-02/update/workshop-proposal-apply",
    "ADM-02/reload/chat-session-snapshot-consumer",
    "ADM-02/reload/config-invalidation",
    "ADM-02/reload/cron-rescan",
    "ADM-02/reload/filesystem-watch-invalidation",
    "ADM-02/reload/fresh-session-reset",
    "ADM-02/reload/manual-plugin-invalidation",
    "ADM-02/reload/missing-prompt-blob-rebuild",
    "ADM-02/reload/plugin-skill-dir-activation",
    "ADM-02/reload/remote-eligibility-invalidation",
    "ADM-02/reload/sandbox-per-run-rescan",
    "ADM-02/reload/session-snapshot-consumer",
    "ADM-02/reload/workshop-invalidation",
)
_EXPECTED_PASS_ROUTES = frozenset(
    {
        config._ROUTE,
        fresh._ROUTE,
        cron._ROUTE,
        prompt._ROUTE,
        session._ROUTE,
        chat._ROUTE,
        archive._ROUTE,
        curator._ROUTE,
        workshop._ROUTE,
        workshop_reload._ROUTE,
        plugin_enable._ROUTE,
    }
)
_CHILDREN = (
    {
        "name": "config_entry_activation",
        "module": config,
        "verifier": "verify_openclaw_final_combined_v2_config_activation",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_config_activation.py"
        ),
        "verifier_digest": (
            "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6"
        ),
        "result_digest": (
            "sha256:488e8fb5dd5e1664f690af4f5740ab05f8ffcccb70ea1f988f75d5a899a11351"
        ),
        "capture_binding": "config_activation_observation",
        "capture_digest": (
            "sha256:34772c46c42541c4e76c1f9888b2ad35c8aa26d3b63746d8853ad1826a51373f"
        ),
        "route": config._ROUTE,
        "image": config._IMAGE,
    },
    {
        "name": "catalog_fixed_fresh_session_reset",
        "module": fresh,
        "verifier": (
            "verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset"
        ),
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_catalog_fixed_"
            "fresh_session_reset.py"
        ),
        "verifier_digest": (
            "sha256:dfea26baa270b7b1aecfa1e40838618d9ab4aa7f6e1d5ef006e5dfee1533b1dd"
        ),
        "result_digest": (
            "sha256:006e169cb8f45ba5d364b9402b3a44b58e45df19390859939d6884ead89708c5"
        ),
        "capture_binding": "fresh_session_reset_observation",
        "capture_digest": (
            "sha256:f804ea2ce5162e5b9317d544a0363d0b247844d6cfb07e4804cd0dc230986982"
        ),
        "route": fresh._ROUTE,
        "image": fresh._IMAGE,
    },
    {
        "name": "catalog_fixed_cron_rescan",
        "module": cron,
        "verifier": "verify_openclaw_final_combined_v2_cron_rescan_catalog_fixed",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_cron_rescan_"
            "catalog_fixed.py"
        ),
        "verifier_digest": (
            "sha256:685e8e17d15f107f66a8864ee0d19ae2fce995d98049c2e6d1eb4331b850d3b5"
        ),
        "result_digest": (
            "sha256:1f00f61957d12325b329dea4ca9cdb8f3f8aa3012380f430b1b358300868799b"
        ),
        "capture_binding": "cron_rescan_observation",
        "capture_digest": (
            "sha256:7914578bfadc88a33e0f2ea0ee97350de7be8881e852326a07294b74c5f3e003"
        ),
        "route": cron._ROUTE,
        "image": cron._IMAGE,
    },
    {
        "name": "catalog_fixed_prompt_rebuild",
        "module": prompt,
        "verifier": "verify_openclaw_final_combined_v2_prompt_rebuild_catalog_fixed",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_prompt_rebuild_"
            "catalog_fixed.py"
        ),
        "verifier_digest": (
            "sha256:df9623c4ff226b070f7cfed903a79d86a4eef0ad757114e61847709485b3ac2e"
        ),
        "result_digest": (
            "sha256:54f0132b56b31a1e3f3f07e58b9e0794fc32c2cbd44c35e718e1e7c8c5919869"
        ),
        "capture_binding": "prompt_rebuild_observation",
        "capture_digest": (
            "sha256:5ba5f02971788a9320f0de8a5ca4bbbdface6f216bafd3510fa42615d670cbb3"
        ),
        "route": prompt._ROUTE,
        "image": prompt._IMAGE,
    },
    {
        "name": "catalog_fixed_session_snapshot_consumer",
        "module": session,
        "verifier": (
            "verify_openclaw_final_combined_v2_session_snapshot_consumer_catalog_fixed"
        ),
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_session_snapshot_"
            "consumer_catalog_fixed.py"
        ),
        "verifier_digest": (
            "sha256:9f8c14d6c109bf0b2d686c354af64b0d65dd70ac5a34f405051f37bfa55dfcfa"
        ),
        "result_digest": (
            "sha256:a8b82efd6195ece5f00d2770c6778378305017318017d4d2419fd524f77d3315"
        ),
        "capture_binding": "session_snapshot_observation",
        "capture_digest": (
            "sha256:f4745ede0f7b4ed044df709ec8fa560dfa5ac98ce5139d766e01fa9f50f22c0f"
        ),
        "route": session._ROUTE,
        "image": session._IMAGE,
    },
    {
        "name": "catalog_fixed_chat_session_snapshot_consumer",
        "module": chat,
        "verifier": (
            "verify_openclaw_final_combined_v2_chat_session_snapshot_consumer_"
            "catalog_fixed"
        ),
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_chat_session_"
            "snapshot_consumer_catalog_fixed.py"
        ),
        "verifier_digest": (
            "sha256:f14ab10c8f005cc678a97a082666f66f886e4f3543a06426e53923f5f947a4d5"
        ),
        "result_digest": (
            "sha256:db740fce3d399a2ea77305ecef279369c02c4774ecb0a0892115dcb380e3bb35"
        ),
        "capture_binding": "session_snapshot_observation",
        "capture_digest": (
            "sha256:f4745ede0f7b4ed044df709ec8fa560dfa5ac98ce5139d766e01fa9f50f22c0f"
        ),
        "route": chat._ROUTE,
        "image": chat.parent._IMAGE,
    },
    {
        "name": "archive_post_write_activation_prevention",
        "module": archive,
        "verifier": "verify_openclaw_final_combined_v2_archive_replacement",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_archive_replacement.py"
        ),
        "verifier_digest": (
            "sha256:c31d209c5ea7af4181396bcdeb8a4e54d965ed793ba4fc4be489cd69e460602e"
        ),
        "result_digest": (
            "sha256:b1ca41a414eb51c47620e4eee26f739f99e7ff19e924c3a0798af55fa8f42d58"
        ),
        "capture_binding": "archive_replacement_observation",
        "capture_digest": (
            "sha256:3f6c258002ee8bd02ca764151145dbf11e58ecf80558f4635a773b6504d37e5b"
        ),
        "route": archive._ROUTE,
        "image": archive._IMAGE,
    },
    {
        "name": "curator_restore_activation",
        "module": curator,
        "verifier": "verify_openclaw_final_combined_v2_curator_restore",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_curator_restore.py"
        ),
        "verifier_digest": (
            "sha256:f03ae87ea84a8dc7af9596e79db7cc573b8ac1027949bf6e914674251008eaa6"
        ),
        "result_digest": (
            "sha256:981205655521c9b9fccb760917bdb77cd93fc1f767509ce3648dfe27aae80047"
        ),
        "capture_binding": "curator_restore_observation",
        "capture_digest": (
            "sha256:4dd8819dbb5dd579480d6f514366b20f1e6f81bd78d608d975c7541f3323b942"
        ),
        "route": curator._ROUTE,
        "image": curator._IMAGE,
    },
    {
        "name": "workshop_proposal_apply",
        "module": workshop,
        "verifier": "verify_openclaw_final_combined_v2_workshop_proposal_apply",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_workshop_"
            "proposal_apply.py"
        ),
        "verifier_digest": (
            "sha256:9eba3ac12956db45c280bc8b1ac8c123be81210c26c9270e180877ac2b9d43f8"
        ),
        "result_digest": (
            "sha256:d4d3ee7230ec1d303b1e8417340d8d48c45f448d1384ba7ba85c0675bc3c45f6"
        ),
        "capture_binding": "workshop_proposal_apply_observation",
        "capture_digest": (
            "sha256:55a6d55988aa79a963a49eb885bb63758daa3b575ff1d16c2d901cafe281b379"
        ),
        "route": workshop._ROUTE,
        "image": workshop._IMAGE,
    },
    {
        "name": "workshop_invalidation",
        "module": workshop_reload,
        "verifier": "verify_openclaw_final_combined_v2_workshop_invalidation",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_workshop_"
            "invalidation.py"
        ),
        "verifier_digest": (
            "sha256:a10e2d9d0da6061c9b28f6a633014f9fbfbf93866f30133418effa2ee54c5339"
        ),
        "result_digest": (
            "sha256:3a426658bff900ceac259229c6941d59c2094086049fc62ad9f6610d2c43b9d3"
        ),
        "capture_binding": "workshop_proposal_apply_observation",
        "capture_digest": (
            "sha256:55a6d55988aa79a963a49eb885bb63758daa3b575ff1d16c2d901cafe281b379"
        ),
        "route": workshop_reload._ROUTE,
        "image": workshop._IMAGE,
    },
    {
        "name": "plugin_enable_activation",
        "module": plugin_enable,
        "verifier": "verify_openclaw_final_combined_v2_plugin_enable",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_plugin_enable.py"
        ),
        "verifier_digest": (
            "sha256:4992378c9ed3d538b82a1e8e836eb45cf2b931b067069a0c04a2c7c76206ef4d"
        ),
        "result_digest": (
            "sha256:e0af5ec1d472e684374a1827a521416db7336e1564421300bcd7bd7946d8d402"
        ),
        "capture_binding": "plugin_enable_observation",
        "capture_digest": (
            "sha256:7b81759b062b62b9337d3e8cb0455b1a52c30b981d296f74211703cdd5c7ef33"
        ),
        "route": plugin_enable._ROUTE,
        "image": plugin_enable._IMAGE,
    },
)
_EXPECTED_CHILD_SEQUENCE = (
    (
        "config_entry_activation",
        config._ROUTE,
        "src/aragorn/admission_protected_final_combined_v2_config_activation.py",
        "config_activation_observation",
        "sha256:34772c46c42541c4e76c1f9888b2ad35c8aa26d3b63746d8853ad1826a51373f",
    ),
    (
        "catalog_fixed_fresh_session_reset",
        fresh._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_catalog_fixed_"
            "fresh_session_reset.py"
        ),
        "fresh_session_reset_observation",
        "sha256:f804ea2ce5162e5b9317d544a0363d0b247844d6cfb07e4804cd0dc230986982",
    ),
    (
        "catalog_fixed_cron_rescan",
        cron._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_cron_rescan_"
            "catalog_fixed.py"
        ),
        "cron_rescan_observation",
        "sha256:7914578bfadc88a33e0f2ea0ee97350de7be8881e852326a07294b74c5f3e003",
    ),
    (
        "catalog_fixed_prompt_rebuild",
        prompt._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_prompt_rebuild_"
            "catalog_fixed.py"
        ),
        "prompt_rebuild_observation",
        "sha256:5ba5f02971788a9320f0de8a5ca4bbbdface6f216bafd3510fa42615d670cbb3",
    ),
    (
        "catalog_fixed_session_snapshot_consumer",
        session._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_session_snapshot_"
            "consumer_catalog_fixed.py"
        ),
        "session_snapshot_observation",
        "sha256:f4745ede0f7b4ed044df709ec8fa560dfa5ac98ce5139d766e01fa9f50f22c0f",
    ),
    (
        "catalog_fixed_chat_session_snapshot_consumer",
        chat._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_chat_session_"
            "snapshot_consumer_catalog_fixed.py"
        ),
        "session_snapshot_observation",
        "sha256:f4745ede0f7b4ed044df709ec8fa560dfa5ac98ce5139d766e01fa9f50f22c0f",
    ),
    (
        "archive_post_write_activation_prevention",
        archive._ROUTE,
        "src/aragorn/admission_protected_final_combined_v2_archive_replacement.py",
        "archive_replacement_observation",
        "sha256:3f6c258002ee8bd02ca764151145dbf11e58ecf80558f4635a773b6504d37e5b",
    ),
    (
        "curator_restore_activation",
        curator._ROUTE,
        "src/aragorn/admission_protected_final_combined_v2_curator_restore.py",
        "curator_restore_observation",
        "sha256:4dd8819dbb5dd579480d6f514366b20f1e6f81bd78d608d975c7541f3323b942",
    ),
    (
        "workshop_proposal_apply",
        workshop._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_workshop_"
            "proposal_apply.py"
        ),
        "workshop_proposal_apply_observation",
        "sha256:55a6d55988aa79a963a49eb885bb63758daa3b575ff1d16c2d901cafe281b379",
    ),
    (
        "workshop_invalidation",
        workshop_reload._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_workshop_"
            "invalidation.py"
        ),
        "workshop_proposal_apply_observation",
        "sha256:55a6d55988aa79a963a49eb885bb63758daa3b575ff1d16c2d901cafe281b379",
    ),
    (
        "plugin_enable_activation",
        plugin_enable._ROUTE,
        "src/aragorn/admission_protected_final_combined_v2_plugin_enable.py",
        "plugin_enable_observation",
        "sha256:7b81759b062b62b9337d3e8cb0455b1a52c30b981d296f74211703cdd5c7ef33",
    ),
)


def compose_openclaw_final_combined_v2_route_coverage(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Compose eleven exact qualifications from nine captures without authority."""

    children: list[dict[str, Any]] = []
    names: set[str] = set()
    pass_routes: set[str] = set()
    results_by_name: dict[str, Mapping[str, Any]] = {}
    captures_by_name: dict[str, Mapping[str, Any]] = {}
    routes_by_capture: dict[str, list[str]] = {}
    shared: dict[str, Any] | None = None
    runtime: dict[str, Any] | None = None

    try:
        child_sequence = tuple(
            (
                child["name"],
                child["route"],
                child["verifier_path"],
                child["capture_binding"],
                child["capture_digest"],
            )
            for child in _CHILDREN
        )
        if child_sequence != _EXPECTED_CHILD_SEQUENCE:
            raise AdmissionEvidenceError("exact ordered V2 child inventory changed")
        for child in _CHILDREN:
            name = child["name"]
            route = child["route"]
            module = child["module"]
            if name in names or route in pass_routes:
                raise AdmissionEvidenceError("duplicate V2 child qualification")
            names.add(name)
            pass_routes.add(route)

            module_path = Path(module.__file__).resolve()
            if (
                not module_path.as_posix().endswith(child["verifier_path"])
                or _digest(module_path.read_bytes()) != child["verifier_digest"]
            ):
                raise AdmissionEvidenceError(f"{name} verifier implementation drifted")

            result = getattr(module, child["verifier"])(evidence_cas=evidence_cas)
            if canonical_digest(result) != child["result_digest"]:
                raise AdmissionEvidenceError(f"{name} canonical result drifted")
            _verify_child(result, child)
            results_by_name[name] = result
            capture = result["bindings"][child["capture_binding"]]
            if not isinstance(capture, Mapping):
                raise AdmissionEvidenceError(f"{name} capture binding is invalid")
            capture_digest = capture.get("digest")
            if (
                type(capture_digest) is not str
                or len(capture_digest) != 71
                or not capture_digest.startswith("sha256:")
                or any(
                    character not in "0123456789abcdef"
                    for character in capture_digest[7:]
                )
                or capture_digest != child["capture_digest"]
            ):
                raise AdmissionEvidenceError(f"{name} capture digest is invalid")
            captures_by_name[name] = capture
            routes_by_capture.setdefault(capture_digest, []).append(route)

            child_shared = {key: result["bindings"][key] for key in _SHARED_BINDINGS}
            if shared is None:
                shared = child_shared
                runtime = result["runtime"]
            elif child_shared != shared or result["runtime"] != runtime:
                raise AdmissionEvidenceError(
                    "V2 child shared contract binding mismatch"
                )

            children.append(
                {
                    "capture": {
                        "binding": child["capture_binding"],
                        "digest": capture_digest,
                    },
                    "image": result["bindings"]["image"],
                    "name": name,
                    "result_canonical_digest": child["result_digest"],
                    "route": route,
                    "source_recorded_at": result["source_recorded_at"],
                    "verifier": {
                        "digest": child["verifier_digest"],
                        "path": child["verifier_path"],
                    },
                }
            )

        children_by_name = {child["name"]: child for child in children}
        session_capture = captures_by_name["catalog_fixed_session_snapshot_consumer"]
        chat_capture = captures_by_name["catalog_fixed_chat_session_snapshot_consumer"]
        if chat_capture != session_capture:
            raise AdmissionEvidenceError(
                "V2 chat/session shared capture binding changed"
            )

        session_child = children_by_name["catalog_fixed_session_snapshot_consumer"]
        chat_result = results_by_name["catalog_fixed_chat_session_snapshot_consumer"]
        if (
            session_child["result_canonical_digest"] != chat._PARENT_RESULT_DIGEST
            or chat_result["bindings"]["parent_qualification_canonical_digest"]
            != chat._PARENT_RESULT_DIGEST
            or session_child["verifier"]
            != {
                "digest": chat._PARENT_MODULE["digest"],
                "path": chat._PARENT_MODULE["path"],
            }
            or chat_result["bindings"]["parent_verifier"]
            != {
                **chat._PARENT_SOURCE,
                "digest": chat._PARENT_MODULE["digest"],
                "path": chat._PARENT_MODULE["path"],
            }
            or chat_result["bindings"]["shared_capture"]
            != {
                "capture_relationship": (
                    "SHARED_WITH_SESSION_SNAPSHOT_CONSUMER_NOT_INDEPENDENT_CAPTURE"
                ),
                "source_route": session._ROUTE,
            }
            or chat_result["route_semantics"]["shared_capture_independent"] is not False
            or chat_result["route_semantics"]["source_capture_route"] != session._ROUTE
        ):
            raise AdmissionEvidenceError("V2 chat/session parent relationship changed")

        workshop_capture = captures_by_name["workshop_proposal_apply"]
        workshop_reload_capture = captures_by_name["workshop_invalidation"]
        if workshop_reload_capture != workshop_capture:
            raise AdmissionEvidenceError(
                "V2 workshop update/reload shared capture binding changed"
            )

        workshop_child = children_by_name["workshop_proposal_apply"]
        workshop_reload_result = results_by_name["workshop_invalidation"]
        if (
            workshop_child["result_canonical_digest"]
            != workshop_reload._PARENT_RESULT_DIGEST
            or workshop_reload_result["bindings"][
                "parent_qualification_canonical_digest"
            ]
            != workshop_reload._PARENT_RESULT_DIGEST
            or workshop_child["verifier"]
            != {
                "digest": workshop_reload._PARENT_MODULE["digest"],
                "path": workshop_reload._PARENT_MODULE["path"],
            }
            or workshop_reload_result["bindings"]["parent_verifier"]
            != {
                **workshop_reload._PARENT_SOURCE,
                "digest": workshop_reload._PARENT_MODULE["digest"],
                "path": workshop_reload._PARENT_MODULE["path"],
            }
            or workshop_reload_result["bindings"]["parent_receipt"]
            != workshop_reload._PARENT_RECEIPT
            or workshop_reload_result["bindings"]["shared_capture"]
            != {
                "capture_relationship": (
                    "SHARED_WITH_WORKSHOP_PROPOSAL_APPLY_NOT_INDEPENDENT_CAPTURE"
                ),
                "source_route": workshop._ROUTE,
            }
            or workshop_reload_result["route_semantics"][
                "shared_capture_independent"
            ]
            is not False
            or workshop_reload_result["route_semantics"]["source_capture_route"]
            != workshop._ROUTE
        ):
            raise AdmissionEvidenceError(
                "V2 workshop update/reload parent relationship changed"
            )

        shared_capture_groups = [
            {"capture_digest": digest, "routes": routes}
            for digest, routes in routes_by_capture.items()
            if len(routes) > 1
        ]
        if len(routes_by_capture) != 9 or shared_capture_groups != [
            {
                "capture_digest": session_capture["digest"],
                "routes": [session._ROUTE, chat._ROUTE],
            },
            {
                "capture_digest": workshop_capture["digest"],
                "routes": [workshop._ROUTE, workshop_reload._ROUTE],
            },
        ]:
            raise AdmissionEvidenceError("exact V2 nine-capture model changed")
    except AdmissionEvidenceError:
        raise
    except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(f"invalid V2 child qualification: {exc}") from exc

    if pass_routes != _EXPECTED_PASS_ROUTES or len(children) != 11:
        raise AdmissionEvidenceError("exact eleven V2 route qualifications are required")
    if shared is None or runtime is None:
        raise AdmissionEvidenceError("V2 child contract bindings are missing")
    implementation_digest = _digest(Path(__file__).resolve().read_bytes())

    qualification_digests = {
        child["route"]: child["result_canonical_digest"] for child in children
    }
    routes = [
        {
            "id": route,
            "qualification_digest": qualification_digests.get(route),
            "status": "PASS" if route in pass_routes else "NOT_TESTED",
        }
        for route in _ROUTES
    ]
    return {
        "schema": ("aragorn/admission-protected-final-combined-v2-route-coverage/v1"),
        "assurance": (
            "ELEVEN_EXACT_REVERIFIED_ROUTE_QUALIFICATIONS_FROM_NINE_CAPTURES_"
            "TWO_EXACT_SHARED_SUBSEQUENCES_ONLY"
        ),
        "bindings": {
            **{key: dict(shared[key]) for key in _SHARED_BINDINGS},
            "child_qualifications": children,
            "verifier_implementation_digest": implementation_digest,
            "verifier_source_path": _VERIFIER_PATH,
        },
        "capture_model": {
            "aggregate_execution_observed": False,
            "distinct_capture_count": len(routes_by_capture),
            "kind": (
                "ELEVEN_EXACT_ROUTE_QUALIFICATIONS_FROM_NINE_CAPTURES_"
                "TWO_EXACT_SHARED_SUBSEQUENCES"
            ),
            "qualification_count": 11,
            "same_image_required": False,
            "shared_capture_groups": shared_capture_groups,
        },
        "decision": {
            "status": "PARTIAL_SEPARATE_CAPTURE_V2_ROUTE_COVERAGE",
            **{key: False for key in _ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ELEVEN_EXACT_ROUTE_QUALIFICATIONS_COMPOSED_FROM_NINE_CAPTURES",
            "TEN_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "SEPARATE_CAPTURES_DO_NOT_ESTABLISH_AGGREGATE_ADMISSION",
            "CHAT_ROUTE_REUSES_SHARED_SESSION_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            "RAW_CAPTURE_ROUTE_ID_REMAINS_SESSION_SNAPSHOT_CONSUMER",
            "BLACK_BOX_NATIVE_CHAT_PERSISTENCE_WITHOUT_DIRECT_SESSION_UPDATE_TRACE",
            "ONE_TAMPER_RECOVERY_TRIGGER_NOT_GENERAL_CHAT_ROUTE_COVERAGE",
            "MODEL_TURNS_FAILED_NO_PROVIDER_BODY_SUCCESSFUL_REPLY_OR_DELIVERY_CLAIM",
            "SESSION_SNAPSHOT_COMPILED_CLOSURE_ACQUISITION_PRE_ROUTE_ONLY",
            "NO_POST_ROUTE_SESSION_CLOSURE_PROVENANCE_OR_CONTINUOUS_IMMUTABILITY_CLAIM",
            "SESSION_SNAPSHOT_DETERMINISTIC_COMPILED_REPLAY_NOT_NATIVE_AGENT_EXECUTION",
            "SESSION_SNAPSHOT_NATIVE_MODEL_ATTEMPTS_ENDED_IN_EXPECTED_NETWORK_ERROR",
            "SESSION_SNAPSHOT_NATIVE_PROVIDER_REQUEST_BODY_AND_SYSTEM_PROMPT_REPORT_NOT_OBSERVED",
            "SESSION_SNAPSHOT_FOURTEEN_SELECTED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "SESSION_SNAPSHOT_COMPILED_CLOSURE_REUSED_FROM_PRIOR_DIFFERENT_IMAGE_CAPTURE",
            "SESSION_SNAPSHOT_LOCAL_DOCKER_VOLUME_NOT_INDEPENDENTLY_ATTESTED",
            "SESSION_SNAPSHOT_ORIGINAL_PROVIDER_REQUEST_AND_SESSION_STORE_RAW_BYTES_NOT_RETAINED",
            "ARCHIVE_DIRECTORY_INSTALL_LEFT_EXCLUDED_WORKSPACE_SKILL_RESIDUE",
            "ARCHIVE_POST_WRITE_CATALOG_REJECTION_MAY_DENY_SKILL_DISCOVERY_AVAILABILITY",
            "NO_PRE_EFFECT_OR_NO_MUTATION_CLAIM_FOR_ARCHIVE_ROUTE",
            "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
            "EXACT_SELECTED_LIFECYCLE_ROW_ONLY_NOT_FULL_DATABASE_STATE",
            "SKILLS_STATUS_ARCHIVED_DIAGNOSTIC_NOT_ACTIVE_CONSUMER_PROOF",
            "WORKSHOP_RESIDUE_PERSISTS_THROUGH_FINAL_OBSERVATION",
            "WORKSHOP_POST_APPLY_AND_FINAL_SKILLS_STATUS_DENIED_BY_EXTERNAL_AUTHORITY",
            "NO_POST_APPLY_WORKSHOP_CATALOG_AVAILABILITY_CLAIM",
            "WORKSHOP_INVALIDATION_REUSES_SHARED_PROPOSAL_APPLY_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            "RAW_WORKSHOP_CAPTURE_ROUTE_ID_REMAINS_WORKSHOP_PROPOSAL_APPLY",
            "WORKSHOP_NEXT_SAME_SESSION_TURN_FAILED_NO_PROVIDER_SUCCESS_REPLY_OR_DELIVERY_CLAIM",
            "WORKSHOP_APPLIED_TARGET_BYTES_NOT_RETAINED_METADATA_DIGEST_ONLY",
            "WORKSHOP_RESIDUE_NOT_CLEANED_UP_NO_CLEANUP_ROLLBACK_OR_QUARANTINE_CLAIM",
            "WORKSHOP_SCAN_CLEAN_IS_SELF_REPORTED_DIAGNOSTIC_ONLY",
            "WORKSHOP_INVALIDATION_BLACK_BOX_NEXT_TURN_NO_DIRECT_FUNCTION_TRACE",
            "PLUGIN_ENABLE_DENIED_PRE_EFFECT_AT_READ_ONLY_SYSTEMD_CREDENTIAL_LOCK",
            "PLUGIN_ENABLE_TARGET_REMAINED_DISABLED_NOT_ALLOWLISTED_AND_UNACTIVATED",
            "SEPARATE_EXACT_CHILD_IMAGE_IDS_RETAINED_NOT_UNIFIED",
            "NO_AGGREGATE_ADMISSION_EDR_PHASE3_RELEASE_OR_INSTALLER_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 11, "NOT_TESTED": 10},
            "name": _PROFILE,
            "route_inventory_canonical_digest": canonical_digest(list(_ROUTES)),
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [
                route for route in _ROUTES if route in pass_routes
            ],
            "transitions_dynamically_exercised_in_one_aggregate_execution": False,
        },
        "runtime": dict(runtime),
    }


def _verify_child(result: Mapping[str, Any], child: Mapping[str, Any]) -> None:
    route = child["route"]
    expected_routes = [
        {"id": route_id, "status": "PASS" if route_id == route else "NOT_TESTED"}
        for route_id in _ROUTES
    ]
    expected_decision = {
        "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
        **{key: False for key in _ELIGIBILITY_KEYS},
    }
    counts = result["profile"]["counts"]
    decision = result["decision"]
    shared = {key: result["bindings"][key] for key in _SHARED_BINDINGS}
    if (
        set(counts) != {"PASS", "NOT_TESTED"}
        or type(counts["PASS"]) is not int
        or type(counts["NOT_TESTED"]) is not int
        or result["profile"]
        != {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": expected_routes,
        }
        or set(decision) != set(expected_decision)
        or decision["status"] != expected_decision["status"]
        or any(decision[key] is not False for key in _ELIGIBILITY_KEYS)
        or shared != _EXPECTED_SHARED_BINDINGS
        or result["runtime"] != _EXPECTED_RUNTIME
        or result["bindings"]["image"] != child["image"]
        or result["bindings"]["verifier_implementation_digest"]
        != child["verifier_digest"]
        or result["route_semantics"]["dynamically_exercised_routes"] != [route]
        or result["route_semantics"]["transitions_dynamically_exercised"] is not True
    ):
        raise AdmissionEvidenceError(
            f"{child['name']} route, decision, or runtime binding changed"
        )


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
