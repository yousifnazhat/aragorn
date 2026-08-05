from __future__ import annotations

import copy
import json
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import (
    RuntimeActionBrokerError,
    RuntimeActionEffectIndeterminate,
)
from aragorn.runtime_action_broker_v2 import (
    RuntimeActionBrokerV2Config,
    mediate_profiled_runtime_create,
)
from aragorn.runtime_process_profile import (
    ATTRIBUTION_AUTHORITY,
    ATTRIBUTION_SCHEMA,
)
from tests.test_runtime_action_broker import _Fixture, _observed_submission

_PROFILE = "sha256:" + "8" * 64


def _profiled_fixture(
    root: Path,
) -> tuple[_Fixture, RuntimeActionBrokerV2Config, dict[str, object]]:
    fixture = _Fixture(root)
    broker = replace(
        fixture.config,
        expected_peer_uid=os.geteuid() + 1,
        expected_peer_gid=os.getegid() + 1,
        expected_runtime_uid=os.geteuid() + 2,
        expected_runtime_gid=os.getegid(),
    )
    legacy = _observed_submission(fixture, broker)
    attribution = {
        "schema": ATTRIBUTION_SCHEMA,
        "authority": ATTRIBUTION_AUTHORITY,
        "profile_digest": _PROFILE,
        "runtime_digest": fixture.request["runtime_digest"],
        "executable_digest": "sha256:" + "5" * 64,
        "active_skill_digest": fixture.request["active_skill_digest"],
        "skill_path": "/opt/aragorn/runtime-profile/SKILL.md",
        "cgroup": "/system.slice/aragorn-openclaw-runtime.service",
        "pid": legacy["runtime_peer"]["pid"],
        "uid": legacy["runtime_peer"]["uid"],
        "gid": legacy["runtime_peer"]["gid"],
        "start_time_ticks": 741,
        "mount_namespace": {"device": 4, "inode": 55},
    }
    submission = {
        **legacy,
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "runtime_attribution": attribution,
    }
    config = RuntimeActionBrokerV2Config(
        broker=broker,
        expected_runtime_profile_digest=_PROFILE,
        profile_pending_path=fixture.control / "profile-pending.json",
        profile_receipt_path=fixture.control / "profile-receipt.json",
    )
    return fixture, config, submission


class RuntimeActionBrokerV2Tests(unittest.TestCase):
    def test_v2_mediation_creates_effect_and_durable_attribution_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, submission = _profiled_fixture(Path(temporary).resolve())
            with patch("aragorn.runtime_action_broker.time.time", return_value=100):
                result = mediate_profiled_runtime_create(submission, config)

            self.assertEqual(result["verdict"], "ALLOW")
            self.assertEqual(result["effect_status"], "CREATED")
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            self.assertFalse(config.profile_pending_path.exists())

            raw = config.profile_receipt_path.read_bytes()
            receipt = json.loads(raw)
            self.assertEqual(raw, canonical_json(receipt))
            self.assertEqual(
                stat.S_IMODE(config.profile_receipt_path.stat().st_mode), 0o400
            )
            self.assertEqual(
                receipt["schema"],
                "aragorn/runtime-process-profile-receipt/v1",
            )
            self.assertEqual(receipt["submission_digest"], canonical_digest(submission))
            self.assertEqual(
                receipt["runtime_attribution"], submission["runtime_attribution"]
            )
            self.assertEqual(
                receipt["runtime_attribution_digest"],
                canonical_digest(submission["runtime_attribution"]),
            )
            self.assertEqual(receipt["broker_result"], result)
            self.assertEqual(receipt["broker_result_digest"], canonical_digest(result))

    def test_v1_submission_is_rejected_before_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, submission = _profiled_fixture(Path(temporary).resolve())
            legacy = {
                **submission,
                "schema": "aragorn/runtime-observed-create-submission/v1",
            }
            legacy.pop("runtime_attribution")

            with self.assertRaisesRegex(
                RuntimeActionBrokerError,
                "profiled runtime submission",
            ):
                mediate_profiled_runtime_create(legacy, config)

            self.assertFalse(fixture.target.exists())
            self.assertFalse(config.profile_receipt_path.exists())
            self.assertEqual(fixture.load_state()["consumed"], [])

    def test_indeterminate_effect_retains_pending_and_blocks_reentry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _fixture, config, submission = _profiled_fixture(Path(temporary).resolve())
            with (
                patch(
                    "aragorn.runtime_action_broker_v2.mediate_observed_runtime_create",
                    side_effect=RuntimeActionEffectIndeterminate("uncertain"),
                ) as mediate,
                self.assertRaises(RuntimeActionEffectIndeterminate),
            ):
                mediate_profiled_runtime_create(submission, config)

            pending = json.loads(config.profile_pending_path.read_bytes())
            self.assertEqual(
                pending["schema"],
                "aragorn/runtime-process-profile-pending/v1",
            )
            self.assertEqual(pending["submission_digest"], canonical_digest(submission))
            with self.assertRaisesRegex(RuntimeActionBrokerError, "unresolved"):
                mediate_profiled_runtime_create(submission, config)
            self.assertEqual(mediate.call_count, 1)
            self.assertFalse(config.profile_receipt_path.exists())

    def test_mutated_or_unbound_attribution_is_rejected_before_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, submission = _profiled_fixture(Path(temporary).resolve())
            mutations = {
                "profile": lambda value: value.update(
                    profile_digest="sha256:" + "9" * 64
                ),
                "skill": lambda value: value.update(
                    active_skill_digest="sha256:" + "a" * 64
                ),
                "peer": lambda value: value.update(pid=value["pid"] + 1),
            }
            for label, mutate in mutations.items():
                candidate = copy.deepcopy(submission)
                mutate(candidate["runtime_attribution"])
                with (
                    self.subTest(label=label),
                    self.assertRaisesRegex(
                        RuntimeActionBrokerError,
                        "runtime process profile attribution is unbound",
                    ),
                ):
                    mediate_profiled_runtime_create(candidate, config)

            self.assertFalse(fixture.target.exists())
            self.assertFalse(config.profile_receipt_path.exists())
            self.assertEqual(fixture.load_state()["consumed"], [])


if __name__ == "__main__":
    unittest.main()
