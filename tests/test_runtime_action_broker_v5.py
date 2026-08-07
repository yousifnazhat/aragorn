from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from aragorn.runtime_action_broker import (
    RuntimeActionBrokerError,
    RuntimeActionEffectIndeterminate,
)
from aragorn.runtime_action_broker_v4 import initialize_runtime_capability_grant
from aragorn.runtime_action_broker_v5 import (
    LINEAGE_ISSUANCE_AUTHORITY,
    LINEAGE_ISSUANCE_SCHEMA,
    RuntimeActionBrokerV5Config,
    mediate_lineage_granted_profiled_runtime_create,
)
from aragorn.runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from aragorn.runtime_lineage_capability_issuer import (
    hold_profiled_runtime_capability_issuance,
)
from tests.test_runtime_action_broker_v4 import _fixture


def _wrapped(issuance: object, lineage: object) -> dict[str, object]:
    return {
        "schema": LINEAGE_ISSUANCE_SCHEMA,
        "authority": LINEAGE_ISSUANCE_AUTHORITY,
        "lineage": lineage,
        "issuance": issuance,
    }


class RuntimeActionBrokerV5Tests(unittest.TestCase):
    def test_sensor_issuer_emits_the_exact_v5_wrapper_while_locked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            _fixture_data, grant_broker, issuance = _fixture(root)
            lineage = {"active_record_digest": "sha256:" + "7" * 64}
            holding = False

            @contextmanager
            def hold(*_args: object, **_kwargs: object) -> Iterator[object]:
                nonlocal holding
                holding = True
                try:
                    yield lineage
                finally:
                    holding = False

            with (
                patch(
                    "aragorn.runtime_lineage_capability_issuer."
                    "hold_runtime_active_skill_lineage",
                    side_effect=hold,
                ),
                patch("aragorn.runtime_lineage_capability_issuer.require_live_pidfd"),
                patch(
                    "aragorn.runtime_lineage_capability_issuer."
                    "issue_profiled_runtime_capability",
                    return_value=issuance,
                ),
                hold_profiled_runtime_capability_issuance(
                    issuance["profiled_submission"],
                    grant_broker.capability_grant,
                    100,
                    pidfd=9,
                    lineage_snapshot=lineage,
                    protected_install_root=root / "protected-installs",
                ) as wrapped,
            ):
                self.assertTrue(holding)
                self.assertEqual(wrapped, _wrapped(issuance, lineage))
            self.assertFalse(holding)

    def test_live_lineage_is_held_through_frozen_v4_mediation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            _fixture_data, grant_broker, issuance = _fixture(root)
            protected_root = root / "protected-installs"
            config = RuntimeActionBrokerV5Config(grant_broker, protected_root)
            lineage = {"active_record_digest": "sha256:" + "7" * 64}
            holding = False

            @contextmanager
            def hold(
                pid: int,
                attribution: object,
                grant: object,
                **kwargs: object,
            ) -> Iterator[dict[str, object]]:
                nonlocal holding
                self.assertEqual(
                    pid, issuance["profiled_submission"]["runtime_attribution"]["pid"]
                )  # type: ignore[index]
                self.assertEqual(kwargs["protected_root"], protected_root)
                self.assertEqual(
                    grant["active_skill_digest"],  # type: ignore[index]
                    attribution["active_skill_digest"],  # type: ignore[index]
                )
                holding = True
                try:
                    yield lineage
                finally:
                    holding = False

            def mediate(*_args: object, **_kwargs: object) -> dict[str, object]:
                self.assertTrue(holding)
                return {"effect_status": "CREATED"}

            with (
                patch("aragorn.runtime_action_broker_v5.time.time", return_value=100),
                patch(
                    "aragorn.runtime_action_broker_v5."
                    "hold_runtime_active_skill_lineage",
                    side_effect=hold,
                ),
                patch(
                    "aragorn.runtime_action_broker_v5."
                    "mediate_granted_profiled_runtime_create",
                    side_effect=mediate,
                ) as frozen_v4,
            ):
                result = mediate_lineage_granted_profiled_runtime_create(
                    _wrapped(issuance, lineage),
                    config,
                )

            self.assertEqual(result["effect_status"], "CREATED")
            self.assertFalse(holding)
            frozen_v4.assert_called_once_with(
                issuance,
                grant_broker,
                deadline_monotonic=None,
            )

    def test_created_effect_with_lineage_cleanup_failure_is_indeterminate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            _fixture_data, grant_broker, issuance = _fixture(root)
            config = RuntimeActionBrokerV5Config(
                grant_broker,
                root / "protected-installs",
            )
            lineage = {"active_record_digest": "sha256:" + "7" * 64}

            @contextmanager
            def cleanup_fails(*_args: object, **_kwargs: object) -> Iterator[object]:
                yield lineage
                raise RuntimeActionObservationPublisherError("cleanup failed")

            with (
                patch("aragorn.runtime_action_broker_v5.time.time", return_value=100),
                patch(
                    "aragorn.runtime_action_broker_v5."
                    "hold_runtime_active_skill_lineage",
                    side_effect=cleanup_fails,
                ),
                patch(
                    "aragorn.runtime_action_broker_v5."
                    "mediate_granted_profiled_runtime_create",
                    return_value={"effect_status": "CREATED"},
                ),
                self.assertRaisesRegex(
                    RuntimeActionEffectIndeterminate,
                    "lineage cleanup failed",
                ),
            ):
                mediate_lineage_granted_profiled_runtime_create(
                    _wrapped(issuance, lineage),
                    config,
                )

    def test_old_or_changed_lineage_never_claims_the_grant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            _fixture_data, grant_broker, issuance = _fixture(root)
            config = RuntimeActionBrokerV5Config(
                grant_broker,
                root / "protected-installs",
            )
            initialize_runtime_capability_grant(grant_broker, now_unix=100)
            state_path = grant_broker.grant_state_path

            with (
                patch(
                    "aragorn.runtime_action_broker_v5.hold_runtime_active_skill_lineage"
                ) as hold,
                patch(
                    "aragorn.runtime_action_broker_v5."
                    "mediate_granted_profiled_runtime_create"
                ) as frozen_v4,
                self.assertRaisesRegex(RuntimeActionBrokerError, "lineage-profiled"),
            ):
                mediate_lineage_granted_profiled_runtime_create(issuance, config)
            hold.assert_not_called()
            frozen_v4.assert_not_called()
            self.assertEqual(json.loads(state_path.read_bytes())["status"], "AVAILABLE")

            @contextmanager
            def changed(*_args: object, **_kwargs: object) -> Iterator[object]:
                yield {"active_record_digest": "sha256:" + "8" * 64}

            with (
                patch("aragorn.runtime_action_broker_v5.time.time", return_value=100),
                patch(
                    "aragorn.runtime_action_broker_v5."
                    "hold_runtime_active_skill_lineage",
                    side_effect=changed,
                ),
                patch(
                    "aragorn.runtime_action_broker_v5."
                    "mediate_granted_profiled_runtime_create"
                ) as frozen_v4,
                self.assertRaisesRegex(RuntimeActionBrokerError, "lineage changed"),
            ):
                mediate_lineage_granted_profiled_runtime_create(
                    _wrapped(
                        issuance,
                        {"active_record_digest": "sha256:" + "7" * 64},
                    ),
                    config,
                )
            frozen_v4.assert_not_called()
            self.assertEqual(json.loads(state_path.read_bytes())["status"], "AVAILABLE")


if __name__ == "__main__":
    unittest.main()
