"""Review the B104/B75 assembly without writing a second full successor tree."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from scripts import prepare_pi_core_b105_payload as subject
from scripts.build_pi_core_linux import BuildError, canonical, sha256


class B105PayloadTests(TestCase):
    def test_exact_projection_preserves_the_retained_worker_and_native_files(self):
        payload, changed, outcome = subject.project()
        self.assertEqual((sha256(canonical(payload)), sha256(canonical(outcome))),
                         (subject.PAYLOAD_PIN, subject.OUTCOME_PIN))
        old = subject.split._index(json.loads(subject.image.read(subject.BASE / "payload.json",
                                                                 subject.BASE_PAYLOAD, 2 << 20))["entries"])
        new = subject.split._index(payload["entries"])
        actual = {p for p, row in new.items() if row != old.get(p)}
        self.assertEqual(set(changed), actual)
        self.assertEqual(len(actual), 46)
        self.assertEqual({p for p in old if p not in new}, set())
        self.assertTrue(all(not any(Path(p).is_relative_to(root) for root in subject.split.WORKER_ROOTS)
                            for p in actual))
        self.assertTrue(all(new[p]["sha256"] == sha256(raw) and new[p]["size"] == len(raw)
                            for p, raw in changed.items()))
        for flag in ("image_assembled", "installed_identity_verified", "activation_performed", "phase3_exit_eligible"):
            self.assertIs(outcome[flag], False)

    def test_b94_inventory_cannot_substitute_for_b104(self):
        with patch.object(subject.sources, "OUT", subject.sources.prior.OUT), patch.object(
                subject.git_sources, "_prepare", side_effect=AssertionError("wrong inventory reached projection")):
            with self.assertRaisesRegex(BuildError, "payload input digest differs"):
                subject.project()

    def test_existing_destination_refuses_before_projection(self):
        with TemporaryDirectory() as root:
            path = Path(root).resolve()
            with patch.object(subject, "OUT", path), patch.object(subject, "project", side_effect=AssertionError("retry")):
                with self.assertRaisesRegex(BuildError, "output already present"):
                    subject.prepare()
            self.assertEqual(list(path.iterdir()), [])
