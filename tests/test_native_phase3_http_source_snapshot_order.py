"""Lazy source inventory imports precede the signed source snapshot; no VM."""

from pathlib import Path
import unittest
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_json
from scripts import capture_native_phase3_http_attempt as capture
from scripts import prepare_native_phase3_http_development_plan as development
from scripts import capture_native_phase3_plugin_update_case as legacy
from scripts import capture_runtime_native_receipt_systemd_check as native
from scripts import prepare_native_plugin_update_identity_pins as pins


class HttpSourceSnapshotOrderTests(unittest.TestCase):
    def test_resolve_before_snapshot_and_refuse_genuine_source_change(self):
        path = "src/aragorn/phase3_reference_tasks.py"
        raw, digest = b"inert source", "sha256:" + "c" * 64
        initial = {"commit": "a" * 40}
        for subject, owner in ((capture, capture.renderer), (development, development)):
            for changed in (False, True):
                with self.subTest(module=subject.__name__, changed=changed):
                    events = []

                    def resolve():
                        events.append("paths")
                        return (path,)

                    def snapshot():
                        self.assertIn("paths", events)
                        events.append("source")
                        return (
                            {"commit": "b" * 40}
                            if changed and events.count("source") == 2
                            else initial
                        )

                    def tree(commit, selected):
                        events.append("tree")
                        self.assertEqual(
                            (commit, selected), (initial["commit"], Path(path))
                        )
                        return {"bytes": len(raw), "digest": digest}

                    def read(selected, pin):
                        events.append("read")
                        self.assertEqual(
                            (selected, pin), (subject.ROOT / path, (len(raw), digest))
                        )
                        return raw

                    with (
                        patch.object(owner, "source_paths", side_effect=resolve),
                        patch.object(legacy, "_current_source", side_effect=snapshot),
                        patch.object(
                            native.acquisition, "_tree_file", side_effect=tree
                        ),
                        patch.object(pins, "_read_fixed", side_effect=read),
                    ):
                        if changed:
                            with self.assertRaisesRegex(
                                ValueError, "signed source changed"
                            ):
                                subject._verified_sources()
                        else:
                            result = subject._verified_sources()
                            expected = {path: raw}
                            if subject is development:
                                expected = (canonical_json(initial), expected)
                            self.assertEqual(result, expected)
                    self.assertEqual(
                        events, ["paths", "source", "tree", "read", "source"]
                    )


if __name__ == "__main__":
    unittest.main()
