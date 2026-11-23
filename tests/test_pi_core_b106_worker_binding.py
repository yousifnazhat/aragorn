"""Check the offline B105 content binding without running a worker or an observer."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from scripts import prepare_pi_core_b106_worker_binding as subject
from scripts.build_pi_core_linux import BuildError, sha256


class B106WorkerBindingTests(TestCase):
    def test_exact_b105_projection_rebinds_only_the_node_observer(self):
        raw, outcome, rows = subject.project()
        self.assertEqual(sha256(raw), subject.PLAN_PIN)
        self.assertFalse(raw.endswith(b"\n"))
        self.assertEqual(outcome["source_plan_digest"], "sha256:" + subject.PLAN_PIN)
        predecessor = (subject.BASE.with_name("Aragorn-B63-Offline") / "worker-source-plan.json").read_bytes()
        self.assertEqual(sha256(predecessor), subject.PRIOR_PLAN)
        plan = json.loads(raw)
        prior = json.loads(predecessor)
        self.assertNotEqual(prior["pins"]["node_observer_digest"], plan["pins"]["node_observer_digest"])
        prior["pins"]["node_observer_digest"] = plan["pins"]["node_observer_digest"]
        self.assertEqual(plan, prior)

        expected = {"/var/lib/aragorn/pi-os" + row["path"]: row["digest"] for row in plan["loader_files"]}
        prefix = "/opt/aragorn/pi-runtime/"
        runtime = "/var/lib/aragorn/pi-runtime/"
        expected.update({runtime + row["path"].removeprefix(prefix): row["digest"] for row in plan["sources"]})
        expected.update({runtime + "observer/source-gate": plan["pins"]["gate_digest"],
                         runtime + "node/bin/node": plan["pins"]["node_digest"]})
        for module, key in (("pi_core_source_observer", "producer_digest"),
                            ("pi_core_node_source_observer", "node_observer_digest")):
            path = "/opt/aragorn/src/aragorn/" + module + ".py"
            expected[path] = expected["/var/lib/aragorn/pi-service-runtime/root" + path] = plan["pins"][key]
        self.assertEqual(len(expected), 16)
        self.assertEqual({path: "sha256:" + row["sha256"] for path, row in rows.items()}, expected)
        for flag in ("installed_identity_verified", "worker_consumption_verified", "activation_authorized",
                     "phase3_exit_eligible"):
            self.assertIs(outcome[flag], False)

    def test_same_length_substituted_worker_member_refuses(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            member = root / "member"
            member.write_bytes(b"wrong")
            member.chmod(0o444)
            row = dict(path="/member", type="file", uid=0, gid=0, size=5, mode=0o444, sha256=sha256(b"right"))
            with self.assertRaises(BuildError):
                subject._read_rows(root, {"/member": row})

    def test_existing_destination_is_not_adopted(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with patch.object(subject, "OUT", root), patch.object(subject, "project", side_effect=AssertionError("retry")):
                with self.assertRaisesRegex(BuildError, "output already present"):
                    subject.prepare()
            self.assertEqual(list(root.iterdir()), [])
