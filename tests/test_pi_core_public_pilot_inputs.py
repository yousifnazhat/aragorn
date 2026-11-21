"""Public pilot inputs only: prepare bytes, never admit a worker, call a provider, or perform an effect."""
from contextlib import redirect_stdout
from dataclasses import replace
from hashlib import sha256
from io import StringIO
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase

from aragorn import cli, pi_core_confined_launch as launch, pi_core_native_provider as native
from aragorn import pi_core_openai_responses as responses
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.pi_core_bundle_install_entry import _supported_bundle
from tests import test_pi_core_confined_launch as launch_fixture
from tests import test_pi_core_openai_responses as responses_fixture
from tests import test_pi_core_provider_start as start_fixture


INPUT = Path(__file__).resolve().parents[1] / "benchmark/pi-core-pilot-v1"
CANDIDATE = INPUT / "candidate"
OUT = Path.home() / "Library/Application Support/Aragorn-B95-Offline"


def digest(raw):
    return "sha256:" + sha256(raw).hexdigest()


class PublicPilotInputs(TestCase):
    def test_exact_pilot_prompt_has_one_tool_and_one_inert_rendered_request(self):
        review = json.loads((INPUT / "review.json").read_bytes())
        skill, task = (CANDIDATE / "SKILL.md").read_bytes(), (INPUT / "task.txt").read_bytes()
        self.assertEqual((digest(skill), digest(task)), (review["skill_digest"], review["task_digest"]))
        self.assertEqual(review["inputs"], [1, 2])
        answer = canonical_json({"total": sum(review["inputs"])})
        self.assertEqual((digest(answer), len(answer)), (review["expected_payload_digest"], review["expected_payload_bytes"]))
        self.assertNotIn(answer, skill)
        self.assertNotIn(answer, task)
        self.assertEqual(review["target_name"], "result.json")
        self.assertEqual(task.count(('"'+review["target_name"]+'"').encode("ascii")), 1)

        route = responses_fixture.route()  # Existing inert model, not a nominated provider configuration.
        cfg = replace(start_fixture.configuration(), task=task.decode("utf-8"),
                      model=responses_fixture.request()["payload"]["model"], provider_route_digest=canonical_digest(route))
        bundle = replace(launch_fixture.prepared_for(launch_fixture.profile_for(cfg)), members=(("SKILL.md", skill),),
                         system_prompt=skill.decode("utf-8"), skill_digest=digest(skill), tree_digest=review["tree_digest"])
        start_bytes = launch._start(cfg, bundle)
        start = json.loads(start_bytes)
        self.assertEqual((start["schema"], start["provider_status"]), ("aragorn/pi-core-bootstrap-start/v3", "PROTECTED"))
        self.assertEqual((start["provider"]["max_requests"], start["limits"]["maxToolCalls"], start["limits"]["maxTurns"]),
                         (1, 1, 1))
        self.assertEqual((review["max_provider_requests"], review["max_tool_calls"]), (1, 1))
        request = native._expected_request(SimpleNamespace(start_bytes=start_bytes))
        body = json.loads(responses.render_request(request, route))
        self.assertEqual((request["sequence"], body["model"]), (1, route["model"]))
        self.assertEqual(body["input"], [{"role": role, "content": [{"type": "input_text", "text": raw.decode("utf-8")}]}
                                        for role, raw in (("system", skill), ("user", task))])
        self.assertEqual([t["name"] for t in body["tools"]], [review["tool_name"]])
        self.assertEqual(review["tool_name"], "aragorn_runtime_create")
        self.assertIs(body["parallel_tool_calls"], False)

    def test_single_use_cli_inventory_and_read_only_supported_bundle(self):
        review = json.loads((INPUT / "review.json").read_bytes())
        skill = (CANDIDATE / "SKILL.md").read_bytes()
        self.assertEqual(digest(skill), review["skill_digest"])
        files = [dict(path="SKILL.md", size=len(skill), digest=digest(skill), executable=False)]
        self.assertEqual(canonical_digest(files), review["tree_digest"])
        expected = dict(schema="aragorn/manifest/v1", source=dict(kind="local", path=str(CANDIDATE.resolve(strict=True))),
                        tree_digest=review["tree_digest"], files=files, closure=dict(scope="source_tree",status="complete"))
        pin = canonical_digest(expected)
        parent = OUT.parent
        self.assertEqual(parent.resolve(strict=True), parent)
        self.assertEqual(parent.stat().st_uid, os.geteuid())
        self.assertFalse(parent.stat().st_mode & 0o022)
        self.assertFalse(os.path.lexists(OUT), "existing or partial B95 stage; do not adopt, overwrite, or retry")
        OUT.mkdir(mode=0o700)  # Exclusive; retain even a failed partial attempt.
        store = OUT / "candidate-cas"
        stream = StringIO()
        with redirect_stdout(stream):
            self.assertEqual(cli.main(["inventory", str(CANDIDATE), "--state", str(store)]), 0)
        self.assertEqual(json.loads(stream.getvalue()), dict(schema="aragorn/inventory-result/v1",
            manifest_digest=pin, tree_digest=review["tree_digest"], file_count=1, closure=expected["closure"]))
        cas = CAS(store, read_only=True)
        self.assertEqual(_supported_bundle(cas, pin), expected)
        self.assertEqual(cas.read(review["skill_digest"], max_bytes=32 * 1024), skill)
        print(json.dumps({"manifest_digest": pin, "tree_digest": review["tree_digest"]}, sort_keys=True))
