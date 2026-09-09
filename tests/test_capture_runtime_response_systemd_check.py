from __future__ import annotations

import json
import unittest
from copy import deepcopy
from unittest.mock import patch

from scripts import capture_runtime_response_systemd_check as subject
from scripts import prepare_runtime_response_systemd_check as prep


class ResponseCaptureTests(unittest.TestCase):
    def test_preparation_refuses_native_host_and_accepts_only_docker_systemd(
        self,
    ) -> None:
        with (
            patch.object(prep.sys, "platform", "linux"),
            patch.object(prep.os, "geteuid", return_value=0),
        ):
            for scope in ("/init.scope", "/", "/docker/../init.scope"):
                with (
                    patch.object(prep.response, "_process_cgroup", return_value=scope),
                    self.assertRaises(RuntimeError),
                ):
                    prep._require_fixture()
            with patch.object(
                prep.response,
                "_process_cgroup",
                return_value="/docker/" + "a" * 64 + "/init.scope",
            ):
                prep._require_fixture()

    def test_owned_cleanup_success_failure_and_parent_drift(self) -> None:
        parent = subject.campaign.current_v3_parent_identity()
        before = {
            "image_inspect": {"id": parent["image_id"]},
            "volume_inspect": {"name": parent["runtime_volume"]},
            "content": {
                "runtime_tree_before": {"digest": "fixed"},
                "runtime_tree_after": {"digest": "fixed"},
                "contract_files": {"config": {"content_base64": "e30="}},
            },
        }
        observation = {
            "check": {
                "status": "OBSERVED",
                "phase3_eligible": False,
                "run_conformance_eligible": False,
            }
        }
        for failure in (None, "create", "exec", "parent", "claim"):
            with self.subTest(failure=failure):
                after = deepcopy(before)
                if failure == "parent":
                    after["content"]["runtime_tree_after"]["digest"] = "changed"

                def docker(*arguments: str, failure: str | None = failure) -> bytes:
                    if arguments[0] == failure:
                        raise RuntimeError("fixture command failed")
                    if arguments[:2] == ("image", "inspect"):
                        layers = (
                            ["base", "child"]
                            if arguments[2] == subject._IMAGE
                            else ["base"]
                        )
                        return json.dumps(
                            [{"Id": arguments[2], "RootFS": {"Layers": layers}}]
                        ).encode()
                    if arguments[0] == "create":
                        return ("c" * 64).encode()
                    if arguments[:2] == ("container", "inspect"):
                        return json.dumps(
                            [
                                {
                                    "Id": "c" * 64,
                                    "Name": "/aragorn-runtime-response-check-"
                                    + "a" * 16,
                                    "Image": subject._IMAGE,
                                    "Config": {
                                        "Labels": {
                                            "dev.aragorn.snapshot-owner": "a" * 64
                                        }
                                    },
                                    "HostConfig": {"NetworkMode": "none"},
                                    "Mounts": [
                                        {
                                            "Destination": "/runtime",
                                            "Name": parent["runtime_volume"],
                                            "RW": False,
                                        }
                                    ],
                                }
                            ]
                        ).encode()
                    if arguments[0] == "exec" and arguments[-1].endswith(
                        "prepare_runtime_response_systemd_check.py"
                    ):
                        result = deepcopy(observation)
                        if failure == "claim":
                            result["check"]["phase3_eligible"] = True
                        return subject.campaign._canonical(result) + b"\n"
                    return b""

                with (
                    patch.object(
                        subject.existing,
                        "_source_identity",
                        return_value={"commit": "b" * 40},
                    ),
                    patch.object(
                        subject.existing.acquisition,
                        "_tree_file",
                        return_value={"bytes": 1, "digest": "test"},
                    ),
                    patch.object(subject.secrets, "token_hex", return_value="a" * 64),
                    patch.object(
                        subject.parent_snapshot,
                        "snapshot_parent",
                        side_effect=[before, after],
                    ),
                    patch.object(
                        subject.parent_snapshot,
                        "_cleanup_snapshot",
                        return_value={"container_name_absent": True},
                    ) as cleanup,
                    patch.object(subject, "_docker", side_effect=docker),
                ):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            subject._capture()
                    else:
                        result = subject._capture()
                        self.assertEqual(result["observation"], observation)
                        self.assertFalse(result["phase3_eligible"])
                    cleanup.assert_called_once_with(
                        "aragorn-runtime-response-check-" + "a" * 16,
                        "a" * 64,
                        subject._IMAGE,
                    )


if __name__ == "__main__":
    unittest.main()
