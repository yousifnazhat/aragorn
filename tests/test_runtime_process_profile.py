from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_process_profile as profile_module
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from aragorn.runtime_process_profile import (
    ATTRIBUTION_SCHEMA,
    PROFILE_AUTHORITY,
    PROFILE_SCHEMA,
    _profile_skill_digest,
    _require_process_status,
    measure_runtime_process_profile,
    runtime_process_profile,
)

_RUNTIME = "sha256:" + "1" * 64
_EXECUTABLE = "sha256:" + "5" * 64
_SKILL = "sha256:" + "2" * 64


def _profile(**changes: object) -> dict[str, object]:
    return {
        "schema": PROFILE_SCHEMA,
        "authority": PROFILE_AUTHORITY,
        "runtime_digest": _RUNTIME,
        "executable_digest": _EXECUTABLE,
        "cgroup": "/system.slice/aragorn-openclaw-runtime.service",
        "skill_path": "/opt/aragorn/runtime-profile/SKILL.md",
        **changes,
    }


class RuntimeProcessProfileTests(unittest.TestCase):
    def test_profile_is_exact_and_canonical_digest_bound(self) -> None:
        document = _profile()
        profile = runtime_process_profile(document)

        self.assertEqual(profile.runtime_digest, _RUNTIME)
        self.assertEqual(profile.executable_digest, _EXECUTABLE)
        self.assertEqual(profile.cgroup, document["cgroup"])
        self.assertEqual(profile.skill_path, Path(document["skill_path"]))
        self.assertEqual(profile.digest, canonical_digest(document))

        invalid = (
            _profile(extra=True),
            _profile(schema="aragorn/runtime-single-skill-process-profile/v2"),
            _profile(runtime_digest="SHA256:" + "1" * 64),
            _profile(executable_digest="SHA256:" + "5" * 64),
            _profile(cgroup="/system.slice/../escape.service"),
            _profile(skill_path="relative/SKILL.md"),
            _profile(skill_path="/opt/aragorn/runtime-profile/not-skill.txt"),
        )
        for candidate in invalid:
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(RuntimeActionObservationPublisherError),
            ):
                runtime_process_profile(candidate)

    def test_measurement_derives_live_process_and_skill_attribution(self) -> None:
        profile = runtime_process_profile(_profile())
        with (
            patch.object(
                profile_module,
                "_process_start_time",
                side_effect=(741, 741),
            ),
            patch.object(
                profile_module,
                "_process_cgroup",
                return_value=profile.cgroup,
            ),
            patch.object(
                profile_module,
                "_cgroup_processes",
                return_value=(123,),
            ),
            patch.object(profile_module, "_require_process_status") as status,
            patch.object(
                profile_module,
                "_mount_namespace",
                return_value={"device": 7, "inode": 8},
            ),
            patch.object(
                profile_module,
                "_profile_skill_digest",
                return_value=_SKILL,
            ),
            patch.object(
                profile_module,
                "_executable_digest",
                return_value=_EXECUTABLE,
            ),
            patch.object(profile_module, "require_live_pidfd") as live,
        ):
            attribution = measure_runtime_process_profile(
                123,
                9,
                profile,
                expected_uid=501,
                expected_gid=20,
            )

        self.assertEqual(attribution["schema"], ATTRIBUTION_SCHEMA)
        self.assertEqual(attribution["profile_digest"], profile.digest)
        self.assertEqual(attribution["active_skill_digest"], _SKILL)
        self.assertEqual(attribution["executable_digest"], _EXECUTABLE)
        self.assertEqual(attribution["start_time_ticks"], 741)
        self.assertEqual(attribution["mount_namespace"], {"device": 7, "inode": 8})
        self.assertEqual(
            (attribution["pid"], attribution["uid"], attribution["gid"]),
            (123, 501, 20),
        )
        self.assertEqual(live.call_count, 2)
        status.assert_called_once_with(123, 501, 20)

        with (
            patch.object(profile_module, "require_live_pidfd"),
            patch.object(profile_module, "_process_start_time", return_value=741),
            patch.object(
                profile_module,
                "_process_cgroup",
                return_value="/system.slice/sibling.service",
            ),
            self.assertRaisesRegex(
                RuntimeActionObservationPublisherError,
                "cgroup does not match",
            ),
        ):
            measure_runtime_process_profile(
                123,
                9,
                profile,
                expected_uid=501,
                expected_gid=20,
            )

    def test_skill_hash_uses_immutable_skill_file_with_companions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            skill = root / "SKILL.md"
            skill.write_bytes(b"bounded skill\n")
            skill.chmod(0o444)
            real_read = profile_module._read_owned_bytes_at

            def read_as_test_owner(
                descriptor: int,
                name: str,
                **kwargs: object,
            ) -> bytes:
                kwargs["expected_uid"] = os.geteuid()
                return real_read(descriptor, name, **kwargs)

            with (
                patch.object(
                    profile_module,
                    "_open_peer_directory",
                    side_effect=lambda _pid, _path: os.open(root, os.O_RDONLY),
                ),
                patch.object(
                    profile_module,
                    "_read_owned_bytes_at",
                    side_effect=read_as_test_owner,
                ),
            ):
                import hashlib

                self.assertEqual(
                    _profile_skill_digest(123, skill),
                    "sha256:" + hashlib.sha256(b"bounded skill\n").hexdigest(),
                )
                extra = root / "extra.txt"
                extra.write_text("ambiguous", encoding="utf-8")
                self.assertEqual(
                    _profile_skill_digest(123, skill),
                    "sha256:" + hashlib.sha256(b"bounded skill\n").hexdigest(),
                )

    def test_process_profile_requires_every_capability_set_empty(self) -> None:
        fields = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")

        def status(nonzero: str | None = None) -> bytes:
            capabilities = "\n".join(
                f"{name}:\t{'1' if name == nonzero else '0'}" for name in fields
            )
            return (
                "Uid:\t501\t501\t501\t501\n"
                "Gid:\t20\t20\t20\t20\n"
                f"{capabilities}\n"
                "NoNewPrivs:\t1\n"
            ).encode()

        with patch.object(profile_module, "_read_virtual_file", return_value=status()):
            _require_process_status(123, 501, 20)

        for field in fields:
            with (
                self.subTest(field=field),
                patch.object(
                    profile_module,
                    "_read_virtual_file",
                    return_value=status(field),
                ),
                self.assertRaisesRegex(
                    RuntimeActionObservationPublisherError,
                    "security profile does not match",
                ),
            ):
                _require_process_status(123, 501, 20)


if __name__ == "__main__":
    unittest.main()
