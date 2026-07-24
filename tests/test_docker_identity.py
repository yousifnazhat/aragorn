from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest


import sys


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from aragorn import docker_identity  # noqa: E402


def encoded(document: object) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode()


def context(
    endpoint: str = "unix:///Users/example/.colima/default/docker.sock",
    *,
    skip_tls_verify: bool = False,
    tls_material_count: int = 0,
) -> dict[str, object]:
    return {
        "Name": "colima",
        "DockerEndpoint": {
            "Host": endpoint,
            "SkipTLSVerify": skip_tls_verify,
            "TLSMaterialCount": tls_material_count,
        },
    }


def version(architecture: str = "arm64") -> dict[str, object]:
    return {
        "PlatformName": "Docker Engine - Community",
        "Version": "29.5.2",
        "APIVersion": "1.54",
        "MinAPIVersion": "1.40",
        "GitCommit": "568f755",
        "GoVersion": "go1.26.3",
        "Os": "linux",
        "Arch": architecture,
        "KernelVersion": "6.8.0-117-generic",
        "BuildTime": "2026-05-20T14:39:25.000000000+00:00",
        "Components": [
            {
                "Name": "runc",
                "Version": "1.3.5",
                "Details": {"GitCommit": "v1.3.5-0-g488fc13e"},
            },
            {
                "Name": "Engine",
                "Version": "29.5.2",
                "Details": {
                    "ApiVersion": "1.54",
                    "GitCommit": "568f755",
                    "Experimental": "false",
                },
            },
            {
                "Name": "docker-init",
                "Version": "0.19.0",
                "Details": {"GitCommit": "de40ad0"},
            },
            {
                "Name": "containerd",
                "Version": "v2.2.4",
                "Details": {
                    "GitCommit": "193637f7ee8ae5f5aa5248f49e7baa3e6164966e"
                },
            },
        ],
    }


def info(architecture: str = "aarch64") -> dict[str, object]:
    return {
        "ID": "0507d4fa-fda8-4eb8-b7b8-ed54db5a1b2a",
        "Name": "colima",
        "ServerVersion": "29.5.2",
        "OperatingSystem": "Ubuntu 24.04.4 LTS",
        "OSType": "linux",
        "Architecture": architecture,
        "KernelVersion": "6.8.0-117-generic",
        "SecurityOptions": [
            "name=seccomp,profile=builtin",
            "name=apparmor",
            "name=cgroupns",
        ],
        "CgroupVersion": "2",
        "DefaultRuntime": "runc",
        "Driver": "overlayfs",
    }


def normalize(
    context_document: dict[str, object] | None = None,
    version_document: dict[str, object] | None = None,
    info_document: dict[str, object] | None = None,
) -> docker_identity.DockerIdentityReceipt:
    return docker_identity.normalize_docker_identity(
        encoded(context_document or context()),
        encoded(version_document or version()),
        encoded(info_document or info()),
    )


class DockerIdentityTests(unittest.TestCase):
    def test_valid_local_identity_is_normalized_and_raw_evidence_is_retained(
        self,
    ) -> None:
        raw_context = encoded(context())
        raw_version = encoded(version())
        raw_info = encoded(info())

        receipt = docker_identity.normalize_docker_identity(
            raw_context,
            raw_version,
            raw_info,
        )
        document = json.loads(receipt.document_json)

        self.assertEqual(receipt.raw_context, raw_context)
        self.assertEqual(receipt.raw_version, raw_version)
        self.assertEqual(receipt.raw_info, raw_info)
        self.assertEqual(
            receipt.endpoint,
            "unix:///Users/example/.colima/default/docker.sock",
        )
        self.assertEqual(
            document["assurance"],
            "docker_daemon_self_report_not_attested",
        )
        self.assertEqual(
            document["context"],
            {
                "name": "colima",
                "endpoint": receipt.endpoint,
                "skip_tls_verify": False,
                "tls_material_count": 0,
            },
        )
        self.assertEqual(document["engine"]["architecture"], "arm64")
        self.assertEqual(document["worker_claim"]["architecture"], "arm64")
        self.assertEqual(document["engine"]["os"], "linux")
        self.assertEqual(document["worker_claim"]["os"], "linux")
        self.assertEqual(
            [item["name"] for item in document["engine"]["components"]],
            ["Engine", "containerd", "docker-init", "runc"],
        )
        self.assertEqual(
            document["worker_claim"]["security_options"],
            [
                "name=apparmor",
                "name=cgroupns",
                "name=seccomp,profile=builtin",
            ],
        )
        with self.assertRaises(FrozenInstanceError):
            receipt.endpoint = "unix:///tmp/other.sock"  # type: ignore[misc]

    def test_context_can_be_parsed_before_version_and_info(self) -> None:
        normalized, endpoint = docker_identity.parse_docker_context(
            encoded(context())
        )

        self.assertEqual(endpoint, normalized["endpoint"])
        self.assertEqual(normalized["name"], "colima")

    def test_supported_architecture_aliases_normalize(self) -> None:
        for engine_arch, worker_arch, expected in (
            ("arm64", "aarch64", "arm64"),
            ("aarch64", "arm64", "arm64"),
            ("amd64", "x86_64", "amd64"),
            ("x86_64", "amd64", "amd64"),
        ):
            with self.subTest(engine_arch=engine_arch, worker_arch=worker_arch):
                document = json.loads(
                    normalize(
                        version_document=version(engine_arch),
                        info_document=info(worker_arch),
                    ).document_json
                )
                self.assertEqual(document["engine"]["architecture"], expected)
                self.assertEqual(
                    document["worker_claim"]["architecture"], expected
                )

    def test_duplicate_nonfinite_and_oversized_json_are_rejected(self) -> None:
        valid_version = encoded(version())
        valid_info = encoded(info())
        invalid_contexts = (
            b'{"Name":"a","Name":"b","DockerEndpoint":{}}',
            b'{"Name":"a","DockerEndpoint":{"Host":NaN}}',
            b'{"Name":"a","DockerEndpoint":{"Host":1e999}}',
            b" " * (1024 * 1024 + 1),
        )
        for raw_context in invalid_contexts:
            with self.subTest(raw_context=raw_context[:40]):
                with self.assertRaises(docker_identity.DockerIdentityError):
                    docker_identity.normalize_docker_identity(
                        raw_context,
                        valid_version,
                        valid_info,
                    )

    def test_remote_and_noncanonical_endpoints_are_rejected(self) -> None:
        invalid_endpoints = (
            "tcp://127.0.0.1:2375",
            "ssh://builder.example",
            "unix://user@/var/run/docker.sock",
            "unix:///var/run/docker.sock?x=1",
            "unix:///var/run/docker.sock#fragment",
            "unix:///var/../run/docker.sock",
            "unix:///var//run/docker.sock",
            "unix:///var/run/docker.sock/",
            "unix:///var/%2e%2e/run/docker.sock",
            "unix:/var/run/docker.sock",
            "unix:///",
        )
        for endpoint in invalid_endpoints:
            with self.subTest(endpoint=endpoint):
                with self.assertRaisesRegex(
                    docker_identity.DockerIdentityError,
                    "endpoint",
                ):
                    docker_identity.parse_docker_context(
                        encoded(context(endpoint))
                    )

    def test_tls_bypass_and_tls_material_are_rejected(self) -> None:
        for context_document in (
            context(skip_tls_verify=True),
            context(tls_material_count=1),
        ):
            with self.subTest(context_document=context_document):
                with self.assertRaises(docker_identity.DockerIdentityError):
                    docker_identity.parse_docker_context(
                        encoded(context_document)
                    )

    def test_missing_duplicate_and_incomplete_components_are_rejected(self) -> None:
        missing = version()
        missing["Components"] = [
            item
            for item in missing["Components"]  # type: ignore[union-attr]
            if item["Name"] != "runc"
        ]
        duplicate = version()
        duplicate["Components"] = [
            *duplicate["Components"],  # type: ignore[list-item]
            duplicate["Components"][1],  # type: ignore[index]
        ]
        no_commit = version()
        no_commit["Components"][0]["Details"] = {}  # type: ignore[index]
        for version_document in (missing, duplicate, no_commit):
            with self.subTest(version_document=version_document):
                with self.assertRaises(docker_identity.DockerIdentityError):
                    normalize(version_document=version_document)

    def test_optional_component_without_git_commit_is_digest_bound(self) -> None:
        rootless = version()
        rootless["Components"] = [
            *rootless["Components"],  # type: ignore[list-item]
            {
                "Name": "rootlesskit",
                "Version": "3.0.2",
                "Details": {
                    "ApiVersion": "1.1.2",
                    "NetworkDriver": "gvisor-tap-vsock",
                    "PortDriver": "builtin",
                    "StateDir": "/run/user/501/dockerd-rootless",
                },
            },
        ]
        first_receipt = normalize(version_document=rootless)
        first = json.loads(first_receipt.document_json)
        component = next(
            item
            for item in first["engine"]["components"]
            if item["name"] == "rootlesskit"
        )
        self.assertRegex(
            component["git_commit"],
            r"^unreported-details-sha256:[0-9a-f]{64}$",
        )

        changed = json.loads(json.dumps(rootless))
        changed["Components"][-1]["Details"]["NetworkDriver"] = "slirp4netns"
        self.assertNotEqual(
            first_receipt.document_json,
            normalize(version_document=changed).document_json,
        )

    def test_version_info_and_engine_mismatches_are_rejected(self) -> None:
        variants: list[tuple[dict[str, object], dict[str, object]]] = []
        for key, value in (
            ("ServerVersion", "29.5.1"),
            ("OSType", "windows"),
            ("Architecture", "x86_64"),
            ("KernelVersion", "different"),
        ):
            changed_info = info()
            changed_info[key] = value
            variants.append((version(), changed_info))

        engine_version = version()
        engine_version["Components"][1]["Version"] = "29.5.1"  # type: ignore[index]
        variants.append((engine_version, info()))
        engine_commit = version()
        engine_commit["Components"][1]["Details"]["GitCommit"] = (  # type: ignore[index]
            "different"
        )
        variants.append((engine_commit, info()))

        for version_document, info_document in variants:
            with self.subTest(
                version_document=version_document,
                info_document=info_document,
            ):
                with self.assertRaises(docker_identity.DockerIdentityError):
                    normalize(
                        version_document=version_document,
                        info_document=info_document,
                    )

    def test_unknown_fields_and_noncanonical_strings_fail_closed(self) -> None:
        extra_context = context()
        extra_context["Unexpected"] = True
        whitespace_info = info()
        whitespace_info["Name"] = " colima"
        duplicate_options = info()
        duplicate_options["SecurityOptions"] = [
            "name=apparmor",
            "name=apparmor",
        ]
        for arguments in (
            {"context_document": extra_context},
            {"info_document": whitespace_info},
            {"info_document": duplicate_options},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(docker_identity.DockerIdentityError):
                    normalize(**arguments)

    def test_canonical_document_is_deterministic(self) -> None:
        first_version = version()
        second_version = version()
        second_version["Components"] = list(  # type: ignore[arg-type]
            reversed(second_version["Components"])
        )
        first_info = info()
        second_info = info()
        second_info["SecurityOptions"] = list(  # type: ignore[arg-type]
            reversed(second_info["SecurityOptions"])
        )

        first = normalize(
            version_document=first_version,
            info_document=first_info,
        )
        second = docker_identity.canonicalize_docker_identity(
            json.dumps(context(), indent=2).encode(),
            json.dumps(second_version, sort_keys=True).encode(),
            json.dumps(second_info, sort_keys=True).encode(),
        )

        self.assertEqual(first.document_json, second.document_json)
        self.assertEqual(
            first.document_json,
            json.dumps(
                json.loads(first.document_json),
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii"),
        )

    def test_templates_target_only_the_parser_contract(self) -> None:
        self.assertIn('"TLSMaterialCount":{{len', docker_identity.DOCKER_CONTEXT_TEMPLATE)
        self.assertTrue(docker_identity.DOCKER_CONTEXT_TEMPLATE.endswith("}}}}"))
        self.assertIn(
            '"Components":{{json .Server.Components}}',
            docker_identity.DOCKER_VERSION_TEMPLATE,
        )
        self.assertIn(
            '"SecurityOptions":{{json .SecurityOptions}}',
            docker_identity.DOCKER_INFO_TEMPLATE,
        )


if __name__ == "__main__":
    unittest.main()
