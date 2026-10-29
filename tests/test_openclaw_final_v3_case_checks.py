from __future__ import annotations

import base64
import json
import re
import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from aragorn import admission_protected_final_combined_v3_prompt_rebuild as fixture
from aragorn.admission_evidence import AdmissionEvidenceError
from scripts import openclaw_final_v3_case_checks as subject

_ROOT = Path(__file__).resolve().parents[1]


def _document():
    return json.loads((_ROOT / fixture._EVIDENCE["path"]).read_bytes())


def _sync_boundaries(document):
    stack = document["route_observation"]["stack_before"]
    stack["service_state"]["sockets"] = deepcopy(stack["sockets"])
    boundary = document["composition"]["action"]["boundaries"]
    for key in stack.keys() - {"pids"}:
        boundary[key] = deepcopy(stack[key])


def _verify(document):
    route = document["route_observation"]
    subject.verify_execution(
        route,
        route["document"],
        host=document["harness"]["document"],
        action=document["composition"]["action"],
        invocation={
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2027-01-01T00:00:00Z",
        },
        native_argv=[
            "/usr/local/bin/node",
            "/route-input/missing-prompt-blob-rebuild/protected-prompt-rebuild-probe.mjs",
        ],
        recorded_at=document["recorded_at"],
        prerequisite=route["document"]["action"]["prerequisites"][
            "gateway_process_before"
        ],
    )


def _fresh_document():
    document = _document()
    container = document["harness"]["document"]["container_id"]
    pids = {
        value: 20000 + index
        for index, value in enumerate(
            document["route_observation"]["stack_before"]["pids"].values()
        )
    }

    def shift(value, key=None):
        if type(value) is dict:
            return {name: shift(item, name) for name, item in value.items()}
        if type(value) is list:
            return [shift(item) for item in value]
        if key in {"started_monotonic_ns", "completed_monotonic_ns"}:
            return value + 1_000_000_000
        if key in {"ExecMainStartTimestampMonotonic", "ActiveEnterTimestampMonotonic"}:
            return str(int(value) + 1_000_000)
        if key == "start_time_ticks":
            return str(int(value) + 100)
        if type(value) is int and key == "pid":
            return pids.get(value, value)
        if type(value) is str:
            value = value.replace(container, "f" * 64)
            if key == "hostname":
                return "f" * 12
            if value in {str(pid) for pid in pids}:
                return str(pids[int(value)])
            for before, after in pids.items():
                value = value.replace(f"/proc/{before}/", f"/proc/{after}/")
                value = value.replace(f"; pid={before} ;", f"; pid={after} ;")
            if re.fullmatch(r"(?:mnt|net):\[[0-9]+\]", value):
                return re.sub(r"[0-9]+", lambda m: str(int(m[0]) + 50000), value)
            if re.match(r"2026-[0-9]{2}-[0-9]{2}T", value):
                return (
                    (datetime.fromisoformat(value) + timedelta(days=1))
                    .isoformat()
                    .replace("+00:00", "Z")
                )
            if key == "ExecStart":
                value = re.sub(
                    r"[A-Z][a-z]{2} 2026-[0-9]{2}-[0-9]{2} [0-9:]{8} UTC",
                    lambda m: (
                        datetime.strptime(m[0], "%a %Y-%m-%d %H:%M:%S UTC").replace(
                            tzinfo=UTC
                        )
                        + timedelta(days=1)
                    ).strftime("%a %Y-%m-%d %H:%M:%S UTC"),
                    value,
                )
        return value

    document = shift(document)
    stack = document["route_observation"]["stack_before"]
    stack["pids"] = {name: pids[pid] for name, pid in stack["pids"].items()}
    for socket in stack["sockets"].values():
        socket["metadata"]["device"] += 1000
        socket["metadata"]["inode"] += 1000
    for entry in stack["service_state"]["units"].values():
        raw = (
            "\n".join(f"{key}={value}" for key, value in entry["properties"].items())
            + "\n"
        ).encode()
        entry["command"]["stdout"] = {
            "base64": base64.b64encode(raw).decode(),
            "bytes": len(raw),
            "digest": subject.det._digest(raw),
        }
    _sync_boundaries(document)
    return document


class SharedNativeBoundaryTests(unittest.TestCase):
    def test_signed_reference_loader_is_used_and_cached_bytes_are_immutable(self):
        subject._static_reference_bytes.cache_clear()
        loader = subject._PARENT_REFERENCE._verify_retained_evidence
        with patch.object(
            subject._PARENT_REFERENCE, "_verify_retained_evidence", wraps=loader
        ) as verified:
            raw = subject._static_reference_bytes()
            changed = json.loads(raw)
            changed["processes"].clear()
            self.assertEqual(subject._static_reference_bytes(), raw)
            self.assertEqual(verified.call_count, 1)
        self.assertIs(type(raw), bytes)

    def test_retained_and_fresh_dynamic_identities_keep_exact_static_contract(self):
        for document in (_document(), _fresh_document()):
            unchanged = deepcopy(document)
            _verify(document)
            self.assertEqual(document, unchanged)
            sensor = document["route_observation"]["stack_before"]["processes"][
                "aragorn-runtime-lineage-capability-observation-publisher.service"
            ]
            self.assertEqual(sensor["uids"], [996, 996, 996, 997])

    def test_coherent_static_mutations_cannot_be_their_own_trusted_reference(self):
        baseline = _document()
        stack = baseline["route_observation"]["stack_before"]
        mutations = []
        for service in stack["processes"]:
            for key, value in (
                ("uids", [0] * 4),
                ("gids", [0] * 4),
                ("groups", [0]),
                ("capabilities_effective", "0000000000000001"),
                ("no_new_privileges", 0),
                ("cmdline", ["/unexpected"]),
                ("extra", 0),
            ):
                mutations.append((("processes", service, key), value))
            for key, value in (
                ("PrivateNetwork", "no"),
                ("ReadWritePaths", "/tmp"),
                ("NoNewPrivileges", "no"),
                ("ProtectSystem", "no"),
                ("FragmentDigest", "sha256:" + "0" * 64),
                ("FragmentPath", "/unexpected"),
                ("User", "root"),
                ("Group", "root"),
                ("extra", "unbound"),
            ):
                if key == "PrivateNetwork" and stack["units"][service][key] == value:
                    value = "yes"
                mutations.append((("units", service, key), value))
        for path in stack["sockets"]:
            for key, value in (
                ("uid", 0),
                ("gid", 0),
                ("mode", "0777"),
                ("nlink", 2),
                ("type", "file"),
                ("device", True),
                ("device", 0),
                ("inode", True),
                ("inode", 0),
                ("extra", 0),
            ):
                mutations.append((("sockets", path, "metadata", key), value))
        for path, value in mutations:
            document = deepcopy(baseline)
            target = document["route_observation"]["stack_before"]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            _sync_boundaries(document)
            with (
                self.subTest(path=path, value=value),
                self.assertRaises(AdmissionEvidenceError),
            ):
                _verify(document)
        for section in ("processes", "units", "sockets"):
            document = deepcopy(baseline)
            records = document["route_observation"]["stack_before"][section]
            del records[next(iter(records))]
            _sync_boundaries(document)
            with (
                self.subTest(section=section),
                self.assertRaises(AdmissionEvidenceError),
            ):
                _verify(document)


if __name__ == "__main__":
    unittest.main()
