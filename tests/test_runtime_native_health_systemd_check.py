"""Inert fixed health fixture checks, with no systemd or Docker execution."""

import json
import sys
import unittest
from contextlib import ExitStack
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import runtime_native_health_systemd_check as subject
from scripts import stage_runtime_native_health_profile as stage

CONTAINER, BOOT = "c" * 64, "b" * 32
SETUP = {
    "runtime_digest": "sha256:" + "1" * 64,
    "skill_digest": "sha256:" + "2" * 64,
    "policy": {"version": 1, "sensor_digest": "sha256:" + "3" * 64},
    "provisioning": {"genesis_digest": "sha256:" + "4" * 64},
}
BEFORE = [
    {"unit": {"Id": unit}, "process": {"pid": index + 10}}
    for index, unit in enumerate(subject.response._UNITS)
]


def _captured(document, unhealthy=False):
    accepted = {
        "snapshot_digest": canonical_digest(document),
        "status": document["status"],
        "epoch": document["epoch"],
        "minimum_mediator_health_epoch": document["epoch"],
        "policy_digest": canonical_digest(SETUP["policy"]),
        "worker_runtime_digest": SETUP["runtime_digest"],
        "sensor_digest": document["sensor_digest"],
        "expires_at_unix": document["expires_at_unix"],
    }
    result = {
        "authority": "LOCAL_ROOT_RESPONSE_RESULT_NOT_RUN_OR_PHASE3_CONFORMANCE",
        "expected_skill_digest": SETUP["skill_digest"],
        "health_snapshot_digest": canonical_digest(document),
        "accepted_health": accepted,
        "before": deepcopy(BEFORE),
        "after": deepcopy(BEFORE),
        "status": "ACCEPTED_HEALTHY_FIXED_RUNTIME_PROFILE",
    }
    if unhealthy:
        result.update(
            status="SUSPENDED_UNHEALTHY_FIXED_RUNTIME_PROFILE",
            after=[
                {
                    "unit": {
                        "Id": unit,
                        "ActiveState": "inactive",
                        "MainPID": "0",
                        "ControlPID": "0",
                    },
                    "cgroup": {"status": "ABSENT"},
                }
                for unit in subject.response._UNITS
            ],
            future_start_barrier={
                "status": "PERSISTENT_FIXED_PROFILE_STARTS_MASKED",
                "directory_fsynced": True,
                "automatic_unmask_supported": False,
                "masks": [{}, {}],
            },
        )
    return {
        "publication": {
            "invocation_id": ("3" if unhealthy else "1") * 32,
            "result": {
                "schema": "aragorn/runtime-health-publication-result/v1",
                "authority": "LOCAL_PROCESS_RESULT_ONLY_NOT_DURABLE_PROVENANCE_OR_RESPONSE_AUTHORITY",
                "health_digest": canonical_digest(document),
                "epoch": document["epoch"],
                "health_status": document["status"],
            },
        },
        "response": {
            "invocation_id": ("4" if unhealthy else "2") * 32,
            "result": {"response": result},
        },
        "units": {},
    }


def _row(cursor="s=new", unit=subject._DISPATCH):
    return {
        "MESSAGE": canonical_json({"schema": "fixture"}).decode(),
        "_SYSTEMD_INVOCATION_ID": "a" * 32,
        "_SYSTEMD_UNIT": unit,
        "_BOOT_ID": BOOT,
        "__CURSOR": cursor,
        "__MONOTONIC_TIMESTAMP": "12345",
        "__REALTIME_TIMESTAMP": "123456789",
    }


class NativeHealthFixtureTests(unittest.TestCase):
    def test_fixed_sources_guard_and_selectors(self):
        original, extra = stage._verified_payloads()
        for name, (size, digest, mode) in subject._CODE.items():
            _, installed_mode, raw = (original | extra)[name.removeprefix("/")]
            self.assertEqual(
                (len(raw), subject.canonical_digest_bytes(raw), installed_mode),
                (size, "sha256:" + digest, mode),
            )
        with (
            patch.object(subject.sys, "platform", "linux"),
            patch.object(subject.os, "geteuid", return_value=0),
            patch.object(
                subject.response,
                "_process_cgroup",
                return_value=f"/docker/{CONTAINER}/init.scope",
            ),
        ):
            subject._guard(CONTAINER)
            with self.assertRaises(subject.HealthFixtureError):
                subject._guard("d" * 64)
        with patch.object(subject.response, "_command") as command:
            for function, arguments in (
                (subject._show, ("other.service",)),
                (subject._property, (subject._PUBLISHER, "Other")),
                (subject._journal, (subject._DISPATCH, "bad cursor", BOOT)),
            ):
                with self.assertRaises(subject.HealthFixtureError):
                    function(*arguments)
            command.assert_not_called()

    def test_observed_systemd_empty_fields_usrmerge_and_fail_job_mode(self):
        for installed, prefix, failure in (
            (False, "/lib", None),
            (True, "/lib", None),
            (True, "/usr/lib", None),
            (True, "/tmp/lib", "alias"),
            (True, "/lib", "resolved_alias"),
            (True, "/lib", "mode"),
            (True, "/lib", "extra_command"),
            (True, "/lib", "wrong_signature"),
            (True, "/lib", "extra_array_entry"),
            (True, "/lib", "missing_empty"),
            (True, "/lib", "extra_property"),
        ):

            def command(
                argv, *, timeout, installed=installed, prefix=prefix, failure=failure
            ):
                self.assertIn("--all", argv)
                unit = argv[-1]
                publisher = unit == subject._PUBLISHER
                executable = (
                    "/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-"
                )
                executable += (
                    f"health-service.py /run/credentials/{unit}/runtime-binding /run/credentials/{unit}/health"
                    if publisher
                    else "response-service.py --health-dispatch"
                )
                fields = {
                    "Id": unit,
                    "LoadState": "loaded",
                    "FragmentPath": prefix + "/systemd/system/" + unit,
                    "DropInPaths": str(subject._HOOK)
                    if publisher and installed
                    else "",
                    "User": "aragorn-broker" if publisher else "root",
                    "Group": "aragorn-runtime" if publisher else "root",
                    "Type": "oneshot",
                    "RemainAfterExit": "no",
                    "RefuseManualStart": "no" if publisher else "yes",
                    "OnSuccess": subject._DISPATCH if publisher and installed else "",
                    "OnSuccessJobMode": "fail",
                    "Before": "shutdown.target"
                    if publisher
                    else subject._PUBLISHER + " shutdown.target",
                    "After": "local-fs.target nss-user-lookup.target",
                    "ExecStart": "{ path=/usr/bin/python3.12 ; argv[]="
                    + executable
                    + " ; ignore_errors=no ; pid=0 ; code=(null) ; status=0/0 }",
                    "NoNewPrivileges": "yes",
                    "PrivateNetwork": "yes",
                    "PrivateMounts": "yes",
                    "ProtectSystem": "strict",
                }
                if failure == "mode":
                    fields["OnSuccessJobMode"] = "replace"
                if failure == "missing_empty":
                    del fields["DropInPaths"]
                if failure == "extra_property":
                    fields["Unexpected"] = "value"
                return "".join(
                    f"{key}={value}\n" for key, value in fields.items()
                ).encode()

            def property_value(unit, name, failure=failure):
                if name in {"ExecStartPre", "ExecStartPost"}:
                    if failure == "extra_command":
                        return ["a(sasbttttuii)", "1"]
                    if failure == "wrong_signature":
                        return ["a(ss)", "0"]
                    if failure == "extra_array_entry":
                        return ["a(sasbttttuii)", "0", "unexpected"]
                    return ["a(sasbttttuii)", "0"]
                if name == "LoadCredential":
                    return (
                        [
                            "a(ss)",
                            "2",
                            "runtime-binding",
                            "/etc/aragorn/runtime-action-runtime.json",
                            "health",
                            str(subject._PUBLICATION),
                        ]
                        if unit == subject._PUBLISHER
                        else ["a(ss)", "0"]
                    )
                if name == "BindPaths":
                    return [
                        "a(ssbt)",
                        "1",
                        "/run/credentials/aragorn-runtime-action-worker.service",
                        "/run/aragorn-runtime-response-worker-credential",
                        "true",
                        "16384",
                    ]
                self.assertEqual(name, "BindReadOnlyPaths")
                return ["a(ssbt)", "0"]

            def resolve(path, *, strict, failure=failure):
                self.assertIs(strict, True)
                return subject.Path("/usr/lib/systemd/system") / (
                    "other.service" if failure == "resolved_alias" else path.name
                )

            with (
                self.subTest(installed=installed, prefix=prefix, failure=failure),
                patch.object(subject.response, "_command", side_effect=command),
                patch.object(subject, "_property", side_effect=property_value),
                patch.object(
                    subject.Path, "resolve", autospec=True, side_effect=resolve
                ),
            ):
                if failure:
                    with self.assertRaises(subject.HealthFixtureError):
                        subject._units(installed=installed)
                else:
                    result = subject._units(installed=installed)
                    self.assertEqual(
                        result["units"][subject._PUBLISHER]["FragmentPath"],
                        prefix + "/systemd/system/" + subject._PUBLISHER,
                    )
                    self.assertEqual(
                        result["units"][subject._DISPATCH]["OnSuccessJobMode"], "fail"
                    )
                    self.assertEqual(
                        result["exec_extra"],
                        {
                            unit: {
                                name: ["a(sasbttttuii)", "0"]
                                for name in ("ExecStartPre", "ExecStartPost")
                            }
                            for unit in subject._UNITS
                        },
                    )

    def test_exact_cursor_rows_baseline_and_malformed_output(self):
        for rows, count in (
            ([], 0),
            ([_row()], 1),
            ([_row("s=old")], 0),
            ([_row("s=old"), _row()], 1),
        ):
            raw = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
            with patch.object(
                subject.response, "_command", return_value=raw
            ) as command:
                self.assertEqual(
                    len(subject._journal(subject._DISPATCH, "s=old", BOOT)), count
                )
                argv = command.call_args.args[0]
                self.assertIn("--cursor=s=old", argv)
                self.assertIn("--lines=3", argv)
                self.assertFalse(any(arg.startswith("--after-cursor") for arg in argv))
        bad_rows = [[_row(), _row()], [_row(), _row("s=another")], [_row()] * 3]
        for key, value in (
            ("_SYSTEMD_UNIT", "other.service"),
            ("__MONOTONIC_TIMESTAMP", "1.2"),
            ("_BOOT_ID", "d" * 32),
            ("MESSAGE", '{"schema": "noncanonical"}'),
            ("extra", "value"),
        ):
            bad_rows.append([{**_row(), key: value}])
        for rows in bad_rows:
            with (
                patch.object(
                    subject.response,
                    "_command",
                    return_value=b"".join(
                        json.dumps(row).encode() + b"\n" for row in rows
                    ),
                ),
                self.assertRaises((RuntimeError, ValueError)),
            ):
                subject._journal(subject._DISPATCH, "s=old", BOOT)

    def test_health_result_binding_noop_stop_and_retention_failures(self):
        for unhealthy in (False, True):
            document = {
                "epoch": 7,
                "status": "unhealthy" if unhealthy else "healthy",
                "sensor_digest": SETUP["policy"]["sensor_digest"],
                "expires_at_unix": 1015,
            }
            capture = _captured(document, unhealthy)
            with patch.object(
                subject.retained,
                "_retained_response",
                side_effect=lambda envelope: (
                    envelope["response"],
                    {"separate_process_readback": True},
                ),
            ) as retention:
                joined = subject._join(
                    capture, document, SETUP, BEFORE, unhealthy=unhealthy
                )
                self.assertTrue(joined["retention"]["separate_process_readback"])
                retention.assert_called_once()
                for mutation in ("runtime", "epoch", "before", "partial"):
                    bad = deepcopy(capture)
                    result = bad["response"]["result"]["response"]
                    if mutation == "runtime":
                        result["accepted_health"]["worker_runtime_digest"] = "wrong"
                    elif mutation == "epoch":
                        bad["publication"]["result"]["epoch"] = 8
                    elif mutation == "before":
                        result["before"] = []
                    else:
                        result["status"] = "INDETERMINATE"
                    with (
                        self.subTest(mutation=mutation),
                        self.assertRaises(subject.HealthFixtureError),
                    ):
                        subject._join(bad, document, SETUP, BEFORE, unhealthy=unhealthy)
            with (
                patch.object(
                    subject.retained,
                    "_retained_response",
                    side_effect=RuntimeError("retention failed"),
                ),
                self.assertRaises(RuntimeError),
            ):
                subject._join(capture, document, SETUP, BEFORE, unhealthy=unhealthy)

    def test_two_publications_preserve_native_receipts_and_only_advance_floor(self):
        for failure in (None, "receipts", "effects", "state"):
            receipt = {"state_digest": "sha256:" + "5" * 64}
            observation = {
                "fixture_container": CONTAINER,
                "status": "OBSERVED",
                "phase3_eligible": False,
                "run_conformance_eligible": False,
                "setup": SETUP,
                "processes": {"fixed": 1},
                "boot_id": BOOT,
                "receipt_store_after_create": receipt,
            }
            state = {
                "minimum_mediator_health_epoch": 5,
                "effect_journal": None,
                "consumed": ["one"],
            }
            native = SimpleNamespace(
                prior=SimpleNamespace(
                    _processes=Mock(return_value={"fixed": 1}),
                    _boot=Mock(return_value=BOOT),
                    _cursor=Mock(return_value="s=baseline"),
                ),
                _snapshot=Mock(return_value={} if failure == "receipts" else receipt),
            )
            published = []

            def publish(p37b, document, cursor, boot, published=published):
                published.append(document)
                return _captured(document, document["status"] == "unhealthy")

            with ExitStack() as stack:
                stack.enter_context(
                    patch.dict(
                        sys.modules,
                        {
                            "runtime_action_worker_openclaw_systemd_probe": SimpleNamespace(
                                lineage=SimpleNamespace(_CONTROL=subject.Path("/fixed"))
                            )
                        },
                    )
                )
                for module, name, kwargs in (
                    (subject, "_guard", {}),
                    (subject, "_sources", {"return_value": {"fixed": "pins"}}),
                    (subject, "_install_hook", {"return_value": {"fixed": "hook"}}),
                    (
                        subject,
                        "_controls",
                        {
                            "side_effect": [
                                state,
                                {**state, "minimum_mediator_health_epoch": 6},
                            ]
                        },
                    ),
                    (
                        subject,
                        "_effect_snapshot",
                        {
                            "side_effect": [
                                {"fixed": "effect"},
                                {} if failure == "effects" else {"fixed": "effect"},
                            ]
                        },
                    ),
                    (subject, "_publish", {"side_effect": publish}),
                    (subject.retained, "_running", {"return_value": BEFORE}),
                    (
                        subject.retained,
                        "_start_refused",
                        {"return_value": {"exit_code": 1}},
                    ),
                    (
                        subject.retained,
                        "_retained_response",
                        {
                            "side_effect": lambda env: (
                                env["response"],
                                {"verified": True},
                            )
                        },
                    ),
                    (
                        subject.response,
                        "_identities",
                        {"return_value": (1, 2, 3, 4, 5, 6, 7)},
                    ),
                    (subject.response, "_read_regular", {"return_value": b"{}"}),
                    (
                        subject.response.broker,
                        "_state",
                        {
                            "return_value": {
                                **state,
                                "minimum_mediator_health_epoch": 8
                                if failure == "state"
                                else 7,
                            }
                        },
                    ),
                    (subject.time, "time", {"return_value": 1000}),
                    (
                        subject.response,
                        "_command",
                        {"side_effect": AssertionError("no actual systemd")},
                    ),
                ):
                    stack.enter_context(patch.object(module, name, **kwargs))
                if failure:
                    with self.assertRaises(subject.HealthFixtureError):
                        subject.run_after_native(CONTAINER, observation, native)
                else:
                    result = subject.run_after_native(CONTAINER, observation, native)
                    self.assertIs(result["phase3_eligible"], False)
                    self.assertIs(result["sensor_loss_detection"], False)
                    self.assertEqual(
                        result["native_receipts_retained"], receipt["state_digest"]
                    )
                self.assertEqual(
                    [
                        (
                            d["status"],
                            d["epoch"],
                            d["observed_at_unix"],
                            d["expires_at_unix"],
                        )
                        for d in published
                    ],
                    [("healthy", 6, 1000, 1015), ("unhealthy", 7, 1000, 1015)],
                )

    def test_cleanup_is_fixed_and_partial_state_refuses(self):
        for active in ("inactive", "active"):
            with (
                patch.object(subject, "_guard") as guard,
                patch.object(subject.response, "_command") as command,
                patch.object(
                    subject,
                    "_show",
                    side_effect=lambda unit, active=active: {
                        "Id": unit,
                        "ActiveState": active,
                        "SubState": "dead",
                        "MainPID": "0",
                        "ControlPID": "0",
                    },
                ),
            ):
                if active == "active":
                    with self.assertRaises(subject.HealthFixtureError):
                        subject.stop_extra_units()
                else:
                    self.assertEqual(
                        set(subject.stop_extra_units()), set(subject._UNITS)
                    )
                guard.assert_called_once_with()
                command.assert_called_once_with(
                    ["/usr/bin/systemctl", "stop", *subject._UNITS], timeout=15
                )


if __name__ == "__main__":
    unittest.main()
