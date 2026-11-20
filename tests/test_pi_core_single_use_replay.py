"""B50 offline protocol examples only. Inputs do not represent a host, permission, capture or boot."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

from scripts import replay_pi_core_single_use_owner as replay
from scripts.build_pi_core_linux import BuildError, canonical, sha256
from test_pi_core_owner_records import owner_fixture
from test_pi_core_owner_watchdog_records import watchdog_files
from test_pi_core_single_use_release import entry, envelope


COMMIT = "7" * 40
SIGNER = "SHA256:" + "A" * 43
PREBUILD = "3" * 40
MEDIA_PATH = replay.ROOT / "packaging/pi-core/immutable-host-b44/media-output.json"
# Deliberately unlike the checkout's root, manager and geometry: a checkout fallback must fail.
MEDIA = {"schema": "aragorn/observable-guest-disk/v1", "disk_sha256": replay.DISK_SHA256,
         "root_sha256": "a" * 64, "manager_sha256": "b" * 64, "uki_sha256": "c" * 64,
         "root_size": 513, "disk_bytes": 2048, "sector_size": 512, "boot_observed": False,
         "phase3_exit_eligible": False, "secure_boot_enrollment": False}
PREFIX = b"\xff other console text\r\n"
GUEST_BOOT = "d9c5f0ce-113c-48d0-8b55-2a70a7a1b968"
SERIAL = PREFIX + (f"ARAGORN_B44_V1 boot={GUEST_BOOT} disk_ro=1 part_ro=1 sector=512 part_bytes=1024 "
                  f"root_ro=1 lib_ro=1 lib_same=1 pid=1 manager_sha256={'b' * 64} "
                  f"root_sha256={'a' * 64}\r\n").encode("ascii")


def b45_pin(raw):
    return {"schema": "aragorn/bound-host-runner-artifact/v1", "identifier": "org.aragorn.pi-core.b45.host-runner",
            "boot_authorized": False, "disk_sha256": replay.DISK_SHA256, "media_pins_sha256": sha256(raw)}


def issued_seal(e):
    return canonical(replay.seal.HELD | {"approved": {"release_sha256": sha256(canonical(envelope(e))),
                     **{k: e[k] for k in ("nomination_sha256", "enrollment_sha256", "boot_approval_sha256")}}})


def example(e, attempt, *, serial=None):
    release = envelope(e)
    digest = sha256(canonical(release))
    pin = {"schema": "aragorn/b50-single-use-owner/v1", "identifier": "org.aragorn.pi-core.b50.host-owner",
           "disk_sha256": e["disk_sha256"], "runner_sha256": "a" * 64, "cdhash": "b" * 40,
           "release_sha256": digest, "boot_authorized": True, "build_seal_sha256": sha256(issued_seal(e)),
           "approval_commit": PREBUILD}
    cfg = {"pin": pin, "commit": COMMIT, "release": release, "bindings": {
        "schema": "aragorn/b50-independent-pre-attempt/v1", "release_commit": COMMIT, "release_sha256": digest, "entry": e}}
    expected = {k: e[k] for k in ("fixture_identity", "disk_identity", "store_identity", "disk_sha256")}
    expected.update(attempt_identity=attempt, runner_sha256=pin["runner_sha256"], runner_cdhash=pin["cdhash"],
                    store_sha256_before=e["store_sha256"], policy_sha256_before=e["policy_sha256"])
    uid = e["attempt_uuid"]
    files, _ = owner_fixture(uid, expected)
    watch = watchdog_files(uid, {"attempt_start_ns": 1000, "recorder_armed_ns": 1003,
                                 "start_issued_ns": 1006, "record_end_ns": 1012})
    wrap = {"schema": "aragorn/b50-owner-terminal/v1", "release_sha256": digest, "host_identity_sha256": e["host_identity_sha256"],
            "consumed_identity": attempt, "start_check_utc_s": e["not_before_utc"], "start_check_raw_ns": 1005,
            "terminal": json.loads(files["owner-terminal.json"])}
    if serial is not None:
        files["serial.raw"] = serial
        wrap["terminal"]["owner"]["capture"].update(capture_bytes=len(serial), capture_sha256=sha256(serial))
    files |= {"owner-terminal.json": canonical(wrap), **watch}
    manifest = {"attempt_uuid": uid, "fixture_identity": e["fixture_identity"], "attempt_identity": attempt,
                "ledger_attempt_identity": {"dev": 1, "ino": 12}, "files": {k: {"source": {"mode": 0o400}} for k in files}}
    return manifest, files, cfg


class SingleUseReplay(unittest.TestCase):
    def setUp(self):
        self.e = entry()
        self.m, self.files, self.cfg = example(self.e, {"dev": 1, "ino": 11})

    def read(self, *, manifest=None, files=None, **kwargs):
        return replay.assess(manifest if manifest is not None else self.m, files if files is not None else self.files,
                             **(self.cfg | kwargs))

    def test_whole_cli_seals_and_replays_original_bytes_without_boot_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            fixture, ledger, dest = (root / n for n in ("fixture", "ledger", "out"))
            uid = self.e["attempt_uuid"]
            for p in (fixture, ledger, dest, fixture / uid, ledger / uid):
                p.mkdir(mode=0o700)
            def ident(p):
                return {"dev": p.stat().st_dev, "ino": p.stat().st_ino}
            _, files, cfg = example(self.e | {"fixture": str(fixture), "fixture_identity": ident(fixture)},
                                    ident(fixture / uid), serial=SERIAL)
            def seal(p, data):
                p.write_bytes(data)
                p.chmod(0o400)
            for name, data in files.items():
                seal((fixture if name in replay.OWNER else ledger) / uid / name, data)
            for name in ("release", "bindings"):
                seal(root / name, canonical(cfg[name]))
            opts = [str(dest), uid, COMMIT, SIGNER, "--release", str(root / "release"), "--bindings",
                    str(root / "bindings"), sha256(canonical(cfg["bindings"]))]
            raw = issued_seal(cfg["bindings"]["entry"])
            # Mock only the unavailable future signed artifacts. This is a protocol fixture, not issuance.
            media = canonical(MEDIA)
            blobs = {(COMMIT, replay.seal.SEAL): raw, (COMMIT, MEDIA_PATH): media, (PREBUILD, MEDIA_PATH): media}
            with patch.object(replay, "authenticated_pin", return_value=cfg["pin"]) as lookup, \
                    patch.object(replay.seal, "_blob", side_effect=lambda rev, path: blobs[rev, path]) as blob, \
                    patch.object(replay, "signed_pin", return_value=b45_pin(media)) as signed, \
                    patch.object(replay, "source_seal", return_value=raw) as source:
                with redirect_stdout(StringIO()) as out:
                    self.assertEqual(replay.main(["export", str(ledger), "--fixture", str(fixture), *opts]), 0)
                    lookup.assert_called_once_with(COMMIT, SIGNER)
                    blob.assert_has_calls([call(*key) for key in blobs], any_order=True)
                    signed.assert_called_once_with(COMMIT, SIGNER)
                    source.assert_called_once_with(PREBUILD, COMMIT, SIGNER)
                result = json.loads(out.getvalue())
                self.assertEqual(result["disposition"], "consistent-single-use-transcript")
                guest = result["guest"]
                self.assertEqual((guest["status"], guest["capture_bytes"], guest["capture_sha256"], guest["record_offset"],
                                  guest["boot_id"]), ("matching_guest_record_only", len(SERIAL), sha256(SERIAL), len(PREFIX), GUEST_BOOT))
                self.assertFalse(guest["host_custody_verified"] or guest["external_boot_id_compared"] or guest["phase3_exit_eligible"])
                self.assertEqual((guest["media_pins_sha256"], guest["approval_commit"]), (sha256(media), PREBUILD))
                self.assertFalse(any(result[k] for k in ("boot_verified", "boot_authorized_by_replay", "phase3_exit_eligible",
                                                         "retry_authorized", "cleanup_authorized", "restoration_verified")))
                self.assertEqual((dest / uid / "serial.raw").read_bytes(), files["serial.raw"])
                with redirect_stdout(StringIO()) as out:
                    self.assertEqual(replay.main(["replay", result["manifest_sha256"], "--host-loss", *opts]), 2)
                    with self.assertRaisesRegex(BuildError, "bindings digest mismatch"):
                        replay.main(["replay", result["manifest_sha256"], *opts[:-1], "0" * 64])
                lost = json.loads(out.getvalue())
                self.assertEqual((lost["disposition"], lost["guest"]["status"]), ("unresolved-host-loss", "not-evaluated"))
                signed.assert_called_once_with(COMMIT, SIGNER)
                opts = ["replay", result["manifest_sha256"], *opts]
                for problem in ("signed guest roots disagree with serial", "signed source missing"):
                    if problem.startswith("signed guest"):
                        other = canonical(MEDIA | {"root_sha256": "d" * 64})
                        blobs[COMMIT, MEDIA_PATH] = blobs[PREBUILD, MEDIA_PATH] = other
                        signed.return_value = b45_pin(other)
                    else:
                        signed.side_effect = FileNotFoundError("missing signed source")
                    with self.subTest(problem=problem), redirect_stdout(StringIO()) as out:
                        self.assertEqual(replay.main(opts), 2)
                        result = json.loads(out.getvalue())
                        self.assertEqual((result["transcript"], result["disposition"], result["guest"]["status"]),
                                         ("consistent-single-use-transcript", "consistent-single-use-transcript", "indeterminate"))
                        self.assertFalse(result["boot_verified"])

    def test_guest_pins_require_exact_signed_blob_in_both_commits_and_matching_candidate(self):
        media = canonical(MEDIA)
        other = canonical(MEDIA | {"root_sha256": "d" * 64})
        bad_disk = canonical(MEDIA | {"disk_sha256": "e" * 64})
        for desc, source, artifact, b45 in (
                ("source changed", other, media, b45_pin(media)),
                ("artifact and source differ only in whitespace", media, media + b"\n", b45_pin(media + b"\n")),
                ("wrong signed digest despite identical disk", other, other, b45_pin(media)),
                ("wrong disk despite authenticated digest", bad_disk, bad_disk, b45_pin(bad_disk))):
            blobs = {(PREBUILD, MEDIA_PATH): source, (COMMIT, MEDIA_PATH): artifact}
            with self.subTest(case=desc), patch.object(replay, "signed_pin", return_value=b45), \
                    patch.object(replay.seal, "_blob", side_effect=lambda rev, path: blobs[rev, path]), self.assertRaises(BuildError):
                replay.authenticated_media(COMMIT, self.cfg["pin"], SIGNER)

    def test_held_refusal_and_capture_mismatch_never_consult_guest_pins(self):
        uid = self.e["attempt_uuid"]
        held = self.cfg["pin"] | {"boot_authorized": False, "release_sha256": sha256(canonical(replay.HELD))}
        bindings = canonical(self.cfg["bindings"])
        cases = [
            (held, replay.HELD, self.m | {"fixture_identity": None, "attempt_identity": None},
             watchdog_files(uid) | {"refusal.stderr": replay.REFUSAL}, [], "consistent-held-refusal", 0),
            (self.cfg["pin"], self.cfg["release"], self.m, self.files | {"serial.raw": SERIAL},
             ["--bindings", "/not-used", sha256(bindings)], "indeterminate", 2),
        ]
        for pin, release, manifest, files, options, disposition, code in cases:
            with self.subTest(host=disposition), patch.object(replay, "authenticated_release", return_value=(pin, release)), \
                    patch.object(replay, "read_owner_archive", return_value=(manifest, files)), \
                    patch.object(replay, "retained", return_value=bindings), patch.object(replay, "authenticated_media") as media, \
                    redirect_stdout(StringIO()) as out:
                self.assertEqual(replay.main(["replay", "0" * 64, "/not-used", uid, COMMIT, SIGNER, *options]), code)
                report = json.loads(out.getvalue())
                self.assertEqual((report["disposition"], report["guest"]["status"]), (disposition, "not-evaluated"))
                media.assert_not_called()

    def test_artifact_pin_alone_cannot_substitute_for_two_matching_signed_seals(self):
        raw = issued_seal(self.e)
        held_raw = canonical(replay.seal.HELD)
        held_pin = self.cfg["pin"] | {"boot_authorized": False, "release_sha256": sha256(canonical(replay.HELD)),
                                     "build_seal_sha256": sha256(held_raw), "approval_commit": None}
        with patch.object(replay, "authenticated_pin", return_value=held_pin), patch.object(replay.seal, "_blob", return_value=held_raw):
            self.assertEqual(replay.authenticated_release(COMMIT, SIGNER, None), (held_pin, replay.HELD))
            with self.assertRaisesRegex(BuildError, "held build seal"):
                replay.authenticated_release(COMMIT, SIGNER, Path("/absent-private-manifest"))
        for p, artifact, source in ((self.cfg["pin"], held_raw, raw), (self.cfg["pin"], raw, held_raw),
                                    (self.cfg["pin"] | {"build_seal_sha256": sha256(held_raw)}, held_raw, held_raw)):
            with patch.object(replay, "authenticated_pin", return_value=p), patch.object(replay.seal, "_blob", return_value=artifact), \
                    patch.object(replay, "source_seal", return_value=source), self.assertRaises(BuildError):
                replay.authenticated_release(COMMIT, SIGNER, Path("/absent-private-manifest"))

    def test_prebuild_signature_and_ancestry_checked_before_reading_approval(self):
        with patch.object(replay, "signed_pin") as signer, patch.object(replay.subprocess, "run", return_value=SimpleNamespace(returncode=1)) as git, \
                patch.object(replay.seal, "_blob") as blob, self.assertRaisesRegex(BuildError, "not an ancestor"):
            replay.source_seal(PREBUILD, COMMIT, SIGNER)
        signer.assert_called_once_with(PREBUILD, SIGNER)
        self.assertEqual(git.call_args.args[0][-4:], ["merge-base", "--is-ancestor", PREBUILD, COMMIT])
        blob.assert_not_called()
        with self.assertRaisesRegex(BuildError, "distinct prebuild"):
            replay.source_seal(COMMIT, COMMIT, SIGNER)

    def test_signed_pin_must_bind_release_count_candidate_and_digest(self):
        for field, substitute in (("schema", "aragorn/b47-held-vm-owner/v1"), ("identifier", "other"),
                                  ("release_sha256", "f" * 64), ("disk_sha256", "e" * 64),
                                  ("runner_sha256", "0" * 64), ("cdhash", True), ("boot_authorized", 1)):
            with self.subTest(field=field), self.assertRaises(BuildError):
                self.read(pin=self.cfg["pin"] | {field: substitute})
        with self.assertRaises(BuildError):
            self.read(release=replay.HELD)

    def test_release_must_match_uuid_independent_pre_attempt_data_and_source_identity(self):
        for bad in (None, self.cfg["bindings"] | {"release_commit": "f" * 40}, self.cfg["bindings"] | {"entry":
                    self.e | {"boot_approval_sha256": "9" * 64}}, self.cfg["bindings"] | {"extra": True}):
            self.assertEqual(self.read(bindings=bad)["disposition"], "indeterminate")
        for bad in ({"attempt_uuid": "417832a0-44c8-4fa6-8861-fcfc59c12934"}, {"fixture_identity": {"dev": True, "ino": 5}},
                    {"attempt_identity": None}, {"ledger_attempt_identity": None}):
            self.assertEqual(self.read(manifest=self.m | bad)["disposition"], "indeterminate")

    def test_terminal_requires_consumption_release_actual_host_and_both_producer_streams(self):
        wrap = json.loads(self.files["owner-terminal.json"])
        for bad in (wrap | {"release_sha256": "f" * 64}, wrap | {"host_identity_sha256": "e" * 64},
                    wrap | {"consumed_identity": self.e["fixture_identity"]}, wrap | {"extra": True},
                    wrap | {"terminal": wrap["terminal"] | {"runner": {"runner_sha256": "e" * 64, "runner_cdhash": "b" * 40}}}):
            self.assertEqual(self.read(files=self.files | {"owner-terminal.json": canonical(bad)})["disposition"], "indeterminate")
        for bad in (self.files | {"serial.raw": b"other"}, {k: v for k, v in self.files.items() if k != "watchdog.json.owner-arm"},
                    self.files | {"owner-terminal.json": self.files["owner-terminal.json"].replace(b'"schema":', b'"schema":1,"schema":', 1)}):
            self.assertEqual(self.read(files=bad)["disposition"], "indeterminate")

    def test_pre_start_window_is_half_open_and_joined_to_ready_and_issue(self):
        wrap = json.loads(self.files["owner-terminal.json"])
        for utc, raw in ((119, 1005), (420, 1005), (120, 1002), (120, 1007), (419, 1005), (120, True)):
            with self.subTest(utc=utc, raw=raw):
                bad = canonical(wrap | {"start_check_utc_s": utc, "start_check_raw_ns": raw})
                self.assertEqual(self.read(files=self.files | {"owner-terminal.json": bad})["disposition"], "indeterminate")

    def test_held_refusal_is_version_specific_and_host_loss_never_closes(self):
        held = self.cfg["pin"] | {"boot_authorized": False, "release_sha256": sha256(canonical(replay.HELD))}
        args = dict(release=replay.HELD, pin=held, bindings=None)
        m = self.m | {"fixture_identity": None, "attempt_identity": None}
        old = watchdog_files(m["attempt_uuid"])
        self.assertEqual(self.read(manifest=m, files=old, **args)["disposition"], "indeterminate")
        self.assertEqual(self.read(manifest=m, files=old | {"refusal.stderr": replay.REFUSAL}, **args)["disposition"],
                         "consistent-held-refusal")
        conflict = self.read(host_loss=True, **args)
        self.assertEqual((conflict["transcript"], conflict["disposition"]),
                         ("transcript-conflicts-with-held-release", "unresolved-host-loss"))
