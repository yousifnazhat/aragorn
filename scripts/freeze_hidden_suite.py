"""Verify the private Phase 0 corpus and freeze its pre-outcome suite binding."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from contextlib import ExitStack
from datetime import date
from io import BytesIO
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aragorn.benchmark import (
    _PHASE0_CORPUS_LOCK_DIGEST,
    _validate_phase0_hidden_binding,
    load_suite_for_run,
)
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase0_candidate import (
    build_candidate_policy,
    candidate_policy_digest,
    candidate_system_identity,
)

_OPAQUE_ID = re.compile(r"case-[0-9a-f]{16}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_MAX_JSON = 4 * 1024 * 1024
_MAX_LEDGER = 4 * 1024 * 1024
_MAX_CASE = 16 * 1024 * 1024
_MAX_CORPUS = 128 * 1024 * 1024
_WORKER_NAME = "skill-scan-corpus-worker-independent-v1.0.0.tar.gz"
_EVALUATOR_NAME = "skill-scan-corpus-label-ledger-independent-v1.0.0.tar.gz.gpg"
_SOURCE_NAME = "skill-scan-corpus-source-independent-v1.0.0.bundle"
_SAFE_EXECUTABLE_ROOTS = (
    Path("/usr/bin"),
    Path("/bin"),
    Path("/usr/sbin"),
    Path("/sbin"),
    Path("/opt/homebrew/bin"),
    Path("/usr/local/bin"),
)
_GPG_CLOSURE = {
    "/opt/homebrew/Cellar/gettext/1.0/lib/libintl.8.dylib": (
        "0c6d618e75fea85cc3d631e164a71766fba9341d19ce1f723300c52e63037c51"
    ),
    "/opt/homebrew/Cellar/gnupg/2.5.20/bin/gpg": (
        "8fc5f38e275f071a09d0446b6514ceef7de4aee1b64477c382ed6ed1a510502e"
    ),
    "/opt/homebrew/Cellar/gnupg/2.5.20/bin/gpg-agent": (
        "350ece1db9830978bd294976f187a4ed043f2d6a42a8642938ceec3529d5e763"
    ),
    "/opt/homebrew/Cellar/libassuan/3.0.2/lib/libassuan.9.dylib": (
        "1c45b3dd61f6f07249149723358e4d8448af5ced1a6b279a99ddbd7a906d1ff6"
    ),
    "/opt/homebrew/Cellar/libgcrypt/1.12.2/lib/libgcrypt.20.dylib": (
        "949a342e6afbf8a4fc0dc8ea90841fa52511ca6f33fd0ef77705cf0ca39b7439"
    ),
    "/opt/homebrew/Cellar/libgpg-error/1.61/lib/libgpg-error.0.dylib": (
        "8d71d115883e68055c0f81356394bb059eefc0829d13b2dd673cba9641fc452d"
    ),
    "/opt/homebrew/Cellar/npth/1.8/lib/libnpth.0.dylib": (
        "f29d1af471de3e3f2c41f1ac212aeb6e14bb37fabf9551a0ebb93b998c5f4665"
    ),
    "/opt/homebrew/Cellar/readline/8.3.3/lib/libreadline.8.3.dylib": (
        "7d74566dcbd3f64a5ec6266c8285e48f0214a9d2f36ad5f158b4282a3f10b9a9"
    ),
}
_GPG_CLOSURE_DIGEST = (
    "sha256:87eb42a2bdd3e709670b4e8159139fff7c9d256d09581ff02d54adf6257ac045"
)
_PRIOR_FREEZE_COMMIT = "7ee1bd3422c11b31ddf2d942019d23a5617673f5"
_PRIOR_FREEZE_TREE = "27100abd85554fa409b7e2dd410ffb0656cdcce7"
_PRIOR_FREEZE_RECEIPT = (
    "benchmark/receipts/phase0-hidden-suite-freeze-2026-07-24.json"
)
_PRIOR_FREEZE_RECEIPT_DIGEST = (
    "sha256:98909fff1a9eddd27f2ad02f27e7705078b713d822c8e5eaa9e11db420a46ad2"
)
_PRIOR_FREEZE_LOCK = "benchmark/phase0-hidden-suite.lock.json"
_PRIOR_FREEZE_LOCK_DIGEST = (
    "sha256:7f05171db56b35f8f76053222a6806228711679d4a5562b0b7328417fae549c7"
)
_PRIOR_SIGNER_PRINCIPAL = "yousif.snazhat@gmail.com"
_PRIOR_SIGNER_FINGERPRINT = (
    "SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk"
)
_PRIOR_ALLOWED_SIGNER = (
    "yousif.snazhat@gmail.com ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIP+34WpE4lJYYXs96Dbx/j7GMMm0WahOQl267+T2ESDA\n"
).encode("ascii")


class FreezeError(ValueError):
    """The hidden-suite freeze could not be verified safely."""


def _read(path: Path, *, max_bytes: int) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise FreezeError(f"required regular file is unavailable: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= max_bytes:
            raise FreezeError(
                f"file is empty, non-regular, or exceeds {max_bytes} bytes: {path}"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            data = source.read(max_bytes + 1)
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
        ):
            raise FreezeError(f"file changed while reading: {path}")
        return data
    finally:
        os.close(descriptor)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _decode_json(raw: bytes, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise FreezeError(f"{label} repeats key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                FreezeError(f"{label} contains non-finite {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise FreezeError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise FreezeError(f"{label} must be a JSON object")
    return value


def _executable(name: str) -> str:
    for root in _SAFE_EXECUTABLE_ROOTS:
        candidate = root / name
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return str(resolved)
    raise FreezeError(f"required executable is unavailable: {name}")


def _exact(value: dict[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise FreezeError(f"{label} fields do not match the frozen contract")


def _run(
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    cwd: Path | None = None,
) -> str:
    arguments = [_executable(arguments[0]), *arguments[1:]]
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(
            ("DYLD_", "GIT_CONFIG_", "GIT_SSH", "GNUPG", "GPG_AGENT", "LD_")
        )
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "PATH": os.pathsep.join(str(path) for path in _SAFE_EXECUTABLE_ROOTS),
        }
    )
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FreezeError(f"cannot execute {arguments[0]}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise FreezeError(f"{arguments[0]} verification failed: {detail}")
    return completed.stdout.decode("utf-8", "strict").strip()


def _verified_gpg_closure() -> tuple[str, str, str]:
    executable = Path(_executable("gpg"))
    agent = Path(_executable("gpg-agent"))
    pending = [executable, agent]
    observed: dict[str, str] = {}
    while pending:
        path = pending.pop().resolve(strict=True)
        path_text = str(path)
        if path_text in observed:
            continue
        if len(observed) >= 16:
            raise FreezeError("GPG dynamic-library closure exceeds its bound")
        raw = _read(path, max_bytes=128 * 1024 * 1024)
        if stat.S_IMODE(path.stat().st_mode) & 0o222:
            raise FreezeError("GPG closure contains a writable executable or library")
        observed[path_text] = hashlib.sha256(raw).hexdigest()
        lines = _run(["otool", "-L", path_text]).splitlines()
        if not lines or not lines[0].endswith(":"):
            raise FreezeError("cannot inspect the GPG dynamic-library closure")
        for line in lines[1:]:
            dependency = line.strip().split(" (", 1)[0]
            if dependency.startswith(("/System/Library/", "/usr/lib/")):
                continue
            if not dependency.startswith("/opt/homebrew/"):
                raise FreezeError("GPG closure contains an unsupported dependency")
            pending.append(Path(dependency))
    if observed != _GPG_CLOSURE:
        raise FreezeError("GPG executable or dynamic-library closure changed")
    records = [
        {"path": path, "sha256": "sha256:" + digest}
        for path, digest in sorted(observed.items())
    ]
    digest = canonical_digest(records)
    if digest != _GPG_CLOSURE_DIGEST:
        raise FreezeError("GPG closure identity changed")
    return str(executable), str(agent), digest


def _require_private_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise FreezeError(f"{label} must be a protected directory")
    status = path.stat()
    if status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) != 0o700:
        raise FreezeError(f"{label} must be owned by the operator with mode 0700")


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _reject_symlink_components(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise FreezeError(f"{label} must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(status.st_mode):
            raise FreezeError(f"{label} contains a symlink component: {current}")


def _signer_material(
    allowed_signers: Path,
    public_key: Path,
    *,
    principal: str,
    fingerprint: str,
) -> tuple[bytes, bytes]:
    allowed_raw = _read(allowed_signers, max_bytes=16 * 1024)
    public_raw = _read(public_key, max_bytes=16 * 1024)
    allowed = allowed_raw.decode("ascii").splitlines()
    public = public_raw.decode("ascii").split()
    if len(allowed) != 1 or len(allowed[0].split()) != 3 or len(public) < 2:
        raise FreezeError("signer material is not one canonical SSH Ed25519 key")
    identity, key_type, key_data = allowed[0].split()
    if (
        identity != principal
        or key_type != "ssh-ed25519"
        or public[:2] != [key_type, key_data]
    ):
        raise FreezeError("allowed signers and public key do not match")
    with tempfile.TemporaryDirectory(prefix="aragorn-signer-") as temporary:
        checked_key = Path(temporary) / "signer.pub"
        _write_new(checked_key, public_raw)
        observed = _run(["ssh-keygen", "-lf", str(checked_key), "-E", "sha256"]).split()
    if len(observed) < 2 or observed[1] != fingerprint:
        raise FreezeError("signer fingerprint does not match corpus lock")
    return allowed_raw, public_raw


def _verify_signature(
    document: bytes,
    signature: Path,
    allowed_signers: Path,
    *,
    principal: str,
) -> None:
    allowed_raw = _read(allowed_signers, max_bytes=16 * 1024)
    signature_raw = _read(signature, max_bytes=16 * 1024)
    with tempfile.TemporaryDirectory(prefix="aragorn-signature-") as temporary:
        checked_allowed = Path(temporary) / "allowed_signers"
        checked_signature = Path(temporary) / "document.sig"
        _write_new(checked_allowed, allowed_raw)
        _write_new(checked_signature, signature_raw)
        _run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(checked_allowed),
                "-I",
                principal,
                "-n",
                "file",
                "-s",
                str(checked_signature),
            ],
            input_bytes=document,
        )


def _artifact_map(release: dict[str, object]) -> dict[str, dict[str, object]]:
    artifacts = release.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 3:
        raise FreezeError("release manifest must name exactly three artifacts")
    result = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise FreezeError("release artifact record must be an object")
        _exact(artifact, {"path", "purpose", "sha256", "size"}, "release artifact")
        name = artifact["path"]
        if (
            not isinstance(name, str)
            or PurePosixPath(name).name != name
            or name in result
            or not isinstance(artifact["purpose"], str)
            or not artifact["purpose"]
            or not isinstance(artifact["sha256"], str)
            or _HEX_DIGEST.fullmatch(artifact["sha256"]) is None
            or isinstance(artifact["size"], bool)
            or not isinstance(artifact["size"], int)
            or not 1 <= artifact["size"] <= 512 * 1024 * 1024
        ):
            raise FreezeError("release artifact path is unsafe or repeated")
        result[name] = artifact
    if set(result) != {_WORKER_NAME, _EVALUATOR_NAME, _SOURCE_NAME}:
        raise FreezeError("release artifact closure does not match Phase 0")
    return result


def _verify_source_freeze(
    bundle: bytes,
    allowed_signers: bytes,
    freeze: dict[str, object],
) -> None:
    with tempfile.TemporaryDirectory(prefix="aragorn-corpus-freeze-") as temporary:
        temporary_root = Path(temporary)
        bundle_path = temporary_root / "corpus.bundle"
        allowed_path = temporary_root / "allowed_signers"
        _write_new(bundle_path, bundle)
        _write_new(allowed_path, allowed_signers)
        repository = Path(temporary) / "corpus.git"
        _run(["git", "clone", "--bare", str(bundle_path), str(repository)])
        _run(
            [
                "git",
                "-C",
                str(repository),
                "config",
                "gpg.ssh.allowedSignersFile",
                str(allowed_path),
            ]
        )
        _run(["git", "-C", str(repository), "config", "gpg.format", "ssh"])
        _run(
            [
                "git",
                "-C",
                str(repository),
                "config",
                "gpg.ssh.program",
                _executable("ssh-keygen"),
            ]
        )
        _run(["git", "-C", str(repository), "verify-commit", freeze["commit"]])
        _run(["git", "-C", str(repository), "verify-tag", freeze["tag"]])
        tag_object = _run(
            ["git", "-C", str(repository), "rev-parse", f"refs/tags/{freeze['tag']}"]
        )
        commit = _run(
            ["git", "-C", str(repository), "rev-parse", f"{freeze['tag']}^{{}}"]
        )
        if tag_object != freeze["tag_object"] or commit != freeze["commit"]:
            raise FreezeError("signed source freeze object identities changed")


def verify_release(
    release_dir: Path,
    corpus_lock: dict[str, object],
) -> dict[str, object]:
    principal = corpus_lock["signing"]["principal"]
    fingerprint = corpus_lock["signing"]["fingerprint"]
    allowed = release_dir / "allowed_signers"
    public_key = release_dir / "codex-independent-corpus-v1.0.0.pub"
    allowed_raw, public_key_raw = _signer_material(
        allowed,
        public_key,
        principal=principal,
        fingerprint=fingerprint,
    )
    release_raw = _read(release_dir / "release-manifest.json", max_bytes=_MAX_JSON)
    _verify_signature(
        release_raw,
        release_dir / "release-manifest.json.sig",
        allowed,
        principal=principal,
    )
    release = _decode_json(release_raw, "release manifest")
    _exact(
        release,
        {
            "schema_version",
            "corpus_version",
            "authorship",
            "case_counts",
            "freeze",
            "signing",
            "artifacts",
            "evaluator_custody",
        },
        "release manifest",
    )
    for field, keys in (
        (
            "authorship",
            {"author", "operator_excluded", "baseline_viewed_before_freeze"},
        ),
        ("case_counts", {"total", "benign", "adversarial"}),
        ("freeze", {"commit", "tag", "tag_object", "public_case_manifest_sha256"}),
        ("signing", {"format", "principal", "fingerprint", "signed_objects"}),
        (
            "evaluator_custody",
            {
                "encryption",
                "key_store",
                "service",
                "account",
                "worker_must_not_receive",
            },
        ),
    ):
        if not isinstance(release[field], dict):
            raise FreezeError(f"release manifest {field} must be an object")
        _exact(release[field], keys, f"release manifest {field}")
    if (
        release["schema_version"] != "1.0"
        or release["corpus_version"] != corpus_lock["corpus_id"]
        or release["authorship"]
        != {
            "author": "OpenAI Codex Independent Corpus Author",
            "operator_excluded": "Yousif",
            "baseline_viewed_before_freeze": False,
        }
        or release["case_counts"] != {"total": 448, "benign": 336, "adversarial": 112}
        or release["freeze"]
        != {
            **corpus_lock["freeze"],
            "public_case_manifest_sha256": corpus_lock["public_manifest"]["sha256"][
                len("sha256:") :
            ],
        }
        or release["signing"]["principal"] != principal
        or release["signing"]["fingerprint"] != fingerprint
        or release["signing"]["format"] != "ssh-ed25519"
        or release["signing"]["signed_objects"]
        != [
            "freeze commit",
            "annotated freeze tag",
            "label ledger",
            "evaluator manifest",
            "release manifest",
        ]
        or release["evaluator_custody"]
        != {
            "encryption": (
                "GnuPG symmetric AES-256 with iterated-and-salted S2K and MDC"
            ),
            "key_store": "macOS login Keychain",
            "service": ("codex-skill-corpus-evaluator-independent-v1.0.0-5ff1144"),
            "account": "independent-evaluator-custodian",
            "worker_must_not_receive": [
                "encrypted evaluator artifact",
                "decryption material",
                "per-case labels",
            ],
        }
    ):
        raise FreezeError("release manifest does not match corpus lock")
    artifacts = _artifact_map(release)
    artifacts_raw = {}
    for name, artifact in artifacts.items():
        path = release_dir / name
        raw = _read(path, max_bytes=512 * 1024 * 1024)
        if (
            len(raw) != artifact["size"]
            or hashlib.sha256(raw).hexdigest() != artifact["sha256"]
        ):
            raise FreezeError(f"release artifact digest or size changed: {name}")
        artifacts_raw[name] = raw
    if (
        "sha256:" + artifacts[_WORKER_NAME]["sha256"]
        != corpus_lock["worker_archive"]["sha256"]
        or "sha256:" + artifacts[_EVALUATOR_NAME]["sha256"]
        != corpus_lock["evaluator_archive"]["sha256"]
    ):
        raise FreezeError("signed release artifacts do not match corpus lock")
    _verify_source_freeze(
        artifacts_raw[_SOURCE_NAME],
        allowed_raw,
        corpus_lock["freeze"],
    )
    return {
        "release_manifest_digest": _sha256(release_raw),
        "worker_archive": artifacts_raw[_WORKER_NAME],
        "worker_archive_digest": "sha256:" + artifacts[_WORKER_NAME]["sha256"],
        "evaluator_archive": artifacts_raw[_EVALUATOR_NAME],
        "evaluator_archive_digest": "sha256:" + artifacts[_EVALUATOR_NAME]["sha256"],
        "source_bundle_digest": "sha256:" + artifacts[_SOURCE_NAME]["sha256"],
        "allowed_signers": allowed_raw,
        "public_key": public_key_raw,
    }


def _public_manifest(
    raw: bytes,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    manifest = _decode_json(raw, "public manifest")
    _exact(
        manifest,
        {
            "schema_version",
            "corpus_version",
            "hash_algorithm",
            "case_count",
            "entries",
        },
        "public manifest",
    )
    entries = manifest["entries"]
    if (
        manifest["schema_version"] != "1.0"
        or manifest["corpus_version"] != "independent-v1.0.0"
        or manifest["hash_algorithm"] != "sha256"
        or manifest["case_count"] != 448
        or not isinstance(entries, list)
        or len(entries) != 448
    ):
        raise FreezeError("public manifest identity or count changed")
    by_id = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise FreezeError("public manifest entry must be an object")
        _exact(entry, {"id", "path", "sha256", "size"}, "public manifest entry")
        case_id = entry["id"]
        if (
            not isinstance(case_id, str)
            or _OPAQUE_ID.fullmatch(case_id) is None
            or case_id in by_id
            or entry["path"] != f"cases/{case_id}/SKILL.md"
            or not isinstance(entry["sha256"], str)
            or _HEX_DIGEST.fullmatch(entry["sha256"]) is None
            or isinstance(entry["size"], bool)
            or not isinstance(entry["size"], int)
            or not 1 <= entry["size"] <= _MAX_CASE
        ):
            raise FreezeError("public manifest entry is invalid or repeated")
        by_id[case_id] = entry
    if list(by_id) != sorted(by_id):
        raise FreezeError("public manifest entries are not sorted")
    return manifest, by_id


def verify_evaluator_package(
    evaluator_dir: Path,
    release: dict[str, object],
    corpus_lock: dict[str, object],
) -> dict[str, object]:
    _require_private_directory(evaluator_dir, "evaluator package")
    outer_allowed = release["allowed_signers"]
    outer_key = release["public_key"]
    inner_allowed = evaluator_dir / "signing" / "allowed_signers"
    inner_key = evaluator_dir / "signing" / "codex-independent-corpus-v1.0.0.pub"
    if (
        _read(inner_allowed, max_bytes=16 * 1024) != outer_allowed
        or _read(inner_key, max_bytes=16 * 1024) != outer_key
    ):
        raise FreezeError("evaluator signer material changed")
    principal = corpus_lock["signing"]["principal"]
    manifest_raw = _read(evaluator_dir / "evaluator-manifest.json", max_bytes=_MAX_JSON)
    _verify_signature(
        manifest_raw,
        evaluator_dir / "evaluator-manifest.json.sig",
        inner_allowed,
        principal=principal,
    )
    manifest = _decode_json(manifest_raw, "evaluator manifest")
    _exact(
        manifest,
        {
            "schema_version",
            "corpus_version",
            "files",
            "freeze_tag",
            "source_commit",
        },
        "evaluator manifest",
    )
    if (
        manifest["schema_version"] != "1.0"
        or manifest["corpus_version"] != corpus_lock["corpus_id"]
        or manifest["freeze_tag"] != corpus_lock["freeze"]["tag"]
        or manifest["source_commit"] != corpus_lock["freeze"]["commit"]
    ):
        raise FreezeError("evaluator manifest does not match signed freeze")
    raw_records = manifest["files"]
    if not isinstance(raw_records, list) or not 1 <= len(raw_records) <= 64:
        raise FreezeError("evaluator manifest files must be a bounded array")
    records = {}
    for record in raw_records:
        if not isinstance(record, dict):
            raise FreezeError("evaluator file record must be an object")
        _exact(record, {"path", "sha256", "size"}, "evaluator file record")
        if (
            not isinstance(record["path"], str)
            or not isinstance(record["sha256"], str)
            or not isinstance(record["size"], int)
            or isinstance(record["size"], bool)
            or not 1 <= record["size"] <= 128 * 1024 * 1024
        ):
            raise FreezeError("evaluator file record has an invalid field")
        relative = PurePosixPath(record["path"])
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() in records
            or _HEX_DIGEST.fullmatch(record["sha256"]) is None
        ):
            raise FreezeError("evaluator file record is unsafe")
        path = evaluator_dir.joinpath(*relative.parts)
        raw = _read(path, max_bytes=128 * 1024 * 1024)
        if (
            len(raw) != record["size"]
            or hashlib.sha256(raw).hexdigest() != record["sha256"]
        ):
            raise FreezeError(f"evaluator file changed: {relative}")
        records[relative.as_posix()] = raw
    actual_files = {
        path.relative_to(evaluator_dir).as_posix()
        for path in evaluator_dir.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    expected_files = {
        *records,
        "evaluator-manifest.json",
        "evaluator-manifest.json.sig",
    }
    if actual_files != expected_files or any(
        path.is_symlink() for path in evaluator_dir.rglob("*")
    ):
        raise FreezeError("evaluator package file closure changed")
    labels = records.get("labels.jsonl")
    public_raw = records.get("public-manifest.json")
    if labels is None or public_raw is None:
        raise FreezeError("evaluator package omits ledger or public manifest")
    _verify_signature(
        labels,
        evaluator_dir / "labels.jsonl.sig",
        inner_allowed,
        principal=principal,
    )
    if _sha256(public_raw) != corpus_lock["public_manifest"]["sha256"]:
        raise FreezeError("evaluator public manifest digest changed")
    _, public_entries = _public_manifest(public_raw)
    labels_by_id, class_counts = _verified_labels(labels, public_entries)
    return {
        "evaluator_manifest_digest": _sha256(manifest_raw),
        "label_ledger_digest": _sha256(labels),
        "public_manifest_digest": _sha256(public_raw),
        "public_manifest_raw": public_raw,
        "public_entries": public_entries,
        "labels_by_id": labels_by_id,
        "class_counts": class_counts,
    }


def _verified_labels(
    labels: bytes,
    public_entries: dict[str, dict[str, object]],
) -> tuple[dict[str, str], dict[str, int]]:
    label_rows = []
    for line in labels.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            raise FreezeError("label ledger rows must end with LF")
        row = _decode_json(line[:-1], "label ledger row")
        _exact(row, {"id", "label", "sha256", "size"}, "label ledger row")
        if canonical_json(row) + b"\n" != line:
            raise FreezeError("label ledger row is not canonical JSONL")
        label_rows.append(row)
    if len(label_rows) != 448:
        raise FreezeError("label ledger must contain 448 rows")
    labels_by_id = {}
    for row in label_rows:
        case_id = row["id"]
        public = public_entries.get(case_id)
        if (
            public is None
            or case_id in labels_by_id
            or row["label"] not in {"benign", "adversarial"}
            or row["sha256"] != public["sha256"]
            or row["size"] != public["size"]
        ):
            raise FreezeError("label ledger does not join exactly to public manifest")
        labels_by_id[case_id] = row["label"]
    counts = Counter(labels_by_id.values())
    if list(labels_by_id) != sorted(labels_by_id) or counts != {
        "benign": 336,
        "adversarial": 112,
    }:
        raise FreezeError("label ledger ordering or class accounting changed")
    return labels_by_id, {"benign": 336, "adversarial": 112}


def _verified_worker_content(
    archive: bytes,
    public_raw: bytes,
    public_entries: dict[str, dict[str, object]],
) -> dict[str, bytes]:
    content_by_id = {}
    total = 0
    with tarfile.open(fileobj=BytesIO(archive), mode="r:gz") as source:
        members = source.getmembers()
        expected_directories = {
            "cases",
            *(f"cases/{case_id}" for case_id in public_entries),
        }
        expected_files = {
            "manifest.json",
            *(entry["path"] for entry in public_entries.values()),
        }
        if (
            len(members) != len({member.name for member in members})
            or {member.name for member in members if member.isdir()}
            != expected_directories
            or {member.name for member in members if member.isfile()} != expected_files
        ):
            raise FreezeError("worker archive member closure changed")
        for member in members:
            relative = PurePosixPath(member.name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or any(part.startswith("._") for part in relative.parts)
                or not (member.isfile() or member.isdir())
                or member.uid != 0
                or member.gid != 0
                or member.mtime != 0
                or member.mode != (0o644 if member.isfile() else 0o755)
            ):
                raise FreezeError("worker archive member metadata is unsafe")
        files = {member.name: member for member in members if member.isfile()}
        manifest_member = files["manifest.json"]
        extracted = source.extractfile(manifest_member)
        if extracted is None:
            raise FreezeError("worker manifest is not readable")
        worker_manifest = extracted.read(_MAX_JSON + 1)
        if worker_manifest != public_raw:
            raise FreezeError("worker and evaluator public manifests differ")
        for case_id, entry in public_entries.items():
            member = files[entry["path"]]
            if member.size != entry["size"]:
                raise FreezeError("worker archive metadata changed")
            extracted = source.extractfile(member)
            if extracted is None:
                raise FreezeError("worker case is not readable")
            raw = extracted.read(_MAX_CASE + 1)
            total += len(raw)
            if (
                len(raw) != entry["size"]
                or hashlib.sha256(raw).hexdigest() != entry["sha256"]
                or total > _MAX_CORPUS
            ):
                raise FreezeError("worker case content changed or exceeds budget")
            content_by_id[case_id] = raw
    return content_by_id


def _extract_evaluator_archive(archive: bytes, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    total = 0
    with tarfile.open(fileobj=BytesIO(archive), mode="r:gz") as source:
        members = source.getmembers()
        if len(members) > 64 or len(members) != len(
            {member.name for member in members}
        ):
            raise FreezeError("evaluator archive member closure is invalid")
        for member in members:
            relative = PurePosixPath(member.name)
            if (
                not relative.parts
                or relative.is_absolute()
                or ".." in relative.parts
                or any(part in {"", "."} for part in relative.parts)
                or not (member.isfile() or member.isdir())
                or member.size < 0
            ):
                raise FreezeError("evaluator archive contains an unsafe member")
            total += member.size
            if total > 128 * 1024 * 1024:
                raise FreezeError("evaluator archive exceeds the extraction budget")
        for member in sorted(
            (item for item in members if item.isdir()),
            key=lambda item: len(PurePosixPath(item.name).parts),
        ):
            destination.joinpath(*PurePosixPath(member.name).parts).mkdir(
                mode=0o700,
                parents=True,
                exist_ok=False,
            )
        for member in (item for item in members if item.isfile()):
            relative = PurePosixPath(member.name)
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            extracted = source.extractfile(member)
            if extracted is None:
                raise FreezeError("evaluator archive member is not readable")
            raw = extracted.read(member.size + 1)
            if len(raw) != member.size:
                raise FreezeError("evaluator archive member size changed")
            _write_new(target, raw)


def _decrypt_evaluator(
    ciphertext: bytes,
    passphrase: bytes,
    destination: Path,
    gpg_executable: str,
    gpg_agent_executable: str,
) -> None:
    if (
        not 1 <= len(passphrase) <= 4096
        or b"\0" in passphrase
        or b"\r" in passphrase
        or b"\n" in passphrase
    ):
        raise FreezeError("evaluator passphrase input is invalid")
    ciphertext_path = destination.parent / "evaluator.tar.gz.gpg"
    archive_path = destination.parent / "evaluator.tar.gz"
    gpg_home = destination.parent / "gnupg"
    gpg_home.mkdir(mode=0o700)
    _write_new(ciphertext_path, ciphertext)
    _run(
        [
            gpg_executable,
            "--no-options",
            "--homedir",
            str(gpg_home),
            "--agent-program",
            gpg_agent_executable,
            "--batch",
            "--no-tty",
            "--no-symkey-cache",
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
            "--output",
            str(archive_path),
            "--decrypt",
            str(ciphertext_path),
        ],
        input_bytes=passphrase + b"\n",
    )
    os.chmod(archive_path, 0o600)
    _extract_evaluator_archive(
        _read(archive_path, max_bytes=128 * 1024 * 1024),
        destination,
    )


def _write_new(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _systems(policy: dict[str, object]) -> tuple[str, list[dict[str, str]]]:
    canonical_policy = build_candidate_policy(policy)
    digest = candidate_policy_digest(canonical_policy)
    systems = sorted(
        [
            candidate_system_identity(canonical_policy),
            *canonical_policy["required_comparators"],
        ],
        key=lambda item: (
            item["name"],
            item["version"],
            item["implementation_digest"],
            item["config_digest"],
        ),
    )
    return digest, systems


def _suite_document(
    entries: dict[str, dict[str, object]],
    labels: dict[str, str],
    systems: list[dict[str, str]],
) -> dict[str, object]:
    cases = []
    for case_id, entry in entries.items():
        case_class = labels[case_id]
        files = [
            {
                "path": "SKILL.md",
                "size": entry["size"],
                "digest": "sha256:" + entry["sha256"],
                "executable": False,
            }
        ]
        cases.append(
            {
                "schema": "aragorn/benchmark-case/v1",
                "id": case_id,
                "class": case_class,
                "family": (
                    "benign" if case_class == "benign" else "agent-skill-adversarial"
                ),
                "lineage": case_id,
                "split": "hidden",
                "path": f"cases/{case_id}",
                "tree_digest": canonical_digest(files),
                "inert": True,
                "source": {
                    "kind": "synthetic",
                    "reference": f"independent-v1.0.0/{case_id}",
                    "license": "private-evaluation-only",
                },
            }
        )
    return {
        "schema": "aragorn/benchmark-suite/v1",
        "id": "phase0-hidden-independent-v1.0.0",
        "purpose": "evidence_smoke",
        "runs_per_case": 1,
        "systems": systems,
        "cases": cases,
    }


def validate_freeze_receipt_bindings(
    receipt: dict[str, object],
    receipt_raw: bytes,
    lock: dict[str, object],
    lock_raw: bytes,
    corpus_lock: dict[str, object],
    corpus_lock_raw: bytes,
) -> None:
    """Reject schema-valid receipts detached from their frozen inputs."""

    try:
        if receipt_raw != canonical_json(receipt):
            raise FreezeError("freeze receipt must use canonical JSON bytes")
        if lock_raw != canonical_json(lock):
            raise FreezeError("hidden-suite lock must use canonical JSON bytes")
        if receipt["lock"]["lock_digest"] != _sha256(lock_raw):
            raise FreezeError("freeze receipt lock digest does not match lock")
        if lock["corpus_lock_digest"] != _sha256(corpus_lock_raw):
            raise FreezeError("hidden-suite lock does not match corpus lock bytes")
        if (
            receipt["release"]["worker_archive_digest"] != lock["worker_archive_digest"]
            or lock["worker_archive_digest"] != corpus_lock["worker_archive"]["sha256"]
        ):
            raise FreezeError("worker archive binding does not match lock")
        if (
            receipt["release"]["evaluator_ciphertext_digest"]
            != lock["evaluator_archive_digest"]
            or lock["evaluator_archive_digest"]
            != corpus_lock["evaluator_archive"]["sha256"]
        ):
            raise FreezeError("evaluator ciphertext binding does not match lock")
        for field in ("principal", "fingerprint"):
            if receipt["release"][field] != corpus_lock["signing"][field]:
                raise FreezeError(f"freeze receipt {field} does not match corpus lock")
        for receipt_field, lock_field in (
            ("freeze_commit", "commit"),
            ("freeze_tag", "tag"),
            ("freeze_tag_object", "tag_object"),
        ):
            if receipt["release"][receipt_field] != corpus_lock["freeze"][lock_field]:
                raise FreezeError(
                    f"freeze receipt {receipt_field} does not match corpus lock"
                )
        if (
            receipt["evaluator"]["public_manifest_digest"]
            != lock["public_manifest_digest"]
            or lock["public_manifest_digest"]
            != corpus_lock["public_manifest"]["sha256"]
        ):
            raise FreezeError("public manifest binding does not match lock")
        if receipt["evaluator"]["label_ledger_digest"] != lock["label_ledger_digest"]:
            raise FreezeError("label ledger digest does not match lock")
        for field in (
            "suite_digest",
            "candidate_policy_digest",
            "case_count",
            "class_counts",
            "runs_per_case",
            "split",
            "systems",
        ):
            if receipt["suite"][field] != lock[field]:
                raise FreezeError(f"freeze receipt suite {field} does not match lock")
    except (KeyError, TypeError) as exc:
        raise FreezeError("freeze receipt binding contract is malformed") from exc


def _verified_prior_freeze(
    corpus_lock: dict[str, object],
    corpus_lock_raw: bytes,
) -> dict[str, object]:
    if _run(["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"]) != str(
        ROOT.resolve(strict=True)
    ):
        raise FreezeError("prior freeze repository root changed")
    with tempfile.TemporaryDirectory(
        prefix="aragorn-prior-freeze-signer-"
    ) as temporary:
        allowed = Path(temporary) / "allowed_signers"
        _write_new(allowed, _PRIOR_ALLOWED_SIGNER)
        fingerprint = _run(
            ["ssh-keygen", "-lf", str(allowed), "-E", "sha256"]
        ).split()
        if len(fingerprint) < 2 or fingerprint[1] != _PRIOR_SIGNER_FINGERPRINT:
            raise FreezeError("prior freeze signer fingerprint changed")
        _run(
            [
                "git",
                "-C",
                str(ROOT),
                "-c",
                "gpg.format=ssh",
                "-c",
                f"gpg.ssh.allowedSignersFile={allowed}",
                "-c",
                f"gpg.ssh.program={_executable('ssh-keygen')}",
                "verify-commit",
                _PRIOR_FREEZE_COMMIT,
            ]
        )
    tree = _run(
        [
            "git",
            "-C",
            str(ROOT),
            "rev-parse",
            f"{_PRIOR_FREEZE_COMMIT}^{{tree}}",
        ]
    )
    if tree != _PRIOR_FREEZE_TREE:
        raise FreezeError("prior freeze signed tree changed")
    _run(
        [
            "git",
            "-C",
            str(ROOT),
            "merge-base",
            "--is-ancestor",
            _PRIOR_FREEZE_COMMIT,
            "HEAD",
        ]
    )
    receipt_raw = _run(
        [
            "git",
            "-C",
            str(ROOT),
            "cat-file",
            "blob",
            f"{_PRIOR_FREEZE_COMMIT}:{_PRIOR_FREEZE_RECEIPT}",
        ]
    ).encode("ascii")
    lock_raw = _run(
        [
            "git",
            "-C",
            str(ROOT),
            "cat-file",
            "blob",
            f"{_PRIOR_FREEZE_COMMIT}:{_PRIOR_FREEZE_LOCK}",
        ]
    ).encode("ascii")
    if (
        _sha256(receipt_raw) != _PRIOR_FREEZE_RECEIPT_DIGEST
        or _sha256(lock_raw) != _PRIOR_FREEZE_LOCK_DIGEST
    ):
        raise FreezeError("prior freeze committed evidence changed")
    receipt = _decode_json(receipt_raw, "prior freeze receipt")
    lock = _decode_json(lock_raw, "prior hidden-suite lock")
    validate_freeze_receipt_bindings(
        receipt,
        receipt_raw,
        lock,
        lock_raw,
        corpus_lock,
        corpus_lock_raw,
    )
    return {
        "commit": _PRIOR_FREEZE_COMMIT,
        "tree": tree,
        "receipt_digest": _PRIOR_FREEZE_RECEIPT_DIGEST,
        "lock_digest": _PRIOR_FREEZE_LOCK_DIGEST,
        "signature_status": "verified",
        "principal": _PRIOR_SIGNER_PRINCIPAL,
        "fingerprint": _PRIOR_SIGNER_FINGERPRINT,
        "receipt": receipt,
    }


def _match_prior_freeze(
    prior: dict[str, object],
    release: dict[str, object],
    evaluator: dict[str, object],
) -> None:
    receipt = prior["receipt"]
    current = {
        "release_manifest_digest": release["release_manifest_digest"],
        "worker_archive_digest": release["worker_archive_digest"],
        "evaluator_ciphertext_digest": release["evaluator_archive_digest"],
        "source_bundle_digest": release["source_bundle_digest"],
        "manifest_digest": evaluator["evaluator_manifest_digest"],
        "label_ledger_digest": evaluator["label_ledger_digest"],
        "public_manifest_digest": evaluator["public_manifest_digest"],
    }
    expected = {
        **{
            field: receipt["release"][field]
            for field in (
                "release_manifest_digest",
                "worker_archive_digest",
                "evaluator_ciphertext_digest",
                "source_bundle_digest",
            )
        },
        **{
            field: receipt["evaluator"][field]
            for field in (
                "manifest_digest",
                "label_ledger_digest",
                "public_manifest_digest",
            )
        },
    }
    if current != expected:
        raise FreezeError("preserved evaluator does not match prior signed freeze")


def freeze(
    *,
    release_dir: Path,
    evaluator_passphrase: bytes | None,
    verified_evaluator_package: Path | None = None,
    corpus_lock_path: Path,
    candidate_policy_path: Path,
    private_suite_root: Path,
    lock_output: Path,
    receipt_output: Path,
    recorded_on: str,
    run_state_root: Path,
) -> dict[str, str]:
    if (evaluator_passphrase is None) == (verified_evaluator_package is None):
        raise FreezeError(
            "select exactly one evaluator passphrase or verified evaluator package"
        )
    try:
        parsed_date = date.fromisoformat(recorded_on)
    except ValueError as exc:
        raise FreezeError("recorded_on must be a real YYYY-MM-DD date") from exc
    if _DATE.fullmatch(recorded_on) is None or parsed_date.isoformat() != recorded_on:
        raise FreezeError("recorded_on must use YYYY-MM-DD")
    pre_outcome_paths = {
        "challenge_ledger": run_state_root / "challenge-ledger",
        "control_state": run_state_root / "control-state",
        "jobs_root": run_state_root / "jobs",
        "outcomes": run_state_root / "outcomes.jsonl",
    }
    pre_outcome_values = list(pre_outcome_paths.values())
    protected_paths = [
        private_suite_root,
        lock_output,
        receipt_output,
        *pre_outcome_values,
    ]
    for index, path in enumerate(protected_paths):
        _reject_symlink_components(path, f"freeze path[{index}]")
    _reject_symlink_components(run_state_root, "run state root")
    if any(
        left == right or left.is_relative_to(right) or right.is_relative_to(left)
        for index, left in enumerate(protected_paths)
        for right in protected_paths[index + 1 :]
    ):
        raise FreezeError(
            "freeze, receipt, and dispatch/outcome paths must not overlap"
        )
    repository_root = ROOT.resolve(strict=True)
    parent = private_suite_root.parent.resolve(strict=True)
    private_suite_target = parent / private_suite_root.name
    if private_suite_target == repository_root or private_suite_target.is_relative_to(
        repository_root
    ):
        raise FreezeError("private suite must remain outside the repository")
    canonical_run_root = run_state_root.resolve(strict=True)
    _require_private_directory(canonical_run_root, "run state root")
    if private_suite_target.is_relative_to(
        canonical_run_root
    ) or canonical_run_root.is_relative_to(private_suite_target):
        raise FreezeError("private suite and run state must not overlap")
    if any(os.path.lexists(path) for path in pre_outcome_values):
        raise FreezeError("all declared dispatch/outcome paths must be absent")
    _require_private_directory(parent, "private suite parent")
    state_binding_digest = canonical_digest(
        {role: str(path) for role, path in sorted(pre_outcome_paths.items())}
    )
    corpus_lock_raw = _read(corpus_lock_path, max_bytes=_MAX_JSON)
    if _sha256(corpus_lock_raw) != _PHASE0_CORPUS_LOCK_DIGEST:
        raise FreezeError("checked corpus lock digest changed")
    corpus_lock = _decode_json(corpus_lock_raw, "corpus lock")
    release = verify_release(release_dir, corpus_lock)
    prior = None
    gpg_executable = None
    gpg_agent_executable = None
    gpg_closure_digest = None
    if verified_evaluator_package is None:
        (
            gpg_executable,
            gpg_agent_executable,
            gpg_closure_digest,
        ) = _verified_gpg_closure()
    else:
        _reject_symlink_components(
            verified_evaluator_package,
            "verified evaluator package",
        )
        _require_private_directory(
            verified_evaluator_package,
            "verified evaluator package",
        )
        prior = _verified_prior_freeze(corpus_lock, corpus_lock_raw)
    policy_raw = _read(candidate_policy_path, max_bytes=_MAX_JSON)
    policy = _decode_json(policy_raw, "candidate policy")
    policy_digest, systems = _systems(policy)
    with ExitStack() as stack:
        if verified_evaluator_package is None:
            temporary = stack.enter_context(
                tempfile.TemporaryDirectory(
                    prefix="aragorn-evaluator-decryption-",
                    dir=parent,
                )
            )
            evaluator_dir = Path(temporary) / "package"
            assert evaluator_passphrase is not None
            assert gpg_executable is not None
            assert gpg_agent_executable is not None
            _decrypt_evaluator(
                release["evaluator_archive"],
                evaluator_passphrase,
                evaluator_dir,
                gpg_executable,
                gpg_agent_executable,
            )
        else:
            evaluator_dir = verified_evaluator_package
        evaluator = verify_evaluator_package(evaluator_dir, release, corpus_lock)
        if prior is not None:
            _match_prior_freeze(prior, release, evaluator)
        content = _verified_worker_content(
            release["worker_archive"],
            evaluator["public_manifest_raw"],
            evaluator["public_entries"],
        )
        suite = _suite_document(
            evaluator["public_entries"],
            evaluator["labels_by_id"],
            systems,
        )

    if any(
        os.path.lexists(path)
        for path in (private_suite_root, lock_output, receipt_output)
    ):
        raise FreezeError("freeze outputs must not already exist")
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{private_suite_root.name}.staging-",
            dir=parent,
        )
    )
    os.chmod(staging, 0o700)
    published_suite = False
    published_files: list[Path] = []
    try:
        cases_root = staging / "cases"
        cases_root.mkdir(mode=0o700)
        for case_id, raw in content.items():
            case_root = cases_root / case_id
            case_root.mkdir(mode=0o700)
            _write_new(case_root / "SKILL.md", raw)
        _write_new(staging / "public-manifest.json", evaluator["public_manifest_raw"])
        _write_new(staging / "suite.json", canonical_json(suite))
        with tempfile.TemporaryDirectory(
            prefix="aragorn-hidden-suite-cas-"
        ) as temporary:
            loaded = load_suite_for_run(
                staging / "suite.json",
                CAS(temporary),
                required_purpose="evidence_smoke",
            )
            lock = {
                "schema": "aragorn/benchmark-phase0-hidden-suite-lock/v1",
                "assurance": (
                    "operator_asserted_pre_outcome_binding_"
                    "not_independent_or_timestamped"
                ),
                "corpus_lock_digest": _PHASE0_CORPUS_LOCK_DIGEST,
                "worker_archive_digest": release["worker_archive_digest"],
                "public_manifest_digest": evaluator["public_manifest_digest"],
                "evaluator_archive_digest": release["evaluator_archive_digest"],
                "label_ledger_digest": evaluator["label_ledger_digest"],
                "candidate_policy_digest": policy_digest,
                "suite_digest": loaded["digest"],
                "case_count": 448,
                "class_counts": evaluator["class_counts"],
                "runs_per_case": 1,
                "split": "hidden",
                "systems": systems,
            }
            lock_raw = canonical_json(lock)
            temporary_lock = staging / "hidden-suite-lock.json"
            _write_new(temporary_lock, lock_raw)
            _validate_phase0_hidden_binding(
                corpus_lock_path=corpus_lock_path,
                public_manifest_path=staging / "public-manifest.json",
                hidden_suite_lock_path=temporary_lock,
                candidate_policy_path=candidate_policy_path,
                label_ledger_digest=evaluator["label_ledger_digest"],
                suite_digest=loaded["digest"],
                runs_per_case=loaded["runs_per_case"],
                cases=loaded["cases"],
                systems=loaded["systems"],
                manifests=loaded["manifests"],
            )
        if any(os.path.lexists(path) for path in pre_outcome_values):
            raise FreezeError("dispatch/outcome state appeared during freeze")
        if prior is None:
            receipt_schema = (
                "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v1"
            )
            evaluator_receipt = {
                "manifest_digest": evaluator["evaluator_manifest_digest"],
                "manifest_signature_status": "verified",
                "ciphertext_link_status": (
                    "in_process_gpg_decryption_then_inner_signature_verification"
                ),
                "gpg_closure_digest": gpg_closure_digest,
                "gpg_passphrase_cache": (
                    "disabled_with_no_symkey_cache_and_private_homedir"
                ),
                "label_ledger_digest": evaluator["label_ledger_digest"],
                "label_ledger_digest_rule": (
                    "raw_sha256_of_signature_verified_canonical_jsonl_bytes"
                ),
                "label_ledger_signature_status": "verified",
                "public_manifest_digest": evaluator["public_manifest_digest"],
                "case_count": 448,
                "class_counts": evaluator["class_counts"],
            }
            limitations = {
                "authorship": (
                    "technical_codex_authorship_not_independent_human_identity"
                ),
                "ordering": (
                    "signed_commit_ordering_must_be_verified_before_dispatch"
                ),
                "custody": (
                    "software_signatures_operator_uid_trusted_"
                    "not_same_uid_or_hardware_attested"
                ),
            }
        else:
            receipt_schema = (
                "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v2"
            )
            evaluator_receipt = {
                "manifest_digest": evaluator["evaluator_manifest_digest"],
                "manifest_signature_status": "verified",
                "package_verification_mode": (
                    "preserved_signed_package_reverified"
                ),
                "ciphertext_link_status": (
                    "matched_prior_signed_freeze_receipt_no_current_decryption"
                ),
                "current_gpg_status": "not_invoked",
                "label_ledger_digest": evaluator["label_ledger_digest"],
                "label_ledger_digest_rule": (
                    "raw_sha256_of_signature_verified_canonical_jsonl_bytes"
                ),
                "label_ledger_signature_status": "verified",
                "public_manifest_digest": evaluator["public_manifest_digest"],
                "case_count": 448,
                "class_counts": evaluator["class_counts"],
                "prior_freeze": {
                    field: prior[field]
                    for field in (
                        "commit",
                        "tree",
                        "receipt_digest",
                        "lock_digest",
                        "signature_status",
                        "principal",
                        "fingerprint",
                    )
                },
            }
            limitations = {
                "authorship": (
                    "technical_codex_authorship_not_independent_human_identity"
                ),
                "ordering": (
                    "signed_commit_ordering_must_be_verified_before_dispatch"
                ),
                "custody": (
                    "software_signatures_operator_uid_trusted_"
                    "not_same_uid_or_hardware_attested"
                ),
                "evaluation_status": (
                    "calibration_rerun_on_previously_evaluated_corpus_"
                    "not_fresh_holdout"
                ),
            }
        receipt = {
            "schema": receipt_schema,
            "recorded_on": recorded_on,
            "assurance": (
                "operator_asserted_pre_outcome_binding_not_independent_or_timestamped"
            ),
            "release": {
                "release_manifest_digest": release["release_manifest_digest"],
                "signature_status": "verified",
                "principal": corpus_lock["signing"]["principal"],
                "fingerprint": corpus_lock["signing"]["fingerprint"],
                "worker_archive_digest": release["worker_archive_digest"],
                "evaluator_ciphertext_digest": release["evaluator_archive_digest"],
                "source_bundle_digest": release["source_bundle_digest"],
                "freeze_commit": corpus_lock["freeze"]["commit"],
                "freeze_tag": corpus_lock["freeze"]["tag"],
                "freeze_tag_object": corpus_lock["freeze"]["tag_object"],
            },
            "evaluator": evaluator_receipt,
            "suite": {
                "suite_digest": lock["suite_digest"],
                "candidate_policy_digest": policy_digest,
                "case_count": 448,
                "class_counts": evaluator["class_counts"],
                "runs_per_case": 1,
                "split": "hidden",
                "systems": systems,
                "private_suite_retained_outside_repository": True,
            },
            "lock": {
                "lock_digest": _sha256(lock_raw),
                "semantic_preflight": "passed",
                "canonical_json": True,
            },
            "pre_outcome": {
                "evidence_status": (
                    "operator_observed_paths_absent_not_timestamp_attested"
                ),
                "state_layout": "phase0-hidden-run-state/v1",
                "state_binding_digest": state_binding_digest,
                "paths_checked_absent": len(pre_outcome_values),
                "dispatch_material_observed": False,
                "outcomes_observed": False,
                "labels_exposed_to_worker": False,
            },
            "limitations": limitations,
        }
        receipt_raw = canonical_json(receipt)
        validate_freeze_receipt_bindings(
            receipt,
            receipt_raw,
            lock,
            lock_raw,
            corpus_lock,
            corpus_lock_raw,
        )
        os.replace(staging, private_suite_root)
        published_suite = True
        _write_new(lock_output, lock_raw)
        published_files.append(lock_output)
        _write_new(receipt_output, receipt_raw)
        published_files.append(receipt_output)
        return {
            "schema": "aragorn/benchmark-phase0-hidden-suite-freeze-result/v1",
            "status": "ok",
            "suite_digest": lock["suite_digest"],
            "lock_digest": _sha256(lock_raw),
            "receipt_digest": _sha256(receipt_raw),
        }
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        for output in reversed(published_files):
            output.unlink(missing_ok=True)
        if published_suite and private_suite_root.exists():
            shutil.rmtree(private_suite_root)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", type=Path, required=True)
    evaluator_source = parser.add_mutually_exclusive_group(required=True)
    evaluator_source.add_argument(
        "--evaluator-passphrase-stdin",
        action="store_true",
    )
    evaluator_source.add_argument(
        "--verified-evaluator-package",
        type=Path,
    )
    parser.add_argument(
        "--corpus-lock",
        type=Path,
        default=ROOT / "benchmark" / "phase0-corpus.lock.json",
    )
    parser.add_argument(
        "--candidate-policy",
        type=Path,
        default=ROOT / "benchmark" / "phase0-candidate-policy-v2.json",
    )
    parser.add_argument("--private-suite-root", type=Path, required=True)
    parser.add_argument("--lock-output", type=Path, required=True)
    parser.add_argument("--receipt-output", type=Path, required=True)
    parser.add_argument("--recorded-on", required=True)
    parser.add_argument("--run-state-root", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        passphrase = None
        if arguments.evaluator_passphrase_stdin:
            if sys.stdin.isatty():
                raise FreezeError("evaluator passphrase must be piped through stdin")
            passphrase = sys.stdin.buffer.read(4097)
            if passphrase.endswith(b"\n"):
                passphrase = passphrase[:-1]
        result = freeze(
            release_dir=arguments.release_dir.resolve(strict=True),
            evaluator_passphrase=passphrase,
            verified_evaluator_package=(
                None
                if arguments.verified_evaluator_package is None
                else arguments.verified_evaluator_package.resolve(strict=True)
            ),
            corpus_lock_path=arguments.corpus_lock.resolve(strict=True),
            candidate_policy_path=arguments.candidate_policy.resolve(strict=True),
            private_suite_root=_lexical_absolute(arguments.private_suite_root),
            lock_output=_lexical_absolute(arguments.lock_output),
            receipt_output=_lexical_absolute(arguments.receipt_output),
            recorded_on=arguments.recorded_on,
            run_state_root=_lexical_absolute(arguments.run_state_root),
        )
    except (
        FreezeError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        tarfile.TarError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema": "aragorn/error/v1",
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 4
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
