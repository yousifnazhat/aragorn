"""Evidence-bound, label-free Phase 0 Aragorn candidate composition."""

from __future__ import annotations

import base64
import hashlib
from html import unescape
import json
import os
import re
import unicodedata
from collections.abc import Iterable
from io import BytesIO
from pathlib import Path
from typing import Any

from .analyze import OBSERVATION_SCHEMA, Observation, _parse_observations
from .artifact_closure import (
    ASSURANCE as SOURCE_GRAPH_ASSURANCE,
)
from .artifact_closure import (
    PROFILE as SOURCE_GRAPH_PROFILE,
)
from .artifact_closure import (
    ArtifactClosureError,
    load_retained_manifest,
    resolve_source_graph,
)
from .benchmark_authenticated_handoff_v2 import (
    load_verified_worker_output_acceptance,
)
from .benchmark_protocol_v2 import (
    canonical_request_digest_v2,
    validate_worker_request_v2,
    validate_worker_result_v2,
    verify_request_subject_v2,
)
from .cas import CAS, CASError
from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_digest,
    canonical_json,
    sanitize_subject_manifest,
)

POLICY_SCHEMA_V2 = "aragorn/benchmark-candidate-policy/v2"
POLICY_SCHEMA = "aragorn/benchmark-candidate-policy/v3"
POLICY_ASSURANCE = "comparative_candidate_only_not_admission"
POLICY_ALGORITHM_V2 = "source-graph-fail-closed-vendor-union/v2"
POLICY_ALGORITHM = "source-graph-fail-closed-correlated-evidence/v3"
COMPOSITION_ASSURANCE = (
    "derived_from_authenticated_comparator_evidence_not_hardware_attested"
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_MAX_DOCUMENT_BYTES = 128 * 1024 * 1024
_POLICY_KEYS = {
    "schema",
    "assurance",
    "algorithm",
    "candidate",
    "required_comparators",
}
_PARTIAL_SYSTEM_KEYS = {"name", "version", "implementation_digest"}
_SYSTEM_KEYS = {*_PARTIAL_SYSTEM_KEYS, "config_digest"}
_CANDIDATE_VERSION = "0.1.0-phase0"
_REQUIRED_COMPARATORS = (
    {
        "name": "cisco-skill-scanner",
        "version": "2.0.12",
        "implementation_digest": (
            "sha256:7fadcfbe836eef9490feba0fadd2ada5"
            "64c11eb541077e3efee5f61edbd2e65c"
        ),
        "config_digest": (
            "sha256:0471e144da9f709a1596d0daa15c6faf"
            "85c6358d12840dadb652a1e45369085a"
        ),
    },
    {
        "name": "skillspector",
        "version": "2.4.3+git.a54947c",
        "implementation_digest": (
            "sha256:e731be01105243f94437a4b9bd449bd4"
            "6bbcb5cb306f44b4845121d109a4a95e"
        ),
        "config_digest": (
            "sha256:2de741d4af73b3047ec0307795f7ceeb"
            "0f39e25837a5a8a7c97fa23992de7207"
        ),
    },
)
_NVIDIA_INCOMPLETE = "NVIDIA_ANALYSIS_INCOMPLETE"
_FIRST_PARTY_ANALYZER = "aragorn-agent-skill-threats"
_FIRST_PARTY_ALGORITHM = "imperative-agent-integrity-clusters/v2"
_FIRST_PARTY_TEXT_LIMIT = 8 * 1024 * 1024
_FIRST_PARTY_SEGMENT_LIMIT = 4096
_BASE64_TEXT_LIMIT = 64 * 1024
_BASE64_TOKEN_LIMIT = 4 * ((_BASE64_TEXT_LIMIT + 2) // 3)
_BASE64_MAX_DEPTH = 2
_BASE64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}"
    r"(?![A-Za-z0-9+/_=-])"
)
_BASE64_LINE = re.compile(r"[A-Za-z0-9+/_-]{4,}={0,2}\Z")
_BASE64_SPACED = re.compile(
    r"(?<![A-Za-z0-9+/_-])"
    r"(?:[A-Za-z0-9+/_-]{4,}={0,2}[ \t]+){1,}"
    r"[A-Za-z0-9+/_-]{4,}={0,2}"
    r"(?![A-Za-z0-9+/_=-])"
)
_HTML_COMMENT = re.compile(
    r"<!--[\s\S]{0,4096}?-->"
)
_HTML_TAG = re.compile(
    r"</?[A-Za-z][^<>\r\n]{0,256}>"
)
_MARKDOWN_LINK = re.compile(
    r"\[([^\]\r\n]{1,256})\]\([^)\r\n]{0,512}\)"
)
_HTML_ENTITY = re.compile(
    r"&(?:#[0-9]{1,7}|#x[0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});"
)
_INTRAWORD_MARKUP = re.compile(
    r"(?<=[A-Za-z0-9+/_-])(?:\*{1,3}|_{1,3}|~{1,2}|`{1,3})"
    r"(?=[A-Za-z0-9+/_-])"
)
_UNICODE_WORD = re.compile(r"[^\W\d_]+")
_MIXED_SCRIPT_CONFUSABLES = {
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "У": "Y",
    "Х": "X",
    "а": "a",
    "е": "e",
    "і": "i",
    "ј": "j",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "α": "a",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "y",
    "χ": "x",
}
_DEFENSIVE_SENSITIVE_CONTEXT = re.compile(
    r"\b(?:never|do not|must not|cannot|can't)\s+"
    r"(?:request|reveal|copy|transform)"
    r"(?:\s*,\s*(?:request|reveal|copy|transform))*"
    r"(?:\s*,?\s*(?:or|and)\s+(?:request|reveal|copy|transform))?"
    r"\s+(?:any\s+)?(?:protected markers?|credential[- ]shaped values?)"
    r"(?:\s+(?:or|and)\s+(?:protected markers?|"
    r"credential[- ]shaped values?))?\b[.!?]?",
    re.IGNORECASE | re.DOTALL,
)
_DEFENSIVE_SENSITIVE_CONTRAST = re.compile(
    r"\A\s*(?:[.!?;,:—-]\s*)?"
    r"(?:but|instead|however|yet|although|notwithstanding)\b",
    re.IGNORECASE,
)
_DEFENSIVE_SENSITIVE_REFERENCE = re.compile(
    r"\b(?:them|those|these|such)\b|"
    r"\b(?:protected markers?|credential[- ]shaped values?)\b",
    re.IGNORECASE,
)
_DEFENSIVE_CONTEXT = re.compile(
    r"\b(?:never|do not|must not|cannot|can't)\s+"
    r"(?:read|fetch|download|execute|run|launch|invoke|inspect|contact|grant|"
    r"send|post|upload|transmit|make\s+network|attach|write|delete|remove|"
    r"modify|source|follow|forward|install)\b|"
    r"\b(?:for display only|as data|classification data|indicators? to discuss|"
    r"flag quoted|identify prompt|dry[- ]run|require explicit confirmation|"
    r"reject absolute paths|review .* as data)\b",
    re.IGNORECASE | re.DOTALL,
)
_ANALYSIS_CONTEXT = re.compile(
    r"\b(?:for display only|as data|classification data|quoted phrases?|"
    r"untrusted content|indicators? to discuss|review .* as data)\b",
    re.IGNORECASE | re.DOTALL,
)
_ANALYSIS_DIRECTIVE = re.compile(
    r"\A\s*(?:explain|discuss|identify|flag|detect|classify|review|analyze)\b",
    re.IGNORECASE,
)
_QUOTED_DATA_SPAN = re.compile(
    r'"[^"]{0,1024}"|'
    r"'[^']{0,1024}'|"
    r"“[^”]{0,1024}”|"
    r"‘[^’]{0,1024}’|"
    r"`[^`]{0,1024}`"
)
_EXPLANATION_GOVERNOR = re.compile(
    r"\b(?:agents?|developers?|users?|operators?|systems?|you|they)\s+"
    r"(?:must|should|can|cannot|can't|need\s+to|are\s+required\s+to)\s+"
    r"(?:never\s+|not\s+)?\Z",
    re.IGNORECASE,
)
_DECODE_BRIDGE = re.compile(
    r"\b(?:decode|base64)\b.{0,160}\b(?:follow|perform|apply|execute|run|"
    r"launch|instruction)\b",
    re.IGNORECASE | re.DOTALL,
)
_PROMPT_OVERRIDE = re.compile(
    r"\b(?:ignore|bypass|override|disregard|supersede|forget|set\s+aside)\b"
    r".{0,100}\b(?:higher[- ]priority|prior|previous|earlier|system|policy|"
    r"policies|direction|directions|instruction|instructions|guardrail|"
    r"guardrails)\b",
    re.IGNORECASE | re.DOTALL,
)
_AGENT_INTEGRITY_ABUSE = re.compile(
    r"\b(?:treat|regard|consider)\b.{0,80}"
    r"\b(?:embedded|document(?:'s)?|procedure|instruction)\b.{0,80}"
    r"\b(?:more authoritative|higher priority)\b|"
    r"\b(?:split|scatter|separate)\b.{0,80}"
    r"\b(?:behavior|intent|instruction)\b.{0,80}"
    r"\b(?:appear|seem|look)(?:s|ed|ing)?\b.{0,30}\bharmless\b|"
    r"\b(?:request|collect|copy|extract|transform)\b.{0,80}"
    r"\b(?:protected markers?|credential[- ]shaped values?)\b|"
    r"\b(?:expand|broaden|extend)\b.{0,80}"
    r"\b(?:assigned|authorized|approved|stated)\b.{0,80}"
    r"\b(?:beyond|outside|unrelated)\b|"
    r"\b(?:replace|substitute|override)\b.{0,80}"
    r"\b(?:policy|review)\b.{0,40}\bverdict\b.{0,80}"
    r"\b(?:self[- ]issued|approval|passed)\b|"
    r"\b(?:present|represent|claim|describe)\b.{0,80}"
    r"\b(?:document|artifact|source)\b.{0,80}"
    r"\b(?:trusted maintainer|trusted source)\b.{0,80}\bunverified\b|"
    r"\b(?:defer|delay)\b.{0,80}\bhidden\b.{0,60}"
    r"\bbehavior(?:al)?\b.{0,40}\b(?:change|instruction)\b.{0,80}\buntil\b|"
    r"\b(?:reuse|alias|shadow)\b.{0,80}"
    r"\b(?:familiar\s+)?tool\s+name\b.{0,80}"
    r"\b(?:different|substitute|unapproved)\b.{0,80}\bbehavior\b|"
    r"\b(?:remove|delete|discard|suppress)\b.{0,80}\bevidence\b.{0,80}"
    r"\b(?:disagrees?|conflicts?|preferred outcome)\b|"
    r"\b(?:invent|fabricate|forge)\b.{0,80}"
    r"\b(?:reviewer|review|approval|test result)\b",
    re.IGNORECASE | re.DOTALL,
)
_PROMPT_DISCLOSURE = re.compile(
    r"\b(?:reveal|disclose|expose|print|return)\b.{0,80}"
    r"\b(?:system\s+prompt|hidden\s+(?:agent\s+)?memory|private\s+memory|secret|"
    r"credential)\b",
    re.IGNORECASE | re.DOTALL,
)
_CONCEALMENT = re.compile(
    r"\b(?:do not|don't|never)\s+(?:show|mention|describe|disclose|report|"
    r"request)\b|"
    r"\b(?:hide|conceal|suppress)\b.{0,50}\b(?:action|step|error|operation)\b|"
    r"\breport only\b|\bclaim\b.{0,80}\bapproved\b",
    re.IGNORECASE | re.DOTALL,
)
_SENSITIVE_ACCESS = re.compile(
    r"\b(?:read|collect|obtain|access|extract|export|reveal|disclose|expose|"
    r"print|return)\b.{0,100}"
    r"(?:credential|credentials|secret|secrets|api[_\s-]?token|"
    r"session[_\s-]?key|private\s+key|id_rsa|environment\s+variable|"
    r"process\s+environment|system\s+prompt|hidden\s+(?:agent\s+)?memory|"
    r"~/\.(?:ssh|aws))\b",
    re.IGNORECASE | re.DOTALL,
)
_TRANSFER_SINK = re.compile(
    r"\b(?:post|send|upload|transmit|exfiltrate|exfiltrates|exfiltrated|"
    r"exfiltrating|forward|dns\s+query|issue\s+(?:a\s+)?dns)\b|"
    r"\b(?:reveal|disclose|expose|return)\b.{0,100}"
    r"(?:https?://|\bwebhook\b|\bremote\b|\bendpoint\b)",
    re.IGNORECASE | re.DOTALL,
)
_FETCH_OR_DECODE = re.compile(
    r"\b(?:download(?:ed|ing|s)?|fetch|retrieve|curl|wget|"
    r"decode(?:d|s|ing)?|base64)\b",
    re.IGNORECASE,
)
_EXECUTION_SINK = re.compile(
    r"\b(?:execute|launch|source|shell|bash|zsh|powershell|cmd\.exe)\b|"
    r"(?<![A-Za-z0-9_])sh(?![A-Za-z0-9_])|"
    r"\brun\b.{0,60}\b(?:downloaded|decoded|payload|script|binary|installer|"
    r"command|it)\b",
    re.IGNORECASE | re.DOTALL,
)
_DESTRUCTIVE_ACTION = re.compile(
    r"\b(?:recursively delete|delete|remove|erase|wipe)\b.{0,120}"
    r"\b(?:workspace|project|repository|version history|history|backup|"
    r"recovery)\b|"
    r"\brm\s+(?:-[A-Za-z]*r[A-Za-z]*f|-rf|-fr)\b.{0,120}"
    r"\b(?:workspace|project|repository|version history|history|backup|"
    r"recovery)\b",
    re.IGNORECASE | re.DOTALL,
)
_PERSISTENCE_ACTION = re.compile(
    r"\b(?:modify|append|write|install)\b.{0,100}"
    r"\b(?:shell profile|\.zshrc|\.bashrc|startup|cron|new terminal|"
    r"later session)\b|"
    r"\b(?:shell profile|\.zshrc|\.bashrc)\b.{0,120}"
    r"\b(?:retrieve|download|launch|execute|source)\b",
    re.IGNORECASE | re.DOTALL,
)
_AGENT_PROPAGATION = re.compile(
    r"\b(?:another|receiving|every|other)\s+agent\b.{0,220}"
    r"\b(?:copy|install|repeat|propagat)\w*\b|"
    r"\b(?:copy|install)\b.{0,120}\b(?:skill|capability)\b.{0,160}"
    r"\b(?:agent|handoff)\b",
    re.IGNORECASE | re.DOTALL,
)
_SIGNAL_NAMES = {
    _PROMPT_OVERRIDE: "prompt_override",
    _AGENT_INTEGRITY_ABUSE: "agent_integrity_abuse",
    _PROMPT_DISCLOSURE: "prompt_disclosure",
    _CONCEALMENT: "concealment",
    _SENSITIVE_ACCESS: "sensitive_access",
    _TRANSFER_SINK: "transfer_sink",
    _FETCH_OR_DECODE: "fetch_or_decode",
    _EXECUTION_SINK: "execution_sink",
    _DESTRUCTIVE_ACTION: "destructive_action",
    _PERSISTENCE_ACTION: "persistence_action",
    _AGENT_PROPAGATION: "agent_propagation",
}
_FIRST_PARTY_ACTIONABLE = {
    "ARAGORN_AGENT_INTEGRITY_ABUSE",
    "ARAGORN_CREDENTIAL_EXFILTRATION",
    "ARAGORN_PROMPT_OVERRIDE",
    "ARAGORN_UNSAFE_EXECUTION_CHAIN",
}
_Segment = tuple[
    str,
    str,
    str,
    int,
    str,
    tuple[int, int],
    tuple[int, ...] | None,
]
_Window = tuple[_Segment, ...]


class CandidateError(ValueError):
    """Phase 0 candidate evidence could not be derived safely."""


def candidate_implementation_digest() -> str:
    """Identify the exact Aragorn Python source closure used by this checkout."""

    root = Path(__file__).parent
    digest = hashlib.sha256(
        b"aragorn-python-source-and-lock-closure/v1\0"
    )
    count = 0
    try:
        for path in sorted(
            root.rglob("*.py"),
            key=lambda item: item.relative_to(root).as_posix(),
        ):
            if path.is_symlink() or not path.is_file():
                raise CandidateError(
                    "candidate implementation contains a non-regular Python source"
                )
            relative = path.relative_to(root).as_posix().encode("utf-8")
            content = path.read_bytes()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
            count += 1
        lock_path = root.parents[1] / "requirements-worker.lock"
        if lock_path.is_symlink() or not lock_path.is_file():
            raise CandidateError(
                "candidate implementation dependency lock is unavailable"
            )
        lock = lock_path.read_bytes()
        lock_name = b"requirements-worker.lock"
        digest.update(len(lock_name).to_bytes(4, "big"))
        digest.update(lock_name)
        digest.update(len(lock).to_bytes(8, "big"))
        digest.update(lock)
    except OSError as exc:
        raise CandidateError(f"cannot identify candidate implementation: {exc}") from exc
    if count == 0:
        raise CandidateError("candidate implementation source closure is empty")
    return "sha256:" + digest.hexdigest()


def build_candidate_policy(document: object) -> dict[str, Any]:
    """Validate and return an independent canonical candidate-policy copy."""

    policy = _exact_object(document, _POLICY_KEYS, "candidate policy")
    schema = policy["schema"]
    algorithms = {
        POLICY_SCHEMA_V2: POLICY_ALGORITHM_V2,
        POLICY_SCHEMA: POLICY_ALGORITHM,
    }
    if schema not in algorithms:
        raise CandidateError("candidate policy schema is unsupported")
    if policy["assurance"] != POLICY_ASSURANCE:
        raise CandidateError("candidate policy assurance is unsupported")
    algorithm = policy["algorithm"]
    if algorithm != algorithms[schema]:
        raise CandidateError("candidate policy algorithm is unsupported")
    candidate = _partial_system(policy["candidate"], "candidate policy candidate")
    if (
        candidate["name"] != "aragorn"
        or candidate["version"] != _CANDIDATE_VERSION
    ):
        raise CandidateError("candidate policy system identity is unsupported")
    if candidate["implementation_digest"] != candidate_implementation_digest():
        raise CandidateError(
            "candidate policy implementation digest does not match composer bytes"
        )
    raw_comparators = policy["required_comparators"]
    if not isinstance(raw_comparators, list) or len(raw_comparators) != 2:
        raise CandidateError(
            "candidate policy requires exactly two comparator identities"
        )
    comparators = [
        _system(value, f"candidate policy comparator[{index}]")
        for index, value in enumerate(raw_comparators)
    ]
    if comparators != list(_REQUIRED_COMPARATORS):
        raise CandidateError("candidate policy comparator identities are unsupported")
    canonical = {
        "schema": schema,
        "assurance": POLICY_ASSURANCE,
        "algorithm": algorithm,
        "candidate": candidate,
        "required_comparators": comparators,
    }
    return json.loads(canonical_json(canonical))


def candidate_policy_digest(document: object) -> str:
    """Return the digest of one validated canonical candidate policy."""

    return canonical_digest(build_candidate_policy(document))


def candidate_system_identity(document: object) -> dict[str, str]:
    """Derive the full benchmark identity from one candidate policy."""

    policy = build_candidate_policy(document)
    return {
        **policy["candidate"],
        "config_digest": canonical_digest(policy),
    }


def detect_first_party_observations(
    manifest: object,
    cas: CAS,
) -> tuple[Observation, ...]:
    """Derive bounded, label-free agent-skill threat observations."""

    if not isinstance(manifest, dict):
        raise CandidateError("candidate manifest must be a JSON object")
    files = manifest.get("files")
    tree_digest = _digest(
        manifest.get("tree_digest"),
        "candidate manifest tree digest",
    )
    if not isinstance(files, list) or not files:
        raise CandidateError("candidate manifest files must be a non-empty array")

    segments: list[_Segment] = []
    text_carriers: list[tuple[str, str, str]] = []
    incomplete: list[dict[str, Any]] = []
    total = 0
    segment_budget_exhausted = False
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            raise CandidateError(f"candidate manifest files[{index}] is invalid")
        path = entry.get("path")
        digest = entry.get("digest")
        size = entry.get("size")
        if (
            not isinstance(path, str)
            or not path
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise CandidateError(f"candidate manifest files[{index}] is invalid")
        digest = _digest(digest, f"candidate manifest files[{index}].digest")
        total += size
        if total > _FIRST_PARTY_TEXT_LIMIT:
            incomplete.append(
                {
                    "path": path,
                    "blob_digest": digest,
                    "line": 1,
                    "signal": "aggregate_text_limit",
                }
            )
            break
        try:
            content = cas.read(digest, max_bytes=size)
        except CASError as exc:
            raise CandidateError(
                f"cannot read candidate manifest file {path}: {exc}"
            ) from exc
        if len(content) != size:
            raise CandidateError(f"candidate manifest file {path} size changed")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            incomplete.append(
                {
                    "path": path,
                    "blob_digest": digest,
                    "line": 1,
                    "signal": "non_utf8_text",
                }
            )
            continue
        incomplete.extend(
            {
                "path": path,
                "blob_digest": digest,
                "line": line,
                "signal": signal,
            }
            for line, signal in _text_incomplete_signals(text)
        )
        text_carriers.append((text, path, digest))
        for segment in _active_text_segments(text, path=path, digest=digest):
            if len(segments) >= _FIRST_PARTY_SEGMENT_LIMIT:
                incomplete.append(
                    {
                        "path": path,
                        "blob_digest": digest,
                        "line": segment[3],
                        "signal": "segment_limit",
                    }
                )
                segment_budget_exhausted = True
                break
            segments.append(segment)
        if segment_budget_exhausted:
            break

    decode_bridge = [
        segment for segment in segments if _DECODE_BRIDGE.search(segment[0])
    ]
    if decode_bridge and not segment_budget_exhausted:
        for text, path, digest in text_carriers:
            for segment in _decoded_text_segments(
                text,
                path=path,
                digest=digest,
            ):
                if segment[4].startswith("analysis_incomplete:"):
                    incomplete.append(
                        {
                            "path": path,
                            "blob_digest": digest,
                            "line": segment[3],
                            "signal": segment[4].split(":", 1)[1],
                        }
                    )
                    continue
                if len(segments) >= _FIRST_PARTY_SEGMENT_LIMIT:
                    incomplete.append(
                        {
                            "path": path,
                            "blob_digest": digest,
                            "line": segment[3],
                            "signal": "segment_limit",
                        }
                    )
                    segment_budget_exhausted = True
                    break
                segments.append(segment)
            if segment_budget_exhausted:
                break

    findings: dict[str, list[dict[str, Any]]] = {}
    if incomplete:
        findings["ARAGORN_ANALYSIS_INCOMPLETE"] = incomplete

    windows = tuple(_relation_windows(segments))
    integrity_windows = [
        window
        for window in windows
        if _AGENT_INTEGRITY_ABUSE.search(_window_text(window))
    ]
    if integrity_windows:
        findings["ARAGORN_AGENT_INTEGRITY_ABUSE"] = _matching_locations(
            integrity_windows,
            (_AGENT_INTEGRITY_ABUSE,),
        )

    prompt_windows = [
        window
        for window in windows
        if _PROMPT_OVERRIDE.search(_window_text(window))
        or (
            _PROMPT_DISCLOSURE.search(_window_text(window))
            and (
                _CONCEALMENT.search(_window_text(window))
                or _TRANSFER_SINK.search(_window_text(window))
            )
        )
    ]
    if prompt_windows:
        findings["ARAGORN_PROMPT_OVERRIDE"] = _matching_locations(
            prompt_windows,
            (
                _PROMPT_OVERRIDE,
                _PROMPT_DISCLOSURE,
                _CONCEALMENT,
                _TRANSFER_SINK,
            ),
        )

    exfil_windows = [
        window
        for window in windows
        if _SENSITIVE_ACCESS.search(_window_text(window))
        and _TRANSFER_SINK.search(_window_text(window))
    ]
    if exfil_windows:
        findings["ARAGORN_CREDENTIAL_EXFILTRATION"] = _matching_locations(
            exfil_windows,
            (_SENSITIVE_ACCESS, _TRANSFER_SINK),
        )

    unsafe_windows = [
        window
        for window in windows
        if (
            _FETCH_OR_DECODE.search(_window_text(window))
            and _EXECUTION_SINK.search(_window_text(window))
        )
        or _DESTRUCTIVE_ACTION.search(_window_text(window))
        or _PERSISTENCE_ACTION.search(_window_text(window))
        or _AGENT_PROPAGATION.search(_window_text(window))
    ]
    if unsafe_windows:
        findings["ARAGORN_UNSAFE_EXECUTION_CHAIN"] = _matching_locations(
            unsafe_windows,
            (
                _FETCH_OR_DECODE,
                _EXECUTION_SINK,
                _DESTRUCTIVE_ACTION,
                _PERSISTENCE_ACTION,
                _AGENT_PROPAGATION,
            ),
        )

    observations = []
    for reason_code in sorted(findings):
        document = {
            "schema": OBSERVATION_SCHEMA,
            "subject_digest": tree_digest,
            "reason_code": reason_code,
            "severity": (
                "medium"
                if reason_code == "ARAGORN_ANALYSIS_INCOMPLETE"
                else "high"
            ),
            "evidence": {
                "analyzer": _FIRST_PARTY_ANALYZER,
                "algorithm": _FIRST_PARTY_ALGORITHM,
                "locations": sorted(
                    findings[reason_code],
                    key=lambda item: (
                        item["path"],
                        item["line"],
                        item["signal"],
                        item["blob_digest"],
                    ),
                )[:16],
            },
        }
        document_json = canonical_json(document).decode("ascii")
        observations.append(
            Observation(
                schema=OBSERVATION_SCHEMA,
                subject_digest=tree_digest,
                reason_code=reason_code,
                severity=document["severity"],
                document_json=document_json,
            )
        )
    return tuple(observations)


def _active_text_segments(
    text: str,
    *,
    path: str,
    digest: str,
) -> Iterable[_Segment]:
    normalized = _normalize_text(text)
    yield from _active_segments_from_normalized(
        normalized,
        path=path,
        digest=digest,
        carrier="text",
        scope_base=0,
    )
    rendered, line_map = _rendered_text(normalized)
    if rendered != normalized:
        yield from _active_segments_from_normalized(
            rendered,
            path=path,
            digest=digest,
            carrier="rendered_text",
            scope_base=0,
            line_map=line_map,
        )


def _decoded_text_segments(
    text: str,
    *,
    path: str,
    digest: str,
) -> Iterable[_Segment]:
    normalized = _normalize_text(text)
    carriers: list[
        tuple[str, int | None, int | None, tuple[int, ...] | None]
    ] = [
        (normalized, None, None, None)
    ]
    rendered, rendered_lines = _rendered_text(normalized)
    if rendered != normalized:
        carriers.append((rendered, None, None, rendered_lines))
    seen: set[str] = set()
    for _depth in range(_BASE64_MAX_DEPTH):
        nested: list[
            tuple[str, int, int, tuple[int, ...] | None]
        ] = []
        for (
            carrier_text,
            inherited_line,
            inherited_scope,
            carrier_lines,
        ) in carriers:
            for token, start in _base64_candidates(carrier_text):
                remainder = len(token) % 4
                if token in seen:
                    continue
                if remainder == 1 or len(token) > _BASE64_TOKEN_LIMIT:
                    line = (
                        inherited_line
                        if inherited_line is not None
                        else carrier_lines[start]
                        if carrier_lines is not None
                        else carrier_text.count("\n", 0, start) + 1
                    )
                    scope = (
                        inherited_scope
                        if inherited_scope is not None
                        else start + 1
                    )
                    yield (
                        "",
                        path,
                        digest,
                        line,
                        "analysis_incomplete:base64_token_limit",
                        (scope, 0),
                        None,
                    )
                    continue
                seen.add(token)
                try:
                    decoded = base64.b64decode(
                        token + "=" * ((4 - remainder) % 4),
                        altchars=b"-_",
                        validate=True,
                    )
                    if not decoded:
                        continue
                    if len(decoded) > _BASE64_TEXT_LIMIT:
                        yield (
                            "",
                            path,
                            digest,
                            inherited_line or 1,
                            "analysis_incomplete:base64_text_limit",
                            (inherited_scope or start + 1, 0),
                            None,
                        )
                        continue
                    decoded_text = decoded.decode("utf-8")
                except (UnicodeDecodeError, ValueError):
                    continue
                printable = sum(
                    character.isprintable() or character.isspace()
                    for character in decoded_text
                )
                if printable / len(decoded_text) < 0.95:
                    continue
                decoded_text = _normalize_text(decoded_text)
                line = (
                    inherited_line
                    if inherited_line is not None
                    else carrier_lines[start]
                    if carrier_lines is not None
                    else carrier_text.count("\n", 0, start) + 1
                )
                scope = (
                    inherited_scope
                    if inherited_scope is not None
                    else start + 1
                )
                yield from _active_segments_from_normalized(
                    decoded_text,
                    path=path,
                    digest=digest,
                    carrier="base64_decoded",
                    fixed_line=line,
                    scope_base=scope,
                )
                rendered, _line_map = _rendered_text(decoded_text)
                if rendered != decoded_text:
                    yield from _active_segments_from_normalized(
                        rendered,
                        path=path,
                        digest=digest,
                        carrier="base64_rendered",
                        fixed_line=line,
                        scope_base=scope,
                    )
                if _depth == _BASE64_MAX_DEPTH - 1 and any(
                    next(_base64_candidates(view), None) is not None
                    for view in {decoded_text, rendered}
                ):
                    yield (
                        "",
                        path,
                        digest,
                        line,
                        "analysis_incomplete:base64_depth_limit",
                        (scope, 0),
                        None,
                    )
                nested.append((decoded_text, line, scope, None))
                if rendered != decoded_text:
                    nested.append((rendered, line, scope, _line_map))
        carriers = nested


def _base64_candidates(text: str) -> Iterable[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    for match in _BASE64_TOKEN.finditer(text):
        candidate = (match.group(0), match.start())
        seen.add(candidate)
        yield candidate

    for match in _BASE64_SPACED.finditer(text):
        candidate = (
            re.sub(r"[ \t]+", "", match.group(0)),
            match.start(),
        )
        if len(candidate[0]) >= 32 and candidate not in seen:
            seen.add(candidate)
            yield candidate

    chunks: list[str] = []
    start = 0
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip(" \t\r\n")
        if _BASE64_LINE.fullmatch(stripped) is not None:
            if not chunks:
                start = offset + len(line) - len(line.lstrip(" \t"))
            chunks.append(stripped)
        else:
            if len(chunks) >= 2:
                candidate = ("".join(chunks), start)
                if len(candidate[0]) >= 32 and candidate not in seen:
                    yield candidate
            chunks = []
            suffix = re.search(
                r"(?<![A-Za-z0-9+/_-])"
                r"([A-Za-z0-9+/_-]{4,}={0,2})[ \t\r\n]*\Z",
                line,
            )
            if suffix is not None:
                chunks = [suffix.group(1)]
                start = offset + suffix.start(1)
        offset += len(line)
    if len(chunks) >= 2:
        candidate = ("".join(chunks), start)
        if len(candidate[0]) >= 32 and candidate not in seen:
            yield candidate


def _normalize_text(text: str) -> str:
    normalized = "".join(
        character
        for character in unicodedata.normalize("NFKC", text)
        if unicodedata.category(character) != "Cf"
    )

    def fold_confusables(match: re.Match[str]) -> str:
        word = match.group(0)
        if not re.search(r"[A-Za-z]", word) or not any(
            character in _MIXED_SCRIPT_CONFUSABLES for character in word
        ):
            return word
        return "".join(
            _MIXED_SCRIPT_CONFUSABLES.get(character, character)
            for character in word
        )

    return _UNICODE_WORD.sub(fold_confusables, normalized)


def _rendered_text(text: str) -> tuple[str, tuple[int, ...]]:
    lines: list[int] = []
    line = 1
    for character in text:
        lines.append(line)
        if character == "\n":
            line += 1

    def drop(pattern: re.Pattern[str]) -> None:
        nonlocal text, lines
        parts: list[str] = []
        mapped: list[int] = []
        cursor = 0
        for match in pattern.finditer(text):
            parts.append(text[cursor : match.start()])
            mapped.extend(lines[cursor : match.start()])
            cursor = match.end()
        parts.append(text[cursor:])
        mapped.extend(lines[cursor:])
        text = "".join(parts)
        lines = mapped

    drop(_HTML_COMMENT)
    drop(_HTML_TAG)

    parts: list[str] = []
    mapped: list[int] = []
    cursor = 0
    for match in _MARKDOWN_LINK.finditer(text):
        parts.append(text[cursor : match.start()])
        mapped.extend(lines[cursor : match.start()])
        parts.append(match.group(1))
        mapped.extend(lines[match.start(1) : match.end(1)])
        cursor = match.end()
    parts.append(text[cursor:])
    mapped.extend(lines[cursor:])
    text = "".join(parts)
    lines = mapped

    for _depth in range(4):
        parts = []
        mapped = []
        cursor = 0
        changed = False
        for match in _HTML_ENTITY.finditer(text):
            replacement = unescape(match.group(0))
            if replacement == match.group(0):
                continue
            changed = True
            parts.append(text[cursor : match.start()])
            mapped.extend(lines[cursor : match.start()])
            parts.append(replacement)
            mapped.extend([lines[match.start()]] * len(replacement))
            cursor = match.end()
        if not changed:
            break
        parts.append(text[cursor:])
        mapped.extend(lines[cursor:])
        text = "".join(parts)
        lines = mapped

    drop(_INTRAWORD_MARKUP)
    return text, tuple(lines)


def _text_incomplete_signals(text: str) -> Iterable[tuple[int, str]]:
    def line_at(index: int) -> int:
        return text.count("\n", 0, index) + 1

    def active_context(index: int, end: int | None = None) -> bool:
        context = text[max(0, index - 256) : index + 768]
        if end is not None and end > index:
            context += text[max(index, end - 256) : end + 768]
        return any(
            pattern.search(context)
            for pattern in (
                _PROMPT_DISCLOSURE,
                _AGENT_INTEGRITY_ABUSE,
                _SENSITIVE_ACCESS,
                _TRANSFER_SINK,
                _EXECUTION_SINK,
                _DESTRUCTIVE_ACTION,
                _PERSISTENCE_ACTION,
                _AGENT_PROPAGATION,
            )
        ) or re.search(
            r"\b(?:previous|prior|earlier)\s+(?:instruction|instructions|"
            r"direction|directions|policy|policies)\b",
            context,
            re.IGNORECASE,
        ) is not None

    cursor = 0
    while (start := text.find("<!--", cursor)) >= 0:
        end = text.find("-->", start + 4)
        if end < 0 or end + 3 - start > 4103:
            yield line_at(start), "opaque_html_comment"
        if end < 0:
            break
        cursor = end + 3

    for match in re.finditer(r"</?[A-Za-z]", text):
        line_end = text.find("\n", match.start())
        if line_end < 0:
            line_end = len(text)
        if (
            match.start() > 0
            and text[match.start() - 1].isalpha()
            and ">" in text[match.start() : line_end]
        ):
            tag = _HTML_TAG.match(text, match.start())
            if tag is None:
                yield line_at(match.start()), "opaque_html_tag"

    for match in re.finditer(r"(?<=[^\W\d_])\[", text):
        link = _MARKDOWN_LINK.match(text, match.start())
        if (
            link is None
            and text.find("](", match.start(), match.start() + 1024) >= 0
        ):
            yield line_at(match.start()), "opaque_markdown_link"

    rendered = text
    for _depth in range(4):
        decoded = unescape(rendered)
        if decoded == rendered:
            break
        rendered = decoded
    if unescape(rendered) != rendered:
        start = text.find("&")
        yield line_at(max(0, start)), "html_entity_depth"

    token_start: int | None = None
    for index, character in enumerate(text + " "):
        if character.isalpha() or unicodedata.category(character).startswith("M"):
            if token_start is None:
                token_start = index
            continue
        if token_start is None:
            continue
        token = text[token_start:index]
        if (
            any(item.isascii() and item.isalpha() for item in token)
            and any(
                (
                    not item.isascii()
                    and (
                        item not in _MIXED_SCRIPT_CONFUSABLES
                        or unicodedata.category(item).startswith("M")
                    )
                )
                for item in token
            )
            and active_context(token_start, index)
        ):
            yield line_at(token_start), "mixed_script_or_combining_token"
        token_start = None


def _active_segments_from_normalized(
    text: str,
    *,
    path: str,
    digest: str,
    carrier: str,
    scope_base: int,
    fixed_line: int | None = None,
    line_map: tuple[int, ...] | None = None,
) -> Iterable[_Segment]:
    quote_is_data = False
    for paragraph in re.finditer(
        r"(?:\A|\n\s*\n)(.*?)(?=\n\s*\n|\Z)",
        text,
        re.DOTALL,
    ):
        raw = paragraph.group(1)
        if not raw.strip():
            continue
        leading = len(raw) - len(raw.lstrip())
        content = raw.strip()
        offset = paragraph.start(1) + leading
        content = _DEFENSIVE_SENSITIVE_CONTEXT.sub(
            _defensive_sensitive_replacement,
            content,
        )
        if not content.strip():
            continue
        quoted = all(
            line.lstrip().startswith(">")
            for line in content.splitlines()
            if line.strip()
        )
        analysis_context = _ANALYSIS_CONTEXT.search(content) is not None
        if quoted and quote_is_data:
            quote_is_data = False
            continue
        quote_is_data = analysis_context and content.rstrip().endswith(":")
        for clause, clause_offset in _clauses(content):
            if _analysis_only(clause):
                continue
            defensive = _DEFENSIVE_CONTEXT.search(clause)
            if defensive is not None:
                active = _DEFENSIVE_CONTEXT.sub(
                    lambda match: " " * len(match.group(0)),
                    clause,
                )
                leading = len(active) - len(active.lstrip())
                clause_offset += leading
                clause = active.strip()
                if not clause:
                    continue
            line = (
                fixed_line
                if fixed_line is not None
                else line_map[offset + clause_offset]
                if line_map is not None
                else text.count("\n", 0, offset + clause_offset) + 1
            )
            clause_lines = (
                line_map[
                    offset
                    + clause_offset : offset
                    + clause_offset
                    + len(clause)
                ]
                if line_map is not None
                else None
            )
            yield (
                clause,
                path,
                digest,
                line,
                carrier,
                (scope_base, paragraph.start(1)),
                clause_lines,
            )


def _defensive_sensitive_replacement(match: re.Match[str]) -> str:
    tail = match.string[match.end() : match.end() + 256]
    sentence_end = re.search(r"[.!?](?=\s|\Z)", tail)
    if sentence_end is not None:
        tail = tail[: sentence_end.end()]
    sensitive_transfer = (
        _DEFENSIVE_SENSITIVE_REFERENCE.search(tail) is not None
        and _TRANSFER_SINK.search(tail) is not None
    )
    unsafe_contrast = (
        _DEFENSIVE_SENSITIVE_CONTRAST.match(tail) is not None
        and (
            (
                _FETCH_OR_DECODE.search(tail) is not None
                and _EXECUTION_SINK.search(tail) is not None
            )
            or _DESTRUCTIVE_ACTION.search(tail) is not None
            or _PERSISTENCE_ACTION.search(tail) is not None
            or _AGENT_PROPAGATION.search(tail) is not None
        )
    )
    return (
        match.group(0)
        if sensitive_transfer or unsafe_contrast
        else " " * len(match.group(0))
    )


def _clauses(text: str) -> Iterable[tuple[str, int]]:
    start = 0
    boundary = re.compile(
        r"(?:[.!?;](?=\s|$)|(?:[,:\u2013\u2014]\s*|\s+-\s+)"
        r"(?=(?:(?:but|instead|however|then|yet)\s+)?"
        r"(?:read|collect|obtain|access|extract|export|reveal|disclose|expose|"
        r"post|send|upload|transmit|download|fetch|retrieve|curl|wget|decode|"
        r"execute|run|launch|source|delete|remove|erase|wipe|copy|install)\b)|"
        r"\s+(?=(?:but|instead|however|then|yet|and\s+then)\b)|"
        r"\s+(?=(?:while|after|before|once)\s+(?:you\s+)?"
        r"(?:read|collect|obtain|access|extract|export|reveal|disclose|expose|"
        r"post|send|upload|transmit|download|fetch|retrieve|curl|wget|decode|"
        r"execute|run|launch|source|delete|remove|erase|wipe|copy|install)\b)|"
        r"\s+(?=and\s+(?:read|collect|obtain|access|extract|export|reveal|"
        r"disclose|expose|post|send|upload|transmit|download|fetch|retrieve|"
        r"curl|wget|decode|execute|run|launch|source|delete|remove|erase|wipe|"
        r"copy|install)\b))",
        re.IGNORECASE,
    )
    for match in boundary.finditer(text):
        end = match.end()
        clause = text[start:end].strip()
        if clause:
            yield clause, start + len(text[start:end]) - len(text[start:end].lstrip())
        start = end
    clause = text[start:].strip()
    if clause:
        yield clause, start + len(text[start:]) - len(text[start:].lstrip())


def _analysis_only(text: str) -> bool:
    directive = _ANALYSIS_DIRECTIVE.search(text)
    if directive is None or not (
        _ANALYSIS_CONTEXT.search(text)
        or re.match(
            r"\s*(?:explain|discuss)\s+(?:why|how)\b",
            text,
            re.IGNORECASE,
        )
    ):
        return False
    matches = [
        match
        for pattern in (
            _PROMPT_OVERRIDE,
            _AGENT_INTEGRITY_ABUSE,
            _PROMPT_DISCLOSURE,
            _SENSITIVE_ACCESS,
            _TRANSFER_SINK,
            _FETCH_OR_DECODE,
            _EXECUTION_SINK,
            _DESTRUCTIVE_ACTION,
            _PERSISTENCE_ACTION,
            _AGENT_PROPAGATION,
        )
        if (match := pattern.search(text, directive.end())) is not None
    ]
    quoted = tuple(_QUOTED_DATA_SPAN.finditer(text))
    return not matches or all(
        any(span.start() <= match.start() < span.end() for span in quoted)
        or _EXPLANATION_GOVERNOR.search(
            text[directive.end() : match.start()]
        ) is not None
        for match in matches
    )


def _relation_windows(segments: Iterable[_Segment]) -> Iterable[_Window]:
    retained = tuple(segments)
    for index, first in enumerate(retained):
        yield (first,)
        for width in (2, 3):
            window = retained[index : index + width]
            if len(window) != width:
                continue
            if all(
                first[1] == segment[1]
                and first[2] == segment[2]
                and first[4] == segment[4]
                and first[5] == segment[5]
                for segment in window[1:]
            ):
                yield window


def _window_text(window: _Window) -> str:
    return "\n".join(segment[0] for segment in window)


def _matching_locations(
    windows: Iterable[_Window],
    patterns: Iterable[re.Pattern[str]],
) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()
    for window in windows:
        window_text = _window_text(window)
        for pattern in patterns:
            match = pattern.search(window_text)
            if match is None:
                continue
            offset = 0
            for text, path, digest, line, carrier, _scope, line_map in window:
                if match.start() <= offset + len(text):
                    break
                offset += len(text) + 1
            signal = f"{carrier}:{_SIGNAL_NAMES[pattern]}"
            relative = max(0, match.start() - offset)
            if line_map:
                match_line = line_map[min(relative, len(line_map) - 1)]
            elif carrier.startswith("base64_"):
                match_line = line
            else:
                match_line = line + text.count("\n", 0, relative)
            key = (path, digest, match_line, signal)
            if key in seen:
                continue
            seen.add(key)
            locations.append(
                {
                    "path": path,
                    "blob_digest": digest,
                    "line": match_line,
                    "signal": signal,
                }
            )
            if len(locations) >= 16:
                return locations
    return locations


def compose_candidate_decision(
    policy: object,
    source_graph: object,
    components: Iterable[object],
    *,
    first_party_observations: Iterable[Observation] = (),
) -> tuple[str, list[str]]:
    """Apply one supported frozen, label-free candidate policy."""

    canonical_policy = build_candidate_policy(policy)
    graph = _source_graph(source_graph)
    normalized = [_component(value) for value in components]
    if len(normalized) != 2:
        raise CandidateError("candidate composition requires two components")
    by_name = {item["system"]["name"]: item for item in normalized}
    required = {
        item["name"]: item
        for item in canonical_policy["required_comparators"]
    }
    if set(by_name) != set(required) or any(
        by_name[name]["system"] != required[name] for name in required
    ):
        raise CandidateError(
            "candidate components do not match the frozen comparator identities"
        )
    for field in (
        "suite_digest",
        "case_id",
        "tree_digest",
        "run_id",
        "private_manifest_digest",
        "dispatch_digest",
    ):
        if len({item[field] for item in normalized}) != 1:
            raise CandidateError(
                f"candidate components do not share one {field}"
            )
    if (
        graph["root_manifest_digest"]
        != normalized[0]["private_manifest_digest"]
        or graph["tree_digest"] != normalized[0]["tree_digest"]
    ):
        raise CandidateError(
            "source-reference graph does not match the candidate components"
        )

    errors: set[str] = set()
    if graph["closure"]["status"] != "complete":
        errors.add("SOURCE_REFERENCE_GRAPH_INCOMPLETE")
    for name, component in by_name.items():
        if component["verdict"] == "ERROR":
            errors.add(f"COMPARATOR_ERROR_{_reason_name(name)}")
    if errors:
        return "ERROR", sorted(errors)

    first_party = tuple(first_party_observations)
    if canonical_policy["algorithm"] == POLICY_ALGORITHM_V2:
        denied = [
            component
            for component in normalized
            if component["verdict"] == "DENY"
        ]
        if denied:
            reasons = _actionable_reasons(denied)
            return "DENY", reasons or ["COMPARATOR_DENY"]
        if any(
            not isinstance(observation, Observation)
            or observation.schema != OBSERVATION_SCHEMA
            or observation.subject_digest != graph["tree_digest"]
            for observation in first_party
        ):
            raise CandidateError(
                "first-party observations do not bind the source graph"
            )
        review_reasons = {
            observation.reason_code for observation in first_party
        }
        cisco = by_name["cisco-skill-scanner"]
        if cisco["verdict"] == "REVIEW":
            review_reasons.update(cisco["reason_codes"])
        nvidia = by_name["skillspector"]
        if nvidia["verdict"] == "REVIEW":
            review_reasons.update(
                reason
                for reason in nvidia["reason_codes"]
                if reason != _NVIDIA_INCOMPLETE
            )
        if review_reasons:
            return "REVIEW", sorted(review_reasons)
        return "ALLOW", []

    if any(
        not isinstance(observation, Observation)
        or observation.schema != OBSERVATION_SCHEMA
        or observation.subject_digest != graph["tree_digest"]
        for observation in first_party
    ):
        raise CandidateError("first-party observations do not bind the source graph")
    incomplete = [
        observation
        for observation in first_party
        if observation.reason_code == "ARAGORN_ANALYSIS_INCOMPLETE"
    ]
    if incomplete:
        if any(observation.severity != "medium" for observation in incomplete):
            raise CandidateError("first-party incomplete analysis is malformed")
        return "ERROR", ["ARAGORN_ANALYSIS_INCOMPLETE"]
    actionable = [
        observation
        for observation in first_party
        if observation.reason_code in _FIRST_PARTY_ACTIONABLE
        and observation.severity == "high"
    ]
    if len(actionable) != len(first_party):
        raise CandidateError("first-party observation is unsupported")

    intervened = [
        component
        for component in normalized
        if component["verdict"] in {"REVIEW", "DENY"}
        and _actionable_reasons((component,))
    ]
    if len(intervened) == 2:
        reasons = {
            reason
            for reason in _actionable_reasons(intervened)
        }
        reasons.update(observation.reason_code for observation in actionable)
        verdict = (
            "DENY"
            if all(component["verdict"] == "DENY" for component in intervened)
            else "REVIEW"
        )
        return verdict, sorted(reasons)
    if actionable:
        return "REVIEW", sorted(
            {observation.reason_code for observation in actionable}
        )
    return "ALLOW", []


def _composition_state(
    *,
    dispatch_digest: str,
    control_state: str | os.PathLike[str],
    challenge_ledger: str | os.PathLike[str],
) -> tuple[str, Path, CAS, dict[str, Any]]:
    dispatch_digest = _digest(dispatch_digest, "dispatch digest")
    control_root = _existing_directory(control_state, "control state")
    ledger_root = _existing_directory(challenge_ledger, "challenge ledger")
    if _paths_overlap(control_root, ledger_root):
        raise CandidateError("control state and challenge ledger must not overlap")
    cas = CAS(control_root)
    dispatch = _read_canonical_document(
        cas,
        dispatch_digest,
        "private dispatch",
    )
    if canonical_digest(dispatch) != dispatch_digest:
        raise CandidateError("private dispatch digest is not canonical")
    return dispatch_digest, ledger_root, cas, dispatch


def _authenticated_components(
    *,
    dispatch_digest: str,
    dispatch: dict[str, Any],
    cas: CAS,
    ledger_root: Path,
) -> tuple[
    list[dict[str, Any]],
    dict[tuple[str, int], list[tuple[str, dict[str, Any]]]],
]:
    suite_digests = {entry["suite_digest"] for entry in dispatch["jobs"]}
    if len(suite_digests) != 1:
        raise CandidateError("private dispatch spans multiple suites")
    suite_digest = next(iter(suite_digests))
    expected_challenges: dict[str, dict[str, Any]] = {}
    subjects: dict[str, dict[str, Any]] = {}
    for entry in dispatch["jobs"]:
        system = entry["system"]
        request = _read_canonical_document(
            cas,
            entry["request_digest"],
            "worker request v2",
        )
        try:
            validate_worker_request_v2(request)
            manifest_digest = entry["private_manifest_digest"]
            subject = subjects.get(manifest_digest)
            if subject is None:
                manifest = load_retained_manifest(cas, manifest_digest)
                subject = sanitize_subject_manifest(manifest)
                subjects[manifest_digest] = subject
            verify_request_subject_v2(request, subject)
        except (ArtifactClosureError, CASError, WorkerProtocolError) as exc:
            raise CandidateError(f"worker request v2 is invalid: {exc}") from exc
        if canonical_request_digest_v2(request) != entry["request_digest"]:
            raise CandidateError("worker request v2 digest changed")
        if (
            request["job_id"] != entry["job_id"]
            or request["subject"]["tree_digest"] != entry["tree_digest"]
            or request["portable_policy_digest"] != system["config_digest"]
            or request["system"]
            != {
                field: system[field]
                for field in ("name", "version", "implementation_digest")
            }
        ):
            raise CandidateError("worker request v2 does not match private dispatch")
        challenge = request["verifier_challenge"]
        if challenge in expected_challenges:
            raise CandidateError("private dispatch repeats a verifier challenge")
        expected_challenges[challenge] = entry

    component_outcomes: list[dict[str, Any]] = []
    component_evidence: dict[
        tuple[str, int], list[tuple[str, dict[str, Any]]]
    ] = {}
    for challenge in sorted(expected_challenges):
        entry = expected_challenges[challenge]
        accepted = load_verified_worker_output_acceptance(
            cas,
            ledger_root,
            challenge,
        )
        issuance_digest = _put_json(cas, accepted["issuance"])
        receipt_digest = _put_json(cas, accepted["receipt"])
        receipt = accepted["receipt"]
        if (
            receipt["job_id"] != entry["job_id"]
            or receipt["request_digest"] != entry["request_digest"]
        ):
            raise CandidateError(
                "authenticated worker acceptance does not match private dispatch"
            )
        result = _read_canonical_document(
            cas,
            receipt["result_digest"],
            "worker result v2",
        )
        try:
            validate_worker_result_v2(result)
        except ValueError as exc:
            raise CandidateError(f"worker result v2 is invalid: {exc}") from exc
        system = entry["system"]
        if (
            result["job_id"] != entry["job_id"]
            or result["request_digest"] != entry["request_digest"]
            or result["tree_digest"] != entry["tree_digest"]
            or result["portable_policy_digest"] != system["config_digest"]
            or result["system"]
            != {
                field: system[field]
                for field in ("name", "version", "implementation_digest")
            }
        ):
            raise CandidateError(
                "authenticated worker result does not match private dispatch"
            )
        _validate_result_observations(cas, result)
        evidence = {
            "schema": "aragorn/benchmark-authenticated-worker-evidence/v1",
            "suite_digest": suite_digest,
            "case_id": entry["case_id"],
            "tree_digest": entry["tree_digest"],
            "run_id": entry["run_id"],
            "system": dict(system),
            "verdict": result["verdict"],
            "reason_codes": list(result["reason_codes"]),
            "private_manifest_digest": entry["private_manifest_digest"],
            "dispatch_digest": dispatch_digest,
            "acceptance_receipt_digest": receipt_digest,
            "issuance_digest": issuance_digest,
        }
        evidence_digest = _put_json(cas, evidence)
        component_outcomes.append(_outcome(evidence, evidence_digest))
        component_evidence.setdefault(
            (entry["case_id"], entry["run_id"]),
            [],
        ).append((evidence_digest, evidence))
    return component_outcomes, component_evidence


def compose_authenticated_comparator_batch(
    *,
    dispatch_digest: str,
    control_state: str | os.PathLike[str],
    challenge_ledger: str | os.PathLike[str],
) -> dict[str, Any]:
    """Compose comparator outcomes from one authenticated protocol-v2 dispatch."""

    dispatch_digest, ledger_root, cas, dispatch = _composition_state(
        dispatch_digest=dispatch_digest,
        control_state=control_state,
        challenge_ledger=challenge_ledger,
    )
    from .label_blind_prepare import validate_private_dispatch

    try:
        validate_private_dispatch(dispatch)
    except ValueError as exc:
        raise CandidateError(f"private dispatch is invalid: {exc}") from exc
    outcomes, _evidence = _authenticated_components(
        dispatch_digest=dispatch_digest,
        dispatch=dispatch,
        cas=cas,
        ledger_root=ledger_root,
    )
    outcomes.sort(key=_outcome_sort_key)
    if len(outcomes) != len(dispatch["jobs"]) or len(
        {canonical_digest(outcome) for outcome in outcomes}
    ) != len(outcomes):
        raise CandidateError("authenticated comparator matrix is incomplete")
    composition = {
        "schema": "aragorn/benchmark-authenticated-worker-composition/v1",
        "assurance": COMPOSITION_ASSURANCE,
        "suite_digest": dispatch["jobs"][0]["suite_digest"],
        "dispatch_digest": dispatch_digest,
        "outcomes_digest": canonical_digest(outcomes),
        "outcomes": outcomes,
    }
    _put_json(cas, composition)
    return composition


def compose_candidate_batch(
    *,
    dispatch_digest: str,
    control_state: str | os.PathLike[str],
    challenge_ledger: str | os.PathLike[str],
) -> dict[str, Any]:
    """Compose a complete candidate matrix without reading benchmark labels."""

    dispatch_digest, ledger_root, cas, dispatch = _composition_state(
        dispatch_digest=dispatch_digest,
        control_state=control_state,
        challenge_ledger=challenge_ledger,
    )
    from .label_blind_prepare import validate_private_dispatch_v2

    try:
        validate_private_dispatch_v2(dispatch)
    except ValueError as exc:
        raise CandidateError(f"private dispatch v2 is invalid: {exc}") from exc

    policy = build_candidate_policy(
        _read_canonical_document(
            cas,
            dispatch["candidate_policy_digest"],
            "candidate policy",
        )
    )
    if (
        policy["candidate"]["implementation_digest"]
        != candidate_implementation_digest()
    ):
        raise CandidateError(
            "candidate policy implementation digest does not match composer bytes"
        )
    policy_digest = canonical_digest(policy)
    if policy_digest != dispatch["candidate_policy_digest"]:
        raise CandidateError("candidate policy digest changed")
    candidate_system = candidate_system_identity(policy)
    if candidate_system != dispatch["candidate_system"]:
        raise CandidateError("candidate system does not match its policy")

    required_comparators = {
        item["name"]: item for item in policy["required_comparators"]
    }
    cells: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for entry in dispatch["jobs"]:
        system = entry["system"]
        if required_comparators.get(system["name"]) != system:
            raise CandidateError(
                "private dispatch system is outside the candidate policy"
            )
        cells.setdefault((entry["case_id"], entry["run_id"]), []).append(entry)

    expected_names = set(required_comparators)
    for entries in cells.values():
        if (
            len(entries) != 2
            or {entry["system"]["name"] for entry in entries} != expected_names
            or len({entry["tree_digest"] for entry in entries}) != 1
            or len({entry["private_manifest_digest"] for entry in entries}) != 1
        ):
            raise CandidateError(
                "private dispatch does not contain one exact comparator pair per cell"
            )

    component_outcomes, component_evidence = _authenticated_components(
        dispatch_digest=dispatch_digest,
        dispatch=dispatch,
        cas=cas,
        ledger_root=ledger_root,
    )

    analyses: dict[
        str,
        tuple[str, tuple[str, ...], tuple[Observation, ...]],
    ] = {}
    candidate_outcomes: list[dict[str, Any]] = []
    for cell in sorted(cells):
        entries = cells[cell]
        manifest_digest = entries[0]["private_manifest_digest"]
        retained = analyses.get(manifest_digest)
        if retained is None:
            try:
                manifest = load_retained_manifest(cas, manifest_digest)
                graph = resolve_source_graph(
                    manifest,
                    cas,
                    root_manifest_digest=manifest_digest,
                )
                first_party_observations = detect_first_party_observations(
                    manifest,
                    cas,
                )
            except (ArtifactClosureError, CASError) as exc:
                raise CandidateError(
                    f"cannot derive candidate analysis: {exc}"
                ) from exc
            graph_digest = _put_json(cas, graph)
            observation_digests = tuple(
                sorted(
                    _put_json(cas, json.loads(observation.document_json))
                    for observation in first_party_observations
                )
            )
            retained = (
                graph_digest,
                observation_digests,
                first_party_observations,
            )
            analyses[manifest_digest] = retained
        else:
            graph_digest, observation_digests, first_party_observations = retained
            graph = _read_canonical_document(
                cas,
                graph_digest,
                "source-reference graph",
            )
        graph_digest, observation_digests, first_party_observations = retained
        components = sorted(
            component_evidence[cell],
            key=lambda item: item[1]["system"]["name"],
        )
        verdict, reasons = compose_candidate_decision(
            policy,
            graph,
            (item[1] for item in components),
            first_party_observations=first_party_observations,
        )
        candidate_evidence = {
            "schema": "aragorn/benchmark-candidate-evidence/v2",
            "suite_digest": dispatch["suite_digest"],
            "case_id": cell[0],
            "tree_digest": entries[0]["tree_digest"],
            "run_id": cell[1],
            "system": candidate_system,
            "verdict": verdict,
            "reason_codes": reasons,
            "private_manifest_digest": manifest_digest,
            "source_graph_digest": graph_digest,
            "dispatch_digest": dispatch_digest,
            "policy_digest": policy_digest,
            "component_evidence_digests": sorted(
                item[0] for item in components
            ),
        }
        candidate_evidence["first_party_observation_digests"] = list(
            observation_digests
        )
        evidence_digest = _put_json(cas, candidate_evidence)
        candidate_outcomes.append(_outcome(candidate_evidence, evidence_digest))

    outcomes = sorted([*component_outcomes, *candidate_outcomes], key=_outcome_sort_key)
    expected_outcomes = len(cells) * 3
    if len(outcomes) != expected_outcomes:
        raise CandidateError("candidate composition matrix is incomplete")
    composition = {
        "schema": "aragorn/benchmark-candidate-composition/v1",
        "assurance": COMPOSITION_ASSURANCE,
        "suite_digest": dispatch["suite_digest"],
        "dispatch_digest": dispatch_digest,
        "policy_digest": policy_digest,
        "outcomes_digest": canonical_digest(outcomes),
        "outcomes": outcomes,
    }
    _put_json(cas, composition)
    return composition


def _component(value: object) -> dict[str, Any]:
    component = _exact_object(
        value,
        {
            "schema",
            "suite_digest",
            "case_id",
            "tree_digest",
            "run_id",
            "system",
            "verdict",
            "reason_codes",
            "private_manifest_digest",
            "dispatch_digest",
            "acceptance_receipt_digest",
            "issuance_digest",
        },
        "candidate component",
    )
    if component["schema"] != "aragorn/benchmark-authenticated-worker-evidence/v1":
        raise CandidateError("candidate component schema is unsupported")
    system = _system(component["system"], "candidate component system")
    verdict, reasons = _verdict(
        component["verdict"],
        component["reason_codes"],
        "candidate component",
    )
    return {**component, "system": system, "verdict": verdict, "reason_codes": reasons}


def _source_graph(value: object) -> dict[str, Any]:
    graph = _exact_object(
        value,
        {
            "schema",
            "profile",
            "assurance",
            "source_assurance",
            "root_manifest_digest",
            "tree_digest",
            "nodes",
            "edges",
            "closure",
        },
        "source-reference graph",
    )
    if graph["schema"] != "aragorn/source-artifact-graph/v1":
        raise CandidateError("source-reference graph schema is unsupported")
    if (
        graph["profile"] != SOURCE_GRAPH_PROFILE
        or graph["assurance"] != SOURCE_GRAPH_ASSURANCE
        or graph["source_assurance"]
        not in {
            "local_manifest_reverified",
            "github_api_membership_asserted_blob_identity_reverified",
        }
    ):
        raise CandidateError("source-reference graph profile is unsupported")
    _digest(graph["root_manifest_digest"], "source-reference graph root manifest")
    _digest(graph["tree_digest"], "source-reference graph tree")
    if not isinstance(graph["nodes"], list) or not isinstance(graph["edges"], list):
        raise CandidateError("source-reference graph collections are invalid")
    closure = _exact_object(
        graph["closure"],
        {"scope", "profile", "status", "unresolved"},
        "source-reference graph closure",
    )
    if (
        closure["scope"] != "source_reference_graph"
        or closure["profile"] != SOURCE_GRAPH_PROFILE
        or closure["status"] not in {"complete", "incomplete"}
        or not isinstance(closure["unresolved"], list)
    ):
        raise CandidateError("source-reference graph closure is invalid")
    if (closure["status"] == "complete") != (not closure["unresolved"]):
        raise CandidateError("source-reference graph closure is inconsistent")
    return graph


def _outcome(evidence: dict[str, Any], evidence_digest: str) -> dict[str, Any]:
    return {
        "schema": "aragorn/benchmark-outcome/v1",
        **{
            field: evidence[field]
            for field in (
                "suite_digest",
                "case_id",
                "tree_digest",
                "run_id",
                "system",
            )
        },
        "evidence_digest": evidence_digest,
        "verdict": evidence["verdict"],
        "reason_codes": list(evidence["reason_codes"]),
    }


def _outcome_sort_key(
    item: dict[str, Any],
) -> tuple[str, str, str, str, str, int]:
    return (
        item["system"]["name"],
        item["system"]["version"],
        item["system"]["implementation_digest"],
        item["system"]["config_digest"],
        item["case_id"],
        item["run_id"],
    )


def _validate_result_observations(cas: CAS, result: dict[str, Any]) -> None:
    raw = b"\n".join(
        cas.read(digest, max_bytes=8 * 1024 * 1024)
        for digest in result["observation_digests"]
    )
    observations, error = _parse_observations(raw, result["tree_digest"])
    if error is not None or len(observations) != len(result["observation_digests"]):
        raise CandidateError("worker result observations do not re-parse")


def _actionable_reasons(components: Iterable[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            reason
            for component in components
            for reason in component["reason_codes"]
            if reason != _NVIDIA_INCOMPLETE
        }
    )


def _reason_name(name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")


def _verdict(
    verdict: object,
    reasons: object,
    label: str,
) -> tuple[str, list[str]]:
    if verdict not in {"ALLOW", "REVIEW", "DENY", "ERROR"}:
        raise CandidateError(f"{label} verdict is unsupported")
    if not isinstance(reasons, list) or any(
        not isinstance(reason, str)
        or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", reason) is None
        for reason in reasons
    ):
        raise CandidateError(f"{label} reason codes are invalid")
    if reasons != sorted(set(reasons)):
        raise CandidateError(f"{label} reason codes must be sorted and unique")
    if (verdict == "ALLOW") != (not reasons):
        raise CandidateError(f"{label} verdict and reason codes are inconsistent")
    return str(verdict), list(reasons)


def _partial_system(value: object, label: str) -> dict[str, str]:
    system = _exact_object(value, _PARTIAL_SYSTEM_KEYS, label)
    return {
        "name": _identifier(system["name"], f"{label}.name"),
        "version": _version(system["version"], f"{label}.version"),
        "implementation_digest": _digest(
            system["implementation_digest"],
            f"{label}.implementation_digest",
        ),
    }


def _system(value: object, label: str) -> dict[str, str]:
    system = _exact_object(value, _SYSTEM_KEYS, label)
    return {
        **_partial_system(
            {field: system[field] for field in _PARTIAL_SYSTEM_KEYS},
            label,
        ),
        "config_digest": _digest(
            system["config_digest"],
            f"{label}.config_digest",
        ),
    }


def _version(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(
            unicodedata.category(character).startswith("C")
            for character in value
        )
    ):
        raise CandidateError(f"{label} is not canonical")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise CandidateError(f"{label} is not a canonical identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise CandidateError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _exact_object(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise CandidateError(f"{label} has missing or unknown fields")
    return value


def _read_canonical_document(
    cas: CAS,
    digest: str,
    label: str,
) -> dict[str, Any]:
    try:
        raw = cas.read(_digest(digest, f"{label} digest"), max_bytes=_MAX_DOCUMENT_BYTES)
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (CASError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CandidateError(f"cannot read {label}: {exc}") from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise CandidateError(f"{label} must be a canonical JSON object")
    return document


def _put_json(cas: CAS, document: object) -> str:
    raw = canonical_json(document)
    try:
        return cas.put(BytesIO(raw), max_bytes=len(raw))
    except CASError as exc:
        raise CandidateError(f"cannot retain candidate evidence: {exc}") from exc


def _existing_directory(
    value: str | os.PathLike[str],
    label: str,
) -> Path:
    try:
        path = Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise CandidateError(f"cannot resolve {label}: {exc}") from exc
    if not path.is_dir():
        raise CandidateError(f"{label} must be a directory")
    return path


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise CandidateError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_nonfinite(value: str) -> None:
    raise CandidateError(f"non-finite JSON number: {value}")
