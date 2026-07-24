"""Control-plane audit of frozen inert benchmark corpus metadata and similarity."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Sequence
import unicodedata

from .benchmark import BenchmarkError, load_suite_for_run
from .cas import CAS, CASError


_TOKEN = re.compile(r"[^\W_]+(?:['’-][^\W_]+)*", re.UNICODE)
_FRONTMATTER = re.compile(r"\A---\s*\n.*?\n---\s*(?:\n|\Z)", re.DOTALL)
_MAX_TEXT_BYTES = 16 * 1024 * 1024


class CorpusAuditError(ValueError):
    """The frozen corpus cannot be audited as a trustworthy control-plane input."""


def audit_suite(
    suite_path: str | Path,
    *,
    near_duplicate_threshold: float = 0.8,
    shingle_size: int = 5,
) -> dict[str, Any]:
    """Validate *suite_path* and report cross-split near-duplicate warnings."""

    threshold = _threshold(near_duplicate_threshold)
    if isinstance(shingle_size, bool) or not isinstance(shingle_size, int):
        raise CorpusAuditError("shingle_size must be an integer")
    if not 2 <= shingle_size <= 20:
        raise CorpusAuditError("shingle_size must be between 2 and 20")

    suite_file = Path(suite_path).expanduser().resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="aragorn-corpus-audit-") as temporary:
        cas = CAS(Path(temporary) / "cas")
        loaded = load_suite_for_run(suite_file, cas)
        references: dict[str, str] = {}
        shingles: dict[str, frozenset[tuple[str, ...]]] = {}
        for case_id, case in loaded["cases"].items():
            reference = case["source"]["reference"]
            lineage = case["lineage"]
            previous = references.setdefault(reference, lineage)
            if previous != lineage:
                raise CorpusAuditError(
                    f"source reference {reference!r} crosses lineages "
                    f"{previous!r} and {lineage!r}"
                )
            text = _case_text(loaded["manifests"][case_id], cas)
            tokens = _normalized_tokens(text)
            shingles[case_id] = _shingles(tokens, shingle_size)

    warnings = []
    case_ids = sorted(loaded["cases"])
    for index, first_id in enumerate(case_ids):
        first = loaded["cases"][first_id]
        for second_id in case_ids[index + 1 :]:
            second = loaded["cases"][second_id]
            if first["split"] == second["split"]:
                continue
            similarity = _jaccard(shingles[first_id], shingles[second_id])
            if similarity >= threshold:
                warnings.append(
                    {
                        "first_case_id": first_id,
                        "second_case_id": second_id,
                        "similarity": round(similarity, 6),
                    }
                )

    splits = []
    for split in sorted({case["split"] for case in loaded["cases"].values()}):
        split_cases = [
            case for case in loaded["cases"].values() if case["split"] == split
        ]
        splits.append(
            {
                "split": split,
                "cases": len(split_cases),
                "benign": sum(case["class"] == "benign" for case in split_cases),
                "adversarial": sum(
                    case["class"] == "adversarial" for case in split_cases
                ),
            }
        )
    return {
        "schema": "aragorn/corpus-audit/v1",
        "suite_digest": loaded["digest"],
        "cases": len(loaded["cases"]),
        "source_references_lineage_bound": True,
        "splits": splits,
        "shingle_size": shingle_size,
        "near_duplicate_threshold": threshold,
        "cross_split_near_duplicates": warnings,
    }


def _case_text(manifest: dict[str, Any], cas: CAS) -> str:
    chunks = []
    total = 0
    for entry in manifest["files"]:
        raw = cas.read(entry["digest"], max_bytes=_MAX_TEXT_BYTES)
        total += len(raw)
        if total > _MAX_TEXT_BYTES:
            raise CorpusAuditError("one case exceeds the corpus-audit text budget")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:  # suite validation should catch this first
            raise CorpusAuditError("fixture text is not UTF-8") from exc
        if entry["path"] == "SKILL.md":
            text = _FRONTMATTER.sub("", text, count=1)
        chunks.append(text)
    return "\n".join(chunks)


def _normalized_tokens(text: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = "".join(
        character
        for character in normalized
        if unicodedata.category(character) != "Cf"
    ).casefold()
    return tuple(match.group(0) for match in _TOKEN.finditer(normalized))


def _shingles(
    tokens: tuple[str, ...], size: int
) -> frozenset[tuple[str, ...]]:
    if len(tokens) < size:
        return frozenset({tokens}) if tokens else frozenset()
    return frozenset(
        tuple(tokens[index : index + size])
        for index in range(len(tokens) - size + 1)
    )


def _jaccard(
    first: frozenset[tuple[str, ...]], second: frozenset[tuple[str, ...]]
) -> float:
    if not first and not second:
        return 1.0
    union = first | second
    return len(first & second) / len(union) if union else 0.0


def _threshold(value: float) -> float:
    if isinstance(value, bool):
        raise CorpusAuditError("near_duplicate_threshold must be finite in [0, 1]")
    try:
        threshold = float(value)
    except (TypeError, ValueError) as exc:
        raise CorpusAuditError(
            "near_duplicate_threshold must be finite in [0, 1]"
        ) from exc
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise CorpusAuditError("near_duplicate_threshold must be finite in [0, 1]")
    return threshold


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aragorn.corpus_audit",
        description="Audit a frozen inert corpus on the private control plane.",
    )
    parser.add_argument("suite", type=Path)
    parser.add_argument("--near-duplicate-threshold", type=float, default=0.8)
    parser.add_argument("--shingle-size", type=int, default=5)
    try:
        arguments = parser.parse_args(argv)
        report = audit_suite(
            arguments.suite,
            near_duplicate_threshold=arguments.near_duplicate_threshold,
            shingle_size=arguments.shingle_size,
        )
    except (BenchmarkError, CASError, CorpusAuditError, OSError, ValueError) as exc:
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
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
