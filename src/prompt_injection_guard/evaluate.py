"""Corpus evaluation: measure the scanner against a labeled JSONL corpus.

Corpus format: one JSON object per line with

    {"text": "...", "label": "malicious" | "benign", "categories": [...]}

``categories`` lists the attack categories a malicious row exercises (used for
per-category recall). A row is "flagged" when the scan produces any finding;
"blocked" additionally requires the severity to reach ``fail_on``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .scanner import PromptInjectionScanner


def load_corpus(path: str | Path) -> List[Dict[str, Any]]:
    """Load and validate a labeled corpus file."""
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict) or "text" not in row or "label" not in row:
                raise ValueError(
                    f"{path}:{lineno}: row needs 'text' and 'label' keys"
                )
            if row["label"] not in ("malicious", "benign"):
                raise ValueError(
                    f"{path}:{lineno}: label must be 'malicious' or 'benign'"
                )
            rows.append(row)
    if not rows:
        raise ValueError(f"{path}: no corpus rows found")
    return rows


def evaluate_corpus(
    path: str | Path,
    fail_on: str = "medium",
    scanner: PromptInjectionScanner | None = None,
) -> Dict[str, Any]:
    """Run the scanner over every corpus row and compute detection metrics.

    Returns a plain-dict report with overall malicious recall, benign clean
    rate, per-category recall, and the false-positive / false-negative rows.
    """
    rows = load_corpus(path)
    scanner = scanner or PromptInjectionScanner(fail_on=fail_on)

    per_category: Dict[str, Dict[str, int]] = {}
    false_positives: List[Dict[str, Any]] = []
    false_negatives: List[Dict[str, Any]] = []
    n_malicious = n_benign = 0
    caught = blocked = 0
    clean = 0

    for i, row in enumerate(rows):
        result = scanner.scan(row["text"], source_name=f"row-{i}")
        flagged = bool(result.findings)
        if row["label"] == "malicious":
            n_malicious += 1
            for category in row.get("categories", []):
                bucket = per_category.setdefault(category, {"caught": 0, "total": 0})
                bucket["total"] += 1
                if flagged:
                    bucket["caught"] += 1
            if flagged:
                caught += 1
                if result.blocked:
                    blocked += 1
            else:
                false_negatives.append(
                    {
                        "text": row["text"],
                        "categories": row.get("categories", []),
                        "note": row.get("note", ""),
                    }
                )
        else:
            n_benign += 1
            if flagged:
                false_positives.append(
                    {
                        "text": row["text"],
                        "severity": result.severity,
                        "pattern_ids": sorted({f.pattern_id for f in result.findings}),
                        "note": row.get("note", ""),
                    }
                )
            else:
                clean += 1

    categories = {
        name: {
            "recall": round(b["caught"] / b["total"], 4),
            "caught": b["caught"],
            "total": b["total"],
        }
        for name, b in sorted(per_category.items())
    }
    return {
        "rows": len(rows),
        "malicious": {
            "total": n_malicious,
            "recall": round(caught / n_malicious, 4) if n_malicious else 0.0,
            "caught": caught,
            "blocked": blocked,
            "missed": n_malicious - caught,
        },
        "benign": {
            "total": n_benign,
            "clean_rate": round(clean / n_benign, 4) if n_benign else 0.0,
            "clean": clean,
            "false_positives": len(false_positives),
        },
        "per_category_recall": categories,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


def format_text_report(report: Dict[str, Any], corpus_path: str | Path) -> str:
    """Render an evaluation report as human-readable text."""
    lines = [f"Corpus evaluation: {corpus_path}", ""]
    mal, ben = report["malicious"], report["benign"]
    lines.append(
        f"rows: {report['rows']} "
        f"({mal['total']} malicious, {ben['total']} benign)"
    )
    lines.append(
        f"malicious recall: {mal['recall']:.3f} "
        f"({mal['caught']}/{mal['total']} flagged, {mal['blocked']} blocked)"
    )
    lines.append(
        f"benign clean rate: {ben['clean_rate']:.3f} "
        f"({ben['clean']}/{ben['total']} clean, "
        f"{ben['false_positives']} false positives)"
    )
    lines.append("")
    lines.append("per-category recall:")
    for name, stats in report["per_category_recall"].items():
        lines.append(
            f"  {name:22s} {stats['recall']:.3f} "
            f"({stats['caught']}/{stats['total']})"
        )
    if report["false_positives"]:
        lines.append("")
        lines.append(f"false positives ({len(report['false_positives'])}):")
        for fp in report["false_positives"]:
            lines.append(f"  [{fp['severity']}] {'/'.join(fp['pattern_ids'])}")
            lines.append(f"    {fp['text'][:100]}")
            if fp["note"]:
                lines.append(f"    note: {fp['note'][:100]}")
    if report["false_negatives"]:
        lines.append("")
        lines.append(f"false negatives ({len(report['false_negatives'])}):")
        for fn in report["false_negatives"]:
            lines.append(f"  [{'/'.join(fn['categories'])}] {fn['text'][:100]}")
    return "\n".join(lines)
