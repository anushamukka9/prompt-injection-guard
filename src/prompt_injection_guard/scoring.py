"""Severity scoring for prompt-injection-guard.

The total score is the sum of the weights of all findings in a scan.
Severity is derived from the total score, with a floor based on the single
strongest finding so that one blatant attack pattern can never be diluted
into a low severity by an otherwise clean text.
"""

from __future__ import annotations

SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")

# Total-score thresholds for each severity band.
_SCORE_BANDS = (
    (100, "critical"),
    (50, "high"),
    (20, "medium"),
    (1, "low"),
)

# A single finding this strong guarantees at least the mapped severity,
# regardless of the total score.
_MAX_WEIGHT_FLOOR = (
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
)


def severity_for_score(total_score: int, max_weight: int = 0) -> str:
    """Map a scan's total score (and strongest finding) to a severity band."""
    if total_score <= 0:
        return "none"
    severity = "low"
    for threshold, band in _SCORE_BANDS:
        if total_score >= threshold:
            severity = band
            break
    floor = "low"
    for weight_threshold, band in _MAX_WEIGHT_FLOOR:
        if max_weight >= weight_threshold:
            floor = band
            break
    if SEVERITY_ORDER.index(floor) > SEVERITY_ORDER.index(severity):
        return floor
    return severity


def severity_rank(severity: str) -> int:
    """Numeric rank of a severity band (higher = more severe)."""
    if severity not in SEVERITY_ORDER:
        raise ValueError(f"unknown severity: {severity!r}")
    return SEVERITY_ORDER.index(severity)


def is_blocked(severity: str, fail_on: str) -> bool:
    """True when a result of `severity` should fail a `--fail-on` threshold."""
    return severity_rank(severity) >= severity_rank(fail_on)
