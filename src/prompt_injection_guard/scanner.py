"""Core scanning engine for prompt-injection-guard."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from .patterns import BUILTIN_PATTERNS, HEURISTICS, Pattern
from .scoring import is_blocked, severity_for_score

# A run of base64 alphabet characters long enough that it is very unlikely
# to be an ordinary English word (>= 24 chars, with optional padding).
# Note: the trailing boundary is a lookahead, not \b, because a match can
# end with '=' padding (a non-word character, where \b would fail).
_BASE64_RE = re.compile(
    r"\b(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    r"(?![A-Za-z0-9+/=])"
)
# A run of hex digits long enough to hold a meaningful payload (>= 8 bytes).
_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")

_SNIPPET_LEN = 120


@dataclass
class Finding:
    """One detected injection signal."""

    pattern_id: str
    category: str
    description: str
    weight: int
    match: str  # snippet of the matched text (truncated)
    start: int  # offset of the match in the scanned text
    end: int
    source: str = "regex"  # "regex" | "base64" | "hex" | "blocklist"

    def to_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "category": self.category,
            "description": self.description,
            "weight": self.weight,
            "match": self.match,
            "start": self.start,
            "end": self.end,
            "source": self.source,
        }

    def severity_hint(self) -> str:
        """Rough severity band implied by this finding's weight alone."""
        return severity_for_score(self.weight, self.weight)


@dataclass
class ScanResult:
    """The outcome of scanning one piece of text."""

    source_name: str
    text_length: int
    findings: list[Finding] = field(default_factory=list)
    fail_on: str = "medium"

    @property
    def total_score(self) -> int:
        return sum(f.weight for f in self.findings)

    @property
    def max_weight(self) -> int:
        return max((f.weight for f in self.findings), default=0)

    @property
    def severity(self) -> str:
        return severity_for_score(self.total_score, self.max_weight)

    @property
    def blocked(self) -> bool:
        return is_blocked(self.severity, self.fail_on)

    def to_dict(self) -> dict:
        return {
            "source": self.source_name,
            "text_length": self.text_length,
            "total_score": self.total_score,
            "severity": self.severity,
            "blocked": self.blocked,
            "fail_on": self.fail_on,
            "findings": [f.to_dict() for f in self.findings],
        }


def _snippet(text: str, start: int, end: int) -> str:
    match = text[start:end]
    if len(match) > _SNIPPET_LEN:
        match = match[: _SNIPPET_LEN - 3] + "..."
    # Keep one-line snippets so reports stay readable.
    return " ".join(match.split())


def _looks_like_text(data: bytes) -> str | None:
    """Return decoded text if bytes look like printable prose, else None."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 8 or not text.strip():
        return None
    alnum_ratio = sum(c.isalnum() for c in text) / len(text)
    if alnum_ratio < 0.5:
        return None
    if not all(c.isprintable() or c.isspace() for c in text):
        return None
    return text


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


class PromptInjectionScanner:
    """Scans text for prompt-injection attack patterns.

    Parameters
    ----------
    extra_patterns:
        Additional :class:`Pattern` objects (e.g. loaded from a blocklist
        file) scanned alongside the built-ins.
    allowlist:
        Regex strings. Any finding whose match overlaps an allowlist match
        is suppressed — use for known-safe phrases in your own prompts.
    fail_on:
        Severity at or above which :attr:`ScanResult.blocked` is True.
    """

    def __init__(
        self,
        extra_patterns: Sequence[Pattern] = (),
        allowlist: Sequence[str] = (),
        fail_on: str = "medium",
    ) -> None:
        self.patterns: list[Pattern] = list(BUILTIN_PATTERNS) + list(extra_patterns)
        self._compiled: list[tuple[Pattern, "re.Pattern[str]", str]] = [
            (p, p.compile(), "blocklist" if p in extra_patterns else "regex")
            for p in self.patterns
        ]
        self.allowlist = [re.compile(rx, re.IGNORECASE) for rx in allowlist]
        self.fail_on = fail_on

    # -- public API --------------------------------------------------------

    def scan(self, text: str, source_name: str = "<text>") -> ScanResult:
        findings: list[Finding] = []
        findings.extend(self._scan_regexes(text))
        findings.extend(self._scan_encoded(text))
        findings = self._apply_allowlist(text, findings)
        findings.sort(key=lambda f: (f.start, -f.weight))
        return ScanResult(
            source_name=source_name,
            text_length=len(text),
            findings=findings,
            fail_on=self.fail_on,
        )

    def scan_file(self, path: str | Path) -> ScanResult:
        path = Path(path)
        text = path.read_text(encoding="utf-8", errors="replace")
        return self.scan(text, source_name=str(path))

    # -- internals ---------------------------------------------------------

    def _scan_regexes(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, compiled, source in self._compiled:
            for match in compiled.finditer(text):
                findings.append(
                    Finding(
                        pattern_id=pattern.id,
                        category=pattern.category,
                        description=pattern.description,
                        weight=pattern.weight,
                        match=_snippet(text, match.start(), match.end()),
                        start=match.start(),
                        end=match.end(),
                        source=source,
                    )
                )
        return findings

    def _scan_encoded(self, text: str) -> list[Finding]:
        """Detect base64/hex payloads, decode them, and re-scan the content."""
        findings: list[Finding] = []
        for candidate in _BASE64_RE.finditer(text):
            blob = candidate.group(0)
            try:
                decoded = base64.b64decode(blob, validate=True)
            except (binascii.Error, ValueError):
                continue
            plain = _looks_like_text(decoded)
            if plain is None:
                continue
            findings.extend(
                self._encoded_findings(
                    blob, plain, candidate.start(), candidate.end(), "base64"
                )
            )
        for candidate in _HEX_RE.finditer(text):
            blob = candidate.group(0)
            try:
                decoded = bytes.fromhex(blob)
            except ValueError:
                continue
            plain = _looks_like_text(decoded)
            if plain is None:
                continue
            findings.extend(
                self._encoded_findings(
                    blob, plain, candidate.start(), candidate.end(), "hex"
                )
            )
        return findings

    def _encoded_findings(
        self, blob: str, plain: str, start: int, end: int, kind: str
    ) -> list[Finding]:
        """Re-scan decoded content; flag it if it contains attack patterns."""
        inner = self._scan_regexes(plain)
        if not inner:
            return []
        strongest = max(inner, key=lambda f: f.weight)
        heuristic = next(h for h in HEURISTICS if h["id"] == f"encoded-{kind}-payload")
        preview = blob if len(blob) <= 48 else blob[:45] + "..."
        return [
            Finding(
                pattern_id=str(heuristic["id"]),
                category=str(heuristic["category"]),
                description=(
                    f"{heuristic['description']} "
                    f"Decoded preview: {plain[:80]!r} "
                    f"(strongest inner signal: {strongest.pattern_id})."
                ),
                weight=int(heuristic["weight"]),
                match=f"{kind}:{preview}",
                start=start,
                end=end,
                source=kind,
            )
        ]

    def _apply_allowlist(
        self, text: str, findings: list[Finding]
    ) -> list[Finding]:
        if not self.allowlist:
            return findings
        safe_spans = [
            (m.start(), m.end())
            for rx in self.allowlist
            for m in rx.finditer(text)
        ]
        return [
            f
            for f in findings
            if not any(_overlaps(f.start, f.end, s, e) for s, e in safe_spans)
        ]


def load_blocklist(path: str | Path) -> list[Pattern]:
    """Load extra detection patterns from a JSON blocklist file.

    The file must contain a list of objects with ``id``, ``regex`` and
    ``weight`` keys; ``category`` and ``description`` are optional.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("blocklist file must contain a JSON list")
    patterns: list[Pattern] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"blocklist entry {i} must be an object")
        try:
            rx, weight = entry["regex"], int(entry["weight"])
        except KeyError as exc:
            raise ValueError(f"blocklist entry {i} missing key: {exc}") from exc
        patterns.append(
            Pattern(
                id=str(entry.get("id", f"blocklist-{i}")),
                category=str(entry.get("category", "blocklist")),
                regex=rx,
                weight=weight,
                description=str(entry.get("description", "Custom blocklist pattern.")),
            )
        )
    # Validate that every regex compiles before returning.
    for pattern in patterns:
        try:
            pattern.compile()
        except re.error as exc:
            raise ValueError(f"blocklist pattern {pattern.id!r}: {exc}") from exc
    return patterns


def load_allowlist(path: str | Path) -> list[str]:
    """Load allowlist regexes from a text file (one per line, ``#`` comments)."""
    regexes: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            regexes.append(line)
    for rx in regexes:
        try:
            re.compile(rx, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"allowlist regex {rx!r}: {exc}") from exc
    return regexes


def scan_text(text: str, **kwargs) -> ScanResult:
    """Convenience wrapper: scan a string with a default scanner."""
    return PromptInjectionScanner(**kwargs).scan(text)
