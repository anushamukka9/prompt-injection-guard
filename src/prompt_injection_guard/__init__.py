"""prompt-injection-guard: heuristic scanner for prompt-injection attacks."""

from .patterns import BUILTIN_PATTERNS, HEURISTICS, Pattern
from .scanner import (
    Finding,
    PromptInjectionScanner,
    ScanResult,
    load_allowlist,
    load_blocklist,
    scan_text,
)
from .scoring import SEVERITY_ORDER, is_blocked, severity_for_score, severity_rank

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "BUILTIN_PATTERNS",
    "HEURISTICS",
    "Pattern",
    "Finding",
    "PromptInjectionScanner",
    "ScanResult",
    "load_allowlist",
    "load_blocklist",
    "scan_text",
    "SEVERITY_ORDER",
    "is_blocked",
    "severity_for_score",
    "severity_rank",
]
