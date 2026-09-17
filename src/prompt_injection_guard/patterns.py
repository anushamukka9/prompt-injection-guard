"""Built-in detection patterns for prompt-injection-guard.

Patterns are organized by attack category. Each pattern carries a numeric
weight that feeds the severity scorer (see scoring.py). Weights are
conservative on purpose: a security scanner should rather over-flag than
miss a real injection attempt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Pattern weight guide:
#   10 - weak signal, only suspicious in combination with other signals
#   25 - medium signal
#   40-50 - strong signal, typical of real injection attempts
#   55-60 - very strong signal, rarely appears in benign text


@dataclass(frozen=True)
class Pattern:
    """A single regex-based detection rule."""

    id: str
    category: str
    regex: str
    weight: int
    description: str
    flags: int = re.IGNORECASE

    def compile(self) -> "re.Pattern[str]":
        return re.compile(self.regex, self.flags)


BUILTIN_PATTERNS: tuple[Pattern, ...] = (
    # ------------------------------------------------------------------
    # instruction-override: attempts to cancel or replace prior instructions
    # ------------------------------------------------------------------
    Pattern(
        "override-ignore-previous",
        "instruction-override",
        r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+"
        r"(instructions?|prompts?|directives?|rules?)\b",
        50,
        "Direct instruction to ignore prior/system instructions.",
    ),
    Pattern(
        "override-disregard",
        "instruction-override",
        r"\bdisregard\s+(all\s+)?(previous|prior|above|earlier)\s+"
        r"(instructions?|prompts?|directives?|rules?)\b",
        50,
        "Direct instruction to disregard prior/system instructions.",
    ),
    Pattern(
        "override-forget-everything",
        "instruction-override",
        r"\bforget\s+everything\b",
        45,
        "Instruction to forget everything previously established.",
    ),
    Pattern(
        "override-new-instructions",
        "instruction-override",
        r"(?m)^\s*(new|updated|revised)\s+instructions?\s*:",
        50,
        "Line claiming to introduce new/updated instructions.",
    ),
    Pattern(
        "override-mode-switch",
        "instruction-override",
        r"\b(system|developer|admin|god|jailbreak)\s+mode\b",
        45,
        "Claim of switching into a privileged or unrestricted mode.",
    ),
    Pattern(
        "override-bypass-safety",
        "instruction-override",
        r"\bbypass\s+(all\s+)?(safety|content|security)\s+"
        r"(filters?|restrictions|policies|guidelines)?\b",
        55,
        "Instruction to bypass safety filters or content policies.",
    ),
    Pattern(
        "override-ignore-confidentiality",
        "instruction-override",
        r"\bignore\s+(all\s+)?(confidentiality|safety)\s+"
        r"(rules|policies|guidelines|restrictions)?\b",
        55,
        "Instruction to ignore confidentiality or safety rules.",
    ),
    # ------------------------------------------------------------------
    # roleplay-jailbreak: persona / role-play tricks to evade alignment
    # ------------------------------------------------------------------
    Pattern(
        "jailbreak-pretend",
        "roleplay-jailbreak",
        r"\bpretend\s+(you\s+are|to\s+be)\b",
        50,
        "Role-play framing ('pretend you are ...').",
    ),
    Pattern(
        "jailbreak-roleplay-as",
        "roleplay-jailbreak",
        r"\brole[\s-]?play\s+as\b",
        45,
        "Explicit role-play instruction.",
    ),
    Pattern(
        "jailbreak-you-are-now",
        "roleplay-jailbreak",
        r"\byou\s+are\s+now\b",
        50,
        "Persona reassignment ('you are now ...').",
    ),
    Pattern(
        "jailbreak-no-restrictions",
        "roleplay-jailbreak",
        r"\bno\s+(restrictions|limits|rules|filters|safety)\s+apply\b",
        40,
        "Claim that no restrictions apply.",
    ),
    Pattern(
        "jailbreak-without-restrictions",
        "roleplay-jailbreak",
        r"\bwithout\s+(any\s+)?(restrictions|limits|rules|moral\s+constraints)\b",
        40,
        "Request to act without restrictions.",
    ),
    Pattern(
        "jailbreak-dan",
        "roleplay-jailbreak",
        r"\bDAN\b",
        45,
        "DAN ('Do Anything Now') jailbreak persona reference.",
        flags=0,  # case-sensitive: avoids matching the name "Dan"
    ),
    Pattern(
        "jailbreak-do-anything-now",
        "roleplay-jailbreak",
        r"\bdo\s+anything\s+now\b",
        40,
        "Literal 'do anything now' jailbreak phrasing.",
    ),
    Pattern(
        "jailbreak-jailbreak-word",
        "roleplay-jailbreak",
        r"\bjailbreak\b",
        45,
        "Explicit mention of jailbreaking the model.",
    ),
    # ------------------------------------------------------------------
    # delimiter-escape: fake structural boundaries to smuggle instructions
    # ------------------------------------------------------------------
    Pattern(
        "delimiter-xml-tags",
        "delimiter-escape",
        r"</?(system|assistant|developer|instruction|instructions)[^>\n]*>",
        55,
        "Fake system/assistant XML-style tags.",
    ),
    Pattern(
        "delimiter-chatml",
        "delimiter-escape",
        r"<\|im_(start|end)\|>",
        60,
        "Raw ChatML control tokens (<|im_start|> / <|im_end|>).",
    ),
    Pattern(
        "delimiter-end-block",
        "delimiter-escape",
        r"---\s*(END|START)\s+(OF\s+)?(SYSTEM|PROMPT|INSTRUCTIONS?)\b",
        55,
        "Fake '--- END OF SYSTEM ---' style boundary markers.",
    ),
    Pattern(
        "delimiter-bracket-tag",
        "delimiter-escape",
        r"(?m)^\s*\[(SYSTEM|INSTRUCTION|DEVELOPER)\]",
        55,
        "Fake [SYSTEM] / [INSTRUCTION] line tags.",
    ),
    Pattern(
        "delimiter-reminder-persona",
        "delimiter-escape",
        r"(?m)^\s*(reminder|note)\s*:\s*you\s+are\b",
        40,
        "Injected persona via a fake 'Reminder: you are ...' line.",
    ),
    # ------------------------------------------------------------------
    # exfiltration-probe: attempts to extract system prompt / training data
    # ------------------------------------------------------------------
    Pattern(
        "exfil-reveal-prompt",
        "exfiltration-probe",
        r"\breveal\s+(your\s+)?(system\s+)?(prompt|instructions?)\b",
        55,
        "Request to reveal the system prompt or instructions.",
    ),
    Pattern(
        "exfil-what-are-instructions",
        "exfiltration-probe",
        r"\bwhat\s+(are|were)\s+your\s+(initial|original|system|hidden)\s+"
        r"(instructions?|prompts?|rules?)\b",
        50,
        "Question probing for the original system instructions.",
    ),
    Pattern(
        "exfil-repeat-above",
        "exfiltration-probe",
        r"\b(repeat|print|output|display|show)\s+(the\s+)?"
        r"(above|previous|earlier)\s+(text|prompt|instructions?|message)\b",
        45,
        "Request to repeat/print text from above the user message.",
    ),
    Pattern(
        "exfil-training-data",
        "exfiltration-probe",
        r"\b(reveal|disclose|leak|dump|output|print)\s+[^\n]{0,60}?"
        r"\b(training\s+data|model\s+weights)\b",
        60,
        "Request to disclose training data or model weights.",
    ),
    # ------------------------------------------------------------------
    # encoded-payload: ask the model to decode attacker-controlled content
    # ------------------------------------------------------------------
    Pattern(
        "encoded-decode-and-follow",
        "encoded-payload",
        r"\b(decode|decrypt|deobfuscate|unscramble)\s+(the\s+)?"
        r"(following|this|below|attached)\b",
        45,
        "Instruction to decode attacker-supplied content and act on it.",
    ),
    # ------------------------------------------------------------------
    # obfuscation: tricks to hide the payload from naive filters
    # ------------------------------------------------------------------
    Pattern(
        "obfuscation-zero-width",
        "obfuscation",
        r"[\u200b\u200c\u200d\ufeff]{2,}",
        30,
        "Zero-width / invisible Unicode characters used to hide text.",
        flags=0,
    ),
)

# Heuristic (non-regex) checks implemented in scanner.py. Listed here so
# `pig patterns` can report the full detection surface.
HEURISTICS: tuple[dict[str, object], ...] = (
    {
        "id": "encoded-base64-payload",
        "category": "encoded-payload",
        "weight": 45,
        "description": (
            "Base64-looking block that decodes to printable text containing "
            "injection patterns; the decoded content is re-scanned."
        ),
    },
    {
        "id": "encoded-hex-payload",
        "category": "encoded-payload",
        "weight": 45,
        "description": (
            "Hex-looking block that decodes to printable text containing "
            "injection patterns; the decoded content is re-scanned."
        ),
    },
)
