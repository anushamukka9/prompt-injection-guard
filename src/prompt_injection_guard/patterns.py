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
    # role-confusion: attacker claims a privileged role or speaks with
    # borrowed authority (the model provider, the system, the developer)
    # ------------------------------------------------------------------
    Pattern(
        "roleclaim-admin",
        "role-confusion",
        r"\b(i\s+am|i'm)\s+(the\s+)?system\s+administrator\b",
        50,
        "Claims to be the system administrator.",
    ),
    Pattern(
        "roleclaim-developer",
        "role-confusion",
        r"\b(i\s+am|i'm|acting\s+as)\s+(your\s+)?developer\b",
        45,
        "Claims to be the developer of the model.",
    ),
    Pattern(
        "roleclaim-authority",
        "role-confusion",
        r"\bon\s+behalf\s+of\s+(openai|anthropic|google|meta|microsoft)\b",
        55,
        "Claims to act on behalf of a model provider.",
    ),
    Pattern(
        "roleclaim-official-directive",
        "role-confusion",
        r"\bthis\s+is\s+an?\s+(official|urgent|priority)\s+"
        r"(message|directive|order|instruction)\s+from\s+(the\s+)?"
        r"(system|developers?|administrators?|openai|anthropic)\b",
        55,
        "Fake official directive claimed to come from the system or developers.",
    ),
    Pattern(
        "roleclaim-speaks-as-system",
        "role-confusion",
        r"\bspeaking\s+as\s+(the\s+)?(system|developer|administrator)\b",
        50,
        "Speaker claims to be the system, developer, or administrator.",
    ),
    Pattern(
        "roleclaim-obey-me",
        "role-confusion",
        r"\byou\s+(were\s+built|are\s+programmed|must)\s+to\s+obey\s+me\b",
        45,
        "Asserts the model is obligated to obey the speaker.",
    ),
    # ------------------------------------------------------------------
    # instruction-smuggling: hide the instruction and forbid mentioning it
    # ------------------------------------------------------------------
    Pattern(
        "smuggle-hide-instruction",
        "instruction-smuggling",
        r"\b(do\s+not|don't|never)\s+(mention|reveal|tell|disclose)\b"
        r".{0,60}\b(this|these?)\s+instructions?\b",
        50,
        "Forbids mentioning the injected instruction(s).",
    ),
    Pattern(
        "smuggle-keep-secret",
        "instruction-smuggling",
        r"\bkeep\s+this\s+(between\s+us|secret|confidential|to\s+yourself)\b",
        40,
        "Asks to keep the injected instruction secret.",
    ),
    Pattern(
        "smuggle-hidden-instructions",
        "instruction-smuggling",
        r"\bfollow\b.{0,50}\b(hidden|embedded|secret)\s+instructions?\b"
        r"|\b(hidden|embedded|secret)\s+instructions?\b.{0,50}\bfollow\b",
        50,
        "Directs the model to follow hidden or embedded instructions.",
    ),
    Pattern(
        "smuggle-act-normal",
        "instruction-smuggling",
        r"\bact\s+(as\s+if|like)\s+(nothing|this\s+never)\s+(happened|changed)\b",
        40,
        "Instructs the model to hide that anything changed.",
    ),
    Pattern(
        "smuggle-quietly",
        "instruction-smuggling",
        r"\b(do\s+this|comply)\s+"
        r"(quietly|silently|without\s+(telling|mentioning|alerting))\b",
        40,
        "Instructs the model to comply without alerting anyone.",
    ),
    # ------------------------------------------------------------------
    # encoding-tricks: dodge keyword filters with leetspeak, spacing,
    # ciphers, or lookalike Unicode
    # ------------------------------------------------------------------
    Pattern(
        "encoding-leet-ignore",
        "encoding-tricks",
        r"\b(?=[a-z0-9!@$ ]{5,}[10!@$349])"
        r"[i1!][g9][n][o0][r][e3]\s+(all\s+)?"
        r"[p][r][e3][v][i1!][o0][u][s5$]\s+"
        r"[i1!][n][s5$][t][r][u][c][t1!][i1!][o0][n][s5$]\b",
        45,
        "Leetspeak-obfuscated 'ignore previous instructions' (e.g. 1gn0r3). "
        "The lookahead requires at least one leet substitution so plain "
        "English does not match.",
    ),
    Pattern(
        "encoding-leet-bypass",
        "encoding-tricks",
        r"\b(?=[a-z0-9!@$]*[10!@$349])[b8][y][p][a4@][s5$][s5$]\b",
        40,
        "Leetspeak-obfuscated 'bypass'.",
    ),
    Pattern(
        "encoding-spaced-letters",
        "encoding-tricks",
        r"\b(?:[a-zA-Z]\s){4,}[a-zA-Z]\b",
        30,
        "Letters spaced out to evade keyword filters (e.g. 'i g n o r e').",
    ),
    Pattern(
        "encoding-rot13-request",
        "encoding-tricks",
        r"\brot-?13\b.{0,60}\b(decode|decrypt|translate)\b"
        r"|\b(decode|decrypt|translate)\b.{0,60}\brot-?13\b",
        45,
        "Asks the model to decode ROT13 content and act on it.",
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
    {
        "id": "obfuscation-unicode-confusable",
        "category": "encoding-tricks",
        "weight": 35,
        "description": (
            "Fullwidth characters or Cyrillic lookalikes mixed into Latin "
            "text to dodge keyword filters (e.g. fullwidth 'ignore' or "
            "Cyrillic 'o' inside an English word)."
        ),
    },
)
