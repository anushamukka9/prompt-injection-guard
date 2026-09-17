"""Command-line interface for prompt-injection-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .patterns import BUILTIN_PATTERNS, HEURISTICS
from .scanner import (
    PromptInjectionScanner,
    ScanResult,
    load_allowlist,
    load_blocklist,
)
from .scoring import SEVERITY_ORDER

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_BLOCKED = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pig",
        description="Scan text for prompt-injection attack patterns.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan files or stdin for injection patterns.")
    scan.add_argument(
        "paths",
        nargs="*",
        help="Files to scan. Use '-' or omit paths to read from stdin.",
    )
    scan.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Report format (default: text).",
    )
    scan.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER[1:],
        default="medium",
        help="Exit with code 2 when a result reaches this severity (default: medium).",
    )
    scan.add_argument(
        "--allowlist",
        metavar="FILE",
        help="Text file with one allowlist regex per line ('#' comments allowed).",
    )
    scan.add_argument(
        "--blocklist",
        metavar="FILE",
        help="JSON file with extra detection patterns.",
    )
    scan.add_argument(
        "--max-findings",
        type=int,
        default=25,
        help="Max findings shown per file in text output (default: 25).",
    )

    sub.add_parser("patterns", help="List all built-in detection patterns as JSON.")
    return parser


def _read_inputs(paths: list[str]) -> list[tuple[str, str]]:
    """Return (source_name, text) pairs for the given paths/stdin."""
    if not paths or paths == ["-"]:
        return [("<stdin>", sys.stdin.read())]
    inputs: list[tuple[str, str]] = []
    for raw in paths:
        if raw == "-":
            inputs.append(("<stdin>", sys.stdin.read()))
            continue
        path = Path(raw)
        if not path.is_file():
            raise FileNotFoundError(f"no such file: {raw}")
        inputs.append((str(path), path.read_text(encoding="utf-8", errors="replace")))
    return inputs


def _format_text(result: ScanResult, max_findings: int) -> str:
    lines = [
        f"== {result.source_name} ==",
        f"severity: {result.severity}   score: {result.total_score}   "
        f"findings: {len(result.findings)}   verdict: "
        f"{'BLOCK' if result.blocked else 'pass'}",
    ]
    for finding in result.findings[:max_findings]:
        lines.append(
            f"  [{finding.severity_hint()}] {finding.pattern_id} "
            f"({finding.category}, weight {finding.weight})"
        )
        lines.append(f"    @{finding.start}: {finding.match}")
        lines.append(f"    {finding.description}")
    hidden = len(result.findings) - max_findings
    if hidden > 0:
        lines.append(f"  ... {hidden} more finding(s) not shown")
    return "\n".join(lines)


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        allowlist = load_allowlist(args.allowlist) if args.allowlist else []
        extra = load_blocklist(args.blocklist) if args.blocklist else []
    except (OSError, ValueError) as exc:
        print(f"pig: error loading rules: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        inputs = _read_inputs(args.paths)
    except (OSError, FileNotFoundError) as exc:
        print(f"pig: {exc}", file=sys.stderr)
        return EXIT_ERROR

    scanner = PromptInjectionScanner(
        extra_patterns=extra, allowlist=allowlist, fail_on=args.fail_on
    )
    results = [scanner.scan(text, source_name=name) for name, text in inputs]

    if args.format == "json":
        report = {
            "tool": f"pig {__version__}",
            "files": [r.to_dict() for r in results],
            "summary": {
                "files_scanned": len(results),
                "files_blocked": sum(r.blocked for r in results),
                "total_findings": sum(len(r.findings) for r in results),
            },
        }
        print(json.dumps(report, indent=2))
    else:
        for result in results:
            print(_format_text(result, args.max_findings))
            print()

    return EXIT_BLOCKED if any(r.blocked for r in results) else EXIT_OK


def _cmd_patterns() -> int:
    payload = [
        {
            "id": p.id,
            "category": p.category,
            "regex": p.regex,
            "weight": p.weight,
            "description": p.description,
            "source": "builtin",
        }
        for p in BUILTIN_PATTERNS
    ] + [
        {
            "id": str(h["id"]),
            "category": str(h["category"]),
            "regex": None,
            "weight": int(h["weight"]),
            "description": str(h["description"]),
            "source": "heuristic",
        }
        for h in HEURISTICS
    ]
    print(json.dumps(payload, indent=2))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "patterns":
        return _cmd_patterns()
    parser.error("unknown command")
    return EXIT_ERROR  # unreachable


if __name__ == "__main__":
    sys.exit(main())
