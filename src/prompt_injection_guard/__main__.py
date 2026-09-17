"""Run the prompt-injection-guard CLI: python -m prompt_injection_guard scan ..."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
