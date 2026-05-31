# AGENTS.md

> Instructions for AI agents (Codex, Claude, Copilot, etc.) working with this repository.

## Project Overview

VSOS Guard is a **zero-dependency Python security plugin** for AI agents. It detects prompt injections, jailbreaks, malicious commands, and other threats at the input layer using a pure rule engine (no LLM calls for detection).

## Repository Structure

```
vsos_guard/           # Main package
├── guard.py          # Core detection engine (VSOSGuard class)
├── __init__.py       # Package init, version, public API exports
├── integrations/     # Framework adapters (LangChain, OpenAI SDK)
├── owasp.py          # OWASP ASI mapping
└── policy.py         # YAML policy loader

tests/                # Test suites
├── test_v100.py      # Core test suite (100+ cases)
├── test_v1000.py     # Extended test suite (1000+ cases)
├── test_v2000.py     # Full regression suite (2000+ cases)
└── ...

examples/             # Usage examples
└── integration.py    # Integration examples

docs/                 # Documentation and assets
```

## Key Constraints

### MUST
- **Zero dependencies**: Never add external package imports in `vsos_guard/`.
- **Python 3.8+ compatible**: Use `from typing import List, Optional` instead of `list[str]`.
- **All tests must pass**: Run `PYTHONPATH=. python tests/test_v100.py` after any change.
- **False positive priority**: 0 false positives > 0 missed attacks.

### MUST NOT
- **Do not add network calls**: VSOS Guard never phones home.
- **Do not use LLM for detection**: All detection is rule-based and deterministic.
- **Do not modify meta-boundary rules** without explicit approval.
- **Do not expose internal architecture details** in code comments or docs.

## Making Changes

1. Read the relevant source file first
2. Make minimal, focused changes
3. Run tests: `PYTHONPATH=. python tests/test_v100.py`
4. If adding features, add test cases
5. Ensure all three modes still work correctly

## Testing

```bash
PYTHONPATH=. python -c "from vsos_guard import VSOSGuard; print(VSOSGuard().check('hello').safe)"
PYTHONPATH=. python tests/test_v100.py
PYTHONPATH=. python tests/test_v2000.py
```

## Version

Current version is defined in `vsos_guard/__init__.py` as `__version__`. Update this and `pyproject.toml` together when bumping version.
