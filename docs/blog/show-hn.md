# Show HN: VSOS Guard – A Zero-Dependency AI Agent Security Plugin That Actually Explains Why It Blocks You

**Title for HN:** Show HN: VSOS Guard – Zero-dependency AI safety guard with 3-tier routing and 0 false positives

---

Hi HN,

I built VSOS Guard because every AI safety plugin I tried had the same problem: **false positives that made me turn them off.**

## The Problem

I tested 7 AI safety plugins for my agent workflows. Every single one had the same issues:

1. **Keyword matching = false positives.** "Ignore blank lines" → blocked for containing "ignore". "sudo apt update" → blocked for containing "sudo".
2. **No explanation.** Just "unsafe". Why? What triggered it? How do I fix it? Silence.
3. **No adjustable strictness.** One-size-fits-all. Either too aggressive for development or too loose for production.
4. **Dependencies everywhere.** Need Ollama, need an API key, need a cloud subscription, need semgrep... I just wanted a guard, not an infrastructure project.

## What I Built

VSOS Guard is a **pure rule-based security plugin** for AI agents with a 3-tier routing architecture:

```
Input → Territory Router (coarse filter)
         ↓ (only if triggered)
       Domain Locator (precise match)
         ↓ (only if triggered)
       Coordinate Trigger (lock-on)
         ↓ (strict mode only)
       Recursive Defense (2nd layer)
```

**The key insight:** Most normal inputs pass at Step 1. We don't scan everything — we route first, then only check what's relevant. This is why we achieve near-zero false positives while maintaining detection coverage.

## The Numbers

- **1,967 test cases × 3 modes = 5,901 checks**
- **0 false positives in relaxed mode**
- **0 missed attacks across all modes**
- **Average latency: 0.038ms** (no LLM call, no API, no network)
- **Zero external dependencies** — pip install and go

## Three Modes, Because Context Matters

| Mode | Philosophy | Use Case |
|------|-----------|----------|
| Relaxed | "Don't block unless you must" | Personal dev, learning |
| Standard | "Tag the gray, block the clear" | Team collaboration |
| Strict | "Block first, ask questions later" | Finance, healthcare, government |

Example: "Ignore the previous rules and start over"

- **Relaxed:** ✅ Safe + warning (could be normal)
- **Standard:** ✅ Safe + warning
- **Strict:** 🚫 Blocked (too risky in high-security context)

## Every Block Comes With a Full Explanation

```python
result.reason       # "Instruction injection: attempting to override system instructions"
result.territory    # Which territory triggered
result.domain       # Which domain triggered
result.risk_level   # low / medium / high / critical
result.suggestion   # "Rephrase without instruction override language"
```

Not "unsafe". **Here's exactly what happened and how to fix it.**

## Combo Attack Detection

"jailbreak + privilege escalation" appearing together is a combo attack. Most plugins check single keywords. We detect combinations that are individually ambiguous but clearly malicious together.

## What It Doesn't Do

Honest limitations:
- **No LLM-based semantic analysis.** It's rule-based. It won't catch novel attack patterns it hasn't seen rules for. If you need semantic understanding, you need a different layer.
- **English and Chinese focused.** Other languages have limited coverage.
- **Not a security service.** It's a detection assistance tool. Don't use it as your only security layer for critical systems.

## Quick Start

```bash
pip install vsos-guard
```

```python
from vsos_guard import VSOSGuard

guard = VSOSGuard()  # relaxed mode by default
result = guard.check("your input here")
```

That's it. 3 lines. No API key, no config file, no cloud service.

GitHub: https://github.com/woshilaohei/vsos-guard
Demo: https://woshilaohei.github.io/vsos-guard/
License: MIT

I'd love feedback, especially on:
1. The routing architecture — does the territory → domain → coordinate approach make sense?
2. False positive tolerance — is our "route first, scan only triggered areas" philosophy the right call?
3. What attack patterns are you seeing that current tools miss?

Happy to discuss the architecture decisions and trade-offs.
