# Frequently Asked Questions

## General

### What is VSOS Guard?

VSOS Guard is a zero-dependency Python security plugin for AI agents. It detects prompt injections, jailbreaks, malicious commands, and other threats at the input layer — before they reach your AI model or agent.

### How is VSOS Guard different from other security tools?

| | VSOS Guard | Others |
|---|---|---|
| **Dependencies** | Zero — `pip install` and go | Require external services, LLM APIs, or heavy frameworks |
| **False positives** | Near-zero, 3-tier adjustable | High false positive rates |
| **Approach** | Pure rule engine, deterministic | Often use LLMs to detect LLM attacks (fragile, slow) |
| **Latency** | ~0.04ms average | 3-10ms+ |
| **Positioning** | Entry-point defense (prompt input) | Execution-point defense (tool calls, shell, files) |

**We're complementary, not competing.** Use VSOS Guard at the front door, use nah/HOL Guard/MS AGT at the back door.

### What does "zero dependencies" actually mean?

No external packages, no network calls, no API keys, no LLM calls for detection. The only thing you need is Python 3.8+. This eliminates supply chain risk — a security tool that itself has no attack surface.

### Is VSOS Guard free?

Yes, fully open source under the MIT License.

## Usage

### Which mode should I use?

- **Relaxed** (default): Personal projects, development, learning. Near-zero false positives.
- **Standard**: Team collaboration, production. Blocks attacks + tags suspicious patterns.
- **Strict**: High-security environments (finance, healthcare, government). Full interception.

### Can I customize the rules?

Yes — custom blacklist, custom whitelist, callbacks, and audit logging. YAML policy configuration is coming soon.

### Does it work with non-English inputs?

Yes. VSOS Guard handles Chinese, English, and mixed-language inputs. It also detects encoding-based attacks across languages.

## Technical

### How does the detection pipeline work?

Input → Territory Router → Domain Location → Coordinate Trigger → (Recursive Defense) → Meta-Boundary

Most normal inputs pass at Step 1 with minimal computation.

### What is "combo attack detection"?

Combo attacks combine multiple attack vectors in a single input (e.g., "jailbreak + privilege escalation"). VSOS Guard detects when multiple attack signals appear together and escalates the response.

### What is "encoding variant detection"?

Attackers encode payloads — base64, unicode, hex, rot13, Leet Speak. VSOS Guard normalizes and detects these before the agent ever sees the raw input.

### What about latency?

Average: **0.038ms** per check. P99: 0.069ms. QPS > 26,000.

## Troubleshooting

### VSOS Guard is blocking my legitimate input!

1. Check `result.reason` and `result.suggestion`
2. Try **relaxed mode**
3. Add a **whitelist** entry
4. [Report it](https://github.com/woshilaohei/vsos-guard/issues/new?template=bug_report.md) — we take false positives very seriously

### VSOS Guard is not catching an attack!

1. Try **standard** or **strict** mode
2. [Report it](https://github.com/woshilaohei/vsos-guard/issues/new?template=bug_report.md)

## Community & Support

- [GitHub Issues](https://github.com/woshilaohei/vsos-guard/issues) — bugs and features
- [Email](mailto:xiaohei-vsos@coze.email) — security reports and collaboration
- See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute
