# Changelog

All notable changes to VSOS Guard are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2] - 2026-05-31

### Added
- **Encoding variant detection**: base64, unicode, hex, rot13, and Leet Speak bypass detection — catches obfuscated payloads before agents see them
- **Confidence 3-tier output**: `critical` (block) / `warning` (alert) / `safe` (pass) — fine-grained risk communication
- **GuardLogger audit trail**: record every check result + reason + timestamp, compliance-ready logging
- **EncodingDetector**: standalone encoding analysis module, reusable for pipeline integration
- **normalize_text utility**: unified text normalization API for external consumption

### Changed
- Python 3.8 compatibility: `list[T]` → `List` from typing

### Testing
- 39 test suites, all passing, 0 false positives

## [0.5.1] - 2026-05-30

### Added
- **Causal chain architecture upgrade**: Signal variable territory + causal chain, fixed territory router blind spots
- Multi-step attack chain hard interception (Tempest 97% success rate attack)
- Physical harm comprehensive expansion: poison-making / gun-making / arson / toxic substances
- Identity forgery expansion: developer mode / authorized penetration testing / red team exercise
- Jailbreak injection expansion: no longer restricted / safety protocols suspended / DAN new variants
- Normalization engine expansion: encoding function detection

### Testing
- 1967 test cases × 3 modes = 5,901 checks, 0 false positives, 0 missed attacks

## [0.4.0] - 2026-05-30

### Added
- Normalization engine full upgrade: 15+ separator handling
- Identity forgery rules massively expanded: 60+ Chinese & English keywords
- Jailbreak injection rules expanded: prior variants / escape constraints
- Combo attack rules expanded: 8 combo patterns

### Fixed
- Meta-boundary fix: `rm -rf /` exact match, prevents false blocking
- Context whitelist fix: injection attack principles goes to gray zone

### Performance
- Latency: avg=0.038ms, P99=0.069ms, QPS>26000

## [0.3.0] - 2026-05-30

### Added
- Text normalization: remove spaces / zero-width characters
- Context whitelist: discussing security ≠ executing attacks
- Expanded attack rules: Chinese-English mixed / variants / bypass verification

### Testing
- 155 cases × 3 modes = 412 checks, 0 false positives, 0 missed attacks

## [0.2.0] - 2026-05-30

### Added
- Initial three-tier mode (relaxed / standard / strict)
- Territory routing + whitelist + gray zone tagging + combo attack detection
- Block with suggestions

## [0.1.0] - 2026-05-29

### Added
- Initial release
- Basic prompt injection detection
- Keyword-based routing

[0.5.2]: https://github.com/woshilaohei/vsos-guard/releases/tag/v0.5.2
[0.5.1]: https://github.com/woshilaohei/vsos-guard/releases/tag/v0.5.1
[0.4.0]: https://github.com/woshilaohei/vsos-guard/releases/tag/v0.4.0
[0.3.0]: https://github.com/woshilaohei/vsos-guard/releases/tag/v0.3.0
[0.2.0]: https://github.com/woshilaohei/vsos-guard/releases/tag/v0.2.0
[0.1.0]: https://github.com/woshilaohei/vsos-guard/releases/tag/v0.1.0
