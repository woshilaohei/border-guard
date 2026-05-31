# -*- coding: utf-8 -*-
"""
VSOS Guard Community Edition v0.6.0

The best security plugin for the community, bar none.

v0.6.0 changes:
- Behavior monitoring: record AI actions (tool calls, searches, file operations)
- Cost tracking: token usage + USD/CNY cost calculation
- Work summary: behavior + cost in one shot, only summarize, never interpret
- GuardLogger ↔ BehaviorSession auto-link: security events auto-flow to behavior session
- VSOSGuard convenience methods: start_session/finish_session/session_summary/session_report/today_stats
- Frontend-ready: to_frontend_data() for Tauri floating panel

v0.5.2 changes:
- Encoding variant detection: base64/unicode/hex/rot13/Leet Speak bypass detection
- Confidence 3-tier output: critical(block)/warning(alert)/safe(pass)
- GuardLogger: record every check result + reason
- Integration hooks: on_block/on_warn callbacks for easy framework integration
- Enhanced context awareness: whitelist covers more normal dev/ops scenarios
"""

from vsos_guard.guard import (
    VSOSGuard, GuardMode, CheckResult, Territory, Domain,
    Confidence, GuardLogger, EncodingDetector, normalize_text,
)
from vsos_guard.behavior import (
    BehaviorSession, BehaviorMonitor, TokenUsage,
    ToolCall, SearchRecord, FileOperation,
)

__version__ = "0.6.0"
__all__ = [
    "VSOSGuard", "GuardMode", "CheckResult", "Territory", "Domain",
    "Confidence", "GuardLogger", "EncodingDetector", "normalize_text",
    "BehaviorSession", "BehaviorMonitor", "TokenUsage",
    "ToolCall", "SearchRecord", "FileOperation",
]
