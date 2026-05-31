# -*- coding: utf-8 -*-
"""
VSOS Guard v0.6.0 - Behavior Monitor & Cost Tracker

只总结不解读，只压缩信息量，不猜意图。
行为记录+算力消耗=工作总统计

核心原则：
- 只记录事实：调了什么工具、搜了什么关键词、读了什么文件
- 不解读意图：不说"AI为了XXX"
- 算力统计：token数、耗时、费用
- 裁决权=人权，我们只当眼睛不当脑子
"""

import time
import json
import os
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict


# ============================================================
# 状态文件路径（跨平台）
# ============================================================
def _get_status_dir() -> str:
    """获取状态文件目录，跨平台"""
    if os.name == 'nt':  # Windows
        base = os.environ.get('USERPROFILE', os.path.expanduser('~'))
    else:  # macOS/Linux
        base = os.path.expanduser('~')
    return os.path.join(base, '.vsos_guard')


def _get_status_file() -> str:
    """获取状态文件路径"""
    return os.path.join(_get_status_dir(), 'status.json')


# ============================================================
# 价格表（每1K tokens，USD）- 2026年5月主流模型
# ============================================================
MODEL_PRICING = {
    # OpenAI
    "gpt-4o": {"input": 0.0025, "output": 0.01},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    # Anthropic
    "claude-3.5-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    # Google
    "gemini-1.5-pro": {"input": 0.0035, "output": 0.0105},
    "gemini-1.5-flash": {"input": 0.00035, "output": 0.00105},
    # DeepSeek
    "deepseek-chat": {"input": 0.00014, "output": 0.00028},
    "deepseek-reasoner": {"input": 0.00055, "output": 0.00219},
    # Default
    "default": {"input": 0.002, "output": 0.008},
}

# 人民币汇率
CNY_RATE = 7.25


@dataclass
class ToolCall:
    """单次工具调用记录"""
    tool_name: str
    params: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    duration_ms: int = 0
    result_summary: str = ""  # 只记结果摘要，不记完整内容

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class SearchRecord:
    """搜索记录——关键词是灵魂"""
    keywords: str  # 搜索关键词
    engine: str = ""  # 搜索引擎
    results_count: int = 0  # 找到多少结果
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class FileOperation:
    """文件操作记录"""
    operation: str  # read/write/edit/create
    file_name: str  # 文件名（不含路径，隐私保护）
    size_bytes: int = 0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class TokenUsage:
    """Token消耗记录"""
    model: str = "default"
    input_tokens: int = 0
    output_tokens: int = 0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def cost_usd(self) -> float:
        """计算本次花费（USD）"""
        pricing = MODEL_PRICING.get(self.model, MODEL_PRICING["default"])
        input_cost = (self.input_tokens / 1000) * pricing["input"]
        output_cost = (self.output_tokens / 1000) * pricing["output"]
        return input_cost + output_cost

    def cost_cny(self) -> float:
        """计算本次花费（人民币）"""
        return self.cost_usd() * CNY_RATE


class BehaviorSession:
    """
    单次工作会话的行为记录
    
    一个session = AI从接任务到交付结果的一次完整工作
    """

    def __init__(self, task_name: str = ""):
        self.task_name = task_name
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.start_time = time.time()
        self.end_time: Optional[float] = None

        # 行为记录
        self.tool_calls: List[ToolCall] = []
        self.searches: List[SearchRecord] = []
        self.file_ops: List[FileOperation] = []

        # 算力记录
        self.token_usages: List[TokenUsage] = []

        # 安全记录（和GuardLogger联动）
        self.security_events: List[Dict] = []

    def finish(self):
        """结束会话"""
        self.end_time = time.time()

    @property
    def duration_seconds(self) -> float:
        """会话耗时（秒）"""
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def duration_display(self) -> str:
        """人可读的耗时"""
        secs = self.duration_seconds
        if secs < 60:
            return f"{secs:.0f}秒"
        mins = secs / 60
        if mins < 60:
            return f"{mins:.1f}分钟"
        hours = mins / 60
        return f"{hours:.1f}小时"

    # === 记录方法 ===

    def record_tool_call(self, tool_name: str, params: Dict[str, Any] = None,
                         duration_ms: int = 0, result_summary: str = ""):
        """记录工具调用"""
        self.tool_calls.append(ToolCall(
            tool_name=tool_name,
            params=params or {},
            duration_ms=duration_ms,
            result_summary=result_summary[:100],  # 限制摘要长度
        ))

    def record_search(self, keywords: str, engine: str = "", results_count: int = 0):
        """记录搜索——关键词是灵魂"""
        self.searches.append(SearchRecord(
            keywords=keywords,
            engine=engine,
            results_count=results_count,
        ))

    def record_file_op(self, operation: str, file_name: str, size_bytes: int = 0):
        """记录文件操作"""
        self.file_ops.append(FileOperation(
            operation=operation,
            file_name=file_name.split("/")[-1],  # 只保留文件名，隐私保护
            size_bytes=size_bytes,
        ))

    def record_tokens(self, model: str, input_tokens: int, output_tokens: int):
        """记录Token消耗"""
        self.token_usages.append(TokenUsage(
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        ))

    def record_security_event(self, event: Dict):
        """记录安全事件（从GuardLogger联动）"""
        self.security_events.append(event)

    # === 统计方法 ===

    @property
    def total_input_tokens(self) -> int:
        return sum(t.input_tokens for t in self.token_usages)

    @property
    def total_output_tokens(self) -> int:
        return sum(t.output_tokens for t in self.token_usages)

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens

    @property
    def total_cost_cny(self) -> float:
        return sum(t.cost_cny() for t in self.token_usages)

    @property
    def total_cost_usd(self) -> float:
        return sum(t.cost_usd() for t in self.token_usages)

    def cost_by_model(self) -> Dict[str, float]:
        """按模型分费用"""
        costs = defaultdict(float)
        for t in self.token_usages:
            costs[t.model] += t.cost_cny()
        return dict(costs)

    def most_expensive_operation(self) -> Optional[str]:
        """最贵的操作"""
        if not self.token_usages:
            return None
        most = max(self.token_usages, key=lambda t: t.cost_cny())
        return f"{most.model} (¥{most.cost_cny():.2f})"

    # === 输出方法 ===

    def summary(self) -> str:
        """
        工作总统计——只总结不解读
        
        核心输出格式：行为+算力一锅出
        关键词是灵魂：工具名+参数、文件名、搜索关键词必须细化
        """
        lines = []
        lines.append("📊 本次工作总结")
        lines.append("━" * 25)

        # 工具调用
        if self.tool_calls:
            tool_counts = defaultdict(int)
            for tc in self.tool_calls:
                tool_counts[tc.tool_name] += 1
            lines.append(f"🔧 工具调用（{len(self.tool_calls)}次）")
            for name, count in tool_counts.items():
                # 找出该工具的参数关键词
                param_keys = set()
                for tc in self.tool_calls:
                    if tc.tool_name == name and tc.params:
                        for k in tc.params:
                            param_keys.add(str(k))
                param_str = f" 参数: {','.join(list(param_keys)[:3])}" if param_keys else ""
                lines.append(f"  • {name} ×{count}{param_str}")

        # 搜索记录——关键词是灵魂
        if self.searches:
            lines.append(f"🔍 网页搜索（{len(self.searches)}次）")
            for s in self.searches[-5:]:  # 最多显示5条
                result_str = f" → {s.results_count}个结果" if s.results_count else ""
                lines.append(f'  • "{s.keywords}"{result_str}')

        # 文件操作
        if self.file_ops:
            lines.append(f"📄 文件操作（{len(self.file_ops)}次）")
            file_counts = defaultdict(lambda: defaultdict(int))
            for f in self.file_ops:
                file_counts[f.operation][f.file_name] += 1
            for op, files in file_counts.items():
                op_label = {"read": "读取", "write": "写入", "edit": "编辑", "create": "创建"}.get(op, op)
                for fname, count in files.items():
                    lines.append(f"  • {op_label}: {fname}" + (f" ×{count}" if count > 1 else ""))

        # 安全事件
        if self.security_events:
            blocked = sum(1 for e in self.security_events if not e.get("safe", True))
            if blocked > 0:
                lines.append(f"🛡️ 安全拦截（{blocked}次）")

        # 分隔
        lines.append("━" * 25)

        # 算力统计
        if self.token_usages:
            lines.append(f"⏱ 耗时: {self.duration_display}")
            lines.append(f"💰 Token: 输入{self.total_input_tokens:,} / 输出{self.total_output_tokens:,}")
            lines.append(f"💰 本次花费: ¥{self.total_cost_cny:.2f}")
            if self.most_expensive_operation():
                lines.append(f"💰 最贵操作: {self.most_expensive_operation()}")
        else:
            lines.append(f"⏱ 耗时: {self.duration_display}")

        lines.append("━" * 25)

        return "\n".join(lines)

    def to_json(self) -> str:
        """导出完整数据（给前端浮窗用）"""
        data = {
            "session_id": self.session_id,
            "task_name": self.task_name,
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "duration_seconds": self.duration_seconds,
            "duration_display": self.duration_display,
            "tool_calls": [asdict(tc) for tc in self.tool_calls],
            "searches": [asdict(s) for s in self.searches],
            "file_ops": [asdict(f) for f in self.file_ops],
            "token_usage": {
                "total_input": self.total_input_tokens,
                "total_output": self.total_output_tokens,
                "total_tokens": self.total_tokens,
                "cost_cny": round(self.total_cost_cny, 4),
                "cost_usd": round(self.total_cost_usd, 4),
                "by_model": {k: round(v, 4) for k, v in self.cost_by_model().items()},
            },
            "security_events": self.security_events,
            "tool_call_count": len(self.tool_calls),
            "search_count": len(self.searches),
            "file_op_count": len(self.file_ops),
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def to_frontend_data(self) -> dict:
        """给前端浮窗的精简数据"""
        return {
            "session_id": self.session_id,
            "task": self.task_name,
            "duration": self.duration_display,
            "tools": [{"name": tc.tool_name, "params": tc.params, "time": tc.timestamp}
                      for tc in self.tool_calls],
            "searches": [{"keywords": s.keywords, "results": s.results_count}
                         for s in self.searches],
            "files": [{"op": f.operation, "name": f.file_name}
                      for f in self.file_ops],
            "tokens": {
                "input": self.total_input_tokens,
                "output": self.total_output_tokens,
                "cost_cny": round(self.total_cost_cny, 2),
            },
            "security": {
                "blocked": sum(1 for e in self.security_events if not e.get("safe", True)),
                "warnings": sum(1 for e in self.security_events
                               if e.get("safe", True) and e.get("confidence") == "warning"),
            },
        }


class BehaviorMonitor:
    """
    行为监控器——全局管理
    
    管理多个session，提供：
    - 当前session的实时数据
    - 历史session查询
    - 给前端浮窗的数据接口
    """

    def __init__(self, auto_save: bool = True):
        self._current_session: Optional[BehaviorSession] = None
        self._history: List[BehaviorSession] = []
        self._all_security_events: List[Dict] = []
        self._auto_save = auto_save
        # 首次初始化时创建目录和文件
        if auto_save:
            self._ensure_status_dir()
            self.save_status()

    def start_session(self, task_name: str = "") -> BehaviorSession:
        """开始新工作会话"""
        if self._current_session and not self._current_session.end_time:
            self._current_session.finish()
            self._history.append(self._current_session)

        self._current_session = BehaviorSession(task_name=task_name)
        return self._current_session

    def finish_session(self) -> Optional[BehaviorSession]:
        """结束当前会话"""
        if self._current_session:
            self._current_session.finish()
            self._history.append(self._current_session)
            finished = self._current_session
            self._current_session = None
            return finished
        return None

    @property
    def current(self) -> Optional[BehaviorSession]:
        return self._current_session

    def get_today_stats(self) -> dict:
        """今日总统计"""
        today = datetime.now().strftime("%Y%m%d")
        today_sessions = [
            s for s in self._history
            if s.session_id.startswith(today)
        ]
        return {
            "sessions_today": len(today_sessions),
            "total_tokens": sum(s.total_tokens for s in today_sessions),
            "total_cost_cny": sum(s.total_cost_cny for s in today_sessions),
            "total_tool_calls": sum(len(s.tool_calls) for s in today_sessions),
            "total_searches": sum(len(s.searches) for s in today_sessions),
            "total_blocked": sum(
                sum(1 for e in s.security_events if not e.get("safe", True))
                for s in today_sessions
            ),
        }

    def get_frontend_data(self) -> dict:
        """给前端浮窗的完整数据"""
        data = {
            "today": self.get_today_stats(),
            "current_session": None,
        }
        if self._current_session:
            data["current_session"] = self._current_session.to_frontend_data()
        return data

    # === 文件桥接：自动保存状态到JSON ===

    def _ensure_status_dir(self):
        """确保状态文件目录存在"""
        status_dir = _get_status_dir()
        os.makedirs(status_dir, exist_ok=True)

    def save_status(self) -> str:
        """
        保存当前状态到JSON文件（给Tauri前端读取）
        
        Returns:
            保存的文件路径
        """
        status_file = _get_status_file()
        data = self.get_frontend_data()
        # 加上时间戳，让前端知道数据是否新鲜
        data["_meta"] = {
            "version": "0.6.0",
            "saved_at": datetime.now().isoformat(),
            "status_file": status_file,
        }
        try:
            with open(status_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except (OSError, PermissionError):
            pass  # 静默失败，不阻塞主流程
        return status_file

    def _auto_save_if_enabled(self):
        """自动保存（内部调用，每个记录方法执行后触发）"""
        if self._auto_save:
            self.save_status()

    # === 便捷记录方法（代理到current session + 自动保存）===

    def log_tool_call(self, tool_name: str, params: Dict[str, Any] = None,
                      duration_ms: int = 0, result_summary: str = ""):
        """记录工具调用并自动保存"""
        if self._current_session:
            self._current_session.record_tool_call(tool_name, params, duration_ms, result_summary)
            self._auto_save_if_enabled()

    def log_search(self, keywords: str, engine: str = "", results_count: int = 0):
        """记录搜索并自动保存"""
        if self._current_session:
            self._current_session.record_search(keywords, engine, results_count)
            self._auto_save_if_enabled()

    def log_file_op(self, operation: str, file_name: str, size_bytes: int = 0):
        """记录文件操作并自动保存"""
        if self._current_session:
            self._current_session.record_file_op(operation, file_name, size_bytes)
            self._auto_save_if_enabled()

    def log_tokens(self, model: str, input_tokens: int, output_tokens: int):
        """记录Token消耗并自动保存"""
        if self._current_session:
            self._current_session.record_tokens(model, input_tokens, output_tokens)
            self._auto_save_if_enabled()

    def log_security_event(self, event: Dict):
        """记录安全事件并自动保存"""
        if self._current_session:
            self._current_session.record_security_event(event)
            self._auto_save_if_enabled()
