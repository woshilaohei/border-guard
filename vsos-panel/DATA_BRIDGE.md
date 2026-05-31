# VSOS Guard v0.6.0 - Data Bridge

behavior.py → JSON文件 → Tauri前端

## 架构

```
AI Agent (Python)
  └─ BehaviorMonitor
       └─ 自动写入 ~/.vsos_guard/status.json
            └─ Tauri前端 每2秒读取
```

## 为什么选文件桥接

1. **零依赖**：不需要HTTP服务器，不需要额外端口
2. **零崩溃**：文件读写是最稳定的IPC方式
3. **跨进程**：Python和Tauri是两个独立进程，文件是天然桥梁
4. **调试友好**：直接看JSON文件就知道数据对不对

## 文件格式

`~/.vsos_guard/status.json` 由 behavior.py 的 `BehaviorMonitor.save_status()` 写入：

```json
{
  "today": {
    "sessions_today": 3,
    "total_tokens": 45000,
    "total_cost_cny": 2.35,
    "total_tool_calls": 12,
    "total_searches": 5,
    "total_blocked": 1
  },
  "current_session": {
    "session_id": "20260601_020000",
    "task": "VSOS Guard Development",
    "duration": "2.3min",
    "tools": [...],
    "searches": [...],
    "files": [...],
    "tokens": {...},
    "security": {...}
  }
}
```

## Tauri命令

Rust侧 `read_status` 命令读取JSON文件，前端 `invoke('read_status')` 调用。

## Demo模式

无status.json文件时，前端自动进入Demo模式，使用内置样例数据，面板顶部显示"DEMO"标签。
