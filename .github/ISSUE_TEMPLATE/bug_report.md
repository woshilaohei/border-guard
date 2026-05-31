---
name: Bug Report
about: Report a bug in VSOS Guard
title: "[BUG] "
labels: bug
assignees: ""
---

## Describe the Bug

A clear description of what the bug is.

## Input That Triggered the Bug

```python
from vsos_guard import VSOSGuard

guard = VSOSGuard(mode="standard")
result = guard.check("YOUR_INPUT_HERE")
```

**Input text:**

**Expected behavior:**

**Actual behavior:**

## Mode Used

- [ ] Relaxed
- [ ] Standard
- [ ] Strict

## Environment

- VSOS Guard version:
- Python version:
- OS:

## Is This a False Positive or False Negative?

- [ ] False positive (legitimate input was blocked)
- [ ] False negative (attack was not caught)
- [ ] Other

## Additional Context

Any other context, logs, or screenshots.
