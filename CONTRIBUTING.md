# 贡献指南

感谢你对 VSOS Guard 的关注！

## 如何贡献

### 报告问题
- 在 [GitHub Issues](https://github.com/vsos-guard/vsos-guard/issues) 提交
- 包含：输入内容、期望结果、实际结果、使用的模式

### 提交代码
1. Fork 本仓库
2. 创建特性分支：`git checkout -b feature/你的特性`
3. 提交改动：`git commit -m '添加某某特性'`
4. 推送分支：`git push origin feature/你的特性`
5. 发起 Pull Request

### 测试要求
- 所有改动必须通过现有测试：`PYTHONPATH=. python tests/test_v100.py`
- 新增功能必须附带测试用例
- 目标：0误拦 + 0漏拦

### 核心原则
- **能不拦就不拦，该拦的绝对不漏**
- 纯规则引擎，不用LLM做检测
- 延迟 < 1ms
- 零依赖

## 许可证

贡献的代码遵循 MIT License。
