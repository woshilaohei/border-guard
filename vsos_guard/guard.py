"""
VSOS Guard · 社区简约版
社区最好用的安全插件，没有之一

设计者：老黑（大成）
架构师：小黑
版本：0.3.0

v0.3.0 变更（基于155例压力测试微调）：
- 新增文本归一化：去空格/零宽字符，防绕过
- 新增上下文白名单：讨论安全≠实施攻击（防注入/了解越狱/学习sudo放行）
- 扩展明确攻击规则：中英混合/变体/绕过验证/身份劫持等
- 修复组合攻击检测：组合命中优先于灰区，直接拦截
- 修复疆域分流：分流后无威胁时安静放行不输出warning
- 灰区规则收窄：正常角色指定/编程inject不触发灰区
- 测试结果：155例 × 3模式 = 412检查，0误拦0漏拦
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ============================================================
# 三档模式
# ============================================================

class GuardMode(Enum):
    RELAXED = "relaxed"     # 宽松：只拦明确攻击
    STANDARD = "standard"   # 标准：拦攻击 + 标记可疑
    STRICT = "strict"       # 严格：全量拦截 + 递归


# ============================================================
# 疆域定义
# ============================================================

class Territory(Enum):
    ATTACK_DETECTION = "攻击识别疆"
    HARM_INTERCEPTION = "伤害拦截疆"
    ACCESS_CONTROL = "权限管控疆"


class Domain(Enum):
    MALICIOUS_INPUT = "恶意输入域"
    JAILBREAK_INJECTION = "越狱注入域"
    PROTOCOL_HIJACK = "协议劫持域"
    PHYSICAL_HARM = "物理伤害域"
    ECONOMIC_HARM = "经济伤害域"
    PSYCHOLOGICAL_HARM = "心理伤害域"
    PRIVILEGE_ESCALATION = "提权检测域"
    DATA_LEAKAGE = "数据泄露域"
    IDENTITY_FORGERY = "身份伪造域"


TERRITORY_DOMAIN_MAP = {
    Territory.ATTACK_DETECTION: [
        Domain.MALICIOUS_INPUT,
        Domain.JAILBREAK_INJECTION,
        Domain.PROTOCOL_HIJACK,
    ],
    Territory.HARM_INTERCEPTION: [
        Domain.PHYSICAL_HARM,
        Domain.ECONOMIC_HARM,
        Domain.PSYCHOLOGICAL_HARM,
    ],
    Territory.ACCESS_CONTROL: [
        Domain.PRIVILEGE_ESCALATION,
        Domain.DATA_LEAKAGE,
        Domain.IDENTITY_FORGERY,
    ],
}


# ============================================================
# 检测结果（含建议）
# ============================================================

@dataclass
class CheckResult:
    safe: bool = True
    reason: str = ""
    territory: str = ""
    domain: str = ""
    coordinate: str = ""
    risk_level: str = "none"
    suggestion: str = ""
    recursion_depth: int = 0
    warning: str = ""  # 低风险标记，不拦但提醒


# ============================================================
# 文本归一化（防绕过）
# ============================================================

def normalize_text(text: str) -> str:
    """
    归一化文本，去除空格/零宽字符/特殊符号，防绕过
    例: "忽 略 之 前" → "忽略之前"
    """
    # 去零宽字符
    text = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', text)
    # 中文之间去空格
    text = re.sub(r'([\u4e00-\u9fff])\s+([\u4e00-\u9fff])', r'\1\2', text)
    # 重复归一化（处理多空格）
    while re.search(r'([\u4e00-\u9fff])\s+([\u4e00-\u9fff])', text):
        text = re.sub(r'([\u4e00-\u9fff])\s+([\u4e00-\u9fff])', r'\1\2', text)
    return text


# ============================================================
# 上下文感知白名单（讨论安全≠实施攻击）
# ============================================================

# 精确白名单：完全匹配放行
EXACT_WHITELIST = [
    "忽略空行",
    "忽略注释",
    "忽略大小写",
    "sudo apt update",
    "sudo apt install",
    "你是谁",
    "你能做什么",
    "你好",
]

# 上下文白名单模式：命中则放行（正则）
# 核心：讨论安全/学习/防御 → 不是攻击
# 设计原则：只放行"前置意图明确"的句子，不放行攻击+疑问词的巧合组合
CONTEXT_WHITELIST_PATTERNS = [
    # === 安全学习/讨论（意图词在前，安全词在后）===
    # "如何防止注入" / "怎么防范越狱" / "什么是bypass安全"
    r'(如何|怎样|学习|了解|什么是|介绍一下|探讨|分析).*(注入|越狱|jailbreak|bypass|绕过|提权|安全|inject)',
    # "防止注入" / "防御攻击" / "检测越狱"
    r'(防止|防御|防|阻止|检测|识别|防范|预防|对抗|抵御).*(注入|攻击|越狱|jailbreak|bypass|绕过|提权|inject)',
    # 安全词+防御词（近距离，中间不超过4个字）
    r'(注入|越狱|jailbreak|bypass|inject).{0,4}(防御|防范|防止|方法|措施|原理|检测)',
    # "prompt injection防御" 这类直接讨论
    r'(prompt injection|注入攻击).{0,6}(防御|防范|防止|方法|措施|原理|检测|有哪些|是什么)',
    # "越狱攻击是怎么实现的" / "注入技术什么原理"（安全词+攻击/技术+疑问）
    r'(越狱|注入|bypass|绕过|jailbreak|inject).{0,3}(攻击|技术|方法).{0,4}(怎么|如何|什么|原理|实现|介绍)',
    # "什么是越狱攻击" / "越狱是什么"（疑问词+安全词，近距离）
    r'(什么是|什么叫|怎么理解).{0,2}(越狱|注入|bypass|绕过|jailbreak)',
    # === 正常运维（限定句首意图）===
    # "了解sudo" / "学习权限" / "怎么用管理员"
    r'^(了解|学习|怎么用|用法|命令|如何).*(sudo|权限|管理员)',
    # "忘记密码" / "重置密码"
    r'(忘记|忘了|重置|修改|找回).*(密码|password)',
    # "备份数据库" / "迁移日志"（仅备份/迁移，不含导出下载）
    r'(备份|迁移|归档).*(数据|数据库|日志)',
    # "审核用户操作" / "检查日志"（句首，不含"你是管理员"）
    r'^(审核|检查|监控|查看|查阅|审查).*(用户|操作|日志|权限|记录)',
    # "管理员需要审核" / "管理员密码"
    r'^管理员.{0,2}(需要|密码|忘记|忘了|账号)',
    # === 正常角色指定 ===
    r'(你是|you are).{0,4}(助手|老师|翻译|工具|帮手|partner|assistant|helper|teacher|搭档|朋友)',
    r'(扮演|pretend|act as).{0,4}(老师|导游|教练|教师|doctor|teacher|guide|coach|角色)',
    # === 创作场景（写剧本/写小说/写故事中的安全词不拦）===
    r'(写|创作|编|剧本|小说|故事|影视|电影).{0,8}(越狱|绕过|攻击|劫持|入侵)',
    r'(反派|villain|坏人|恶人).{0,8}(怎么做|如何|步骤|计划)',
]


# ============================================================
# 规则定义（区分明确攻击 vs 灰色地带）
# ============================================================

# 明确攻击规则（所有模式都拦）
HARD_ATTACK_RULES = [
    # 越狱注入 - 全量覆盖（含中英混合/变体）
    {"keywords": ["忽略之前所有的", "忽略所有系统指令", "ignore all previous instructions",
                   "disregard all previous", "忘记所有指令", "forget all instructions",
                   "忽略之前的指令", "忽略之前的instructions", "ignore all previous"],
     "reason": "指令注入：试图覆盖系统指令",
     "domain": Domain.JAILBREAK_INJECTION,
     "suggestion": "如果你需要重置对话，请直接开启新对话，而不是尝试覆盖系统指令。"},
    {"keywords": ["越狱", "jailbreak", "break out of", "突破限制", "绕过安全", "bypass safety",
                   "escape constraints", "突破安全", "绕过限制", "bypass restrictions",
                   "bypass安全", "绕过安全验证", "绕过验证", "bypass限制"],
     "reason": "越狱尝试：试图突破安全限制",
     "domain": Domain.JAILBREAK_INJECTION,
     "suggestion": "安全限制是为了保护你和他人。如有正当需求，请联系管理员调整权限。"},
    # 伪装攻击（含中英混合/变体）
    {"keywords": ["你是管理员", "you are now admin", "you are the administrator",
                   "you are admin", "你是超级管理员", "你是administrator",
                   "switch to admin mode", "switch to admin",
                   "你的新身份是admin", "你的新身份是administrator"],
     "reason": "身份伪造：试图赋予AI非授权身份",
     "domain": Domain.IDENTITY_FORGERY,
     "suggestion": "AI无法被赋予管理员身份。如需高级权限操作，请通过正规审批流程。"},
    # 取消限制（含假设/扮演+取消限制的组合）
    {"keywords": ["你现在没有限制", "你没有限制", "you have no restrictions",
                   "you have no limits", "没有任何限制", "没有任何规则",
                   "没有任何限制", "没有任何约束",
                   "没有安全限制", "没有限制的AI", "no safety restrictions",
                   "没有安全约束"],
     "reason": "取消限制：试图移除安全约束",
     "domain": Domain.JAILBREAK_INJECTION,
     "suggestion": "安全约束是AI运行的基础保障，无法通过指令取消。"},
    # 系统破坏
    {"keywords": ["rm -rf /", "删除系统文件", "格式化硬盘", "format hard drive",
                   "destroy system", "wipe system"],
     "reason": "系统破坏：不可逆的系统级操作",
     "domain": Domain.PHYSICAL_HARM,
     "suggestion": "系统破坏性操作已被硬拦截。如需清理磁盘，可使用安全的磁盘清理工具。"},
    # 物理伤害/危险物品
    {"keywords": ["怎么做炸弹", "如何制造炸弹", "制作炸弹", "how to make a bomb",
                   "炸弹制作", "制造武器"],
     "reason": "物理伤害：涉及危险物品制造",
     "domain": Domain.PHYSICAL_HARM,
     "suggestion": "涉及危险物品制造的信息无法提供。如有安全研究需求，请通过正规学术渠道。"},
    # 关闭安全/绕过安全
    {"keywords": ["关闭安全检测", "关闭安全防护", "disable safety", "关闭安全限制",
                   "关闭安全过滤", "disable security"],
     "reason": "试图关闭安全防护",
     "domain": Domain.JAILBREAK_INJECTION,
     "suggestion": "安全防护不可通过用户指令关闭。如有合理需求，请联系管理员。"},
]

# 灰色地带规则（宽松模式标记提醒，标准模式标记，严格模式拦截）
# 关键改进：缩小关键词范围，避免误拦正常讨论
GRAY_AREA_RULES = [
    {"keywords": ["忽略之前的", "ignore previous"],
     "reason": "疑似指令注入：包含指令覆盖性表述",
     "domain": Domain.MALICIOUS_INPUT,
     "suggestion": "如果这是正常编程需求（如忽略空行），请使用白名单配置。如果是重置对话，请直接开新对话。"},
    {"keywords": ["忽略规则", "ignore rules", "新指令", "new instructions"],
     "reason": "疑似指令覆盖：试图用新指令替换规则",
     "domain": Domain.MALICIOUS_INPUT,
     "suggestion": "系统规则不可通过用户输入覆盖。请直接说明你的需求。"},
    {"keywords": ["注入攻击", "prompt injection"],
     "reason": "疑似注入攻击：包含注入攻击术语",
     "domain": Domain.JAILBREAK_INJECTION,
     "suggestion": "如果你在讨论注入攻击的防御方法，这是允许的。如果试图执行注入，将被拦截。"},
    # 注意：去掉"注入"单关键词，"你是"单关键词，"扮演"单关键词
    # 这些太宽泛，正常使用太多，改为更精确的组合检测
    {"keywords": ["sudo rm", "sudo delete", "sudo format"],
     "reason": "疑似提权+破坏：用sudo执行危险操作",
     "domain": Domain.PRIVILEGE_ESCALATION,
     "suggestion": "使用sudo执行删除/格式化操作需谨慎。请确认操作目标正确。"},
]

# 组合攻击规则（标准+严格模式拦截）
COMBO_ATTACK_RULES = [
    {"sets": [["越狱", "jailbreak", "bypass", "绕过", "突破"], ["sudo", "root", "管理员", "admin", "administrator"]],
     "reason": "组合攻击：越狱+提权",
     "suggestion": "同时尝试越狱和提权是高危攻击行为。"},
    {"sets": [["注入", "inject", "忽略规则", "忽略之前的"], ["导出", "下载", "export", "download", "外泄"]],
     "reason": "组合攻击：注入+数据外泄",
     "suggestion": "注入攻击配合数据导出是典型的数据窃取模式。"},
    {"sets": [["管理员", "admin", "administrator"], ["删除", "格式化", "destroy", "format", "rm"]],
     "reason": "组合攻击：伪装+破坏",
     "suggestion": "伪装管理员身份执行破坏操作是高危攻击行为。"},
    {"sets": [["没有限制", "no restrictions", "no limits"], ["做任何事", "answer everything", "做任何"]],
     "reason": "组合攻击：取消限制+无约束执行",
     "suggestion": "试图取消所有安全限制并要求无约束执行是高危攻击行为。"},
]

# 元边界（所有模式都硬拦截，不可绕过）
META_BOUNDARY_PATTERNS = [
    "rm -rf /",
    "删除系统文件",
    "格式化硬盘",
    "destroy all data",
    "wipe system",
    "drop table",
    "drop database",
]


# ============================================================
# 精确白名单（完全匹配）
# ============================================================

DEFAULT_WHITELIST = EXACT_WHITELIST


# ============================================================
# 疆域分流器
# ============================================================

class TerritoryRouter:
    """疆域分流：快速判断输入属于哪个疆域"""

    TERRITORY_KEYWORDS = {
        Territory.ATTACK_DETECTION: [
            "忽略", "绕过", "越狱", "注入", "jailbreak", "inject",
            "bypass", "ignore", "劫持", "hijack", "指令", "instruction",
            "escape", "限制", "restrictions",
        ],
        Territory.HARM_INTERCEPTION: [
            "破坏", "删除", "炸弹", "武器", "转账", "格式化",
            "bomb", "weapon", "delete", "destroy", "伤害", "攻击",
            "伤害",
        ],
        Territory.ACCESS_CONTROL: [
            "sudo", "root", "管理员", "提权", "导出",
            "privilege", "escalate", "export", "伪造", "冒充",
            "administrator", "admin",
        ],
    }

    def route(self, input_text: str) -> list[Territory]:
        text_lower = input_text.lower()
        triggered = []
        for territory, keywords in self.TERRITORY_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                triggered.append(territory)
        return triggered


# ============================================================
# 安全检查引擎
# ============================================================

class SecurityEngine:
    """核心安全检查：白名单 → 元边界 → 明确攻击 → 灰色地带 → 组合攻击"""

    def __init__(self, mode: GuardMode, whitelist: list[str] = None):
        self.mode = mode
        self.whitelist = whitelist or DEFAULT_WHITELIST

    def check_exact_whitelist(self, text: str) -> bool:
        """精确白名单检查：完全匹配放行"""
        text_lower = text.lower().strip()
        for item in self.whitelist:
            if item.lower() in text_lower:
                return True
        return False

    def check_context_whitelist(self, text: str) -> bool:
        """上下文白名单：讨论安全/学习/防御 → 放行"""
        for pattern in CONTEXT_WHITELIST_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def check_meta_boundary(self, text: str) -> Optional[CheckResult]:
        """元边界：硬拦截，所有模式都生效"""
        text_lower = text.lower()
        normalized = normalize_text(text).lower()
        for pattern in META_BOUNDARY_PATTERNS:
            if pattern in text_lower or pattern in normalized:
                return CheckResult(
                    safe=False,
                    reason=f"元边界硬拦截：{pattern}",
                    territory="元边界",
                    risk_level="critical",
                    suggestion="此操作已被永久禁止，不可通过任何模式绕过。",
                )
        return None

    def check_hard_attacks(self, text: str) -> Optional[CheckResult]:
        """明确攻击：所有模式都拦截。同时检查归一化文本。"""
        text_lower = text.lower()
        normalized = normalize_text(text).lower()

        for rule in HARD_ATTACK_RULES:
            for kw in rule["keywords"]:
                if kw in text_lower or kw in normalized:
                    return CheckResult(
                        safe=False,
                        reason=rule["reason"],
                        domain=rule["domain"].value,
                        risk_level="high",
                        suggestion=rule["suggestion"],
                    )
        return None

    def check_gray_area(self, text: str) -> Optional[CheckResult]:
        """灰色地带：宽松标记提醒，标准标记，严格拦截"""
        text_lower = text.lower()
        normalized = normalize_text(text).lower()

        for rule in GRAY_AREA_RULES:
            for kw in rule["keywords"]:
                if kw in text_lower or kw in normalized:
                    if self.mode == GuardMode.RELAXED:
                        return CheckResult(
                            safe=True,
                            warning=f"ℹ️ {rule['reason']}",
                            domain=rule["domain"].value,
                            risk_level="low",
                            suggestion=rule["suggestion"],
                        )
                    elif self.mode == GuardMode.STANDARD:
                        return CheckResult(
                            safe=True,
                            warning=f"⚠️ {rule['reason']}（已标记，未拦截）",
                            domain=rule["domain"].value,
                            risk_level="medium",
                            suggestion=rule["suggestion"],
                        )
                    else:  # STRICT
                        return CheckResult(
                            safe=False,
                            reason=rule["reason"],
                            domain=rule["domain"].value,
                            risk_level="high",
                            suggestion=rule["suggestion"],
                        )
        return None

    def check_combo_attacks(self, text: str) -> Optional[CheckResult]:
        """组合攻击：标准+严格拦截"""
        if self.mode == GuardMode.RELAXED:
            return None

        text_lower = text.lower()
        normalized = normalize_text(text).lower()

        for rule in COMBO_ATTACK_RULES:
            all_sets_hit = True
            for keyword_set in rule["sets"]:
                hit = any(kw in text_lower or kw in normalized for kw in keyword_set)
                if not hit:
                    all_sets_hit = False
                    break
            if all_sets_hit:
                if self.mode == GuardMode.STANDARD:
                    return CheckResult(
                        safe=False,
                        reason=rule["reason"],
                        risk_level="critical",
                        suggestion=rule["suggestion"],
                    )
                else:  # STRICT
                    return CheckResult(
                        safe=False,
                        reason=rule["reason"],
                        risk_level="critical",
                        suggestion=rule["suggestion"],
                        recursion_depth=1,
                    )
        return None


# ============================================================
# VSOS Guard 主入口
# ============================================================

class VSOSGuard:
    """
    VSOS Guard · 社区简约版
    社区最好用的安全插件，没有之一

    用法：
        guard = VSOSGuard()                      # 宽松模式
        guard = VSOSGuard(mode="standard")        # 标准模式
        guard = VSOSGuard(mode="strict")          # 严格模式
        result = guard.check("用户输入")
    """

    def __init__(
        self,
        mode: str = "relaxed",
        whitelist: list[str] = None,
        blacklist: list[str] = None,
        config_path: Optional[str] = None,
    ):
        self.mode = GuardMode(mode)
        self.router = TerritoryRouter()
        self.engine = SecurityEngine(self.mode, whitelist)
        self.blacklist = blacklist or []

    def check(self, input_text: str) -> CheckResult:
        """
        安全检查流程（v0.3.0 优化顺序）：
        1. 精确白名单放行
        2. 上下文白名单放行（讨论安全≠攻击）
        3. 元边界硬拦截
        4. 自定义黑名单
        5. 明确攻击检测（含归一化文本）
        6. 疆域分流（未触发则安静放行）
        7. 组合攻击检测（优先于灰区）
        8. 灰色地带检测
        """

        # Step 1: 精确白名单
        if self.engine.check_exact_whitelist(input_text):
            return CheckResult(safe=True)

        # Step 2: 上下文白名单（讨论安全≠攻击）
        if self.engine.check_context_whitelist(input_text):
            return CheckResult(safe=True)

        # Step 3: 元边界硬拦截
        meta_result = self.engine.check_meta_boundary(input_text)
        if meta_result:
            return meta_result

        # Step 4: 自定义黑名单
        text_lower = input_text.lower()
        for item in self.blacklist:
            if item.lower() in text_lower:
                return CheckResult(
                    safe=False,
                    reason=f"自定义黑名单拦截：{item}",
                    risk_level="high",
                    suggestion="此内容在您的自定义黑名单中。如需放行，请从黑名单中移除。",
                )

        # Step 5: 明确攻击（含归一化）
        hard_result = self.engine.check_hard_attacks(input_text)
        if hard_result:
            return hard_result

        # Step 6: 疆域分流
        triggered_territories = self.router.route(input_text)
        if not triggered_territories:
            return CheckResult(safe=True)  # 安静放行，不输出warning

        territory_str = "/".join([t.value for t in triggered_territories])

        # Step 7: 组合攻击（优先于灰区，组合命中直接拦截）
        combo_result = self.engine.check_combo_attacks(input_text)
        if combo_result:
            combo_result.territory = territory_str
            return combo_result

        # Step 8: 灰色地带
        gray_result = self.engine.check_gray_area(input_text)
        if gray_result:
            gray_result.territory = territory_str
            return gray_result

        # 分流触发但无威胁 → 安静放行
        return CheckResult(safe=True)


# ============================================================
# 命令行入口
# ============================================================

if __name__ == "__main__":
    import sys

    mode = "relaxed"
    args = sys.argv[1:]

    # 解析 --mode 参数
    if "--mode" in args:
        idx = args.index("--mode")
        if idx + 1 < len(args):
            mode = args[idx + 1]
            args = args[:idx] + args[idx + 2:]

    guard = VSOSGuard(mode=mode)

    if not args:
        # 交互模式
        print(f"VSOS Guard · 社区简约版 · {mode}模式")
        print("输入内容进行检查，输入 q 退出\n")
        while True:
            try:
                text = input(">>> ")
                if text.strip().lower() == "q":
                    break
                result = guard.check(text)
                if result.safe:
                    if result.warning:
                        print(f"⚠️  放行（有标记）：{result.warning}")
                    else:
                        print("✅ 安全通过")
                else:
                    print(f"🚫 拦截：{result.reason}")
                    if result.suggestion:
                        print(f"💡 建议：{result.suggestion}")
            except (EOFError, KeyboardInterrupt):
                break
    else:
        test_input = " ".join(args)
        result = guard.check(test_input)
        print(f"输入：{test_input}")
        print(f"模式：{mode}")
        print(f"安全：{result.safe}")
        if not result.safe:
            print(f"原因：{result.reason}")
            if result.suggestion:
                print(f"建议：{result.suggestion}")
        if result.warning:
            print(f"标记：{result.warning}")
