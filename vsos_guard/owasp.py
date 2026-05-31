# -*- coding: utf-8 -*-
"""
VSOS Guard OWASP Mapping v0.5.3

Automatic mapping from VSOS Guard detection results to OWASP categories.

OWASP LLM Top 10 (2025):
- LLM01: Prompt Injection
- LLM02: Sensitive Information Disclosure
- LLM06: Excessive Agency

OWASP Agentic AI Security Top 10 (ASI):
- ASI01: Agent Injection (indirect prompt injection into agentic workflows)
- ASI02: Insecure Output Handling
- ASI06: Memory Poisoning

Usage:
    from vsos_guard.owasp import map_to_owasp

    result = guard.check(user_input)
    owasp = map_to_owasp(result)
    print(owasp.category)  # "LLM01"
    print(owasp.name)      # "Prompt Injection"
    print(owasp.url)       # "https://..."
"""

from dataclasses import dataclass
from typing import Optional, List
from vsos_guard.guard import CheckResult, Domain


@dataclass
class OWASPMapping:
    """OWASP category mapping for a security check result."""
    category: str = ""
    name: str = ""
    description: str = ""
    url: str = ""
    severity: str = ""  # low / medium / high / critical


# Domain -> OWASP mapping table
# Each domain maps to one or more OWASP categories (primary + secondary)
_DOMAIN_OWASP_MAP = {
    # LLM01: Prompt Injection
    Domain.JAILBREAK_INJECTION: OWASPMapping(
        category="LLM01",
        name="Prompt Injection",
        description="Attempt to manipulate LLM behavior through crafted input that overrides system instructions or safety constraints.",
        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM01",
        severity="critical",
    ),
    Domain.MALICIOUS_INPUT: OWASPMapping(
        category="LLM01/ASI01",
        name="Prompt Injection / Agent Injection",
        description="Direct or indirect injection of malicious instructions into LLM or agentic workflows, including multi-step and encoding-based attacks.",
        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM01",
        severity="critical",
    ),
    # ASI01: Agent Injection (indirect injection via external content)
    Domain.PROTOCOL_HIJACK: OWASPMapping(
        category="ASI01",
        name="Agent Injection",
        description="Indirect prompt injection through external content (documents, emails, web pages) that contains hidden triggers or conditional instructions.",
        url="https://owasp.org/www-project-agentic-ai-security/",
        severity="critical",
    ),
    # LLM02: Sensitive Information Disclosure
    Domain.DATA_LEAKAGE: OWASPMapping(
        category="LLM02",
        name="Sensitive Information Disclosure",
        description="Attempts to extract sensitive data such as API keys, passwords, system prompts, or internal configuration through manipulation.",
        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM02",
        severity="high",
    ),
    # LLM06: Excessive Agency
    Domain.PRIVILEGE_ESCALATION: OWASPMapping(
        category="LLM06",
        name="Excessive Agency",
        description="Attempts to grant the AI system unauthorized permissions or escalate privileges beyond intended scope.",
        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM06",
        severity="high",
    ),
    Domain.IDENTITY_FORGERY: OWASPMapping(
        category="LLM06",
        name="Excessive Agency (Identity Forgery)",
        description="Identity manipulation to grant the AI unauthorized roles (admin, developer, security researcher) to bypass safety controls.",
        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM06",
        severity="high",
    ),
    # Physical/economic/psychological harm
    Domain.PHYSICAL_HARM: OWASPMapping(
        category="LLM02/LLM06",
        name="Harmful Content / Excessive Agency",
        description="Requests for dangerous content (weapons, explosives, drugs) or attempts to use AI for physical harm.",
        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM06",
        severity="critical",
    ),
    Domain.ECONOMIC_HARM: OWASPMapping(
        category="LLM06",
        name="Excessive Agency (Economic Harm)",
        description="Attempts to manipulate AI into performing unauthorized financial operations or economic damage.",
        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM06",
        severity="high",
    ),
    Domain.PSYCHOLOGICAL_HARM: OWASPMapping(
        category="LLM06",
        name="Excessive Agency (Psychological Harm)",
        description="Attempts to use AI for psychological manipulation, harassment, or social engineering.",
        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM06",
        severity="medium",
    ),
}

# ASI02: Insecure Output Handling (for check_output results)
ASI02_MAPPING = OWASPMapping(
    category="ASI02",
    name="Insecure Output Handling",
    description="AI output contains sensitive information leakage, instruction injection propagation, or unauthorized action suggestions.",
    url="https://owasp.org/www-project-agentic-ai-security/",
    severity="high",
)

# ASI06: Memory Poisoning (for future memory-related detection)
ASI06_MAPPING = OWASPMapping(
    category="ASI06",
    name="Memory Poisoning",
    description="Attempts to corrupt or manipulate agent memory to alter future behavior through persistent instructions.",
    url="https://owasp.org/www-project-agentic-ai-security/",
    severity="high",
)

# Encoding detection -> LLM01 (bypass attempt)
ENCODING_OWASP_MAPPING = OWASPMapping(
    category="LLM01",
    name="Prompt Injection (Encoding Bypass)",
    description="Encoding-based bypass attempts (base64, unicode escape, hex escape, leet speak, rot13) used to evade security detection.",
    url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM01",
    severity="high",
)


def map_to_owasp(result: CheckResult) -> OWASPMapping:
    """
    Map a CheckResult to its OWASP category.

    Args:
        result: A CheckResult from guard.check() or guard.check_output()

    Returns:
        OWASPMapping with category, name, description, and reference URL.
        Returns empty OWASPMapping if the result is safe or has no mapping.
    """
    if result.safe and not result.warning:
        return OWASPMapping()

    # Check for encoding bypass pattern
    if result.matched_pattern and "bypass" in result.matched_pattern.lower():
        mapping = ENCODING_OWASP_MAPPING
        mapping.severity = _adjust_severity(mapping.severity, result)
        return mapping

    # Check for output detection (ASI02)
    if result.domain and "output" in result.domain.lower():
        mapping = ASI02_MAPPING
        mapping.severity = _adjust_severity(mapping.severity, result)
        return mapping

    # Map by domain
    domain_str = result.domain
    if domain_str:
        # Try to match domain string to Domain enum
        for domain_enum, mapping in _DOMAIN_OWASP_MAP.items():
            if domain_enum.value == domain_str:
                # Create a copy to avoid mutating the static mapping
                owasp = OWASPMapping(
                    category=mapping.category,
                    name=mapping.name,
                    description=mapping.description,
                    url=mapping.url,
                    severity=_adjust_severity(mapping.severity, result),
                )
                return owasp

    # Fallback: try keyword-based mapping
    return _keyword_fallback_mapping(result)


def _adjust_severity(base_severity: str, result: CheckResult) -> str:
    """Adjust OWASP severity based on confidence level."""
    if result.confidence == "critical":
        return "critical"
    elif result.confidence == "warning":
        if base_severity == "critical":
            return "high"
        return "medium"
    return base_severity


def _keyword_fallback_mapping(result: CheckResult) -> OWASPMapping:
    """Fallback OWASP mapping based on reason keywords."""
    reason = (result.reason or "").lower()
    warning = (result.warning or "").lower()
    text = reason + " " + warning

    if any(kw in text for kw in ["inject", "jailbreak", "bypass", "dan mode", "injection"]):
        return OWASPMapping(
            category="LLM01",
            name="Prompt Injection",
            description="Detected prompt injection or jailbreak attempt.",
            url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM01",
            severity="high" if not result.is_blocked() else "critical",
        )

    if any(kw in text for kw in ["identity", "forgery", "admin", "developer", "pentester"]):
        return OWASPMapping(
            category="LLM06",
            name="Excessive Agency",
            description="Detected identity forgery or unauthorized role assignment attempt.",
            url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM06",
            severity="high",
        )

    if any(kw in text for kw in ["data", "leakage", "export", "credentials", "password"]):
        return OWASPMapping(
            category="LLM02",
            name="Sensitive Information Disclosure",
            description="Detected data exfiltration or sensitive information disclosure attempt.",
            url="https://owasp.org/www-project-top-10-for-large-language-model-applications/entries/LLM02",
            severity="high",
        )

    if any(kw in text for kw in ["encoding", "base64", "unicode", "hex", "rot13", "leet"]):
        return ENCODING_OWASP_MAPPING

    # Generic mapping for blocked results
    if result.is_blocked():
        return OWASPMapping(
            category="LLM01",
            name="Prompt Injection",
            description="Security threat detected. Classified under Prompt Injection as primary OWASP category.",
            url="https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            severity="high",
        )

    return OWASPMapping()


def get_all_mappings() -> dict:
    """Return all OWASP mappings for documentation/reference purposes."""
    result = {}
    for domain, mapping in _DOMAIN_OWASP_MAP.items():
        result[domain.value] = {
            "category": mapping.category,
            "name": mapping.name,
            "severity": mapping.severity,
            "url": mapping.url,
        }
    result["ASI02 (Output)"] = {
        "category": ASI02_MAPPING.category,
        "name": ASI02_MAPPING.name,
        "severity": ASI02_MAPPING.severity,
        "url": ASI02_MAPPING.url,
    }
    result["ASI06 (Memory)"] = {
        "category": ASI06_MAPPING.category,
        "name": ASI06_MAPPING.name,
        "severity": ASI06_MAPPING.severity,
        "url": ASI06_MAPPING.url,
    }
    result["Encoding Bypass"] = {
        "category": ENCODING_OWASP_MAPPING.category,
        "name": ENCODING_OWASP_MAPPING.name,
        "severity": ENCODING_OWASP_MAPPING.severity,
        "url": ENCODING_OWASP_MAPPING.url,
    }
    return result
