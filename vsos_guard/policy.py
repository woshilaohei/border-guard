# -*- coding: utf-8 -*-
"""
VSOS Guard Policy Loader v0.5.3

YAML-based policy configuration with restricted openness.
Framework locked, parameters open, core never exposed.

Restricted openness principle:
- GREEN: Fully customizable (thresholds, toggles, custom keywords, output format)
- YELLOW: Restricted (fixed domain/action choices, fixed pipeline order)
- RED: Never exposed (territory logic, causal chain rules, layer mapping)

Usage:
    guard = VSOSGuard(policy_file="vsos_policy.yaml")

YAML format:
    vsos_guard:
      mode: standard
      domains:
        injection: true
        encoding: true
        behavior: false
        exfiltration: true
      sensitivity:
        encoding_confidence: 0.7
        injection_level: 2
      custom_blocklist:
        - "rm -rf"
        - "drop table"
      output:
        format: json
        owasp_mapping: true
        include_evidence: true
"""

import os
import re
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field


# ============================================================
# Fixed domain/action definitions (YELLOW zone - restricted)
# ============================================================

VALID_DOMAINS = {
    "injection": "Jailbreak and injection detection",
    "encoding": "Encoding-based bypass detection",
    "behavior": "Harmful behavior detection",
    "exfiltration": "Data leakage and exfiltration detection",
}

VALID_ACTIONS = {"block", "warn", "allow"}

VALID_MODES = {"relaxed", "standard", "strict"}

VALID_OUTPUT_FORMATS = {"json", "dict"}

# Default sensitivity values
DEFAULT_SENSITIVITY = {
    "encoding_confidence": 0.7,
    "injection_level": 2,
}


@dataclass
class GuardPolicy:
    """
    Parsed guard policy from YAML configuration.

    This is what users can configure. Territory logic, causal chain rules,
    and layer mapping are NOT configurable - they stay in guard.py.
    """
    # Mode
    mode: str = "standard"

    # Domain toggles (can only toggle predefined domains)
    domains: Dict[str, bool] = field(default_factory=lambda: {
        "injection": True,
        "encoding": True,
        "behavior": True,
        "exfiltration": True,
    })

    # Sensitivity thresholds
    sensitivity: Dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_SENSITIVITY))

    # Custom blocklist keywords (GREEN zone)
    custom_blocklist: List[str] = field(default_factory=list)

    # Output configuration
    output_format: str = "dict"
    owasp_mapping: bool = True
    include_evidence: bool = True

    # Source tracking
    source_file: Optional[str] = None


def load_policy(policy_file: str) -> GuardPolicy:
    """
    Load and validate a YAML policy file.

    Args:
        policy_file: Path to YAML policy configuration file.

    Returns:
        GuardPolicy with validated settings.

    Raises:
        FileNotFoundError: If policy file does not exist.
        ValueError: If policy contains invalid configuration.
    """
    if not os.path.exists(policy_file):
        raise FileNotFoundError(f"Policy file not found: {policy_file}")

    with open(policy_file, "r", encoding="utf-8") as f:
        content = f.read()

    # Try pyyaml first if available, fall back to built-in parser
    raw_config = _parse_yaml(content)

    return _build_policy(raw_config, policy_file)


def _parse_yaml(content: str) -> Dict[str, Any]:
    """
    Parse YAML content. Uses pyyaml if available, otherwise built-in parser.
    """
    try:
        import yaml
        return yaml.safe_load(content) or {}
    except ImportError:
        return _parse_yaml_builtin(content)


def _parse_yaml_builtin(content: str) -> Dict[str, Any]:
    """
    Built-in YAML parser for our specific config format.
    Zero dependency fallback when pyyaml is not installed.
    """
    result: Dict[str, Any] = {}
    # Stack tracks: [(dict_ref, key_at_level, indent)]
    # We build nested dicts by tracking indentation
    stack: List[tuple] = [(result, None, -1)]
    pending_list_key: Optional[str] = None
    pending_list: List[str] = []
    pending_list_indent: int = -1

    def _flush_list():
        nonlocal pending_list_key, pending_list, pending_list_indent
        if pending_list_key and pending_list:
            # Find the right dict to put the list in
            current = stack[0][0]
            for _, key, _ in stack[1:]:
                if key and key in current:
                    current = current[key]
                else:
                    break
            current[pending_list_key] = pending_list
        pending_list_key = None
        pending_list = []
        pending_list_indent = -1

    for line_num, line in enumerate(content.split("\n")):
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        # List item
        if stripped.startswith("- "):
            item = stripped[2:].strip()
            # Remove inline comments
            if " #" in item:
                item = item[:item.index(" #")].strip()
            # Strip quotes
            if (item.startswith('"') and item.endswith('"')) or \
               (item.startswith("'") and item.endswith("'")):
                item = item[1:-1]
            pending_list.append(item)
            continue

        # Key-value pair
        if ":" in stripped:
            # Flush any pending list
            _flush_list()

            # Pop stack entries that are at same or deeper indent
            while len(stack) > 1 and stack[-1][2] >= indent:
                stack.pop()

            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()

            # Remove inline comments from value
            if value and " #" in value:
                value = value[:value.index(" #")].strip()

            # Get current dict from stack top
            current_dict = stack[-1][0]

            if value:
                # Leaf node with value
                parsed = _parse_value(value)
                current_dict[key] = parsed
            else:
                # Parent node - create nested dict
                new_dict = {}
                current_dict[key] = new_dict
                stack.append((new_dict, key, indent))
                # This could be a list parent
                pending_list_key = key
                pending_list_indent = indent

    # Flush final list
    _flush_list()

    return result


def _parse_value(value: str) -> Any:
    """Parse a YAML value string into Python type."""
    value = value.strip()

    # Strip quotes
    if (value.startswith('"') and value.endswith('"')) or \
       (value.startswith("'") and value.endswith("'")):
        return value[1:-1]

    # Boolean
    if value.lower() in ("true", "yes", "on"):
        return True
    if value.lower() in ("false", "no", "off"):
        return False

    # Number
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        pass

    # String
    return value


def _set_nested(d: Dict, keys: List[str], value: Any) -> None:
    """Set a nested dict value by key path."""
    for key in keys[:-1]:
        if key not in d:
            d[key] = {}
        d = d[key]
    if keys:
        d[keys[-1]] = value


def _build_policy(raw: Dict[str, Any], source_file: str) -> GuardPolicy:
    """
    Build and validate a GuardPolicy from raw parsed config.

    Validates against restricted openness rules:
    - Domains can only be from VALID_DOMAINS
    - Mode can only be from VALID_MODES
    - Output format can only be from VALID_OUTPUT_FORMATS
    """
    # Extract vsos_guard root (or use raw directly)
    config = raw.get("vsos_guard", raw)

    policy = GuardPolicy()
    policy.source_file = source_file

    # Mode validation (YELLOW zone)
    if "mode" in config:
        mode = config["mode"]
        if isinstance(mode, str):
            mode = mode.strip()
        if mode not in VALID_MODES:
            raise ValueError(
                f"Invalid mode '{mode}'. Must be one of: {', '.join(VALID_MODES)}"
            )
        policy.mode = mode

    # Domain toggles (YELLOW zone - only predefined domains)
    if "domains" in config:
        domains = config["domains"]
        if not isinstance(domains, dict):
            raise ValueError("domains must be a mapping of domain: boolean")

        for domain_name, enabled in domains.items():
            if domain_name not in VALID_DOMAINS:
                raise ValueError(
                    f"Invalid domain '{domain_name}'. "
                    f"Valid domains: {', '.join(VALID_DOMAINS.keys())}"
                )
            # Accept both bool and string "true"/"false"
            if isinstance(enabled, str):
                enabled = enabled.lower() in ("true", "yes", "on")
            if not isinstance(enabled, bool):
                raise ValueError(f"Domain '{domain_name}' value must be true/false")
            policy.domains[domain_name] = enabled

    # Sensitivity (GREEN zone)
    if "sensitivity" in config:
        sensitivity = config["sensitivity"]
        if not isinstance(sensitivity, dict):
            raise ValueError("sensitivity must be a mapping")

        if "encoding_confidence" in sensitivity:
            val = sensitivity["encoding_confidence"]
            if isinstance(val, str):
                try: val = float(val)
                except ValueError: pass
            if not isinstance(val, (int, float)) or not (0.0 <= val <= 1.0):
                raise ValueError("encoding_confidence must be a number between 0.0 and 1.0")
            policy.sensitivity["encoding_confidence"] = val

        if "injection_level" in sensitivity:
            val = sensitivity["injection_level"]
            if isinstance(val, str):
                try: val = int(val)
                except ValueError: pass
            if not isinstance(val, int) or not (1 <= val <= 3):
                raise ValueError("injection_level must be 1, 2, or 3")
            policy.sensitivity["injection_level"] = val

    # Custom blocklist (GREEN zone)
    if "custom_blocklist" in config:
        blocklist = config["custom_blocklist"]
        if isinstance(blocklist, str):
            if blocklist.strip() in ("[]", ""):
                blocklist = []
            else:
                blocklist = [blocklist]
        if not isinstance(blocklist, list):
            raise ValueError("custom_blocklist must be a list of strings")
        policy.custom_blocklist = [str(item) for item in blocklist]

    # Output configuration (GREEN zone)
    if "output" in config:
        output = config["output"]
        if not isinstance(output, dict):
            raise ValueError("output must be a mapping")

        if "format" in output:
            fmt = output["format"]
            if isinstance(fmt, str):
                fmt = fmt.strip()
            if fmt not in VALID_OUTPUT_FORMATS:
                raise ValueError(
                    f"Invalid output format '{fmt}'. Must be one of: {', '.join(VALID_OUTPUT_FORMATS)}"
                )
            policy.output_format = fmt

        if "owasp_mapping" in output:
            val = output["owasp_mapping"]
            policy.owasp_mapping = bool(val) if isinstance(val, bool) else str(val).lower() in ("true", "yes", "on")

        if "include_evidence" in output:
            val = output["include_evidence"]
            policy.include_evidence = bool(val) if isinstance(val, bool) else str(val).lower() in ("true", "yes", "on")

    return policy


def create_default_policy_file(path: str) -> str:
    """
    Create a default policy YAML file at the given path.

    Args:
        path: File path to create the default policy

    Returns:
        The path where the file was created.
    """
    default_content = """# VSOS Guard Policy Configuration
# Framework locked, parameters open, core never exposed.

vsos_guard:
  # Mode: relaxed / standard / strict
  mode: standard

  # Domain toggles (only predefined domains allowed)
  domains:
    injection: true
    encoding: true
    behavior: true
    exfiltration: true

  # Sensitivity thresholds
  sensitivity:
    encoding_confidence: 0.7
    injection_level: 2

  # Custom blocklist (add your own keywords)
  custom_blocklist:
    - "rm -rf"
    - "drop table"

  # Output configuration
  output:
    format: json
    owasp_mapping: true
    include_evidence: true
"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(default_content)

    return path
