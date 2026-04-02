"""WinLogBeat JSON message parser and sanitizer."""

import json
import re
from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.patterns import IPV4, FQDN, WINDOWS_SID, MACHINE_ACCOUNT, is_private_ip

# Prefix used by WitFoo to wrap WinLogBeat messages
WINLOGBEAT_PREFIX = "WitFoo-WinLogBeat :::"

# Keys in WinLogBeat JSON that contain PII.
# Uses LOWERCASE for comparison — all key lookups are lowercased.
_PII_KEYS = {
    # Agent/host info
    "hostname": "hostname",
    "ip": "ip",
    "computer_name": "fqdn",
    # User info (both snake_case and PascalCase lowercased)
    "user": "username",
    "targetusername": "username",
    "target_user_name": "username",
    "subjectusername": "username",
    "subject_user_name": "username",
    "callerprocessname": "passthrough",  # file path, not PII
    # Domain info
    "domain": "org",
    "targetdomainname": "org",
    "target_domain_name": "org",
    "subjectdomainname": "org",
    "subject_domain_name": "org",
    # Organization (WitFoo-added field within the JSON)
    "organization": "org",
    # SID (both snake_case and PascalCase lowercased)
    "targetusersid": "sid",
    "target_user_sid": "sid",
    "subjectusersid": "sid",
    "subject_user_sid": "sid",
    "targetlogonid": "passthrough",
    "subjectlogonid": "passthrough",
    # Network
    "source_address": "ip",
    "sourceaddress": "ip",
    "ip_address": "ip",
    "ipaddress": "ip",
    # Host fields (WitFoo-added)
    "senderhost": "hostname",
    "serverhostname": "hostname",
    "localhostname": "hostname",
    # Workstation
    "workstationname": "hostname",
    "targetservername": "hostname",
}

# Domain values that are Windows built-ins, not customer PII
_SAFE_DOMAINS = {
    "NT AUTHORITY", "BUILTIN", "NT SERVICE", "Window Manager",
    "Font Driver Host", "IIS APPPOOL", "WORKGROUP",
}

# Username values that are Windows built-ins
_SAFE_USERNAMES = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
    "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
    "-", "",
}


def sanitize_winlogbeat(message: str, registry: PIIRegistry) -> str:
    """Sanitize a WinLogBeat JSON message."""
    # Strip prefix
    if message.strip().startswith(WINLOGBEAT_PREFIX):
        json_str = message.strip()[len(WINLOGBEAT_PREFIX):].strip()
    else:
        json_str = message.strip()

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        # Not valid JSON, return as-is for generic handler
        return message

    sanitized = _sanitize_winlogbeat_dict(data, registry)

    # Re-serialize
    result_json = json.dumps(sanitized, separators=(",", ":"))

    if message.strip().startswith(WINLOGBEAT_PREFIX):
        return f"{WINLOGBEAT_PREFIX} {result_json}"
    return result_json


def _sanitize_winlogbeat_dict(d: dict, registry: PIIRegistry, parent_key: str = "") -> dict:
    """Recursively sanitize WinLogBeat JSON."""
    result = {}
    for key, value in d.items():
        key_lower = key.lower()

        if isinstance(value, dict):
            result[key] = _sanitize_winlogbeat_dict(value, registry, key)
        elif isinstance(value, list):
            result[key] = [
                _sanitize_winlogbeat_dict(item, registry, key)
                if isinstance(item, dict) else item
                for item in value
            ]
        elif isinstance(value, str):
            result[key] = _sanitize_winlogbeat_value(key, key_lower, value, registry, parent_key)
        else:
            result[key] = value

    return result


def _sanitize_winlogbeat_value(
    key: str, key_lower: str, value: str,
    registry: PIIRegistry, parent_key: str
) -> str:
    """Sanitize a single string value in WinLogBeat JSON."""
    if not value or value == "-":
        return value

    # Check if key indicates PII
    if key_lower in _PII_KEYS:
        pii_type = _PII_KEYS[key_lower]

        if pii_type == "passthrough":
            return value

        if pii_type == "hostname":
            return _sanitize_host_value(value, registry)

        if pii_type == "fqdn":
            if "." in value and FQDN.fullmatch(value):
                return registry.get_or_create("fqdn", value)
            return registry.get_or_create("hostname", value)

        if pii_type == "ip":
            if IPV4.fullmatch(value):
                cat = "ipv4_priv" if is_private_ip(value) else "ipv4_pub"
                return registry.get_or_create(cat, value)
            return value

        if pii_type == "username":
            if value.upper() in _SAFE_USERNAMES:
                return value
            # Machine accounts (HOSTNAME$)
            if MACHINE_ACCOUNT.fullmatch(value):
                return registry.get_or_create("machine_account", value)
            return registry.get_or_create("username", value)

        if pii_type == "org":
            if value in _SAFE_DOMAINS:
                return value
            return registry.get_or_create("org", value)

        if pii_type == "sid":
            if WINDOWS_SID.fullmatch(value):
                return registry.get_or_create("sid", value)
            return value

    # Key is "name" — depends on parent context
    if key_lower == "name" and parent_key.lower() in ("agent", "host"):
        return _sanitize_host_value(value, registry)

    return value


def _sanitize_host_value(value: str, registry: PIIRegistry) -> str:
    """Sanitize a hostname/IP value."""
    if IPV4.fullmatch(value):
        cat = "ipv4_priv" if is_private_ip(value) else "ipv4_pub"
        return registry.get_or_create(cat, value)
    if "." in value and FQDN.fullmatch(value):
        return registry.get_or_create("fqdn", value)
    return registry.get_or_create("hostname", value)
