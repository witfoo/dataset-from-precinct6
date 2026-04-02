"""Centralized regex patterns for PII detection across all sanitization layers."""

import re


# --- IP Addresses ---

# Standard IPv4 address
IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
)

# IPv4 with port suffix (e.g., 198.235.24.235/51282 or 198.235.24.235:8080)
IPV4_WITH_PORT = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))'
    r'([/:](\d{1,5}))\b'
)

# RFC1918 private address ranges
RFC1918 = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3})\b'
)

# RFC 5737 TEST-NET (our replacement IPs — used for validation)
TEST_NET = re.compile(
    r'\b(?:192\.0\.2\.\d{1,3}|198\.51\.100\.\d{1,3}|203\.0\.113\.\d{1,3})\b'
)

# Loopback
LOOPBACK = re.compile(r'\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')


# --- Hostnames & Domains ---

# FQDN (at least 2 dot-separated segments, ending with a valid TLD)
FQDN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){2,}'
    r'[a-zA-Z]{2,}\b'
)

# Known customer domains — built dynamically from customer_config.json.
# Initialized to match nothing; call build_customer_domain_pattern() to populate.
KNOWN_CUSTOMER_DOMAINS = re.compile(r'(?!)')  # matches nothing by default


def build_customer_domain_pattern(domains: list[str]) -> re.Pattern:
    """Build a regex pattern matching any customer-owned domain.

    Call this at startup with domains from customer_config.json or CUSTOMER_DOMAINS env var.
    Returns a compiled pattern that matches subdomains too (e.g., host.yourdomain.com).
    """
    if not domains:
        return re.compile(r'(?!)')  # matches nothing
    escaped = [re.escape(d) for d in domains]
    return re.compile(
        r'\b[\w.-]*(?:' + '|'.join(escaped) + r')\b',
        re.IGNORECASE,
    )

# Hex-encoded IP in hostname (e.g., IP-C61302E6)
HEX_ENCODED_IP = re.compile(r'\bIP-([0-9A-Fa-f]{8})\b')


# --- User Identities ---

# Email addresses
EMAIL = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

# Windows SIDs
WINDOWS_SID = re.compile(
    r'\bS-1-(?:0|1|2|3|5)-(?:\d+-){1,14}\d+\b'
)

# DOMAIN\username format
DOMAIN_BACKSLASH_USER = re.compile(
    r'\b([A-Z][A-Z0-9-]+)\\([A-Za-z0-9._-]+)\b'
)

# Machine accounts (ending with $)
MACHINE_ACCOUNT = re.compile(r'\b[A-Z][A-Z0-9-]{2,30}\$\b')


# --- Cloud/AWS ---

# AWS Account IDs (12 digits, not part of longer number)
AWS_ACCOUNT_ID = re.compile(r'(?<!\d)\d{12}(?!\d)')

# AWS ARNs
AWS_ARN = re.compile(
    r'\barn:aws(?:-[a-z]+)?:[a-z0-9-]+(?::[a-z0-9-]*){2}:\S+\b'
)

# TrustedAdvisor credential format
TRUSTED_ADVISOR = re.compile(
    r'\bTrustedAdvisor_(\d{12})_([a-f0-9-]{36})\b'
)


# --- Organization Identifiers ---

# Org with domain format: "OrgName (slug.domain.com)"
# This pattern matches WitFoo's org display format in artifact data.
# The domain portion is matched generically — customer domains are handled by KNOWN_CUSTOMER_DOMAINS.
ORG_WITH_DOMAIN = re.compile(
    r'([A-Za-z][A-Za-z0-9 ]*?)\s*\(([a-z0-9-]+\.[a-z0-9.-]+\.[a-z]{2,})\)',
    re.IGNORECASE,
)


# --- Syslog/Log Specific ---

# Cisco ASA IP:port in log messages
CISCO_ASA_IFACE_IP = re.compile(
    r'(?P<direction>src|dst)\s+(?P<iface>[a-zA-Z0-9_-]+):'
    r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})/(?P<port>\d+)'
)

# Cisco ASA original address
CISCO_ASA_ORIG_ADDR = re.compile(
    r'Original\s+Address=(?P<ip>(?:\d{1,3}\.){3}\d{1,3})'
)

# Meraki flow src/dst
MERAKI_FLOW_IP = re.compile(
    r'(?P<dir>src|dst)=(?P<ip>(?:\d{1,3}\.){3}\d{1,3})'
)

# Syslog header hostname (RFC 5424: after timestamp)
SYSLOG_HEADER_HOST = re.compile(
    r'^(<\d+>1?\s*\d{4}-\d{2}-\d{2}T[\d:.+-]+\s+)(\S+)(\s+)',
    re.MULTILINE,
)

# DNS reply/query with IP
DNS_REPLY_IP = re.compile(
    r'(reply|query)\s+(\S+)\s+is\s+((?:\d{1,3}\.){3}\d{1,3})'
)


# --- Windows Event XML ---

# XML elements containing PII
XML_PII_ELEMENTS = re.compile(
    r'<(TargetUserName|SubjectUserName|IpAddress|WorkstationName|'
    r'Computer|TargetDomainName|SubjectDomainName|TargetServerName|'
    r'CallerProcessName|ObjectName|TargetLogonId|SubjectLogonId)>'
    r'([^<]*)</\1>',
    re.IGNORECASE,
)

# Windows event Computer element
XML_COMPUTER = re.compile(
    r'<Computer>([^<]+)</Computer>',
    re.IGNORECASE,
)


# --- WinLogBeat JSON ---

# Agent name in WinLogBeat
WINLOGBEAT_AGENT_NAME = re.compile(r'"name"\s*:\s*"([^"]+)"')


# --- Generic UUID ---

UUID_PATTERN = re.compile(
    r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
    re.IGNORECASE,
)


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP string is in RFC1918 private range."""
    return bool(RFC1918.fullmatch(ip_str))


def is_test_net_ip(ip_str: str) -> bool:
    """Check if an IP is in RFC 5737 TEST-NET range (our replacements)."""
    return bool(TEST_NET.fullmatch(ip_str))


def is_loopback_ip(ip_str: str) -> bool:
    """Check if an IP is loopback."""
    return bool(LOOPBACK.fullmatch(ip_str))


def is_sanitized_ip(ip_str: str) -> bool:
    """Check if an IP is already a sanitized replacement."""
    return is_test_net_ip(ip_str) or ip_str.startswith("100.64.")


def decode_hex_ip(hex_str: str) -> str:
    """Decode a hex-encoded IP like C61302E6 -> 198.19.2.230."""
    try:
        b = bytes.fromhex(hex_str)
        return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"
    except (ValueError, IndexError):
        return ""


def encode_ip_hex(ip_str: str) -> str:
    """Encode an IP as hex: 198.19.2.230 -> C61302E6."""
    try:
        parts = [int(x) for x in ip_str.split(".")]
        return "".join(f"{p:02X}" for p in parts)
    except (ValueError, IndexError):
        return "00000000"
