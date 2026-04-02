"""Allowlists of safe tokens that should NOT be flagged as PII.

These prevent false positives in ML/NER detection layers.
"""

# Protocol and network terms
PROTOCOL_TERMS = {
    "tcp", "udp", "icmp", "http", "https", "dns", "smtp", "smb", "ldap",
    "ssh", "ftp", "snmp", "ntp", "dhcp", "arp", "bgp", "ospf", "rip",
    "tls", "ssl", "rdp", "vnc", "telnet", "kerberos", "sip", "rtsp",
    "pop3", "imap", "tftp", "syslog", "radius", "tacacs",
}

# Security vendor and product names (these are public, not PII)
VENDOR_TERMS = {
    "cisco", "microsoft", "windows", "linux", "vmware", "amazon",
    "aws", "azure", "google", "fortinet", "palo alto", "checkpoint",
    "crowdstrike", "splunk", "elastic", "meraki", "juniper", "sophos",
    "sentinel", "defender", "cloudtrail", "guardduty", "securityhub",
    "vcenter", "esxi", "datto", "limacharlie", "witfoo", "precinct",
    "dnsmasq", "vpxd-main", "eam-main", "eam-api", "winlogbeat",
    "fortigate", "apache", "nginx", "iis", "oracle", "mysql",
    "postgresql", "mongodb", "redis", "docker", "kubernetes",
}

# Windows event terms
WINDOWS_TERMS = {
    "security", "system", "application", "eventdata", "eventid",
    "level", "task", "opcode", "keywords", "channel", "provider",
    "correlation", "execution", "logon", "logoff", "audit",
    "privilege", "process", "object", "handle", "token", "account",
    "microsoft-windows-security-auditing", "winlogbeat",
    "sec_login", "login success", "login failure", "users", "local",
    "localhost", "administrators", "domain users", "domain admins",
    "backup operators", "authenticated users", "everyone",
}

# Cisco ASA terms
CISCO_TERMS = {
    "asa", "deny", "permit", "teardown", "built", "outside", "inside",
    "dmz", "dmz-1", "dmz-2", "management", "access-group", "outside_access_in",
}

# MITRE ATT&CK technique IDs
MITRE_ATTACK_PATTERN_PREFIX = {"T1", "TA0", "T2"}

# NIST/Framework terms
FRAMEWORK_TERMS = {
    "nist", "cis", "cmmc", "pci", "soc2", "iso27001", "csf",
    "hipaa", "gdpr", "ccpa", "d3fend",
}

# Common safe syslog fields
SYSLOG_FIELDS = {
    "local0", "local1", "local2", "local3", "local4", "local5",
    "local6", "local7", "kern", "user", "mail", "daemon", "auth",
    "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "informational", "notice", "warning", "error", "critical",
    "alert", "emergency", "debug",
}

# AWS service names (public, not PII)
AWS_SERVICE_TERMS = {
    "ec2", "s3", "iam", "lambda", "rds", "dynamodb", "cloudwatch",
    "cloudformation", "elasticache", "ecs", "eks", "fargate",
    "sqs", "sns", "ses", "route53", "vpc", "elb", "alb", "nlb",
    "trustedadvisor", "config", "inspector", "guardduty",
    "securityhub", "waf", "shield", "kms", "secretsmanager",
    "ssm", "codepipeline", "codebuild", "codedeploy",
}

# Public domain names that should NOT be sanitized (top services)
PUBLIC_DOMAINS = {
    "google.com", "amazonaws.com", "aws.amazon.com", "microsoft.com",
    "github.com", "cloudfront.net", "azure.com", "office365.com",
    "office.com", "live.com", "outlook.com", "windows.net",
    "akamai.net", "akamaized.net", "cloudflare.com", "fastly.net",
    "facebook.com", "twitter.com", "linkedin.com", "apple.com",
    "ubuntu.com", "debian.org", "centos.org", "redhat.com",
    "docker.io", "docker.com", "npmjs.org", "pypi.org",
    "mozilla.org", "mozilla.com", "firefox.com",
    "crl.microsoft.com", "ocsp.digicert.com", "pki.goog",
    "update.microsoft.com", "download.microsoft.com",
    "example.com", "example.net", "example.org", "example.internal",
    "sni.global.fastly.net",
}


def build_full_allowlist() -> set[str]:
    """Build the complete allowlist of terms that should not be flagged as PII."""
    allowlist = set()
    for group in [
        PROTOCOL_TERMS, VENDOR_TERMS, WINDOWS_TERMS, CISCO_TERMS,
        FRAMEWORK_TERMS, SYSLOG_FIELDS, AWS_SERVICE_TERMS,
    ]:
        allowlist.update(group)
    return allowlist


import re

# Pattern matching our own sanitized replacement tokens
_SANITIZED_TOKEN = re.compile(
    r'^(?:HOST-\d+|USER-\d+|ORG-\d+|CRED-\d+|MACHINE-\d+\$|AGENT-\d+|'
    r'REDACTED-[A-Z]+-\d+|'
    r'domain-\d+\.example\.net|host-\d+\.example\.internal|'
    r'user-\d+@example\.net|'
    r'S-1-5-21-1000000000-2000000000-3000000000-\d+|'
    r'arn:aws:iam::\d+:sanitized/\d+)$',
    re.IGNORECASE,
)


def is_sanitized_token(value: str) -> bool:
    """Check if a value is one of our own sanitized replacement tokens."""
    return bool(_SANITIZED_TOKEN.match(value.strip()))


def is_public_domain(fqdn: str) -> bool:
    """Check if a FQDN belongs to a public domain (should NOT be sanitized)."""
    fqdn_lower = fqdn.lower().strip().rstrip(".")
    if fqdn_lower in PUBLIC_DOMAINS:
        return True
    for pd in PUBLIC_DOMAINS:
        if fqdn_lower.endswith("." + pd):
            return True
    # Common TLDs that are public infrastructure
    public_suffixes = (
        ".com", ".net", ".org", ".edu", ".gov", ".mil", ".io", ".co",
        ".cloud", ".app", ".dev",
    )
    # But only if it's a well-known service, not customer domains.
    # Customer domains should NOT be considered public.
    # So we only return True for domains IN the PUBLIC_DOMAINS set.
    return False


def is_allowed(term: str) -> bool:
    """Check if a term is in the allowlist (case-insensitive)."""
    term_lower = term.lower().strip()

    # Direct match
    full_allowlist = build_full_allowlist()
    if term_lower in full_allowlist:
        return True

    # Public domain
    if term_lower in PUBLIC_DOMAINS:
        return True

    # Ends with a public domain
    for pd in PUBLIC_DOMAINS:
        if term_lower.endswith("." + pd):
            return True

    # MITRE technique ID
    for prefix in MITRE_ATTACK_PATTERN_PREFIX:
        if term_lower.upper().startswith(prefix) and len(term_lower) <= 10:
            return True

    return False
