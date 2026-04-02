"""VMware vCenter log parser and sanitizer."""

from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.patterns import IPV4, SYSLOG_HEADER_HOST, is_private_ip


def sanitize_vmware(message: str, registry: PIIRegistry) -> str:
    """Sanitize a VMware vCenter syslog message."""

    # Replace hostname in syslog header
    def replace_syslog_host(m):
        prefix = m.group(1)
        hostname = m.group(2)
        suffix = m.group(3)
        sanitized = registry.get_or_create("hostname", hostname)
        return f"{prefix}{sanitized}{suffix}"

    result = SYSLOG_HEADER_HOST.sub(replace_syslog_host, message)

    # Replace any IPs in the message
    def replace_ip(m):
        ip = m.group(0)
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        return registry.get_or_create(cat, ip)

    result = IPV4.sub(replace_ip, result)

    return result
