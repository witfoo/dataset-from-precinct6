"""Palo Alto Networks firewall log parser and sanitizer."""

import re
from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.patterns import IPV4, is_private_ip

# BSD syslog header: <pri>Mon DD HH:MM:SS HOSTNAME
BSD_SYSLOG_HEADER = re.compile(
    r'^(<\d+>)(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+'
)


def sanitize_palo_alto(message: str, registry: PIIRegistry) -> str:
    """Sanitize a Palo Alto TRAFFIC/THREAT log message.

    Format: syslog header + CSV fields with IPs at known positions.
    Example: <14>Apr 16 02:53:39 DC1-PA3220-1 1,2023/04/16 02:53:39,...,src_ip,dst_ip,...
    """
    result = message

    # Replace hostname in BSD syslog header
    m = BSD_SYSLOG_HEADER.match(result)
    if m:
        pri = m.group(1)
        timestamp = m.group(2)
        hostname = m.group(3)
        sanitized_host = registry.get_or_create("hostname", hostname)
        result = f"{pri}{timestamp} {sanitized_host} " + result[m.end():]

    # Replace hostname wherever it appears in the body (PAN logs repeat hostname in CSV)
    if m:
        hostname = m.group(3)
        sanitized_host = registry.get("hostname", hostname)
        if sanitized_host:
            result = result.replace(hostname, sanitized_host)

    # Replace all IPs in the message
    def replace_ip(m):
        ip = m.group(0)
        if ip == "0.0.0.0":
            return ip  # NAT placeholder, not PII
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        return registry.get_or_create(cat, ip)

    result = IPV4.sub(replace_ip, result)

    return result
