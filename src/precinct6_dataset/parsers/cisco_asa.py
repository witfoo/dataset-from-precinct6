"""Cisco ASA syslog message parser and sanitizer."""

import re
from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.patterns import CISCO_ASA_IFACE_IP, CISCO_ASA_ORIG_ADDR, IPV4, is_private_ip


def sanitize_cisco_asa(message: str, registry: PIIRegistry) -> str:
    """Sanitize a Cisco ASA syslog message, replacing IPs while preserving structure."""

    # Replace IPs in src/dst interface:IP/port patterns
    def replace_iface_ip(m):
        ip = m.group("ip")
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        new_ip = registry.get_or_create(cat, ip)
        return f'{m.group("direction")} {m.group("iface")}:{new_ip}/{m.group("port")}'

    result = CISCO_ASA_IFACE_IP.sub(replace_iface_ip, message)

    # Replace Original Address= patterns (Meraki-style)
    def replace_orig_addr(m):
        ip = m.group("ip")
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        new_ip = registry.get_or_create(cat, ip)
        return f'Original Address={new_ip}'

    result = CISCO_ASA_ORIG_ADDR.sub(replace_orig_addr, result)

    # Catch any remaining bare IPs not in the above patterns
    def replace_bare_ip(m):
        ip = m.group(0)
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        return registry.get_or_create(cat, ip)

    result = IPV4.sub(replace_bare_ip, result)

    return result
