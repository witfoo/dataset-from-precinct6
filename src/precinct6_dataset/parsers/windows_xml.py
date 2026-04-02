"""Windows Security Event XML parser and sanitizer."""

import re
from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.patterns import (
    XML_PII_ELEMENTS, XML_COMPUTER, IPV4, WINDOWS_SID, FQDN,
    is_private_ip,
)

# XML elements that contain usernames
_USERNAME_ELEMENTS = {
    "targetusername", "subjectusername",
}

# XML elements that contain hostnames
_HOSTNAME_ELEMENTS = {
    "workstationname", "targetservername", "computer",
}

# XML elements that contain IPs
_IP_ELEMENTS = {
    "ipaddress",
}

# XML elements that contain domain names
_DOMAIN_ELEMENTS = {
    "targetdomainname", "subjectdomainname",
}

# XML elements that contain SIDs
_SID_ELEMENTS = {
    "targetlogonid", "subjectlogonid",
}

# Elements that contain file paths (may contain hostnames)
_PATH_ELEMENTS = {
    "callerprocessname", "objectname",
}


def sanitize_windows_xml(message: str, registry: PIIRegistry) -> str:
    """Sanitize a Windows Security Event XML message."""

    def replace_element(m):
        element_name = m.group(1)
        value = m.group(2).strip()
        name_lower = element_name.lower()

        if not value or value == "-" or value == "%%1793" or value.startswith("%%"):
            return m.group(0)  # Windows well-known constants

        if name_lower in _USERNAME_ELEMENTS:
            if value in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-"):
                return m.group(0)
            sanitized = registry.get_or_create("username", value)
            return f"<{element_name}>{sanitized}</{element_name}>"

        if name_lower in _HOSTNAME_ELEMENTS:
            sanitized = _sanitize_xml_hostname(value, registry)
            return f"<{element_name}>{sanitized}</{element_name}>"

        if name_lower in _IP_ELEMENTS:
            if IPV4.fullmatch(value):
                cat = "ipv4_priv" if is_private_ip(value) else "ipv4_pub"
                sanitized = registry.get_or_create(cat, value)
                return f"<{element_name}>{sanitized}</{element_name}>"
            if value == "-" or value == "::1" or value == "127.0.0.1":
                return m.group(0)
            return m.group(0)

        if name_lower in _DOMAIN_ELEMENTS:
            if value in ("NT AUTHORITY", "BUILTIN", "NT SERVICE", "-", "Window Manager"):
                return m.group(0)
            sanitized = registry.get_or_create("org", value)
            return f"<{element_name}>{sanitized}</{element_name}>"

        if name_lower in _SID_ELEMENTS:
            if WINDOWS_SID.fullmatch(value):
                sanitized = registry.get_or_create("sid", value)
                return f"<{element_name}>{sanitized}</{element_name}>"
            return m.group(0)

        if name_lower in _PATH_ELEMENTS:
            # Sanitize any embedded hostnames or IPs in paths
            sanitized = _sanitize_path(value, registry)
            return f"<{element_name}>{sanitized}</{element_name}>"

        return m.group(0)

    result = XML_PII_ELEMENTS.sub(replace_element, message)

    # Handle Computer element separately (not in the union pattern)
    def replace_computer(m):
        value = m.group(1).strip()
        sanitized = _sanitize_xml_hostname(value, registry)
        return f"<Computer>{sanitized}</Computer>"

    result = XML_COMPUTER.sub(replace_computer, result)

    return result


def _sanitize_xml_hostname(value: str, registry: PIIRegistry) -> str:
    """Sanitize a hostname found in XML."""
    if IPV4.fullmatch(value):
        cat = "ipv4_priv" if is_private_ip(value) else "ipv4_pub"
        return registry.get_or_create(cat, value)
    if "." in value and FQDN.fullmatch(value):
        return registry.get_or_create("fqdn", value)
    return registry.get_or_create("hostname", value)


def _sanitize_path(value: str, registry: PIIRegistry) -> str:
    """Sanitize file paths that may contain hostnames."""
    # Replace any embedded IPs
    def replace_ip(m):
        ip = m.group(0)
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        return registry.get_or_create(cat, ip)

    result = IPV4.sub(replace_ip, value)
    return result
