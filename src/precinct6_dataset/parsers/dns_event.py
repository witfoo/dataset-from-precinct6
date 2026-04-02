"""DNS event log parser and sanitizer."""

from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.patterns import IPV4, DNS_REPLY_IP, is_private_ip
from precinct6_dataset.allowlists import PUBLIC_DOMAINS


def sanitize_dns_event(message: str, registry: PIIRegistry) -> str:
    """Sanitize a DNS event message, replacing resolved IPs and private domains."""

    # Handle dns reply/query patterns: "reply example.com is 1.2.3.4"
    def replace_dns_reply(m):
        verb = m.group(1)
        domain = m.group(2)
        ip = m.group(3)

        # Sanitize domain if not public
        sanitized_domain = _sanitize_domain(domain, registry)

        # Sanitize IP
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        sanitized_ip = registry.get_or_create(cat, ip)

        return f"{verb} {sanitized_domain} is {sanitized_ip}"

    result = DNS_REPLY_IP.sub(replace_dns_reply, message)

    # Replace any remaining bare IPs
    def replace_ip(m):
        ip = m.group(0)
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        return registry.get_or_create(cat, ip)

    result = IPV4.sub(replace_ip, result)

    return result


def _sanitize_domain(domain: str, registry: PIIRegistry) -> str:
    """Sanitize a domain name, preserving public domains."""
    domain_lower = domain.lower()

    # Check if it's a public domain
    if domain_lower in PUBLIC_DOMAINS:
        return domain

    # Check if it ends with a public domain
    for pd in PUBLIC_DOMAINS:
        if domain_lower.endswith("." + pd):
            return domain

    # Private/customer domain — sanitize
    return registry.get_or_create("fqdn", domain)
