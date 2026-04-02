"""Generic/fallback message sanitizer — applies all patterns."""

from precinct6_dataset.registry import PIIRegistry
import re
from precinct6_dataset.patterns import (
    IPV4, EMAIL, WINDOWS_SID, MACHINE_ACCOUNT, AWS_ACCOUNT_ID,
    AWS_ARN, TRUSTED_ADVISOR, FQDN, DOMAIN_BACKSLASH_USER,
    KNOWN_CUSTOMER_DOMAINS, HEX_ENCODED_IP,
    is_private_ip, is_sanitized_ip, decode_hex_ip, encode_ip_hex,
    MERAKI_FLOW_IP,
)
from precinct6_dataset.allowlists import is_public_domain

# BSD syslog header: <pri>Mon DD HH:MM:SS HOSTNAME (or with year)
BSD_SYSLOG_HEADER = re.compile(
    r'^(<\d+>)(\w{3}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}[:.]*\s*)(\S+)(\s+)'
)

# UNC paths: \\server\share
UNC_PATH = re.compile(r'\\\\([A-Za-z0-9._-]+)((?:\\[A-Za-z0-9._$ -]+)*)')

# LDAP Distinguished Name components: CN=value, OU=value, DC=value
LDAP_DN_COMPONENT = re.compile(r'(CN|OU|DC)=([^,\s]+)', re.IGNORECASE)
from precinct6_dataset.allowlists import is_allowed, PUBLIC_DOMAINS


def sanitize_generic(message: str, registry: PIIRegistry) -> str:
    """Apply all known patterns to sanitize a message. Used as fallback."""

    result = message

    # 0. Replace hostname in BSD syslog header
    m = BSD_SYSLOG_HEADER.match(result)
    if m:
        hostname = m.group(3)
        # Don't sanitize if it looks like an IP (handled below) or a known safe term
        if not IPV4.fullmatch(hostname) and not is_allowed(hostname) and len(hostname) >= 3:
            sanitized_host = registry.get_or_create("hostname", hostname)
            result = f"{m.group(1)}{m.group(2)}{sanitized_host}{m.group(4)}" + result[m.end():]

    # 1. Replace Meraki flow src/dst IPs
    def replace_meraki_ip(m):
        direction = m.group("dir")
        ip = m.group("ip")
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        new_ip = registry.get_or_create(cat, ip)
        return f"{direction}={new_ip}"

    result = MERAKI_FLOW_IP.sub(replace_meraki_ip, result)

    # 2. Replace known customer domains
    def replace_customer_domain(m):
        domain = m.group(0)
        return registry.get_or_create("fqdn", domain)

    result = KNOWN_CUSTOMER_DOMAINS.sub(replace_customer_domain, result)

    # 3. Replace hex-encoded IPs
    def replace_hex_ip(m):
        hex_str = m.group(1)
        real_ip = decode_hex_ip(hex_str)
        if real_ip:
            cat = "ipv4_priv" if is_private_ip(real_ip) else "ipv4_pub"
            sanitized_ip = registry.get_or_create(cat, real_ip)
            return f"IP-{encode_ip_hex(sanitized_ip)}"
        return m.group(0)

    result = HEX_ENCODED_IP.sub(replace_hex_ip, result)

    # 4. Replace TrustedAdvisor credentials
    def replace_ta(m):
        acct = registry.get_or_create("aws_account", m.group(1))
        cred = registry.get_or_create("credential", m.group(2))
        return f"TrustedAdvisor_{acct}_{cred}"

    result = TRUSTED_ADVISOR.sub(replace_ta, result)

    # 5. Replace DOMAIN\user patterns
    def replace_domain_user(m):
        domain = m.group(1)
        user = m.group(2)
        if domain in ("NT AUTHORITY", "BUILTIN", "NT SERVICE"):
            return m.group(0)
        san_domain = registry.get_or_create("org", domain)
        san_user = registry.get_or_create("username", user)
        return f"{san_domain}\\{san_user}"

    result = DOMAIN_BACKSLASH_USER.sub(replace_domain_user, result)

    # 6. Replace email addresses
    def replace_email(m):
        email = m.group(0)
        return registry.get_or_create("email", email)

    result = EMAIL.sub(replace_email, result)

    # 7. Replace Windows SIDs
    def replace_sid(m):
        sid = m.group(0)
        return registry.get_or_create("sid", sid)

    result = WINDOWS_SID.sub(replace_sid, result)

    # 8. Replace machine accounts
    def replace_machine(m):
        acct = m.group(0)
        return registry.get_or_create("machine_account", acct)

    result = MACHINE_ACCOUNT.sub(replace_machine, result)

    # 9. Replace AWS ARNs
    def replace_arn(m):
        arn = m.group(0)
        return registry.get_or_create("arn", arn)

    result = AWS_ARN.sub(replace_arn, result)

    # 10. Replace UNC paths (\\server\share)
    def replace_unc(m):
        server = m.group(1)
        if not is_allowed(server) and len(server) >= 3:
            san_server = registry.get_or_create("hostname", server)
            return m.group(0).replace(m.group(1), san_server, 1)
        return m.group(0)

    result = UNC_PATH.sub(replace_unc, result)

    # 11. Replace LDAP DN components (CN=user, OU=group, DC=domain)
    def replace_ldap(m):
        attr = m.group(1).upper()
        val = m.group(2)
        if is_allowed(val) or len(val) < 2:
            return m.group(0)
        if attr == "CN":
            return f"{m.group(1)}={registry.get_or_create('username', val)}"
        elif attr in ("DC", "OU"):
            return f"{m.group(1)}={registry.get_or_create('org', val)}"
        return m.group(0)

    result = LDAP_DN_COMPONENT.sub(replace_ldap, result)

    # 12. Replace FQDNs in free text (not just known customer domains)
    def replace_fqdn(m):
        fqdn = m.group(0)
        if is_allowed(fqdn) or is_public_domain(fqdn):
            return fqdn
        # Don't re-sanitize already sanitized values
        if fqdn.endswith(('.example.internal', '.example.net', '.example.com', '.example.org')):
            return fqdn
        return registry.get_or_create("fqdn", fqdn)

    result = FQDN.sub(replace_fqdn, result)

    # 13. Replace remaining IPs (last, after format-specific patterns)
    def replace_ip(m):
        ip = m.group(0)
        if is_sanitized_ip(ip):
            return ip
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        return registry.get_or_create(cat, ip)

    result = IPV4.sub(replace_ip, result)

    # 14. Final pass: replace known customer domains in the text
    def replace_known_domain(m):
        domain = m.group(0)
        return registry.get_or_create("fqdn", domain)

    result = KNOWN_CUSTOMER_DOMAINS.sub(replace_known_domain, result)

    return result
