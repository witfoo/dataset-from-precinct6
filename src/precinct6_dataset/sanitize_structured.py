"""Layer 1: Sanitize structured JSON fields with known semantics."""

from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.patterns import (
    IPV4, RFC1918, ORG_WITH_DOMAIN, FQDN, EMAIL, WINDOWS_SID,
    MACHINE_ACCOUNT, AWS_ACCOUNT_ID, TRUSTED_ADVISOR,
    is_private_ip, is_sanitized_ip, is_loopback_ip,
    HEX_ENCODED_IP, decode_hex_ip, encode_ip_hex,
)
from precinct6_dataset.config import KNOWN_ORGS, KNOWN_ORG_DISPLAY, KNOWN_ORG_IDS
from precinct6_dataset.allowlists import is_allowed, is_public_domain, is_sanitized_token


# Fields that are safe to pass through without sanitization
PASSTHROUGH_FIELDS = {
    "messageType", "messagetype",
    "action",
    "streamName", "streamname",
    "pipelineName", "pipelinename",
    "pipelineEntrypoint", "pipelineentrypoint",
    "fieldExtractorName", "fieldextractorname",
    "tags",
    "vendorCode", "vendorcode",
    "protocol",
    "clientPort", "clientport", "serverPort", "serverport",
    "priority", "severityCode", "severitycode",
    "severityLabel", "severitylabel",
    "facilityCode", "facilitycode", "facilityLabel", "facilitylabel",
    "sensitivity",
    "sourceInfo", "sourceinfo",
    "clientSetIds", "clientsetids",
    "serverSetIds", "serversetids",
    "userSetIds", "usersetids",
    "fileSetIds", "filesetids",
    "foreignIds", "foreignids",
    "productIds", "productids",
    "matchedLeadRuleIds", "matchedleadruleids",
    "clientSyn", "clientAck", "clientFin", "clientUrg", "clientPsh", "clientRst",
    "serverSyn", "serverAck", "serverFin", "serverUrg", "serverPsh", "serverRst",
    "clientPackets", "clientBytes", "serverPackets", "serverBytes",
    "clientsyn", "clientack", "clientfin", "clienturg", "clientpsh", "clientrst",
    "serversyn", "serverack", "serverfin", "serverurg", "serverpsh", "serverrst",
    "clientpackets", "clientbytes", "serverpackets", "serverbytes",
    # Timestamps
    "localStartTime", "localstarttime",
    "localEndTime", "localendtime",
    "startTimeUtc", "starttimeutc",
    "endTimeUtc", "endtimeutc",
    "created_at", "updated_at", "observed_at",
    "first_observed_at", "last_observed_at",
    "_created_at", "_created_at_uuid", "_partition",
    # Labels and framework data (preserve as-is)
    "suspicion_score", "status_id", "status_name",
    "mo_id", "mo_name",
    "ttl_interval", "ttl",
    "sets", "primary_sets", "target_sets",
    "frameworks",
    "type",  # node type: host, cred, etc.
    "internal", "managed",
    "needs_create", "needs_update",
    "notified", "analyze_cycles", "last_analyzed",
    "cost", "assigned",
    "lead_count", "top_set",
    # Incident metadata
    "mosteps", "tasks", "cyto",
    "annotations",
    # Program names from syslog (generic, not PII)
    "program", "pid", "application",
    # Dupes (internal tracking)
    "dupes",
    "parent_sets",
    "index_partition",
}

# Fields that contain IP addresses
IP_FIELDS = {
    "clientIP", "clientip",
    "serverIP", "serverip",
    "ip_address", "ip",
    "senderHost", "senderhost",  # sometimes IP, sometimes hostname
}

# Fields that contain organization info
ORG_FIELDS = {
    "organization", "org",
}

# Fields that contain hostnames
HOSTNAME_FIELDS = {
    "localHostname", "localhostname",
    "serverHostname", "serverhostname",
    "clientHostname", "clienthostname",
    "hostname",
}

# Fields that contain usernames
USERNAME_FIELDS = {
    "userName", "username",
}

# Fields that contain credentials
CREDENTIAL_FIELDS = {
    "credential",
}


def sanitize_structured_field(key: str, value, registry: PIIRegistry):
    """Sanitize a single structured field based on its key name.

    Returns the sanitized value, or the original if it's a passthrough.
    """
    if value is None:
        return None

    # Check passthrough
    if key in PASSTHROUGH_FIELDS:
        return value

    # IP address fields
    if key in IP_FIELDS:
        return _sanitize_ip_value(str(value), registry)

    # Organization fields
    if key in ORG_FIELDS:
        return _sanitize_org_value(str(value), registry)

    # Hostname fields
    if key in HOSTNAME_FIELDS:
        return _sanitize_hostname_value(str(value), registry)

    # Username fields
    if key in USERNAME_FIELDS:
        return _sanitize_username_value(str(value), registry)

    # Credential fields
    if key in CREDENTIAL_FIELDS:
        return _sanitize_credential_value(str(value), registry)

    # orgId
    if key in ("orgId", "orgid"):
        return _sanitize_org_id(value, registry)

    # 'name' field — in nodes it may contain IPs or hostnames
    if key == "name":
        if isinstance(value, str) and IPV4.fullmatch(value.strip()):
            return _sanitize_ip_value(value.strip(), registry)
        return value  # incident names like "Bitter Reindeer" are auto-generated

    # _org_id metadata field
    if key == "_org_id":
        return registry.get_or_create("org", str(value))

    # For unknown fields: inspect the value for PII patterns
    if isinstance(value, str):
        return _sanitize_unknown_string(key, value, registry)
    elif isinstance(value, dict):
        return {k: sanitize_structured_field(k, v, registry) for k, v in value.items()}
    elif isinstance(value, list):
        return [
            sanitize_structured_field(key, item, registry) if isinstance(item, (str, dict, list))
            else item for item in value
        ]
    return value


# Safe values that should never be registered as PII
_SAFE_USERNAMES = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
    "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
    "-", "", "root", "nobody", "daemon", "bin", "sys", "adm",
}
_SAFE_DOMAINS = {
    "NT AUTHORITY", "BUILTIN", "NT SERVICE", "Window Manager",
    "Font Driver Host", "IIS APPPOOL", "WORKGROUP",
}


def _sanitize_unknown_string(key: str, value: str, registry: PIIRegistry) -> str:
    """For unrecognized field names, check if the value itself looks like PII."""
    v = value.strip()
    if not v or len(v) < 3 or len(v) > 500:
        return value
    if is_allowed(v):
        return value

    # Quick check: is it already in registry?
    existing = registry.lookup(v)
    if existing:
        return existing

    # IP address
    if IPV4.fullmatch(v) and not is_sanitized_ip(v) and not is_loopback_ip(v):
        cat = "ipv4_priv" if is_private_ip(v) else "ipv4_pub"
        return registry.get_or_create(cat, v)

    # Email
    if EMAIL.fullmatch(v):
        return registry.get_or_create("email", v)

    # Windows SID
    if WINDOWS_SID.fullmatch(v):
        return registry.get_or_create("sid", v)

    # Machine account
    if MACHINE_ACCOUNT.fullmatch(v):
        return registry.get_or_create("machine_account", v)

    # FQDN (not public domain)
    if "." in v and FQDN.fullmatch(v) and not is_public_domain(v):
        return registry.get_or_create("fqdn", v)

    # Field-name hint: classify by key name pattern
    key_lower = key.lower()
    if any(h in key_lower for h in ("host", "computer", "server", "workstation", "machine", "node")):
        if not is_allowed(v) and v != "-":
            return registry.get_or_create("hostname", v)
    elif any(h in key_lower for h in ("user", "account", "principal", "owner", "creator")):
        if v.upper() not in _SAFE_USERNAMES and not is_allowed(v):
            return registry.get_or_create("username", v)
    elif any(h in key_lower for h in ("org", "domain", "company", "tenant", "realm")):
        if v not in _SAFE_DOMAINS and not is_allowed(v):
            return registry.get_or_create("org", v)

    return value


def _sanitize_ip_value(value: str, registry: PIIRegistry) -> str:
    """Sanitize an IP address value."""
    value = value.strip()
    if not IPV4.fullmatch(value):
        # Might be a hostname
        return _sanitize_hostname_value(value, registry)

    if is_private_ip(value):
        return registry.get_or_create("ipv4_priv", value)
    else:
        return registry.get_or_create("ipv4_pub", value)


def _sanitize_org_value(value: str, registry: PIIRegistry) -> str:
    """Sanitize an organization value, handling composite formats."""
    value = value.strip()

    # Handle "OrgName (slug.domain.com)" format (WitFoo org display format)
    m = ORG_WITH_DOMAIN.match(value)
    if m:
        org_name = registry.get_or_create("org", m.group(1).strip())
        domain = registry.get_or_create("domain", m.group(2).strip())
        return f"{org_name} ({domain})"

    # Check known org names (case-insensitive)
    val_lower = value.lower()
    for known, _ in KNOWN_ORGS.items():
        if val_lower == known:
            return registry.get_or_create("org", value)

    for known, _ in KNOWN_ORG_DISPLAY.items():
        if value == known:
            return registry.get_or_create("org", value)

    # Generic org field
    if value:
        return registry.get_or_create("org", value)
    return value


def _sanitize_hostname_value(value: str, registry: PIIRegistry) -> str:
    """Sanitize a hostname value."""
    value = value.strip()
    if not value or value == "-":
        return value

    # Check if it's actually an IP
    if IPV4.fullmatch(value):
        return _sanitize_ip_value(value, registry)

    # Check for hex-encoded IP
    m = HEX_ENCODED_IP.match(value)
    if m:
        real_ip = decode_hex_ip(m.group(1))
        if real_ip:
            sanitized_ip = _sanitize_ip_value(real_ip, registry)
            hex_sanitized = encode_ip_hex(sanitized_ip)
            return f"IP-{hex_sanitized}"

    # FQDN
    if "." in value and FQDN.fullmatch(value):
        return registry.get_or_create("fqdn", value)

    # Simple hostname
    return registry.get_or_create("hostname", value)


def _sanitize_username_value(value: str, registry: PIIRegistry) -> str:
    """Sanitize a username value."""
    value = value.strip()
    if not value or value == "-" or value == "SYSTEM" or value == "LOCAL SERVICE":
        return value

    return registry.get_or_create("username", value)


def _sanitize_credential_value(value: str, registry: PIIRegistry) -> str:
    """Sanitize a credential value."""
    value = value.strip()
    if not value:
        return value

    # TrustedAdvisor pattern
    m = TRUSTED_ADVISOR.match(value)
    if m:
        acct = registry.get_or_create("aws_account", m.group(1))
        return f"TrustedAdvisor_{acct}_{registry.get_or_create('credential', m.group(2))}"

    # Machine account
    if MACHINE_ACCOUNT.match(value):
        return registry.get_or_create("machine_account", value)

    return registry.get_or_create("credential", value)


def _sanitize_org_id(value, registry: PIIRegistry):
    """Sanitize an organization ID."""
    if isinstance(value, int):
        if value in KNOWN_ORG_IDS:
            return KNOWN_ORG_IDS[value]
        return registry.get_or_create("org_id", str(value))
    return value


def sanitize_record_structured(record: dict, registry: PIIRegistry) -> dict:
    """Sanitize all structured fields in a record (Layer 1).

    Handles nested structures (incidents with nodes, edges, leads).
    """
    return _sanitize_dict(record, registry)


def _sanitize_dict(d: dict, registry: PIIRegistry) -> dict:
    """Recursively sanitize a dictionary."""
    result = {}
    for key, value in d.items():
        if key == "message":
            # Layer 2 handles message field
            result[key] = value
        elif isinstance(value, dict):
            result[key] = _sanitize_dict(value, registry)
        elif isinstance(value, list):
            result[key] = _sanitize_list(value, registry)
        else:
            result[key] = sanitize_structured_field(key, value, registry)
    return result


def _sanitize_list(lst: list, registry: PIIRegistry) -> list:
    """Recursively sanitize a list."""
    result = []
    for item in lst:
        if isinstance(item, dict):
            result.append(_sanitize_dict(item, registry))
        elif isinstance(item, list):
            result.append(_sanitize_list(item, registry))
        else:
            result.append(item)
    return result
