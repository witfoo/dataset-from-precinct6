"""AWS CloudTrail event parser and sanitizer."""

import json
from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.patterns import IPV4, AWS_ACCOUNT_ID, AWS_ARN, is_private_ip


# CloudTrail keys that contain PII
_CT_PII_KEYS = {
    "accountId": "aws_account",
    "sourceIPAddress": "ip",
    "recipientAccountId": "aws_account",
    "userName": "username",
    "arn": "arn",
    "principalId": "credential",
    "accessKeyId": "credential",
    "sessionIssuer": None,  # nested dict
}

# Keys safe to pass through
_CT_SAFE_KEYS = {
    "eventTime", "eventSource", "eventName", "awsRegion",
    "eventType", "eventCategory", "eventVersion",
    "readOnly", "managementEvent",
    "userAgent", "requestParameters", "responseElements",
    "eventID", "errorCode", "errorMessage",
}


def sanitize_cloudtrail(message: str, registry: PIIRegistry) -> str:
    """Sanitize AWS CloudTrail event data in a message."""
    # CloudTrail events may be in the artifact_json fields directly,
    # or embedded in the message field
    try:
        data = json.loads(message) if message.strip().startswith("{") else None
    except json.JSONDecodeError:
        data = None

    if data:
        sanitized = _sanitize_ct_dict(data, registry)
        return json.dumps(sanitized, separators=(",", ":"))

    # If not JSON, apply regex-based sanitization
    return _sanitize_ct_text(message, registry)


def _sanitize_ct_dict(d: dict, registry: PIIRegistry) -> dict:
    """Recursively sanitize a CloudTrail JSON dict."""
    result = {}
    for key, value in d.items():
        if isinstance(value, dict):
            result[key] = _sanitize_ct_dict(value, registry)
        elif isinstance(value, list):
            result[key] = [
                _sanitize_ct_dict(item, registry) if isinstance(item, dict) else item
                for item in value
            ]
        elif isinstance(value, str):
            result[key] = _sanitize_ct_value(key, value, registry)
        else:
            result[key] = value
    return result


def _sanitize_ct_value(key: str, value: str, registry: PIIRegistry) -> str:
    """Sanitize a single CloudTrail value."""
    if not value:
        return value

    if key in _CT_PII_KEYS:
        pii_type = _CT_PII_KEYS[key]

        if pii_type == "aws_account":
            return registry.get_or_create("aws_account", value)

        if pii_type == "ip":
            if IPV4.fullmatch(value):
                cat = "ipv4_priv" if is_private_ip(value) else "ipv4_pub"
                return registry.get_or_create(cat, value)
            # May be a hostname like "ec2.amazonaws.com" — safe
            return value

        if pii_type == "username":
            return registry.get_or_create("username", value)

        if pii_type == "arn":
            return _sanitize_arn(value, registry)

        if pii_type == "credential":
            return registry.get_or_create("credential", value)

    # Check for ARN-like values in other fields
    if value.startswith("arn:aws"):
        return _sanitize_arn(value, registry)

    # Check for account IDs in other fields
    if AWS_ACCOUNT_ID.fullmatch(value):
        return registry.get_or_create("aws_account", value)

    return value


def _sanitize_arn(arn: str, registry: PIIRegistry) -> str:
    """Sanitize an AWS ARN, replacing account ID and resource identifiers."""
    # arn:aws:service:region:account-id:resource
    parts = arn.split(":")
    if len(parts) >= 5:
        # Sanitize account ID (part 4)
        if parts[4] and parts[4].isdigit():
            parts[4] = registry.get_or_create("aws_account", parts[4])
        # Sanitize resource (part 5+) — may contain usernames
        if len(parts) >= 6:
            resource = ":".join(parts[5:])
            if "/" in resource:
                resource_parts = resource.split("/")
                # resource_type/resource_name
                if len(resource_parts) >= 2:
                    resource_parts[-1] = registry.get_or_create("credential", resource_parts[-1])
                resource = "/".join(resource_parts)
            parts = parts[:5] + [resource]
        return ":".join(parts)
    return registry.get_or_create("arn", arn)


def _sanitize_ct_text(text: str, registry: PIIRegistry) -> str:
    """Sanitize CloudTrail data in non-JSON text format."""
    def replace_ip(m):
        ip = m.group(0)
        cat = "ipv4_priv" if is_private_ip(ip) else "ipv4_pub"
        return registry.get_or_create(cat, ip)

    result = IPV4.sub(replace_ip, text)

    # Replace 12-digit account IDs in context
    def replace_acct(m):
        acct = m.group(0)
        return registry.get_or_create("aws_account", acct)

    result = AWS_ACCOUNT_ID.sub(replace_acct, result)

    return result
