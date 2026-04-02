"""Layer 2: Format-aware message field sanitization.

Detects the message format based on streamName/messageType/content,
dispatches to the appropriate parser, then runs a generic sweep as safety net.
"""

from precinct6_dataset.registry import PIIRegistry
from precinct6_dataset.parsers.cisco_asa import sanitize_cisco_asa
from precinct6_dataset.parsers.windows_xml import sanitize_windows_xml
from precinct6_dataset.parsers.winlogbeat import sanitize_winlogbeat, WINLOGBEAT_PREFIX
from precinct6_dataset.parsers.aws_cloudtrail import sanitize_cloudtrail
from precinct6_dataset.parsers.dns_event import sanitize_dns_event
from precinct6_dataset.parsers.vmware import sanitize_vmware
from precinct6_dataset.parsers.palo_alto import sanitize_palo_alto
from precinct6_dataset.parsers.generic import sanitize_generic


class MessageFormat:
    CISCO_ASA = "cisco_asa"
    WINDOWS_XML = "windows_xml"
    WINLOGBEAT = "winlogbeat"
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    DNS_EVENT = "dns_event"
    VMWARE = "vmware"
    MERAKI = "meraki"
    PALO_ALTO = "palo_alto"
    GENERIC = "generic"


def detect_message_format(
    message: str,
    stream_name: str = "",
    message_type: str = "",
    pipeline_name: str = "",
) -> str:
    """Detect the format of a message for appropriate parser dispatch."""
    sn = (stream_name or "").lower()
    mt = (message_type or "").lower()
    pn = (pipeline_name or "").lower()

    # Stream name is the most reliable signal
    if sn in ("cisco_asa",):
        return MessageFormat.CISCO_ASA

    if sn in ("windows_security_audit", "microsoft-windows-security-auditing"):
        if message.strip().startswith(WINLOGBEAT_PREFIX):
            return MessageFormat.WINLOGBEAT
        if "<Event" in message or "<EventData" in message:
            return MessageFormat.WINDOWS_XML
        return MessageFormat.WINLOGBEAT

    if sn in ("aws_cloud_trail", "aws_cloudtrail_events"):
        return MessageFormat.AWS_CLOUDTRAIL

    if "cloudtrail" in pn:
        return MessageFormat.AWS_CLOUDTRAIL

    if sn in ("dnsmasq",) or mt == "dns_event":
        return MessageFormat.DNS_EVENT

    if sn in ("vcenter",) or sn in ("vmware",):
        return MessageFormat.VMWARE

    if sn in ("meraki",):
        return MessageFormat.MERAKI

    if sn in ("pan_firewall", "palo_alto") or mt in ("traffic_drop", "traffic_allow"):
        return MessageFormat.PALO_ALTO

    # Content-based fallback
    if message.strip().startswith(WINLOGBEAT_PREFIX):
        return MessageFormat.WINLOGBEAT

    if "<Event" in message[:200] or "<EventData" in message[:200]:
        return MessageFormat.WINDOWS_XML

    if "%ASA-" in message[:200]:
        return MessageFormat.CISCO_ASA

    if "cloudtrail" in message[:200].lower():
        return MessageFormat.AWS_CLOUDTRAIL

    return MessageFormat.GENERIC


def sanitize_message_field(
    message: str,
    registry: PIIRegistry,
    stream_name: str = "",
    message_type: str = "",
    pipeline_name: str = "",
    aho_automaton=None,
) -> str:
    """Sanitize the message field using format-specific parsing + generic sweep.

    Args:
        message: The raw message string
        registry: PII registry for consistent mapping
        stream_name: The streamName from the artifact
        message_type: The messageType from the artifact
        pipeline_name: The pipelineName from the artifact
        aho_automaton: Optional Aho-Corasick automaton for fast substring matching

    Returns:
        Sanitized message string
    """
    if not message:
        return message

    fmt = detect_message_format(message, stream_name, message_type, pipeline_name)

    # Apply format-specific parser
    if fmt == MessageFormat.CISCO_ASA:
        result = sanitize_cisco_asa(message, registry)
    elif fmt == MessageFormat.WINDOWS_XML:
        result = sanitize_windows_xml(message, registry)
    elif fmt == MessageFormat.WINLOGBEAT:
        result = sanitize_winlogbeat(message, registry)
    elif fmt == MessageFormat.AWS_CLOUDTRAIL:
        result = sanitize_cloudtrail(message, registry)
    elif fmt == MessageFormat.DNS_EVENT:
        result = sanitize_dns_event(message, registry)
    elif fmt == MessageFormat.VMWARE:
        result = sanitize_vmware(message, registry)
    elif fmt == MessageFormat.PALO_ALTO:
        result = sanitize_palo_alto(message, registry)
    elif fmt == MessageFormat.MERAKI:
        result = message  # generic handler below covers meraki
    else:
        result = message  # generic will handle it below

    # Always run generic sweep as safety net
    result = sanitize_generic(result, registry)

    # Run Aho-Corasick sweep if automaton is provided
    if aho_automaton is not None:
        result = _aho_corasick_sweep(result, aho_automaton, registry)

    return result


def build_aho_automaton(registry: PIIRegistry):
    """Build Aho-Corasick automaton from full PII registry for fast multi-pattern matching.

    Returns (automaton, patterns_list) where patterns_list[i] = (original_lower, category, sanitized).
    """
    import ahocorasick_rs

    patterns = []
    seen = set()

    for category, original, sanitized in registry.all_entries():
        orig_lower = original.lower().strip()
        # Skip very short patterns (high false positive rate)
        if len(orig_lower) < 4:
            continue
        # Skip our own replacement tokens
        if orig_lower.startswith(("host-", "user-", "org-", "cred-", "machine-",
                                   "agent-", "domain-", "redacted-",
                                   "192.0.2.", "198.51.100.", "203.0.113.", "100.64.",
                                   "s-1-5-21-1000000000",
                                   "arn:aws:iam::1000")):
            continue
        if orig_lower.endswith(("@example.net", ".example.internal", ".example.net")):
            continue
        # Dedup
        if orig_lower in seen:
            continue
        seen.add(orig_lower)
        patterns.append((orig_lower, category, sanitized))

    if not patterns:
        return None, []

    # Build automaton — use LEFTMOST_FIRST for fast build (seconds vs hours)
    # LEFTMOST_LONGEST is too slow for 200k+ patterns
    # Sort patterns longest-first so LEFTMOST_FIRST prefers longer matches
    patterns.sort(key=lambda p: -len(p[0]))
    needles = [p[0] for p in patterns]
    print(f"  Building Aho-Corasick automaton with {len(needles):,} patterns...", flush=True)
    automaton = ahocorasick_rs.AhoCorasick(
        needles,
        matchkind=ahocorasick_rs.MATCHKIND_LEFTMOST_FIRST,
    )

    return automaton, patterns


def _aho_corasick_sweep(
    text: str,
    automaton,
    registry: PIIRegistry,
) -> str:
    """Use Aho-Corasick automaton to find and replace known PII substrings."""
    if automaton is None:
        return text
    return aho_sweep(text, automaton, registry._aho_patterns)


def aho_sweep(text: str, automaton, patterns: list) -> str:
    """Single-pass multi-pattern replacement using Aho-Corasick.

    Args:
        text: Input text to sanitize
        automaton: ahocorasick_rs.AhoCorasick instance
        patterns: List of (original_lower, category, sanitized) tuples matching automaton needle order
    """
    if not text or automaton is None or not patterns:
        return text

    text_lower = text.lower()

    try:
        matches = automaton.find_matches_as_indexes(text_lower)
    except Exception:
        return text

    if not matches:
        return text

    # matches is list of (pattern_idx, start, end) — end is exclusive
    # Deduplicate overlapping matches: keep longest, leftmost wins
    matches.sort(key=lambda m: (m[1], -(m[2] - m[1])))
    filtered = []
    last_end = -1
    for pattern_idx, start, end in matches:
        if start >= last_end:
            filtered.append((pattern_idx, start, end))
            last_end = end

    if not filtered:
        return text

    # Build result by applying replacements
    result_parts = []
    prev_end = 0
    for pattern_idx, start, end in filtered:
        _orig_lower, _category, sanitized = patterns[pattern_idx]
        result_parts.append(text[prev_end:start])
        result_parts.append(sanitized)
        prev_end = end

    result_parts.append(text[prev_end:])
    return "".join(result_parts)
