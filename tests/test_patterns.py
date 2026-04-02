"""Test regex patterns."""

from precinct6_dataset.patterns import (
    IPV4, FQDN, EMAIL, WINDOWS_SID, MACHINE_ACCOUNT,
    build_customer_domain_pattern, is_private_ip,
)


def test_ipv4_matches():
    assert IPV4.fullmatch("192.168.1.1")
    assert IPV4.fullmatch("10.0.0.1")
    assert IPV4.fullmatch("8.8.8.8")
    assert not IPV4.fullmatch("999.999.999.999")
    assert not IPV4.fullmatch("not-an-ip")


def test_private_ip():
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("172.16.0.1")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("1.2.3.4")


def test_fqdn_matches():
    assert FQDN.fullmatch("host.example.com")
    assert FQDN.fullmatch("a.b.c.d.example.com")
    assert not FQDN.fullmatch("localhost")
    assert not FQDN.fullmatch("single")


def test_email_matches():
    assert EMAIL.fullmatch("user@example.com")
    assert EMAIL.fullmatch("first.last@company.net")
    assert not EMAIL.fullmatch("not-an-email")


def test_windows_sid():
    assert WINDOWS_SID.fullmatch("S-1-5-21-1234567890-1234567890-1234567890-1001")
    assert not WINDOWS_SID.fullmatch("S-1-5-18")  # well-known, too short


def test_machine_account():
    assert MACHINE_ACCOUNT.fullmatch("HOSTNAME$")
    assert MACHINE_ACCOUNT.fullmatch("DC-SERVER01$")
    assert not MACHINE_ACCOUNT.fullmatch("regular-user")


def test_customer_domain_pattern_empty():
    pattern = build_customer_domain_pattern([])
    assert not pattern.search("anything.example.com")


def test_customer_domain_pattern():
    pattern = build_customer_domain_pattern(["acme.com", "internal.net"])
    assert pattern.search("host.acme.com")
    assert pattern.search("server.internal.net")
    assert not pattern.search("google.com")
