import pytest

from security.scope_validator import (
    ScopeValidator,
    ScopeValidationError
)


@pytest.fixture
def validator():
    return ScopeValidator(
        allowed_domains=["example.com"],
        allowed_ips=["127.0.0.1"]
    )


def test_exact_domain_allowed(validator):
    assert validator.validate("https://example.com") is True


def test_subdomain_rejected_by_default(validator):
    with pytest.raises(ScopeValidationError):
        validator.validate("https://api.example.com")


def test_subdomain_allowed_when_enabled():
    scoped = ScopeValidator(
        allowed_domains=["example.com"],
        allow_subdomains=True
    )
    assert scoped.validate("https://api.example.com") is True


def test_external_domain_rejected(validator):
    with pytest.raises(ScopeValidationError):
        validator.validate("https://google.com")


def test_fake_suffix_rejected(validator):
    with pytest.raises(ScopeValidationError):
        validator.validate("https://example.com.attacker.test")


def test_uppercase_domain_allowed(validator):
    assert validator.validate("https://EXAMPLE.COM") is True


def test_trailing_dot_domain_allowed(validator):
    assert validator.validate("https://example.com.") is True


def test_localhost_ip_allowed(validator):
    assert validator.validate("http://127.0.0.1") is True


def test_unapproved_ip_rejected(validator):
    with pytest.raises(ScopeValidationError):
        validator.validate("http://192.168.1.10")


def test_approved_ipv6_allowed():
    scoped = ScopeValidator(allowed_ips=["::1"])
    assert scoped.validate("http://[::1]") is True


def test_unapproved_ipv6_rejected(validator):
    with pytest.raises(ScopeValidationError):
        validator.validate("http://[::1]")


def test_unsupported_scheme_rejected(validator):
    with pytest.raises(ScopeValidationError):
        validator.validate("ftp://example.com")


def test_empty_target_rejected(validator):
    with pytest.raises(ScopeValidationError):
        validator.validate("")


def test_credentials_rejected(validator):
    with pytest.raises(ScopeValidationError):
        validator.validate("https://user:pass@example.com")


def test_invalid_port_rejected(validator):
    with pytest.raises(ScopeValidationError):
        validator.validate("https://example.com:99999")


def test_malformed_ipv6_rejected(validator):
    with pytest.raises(ScopeValidationError):
        validator.validate("http://[invalid-ipv6]")
