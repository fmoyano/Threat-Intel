import pytest

from threatintel.models import IOC, IOCType
from threatintel.normalize import (
    normalize_domain,
    normalize_ioc,
    normalize_ip,
    normalize_ip_port,
    normalize_sha256,
)


def test_valid_ipv4():
    ipv4 = "192.168.1.10"
    result = normalize_ip(ipv4)

    assert result == ipv4

def test_canonical_ipv6():
    ipv6 = "2001:0db8:0000:0000:0000:ff00:0042:8329"
    result = normalize_ip(ipv6)

    assert result == "2001:db8::ff00:42:8329"

def test_raises_error_invalid_ip():    
    with pytest.raises(ValueError):
        normalize_ip("999.999.999.999")

def test_domain_lowercase():
    result = normalize_domain("EVIL.COM")

    assert result == "evil.com"

def test_domain_removes_trailing_dot():
    result = normalize_domain("evil.com.")

    assert result == "evil.com"

def test_invalid_domain_empty_label():
    with pytest.raises(ValueError):
        normalize_domain(".com")

def test_invalid_domain_label_starts_with_hyphen():
    with pytest.raises(ValueError):
        normalize_domain("-evil.com")

def test_invalid_domain_label_ends_with_hyphen():
    with pytest.raises(ValueError):
        normalize_domain("evil-.com")

def test_invalid_domain_character():
    with pytest.raises(ValueError):
        normalize_domain("evi;l.com")

def test_invalid_too_long_label():
    with pytest.raises(ValueError):
        normalize_domain("a" * 64 + ".com")

def test_valid_max_length_label():
    domain = "a" * 63 + ".com"
    result = normalize_domain(domain)

    assert result == domain

def test_invalid_multiple_trailing_dots():
    with pytest.raises(ValueError):
        normalize_domain("evil.com..")

def test_invalid_non_ascii_character():
    with pytest.raises(ValueError):
        normalize_domain("españa.com")

def test_sha256_lowercase():
    sha256 = "A" * 64
    result = normalize_sha256(sha256)

    assert result == sha256.lower()

def test_valid_sha256_unchanged():
    sha256 = "a" * 64
    result = normalize_sha256(sha256)

    assert result == sha256

def test_short_sha256():
    with pytest.raises(ValueError):
        normalize_sha256("abc")

def test_long_sha256():
    with pytest.raises(ValueError):
        normalize_sha256("a" * 65)

def test_invalid_hex_sha256():
    with pytest.raises(ValueError):
        normalize_sha256("g" * 64)

def test_invalid_char_sha256():
    with pytest.raises(ValueError):
        normalize_sha256("a" * 63 + "-")

def test_normalize_ioc_domain():
    ioc = IOC(IOCType.DOMAIN, "EVIL.COM", {"feed_a"})
    result = normalize_ioc(ioc)

    assert result.value == "evil.com"

def test_normalize_ioc_ip():
    ipv6 = "2001:0db8:0000:0000:0000:ff00:0042:8329"
    ioc = IOC(IOCType.IP, ipv6, {"feed_a"})
    result = normalize_ioc(ioc)

    assert result.value == "2001:db8::ff00:42:8329"

def test_normalize_ioc_sha256():
    ioc = IOC(IOCType.SHA256, "A" * 64, {"feed_a"})
    result = normalize_ioc(ioc)

    assert result.value == "a" * 64

def test_normalization_original_untouched():
    ioc = IOC(IOCType.SHA256, "A" * 64, {"feed_a"})
    result = normalize_ioc(ioc)

    ioc.sources.add("feed_b")

    assert result.sources == {"feed_a"}
    assert ioc.value == "A" * 64

@pytest.mark.parametrize("value",
    [
        "128.1.1.1:65535",
        "128.1.1.1:0",
    ])
def test_normalization_ip_port_limits(value):    
    assert normalize_ip_port(value) == value

def test_normalization_ip_port_non_canonical():    
    assert normalize_ip_port("128.1.1.1:00443") == "128.1.1.1:443"

def test_normalization_ip_port_incorrect_ip():
    with pytest.raises(ValueError):
        normalize_ip_port("999.1.1.1:80")


def test_normalization_ip_port_invalid_port_value():
    with pytest.raises(ValueError):
        normalize_ip_port("128.1.1.1:65536")


@pytest.mark.parametrize("value",
    [        
        "128.1.1.1:abc",
        "128.1.1.1:+80",
        "128.1.1.1: 80",
        "128.1.1.1:1_000",
        "128.1.1.1:",
        "128.1.1.1:-1"
    ])
def test_normalization_ip_port_invalid_port_syntax(value):
     with pytest.raises(ValueError):
        normalize_ip_port(value)

@pytest.mark.parametrize("value",
    [        
        "128.1.1.1",
        "128.1.1.1:80:",
        "128.1.1.1:80:90"
    ])
def test_normalization_ip_port_wrong_format(value):
     with pytest.raises(ValueError):
        normalize_ip_port(value)

def test_normalization_ip_port_numeric_unicode_fails():
    with pytest.raises(ValueError):
        normalize_ip_port("192.168.1.3:٤")

def test_normalization_ip_port_rejects_ipv6():
    with pytest.raises(ValueError):
        normalize_ip_port("[2001:db8::1]:443")