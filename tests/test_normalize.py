import pytest

from threatintel.models import IOC, IOCType
from threatintel.normalize import (
    normalize_domain,
    normalize_ioc,
    normalize_ip,
    normalize_ip_port,
    normalize_sha256,
    normalize_url,
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

def test_normalize_url_domain_lowercase_and_removes_final_dot():
    value = "https://EVIL.COM./Mozi.m"
    result = normalize_url(value)

    assert result == "https://evil.com/Mozi.m"

def test_normalize_url_lowercases_scheme_and_hostname():
    value = "HTTP://EVIL.COM/Mozi.m"
    result = normalize_url(value)

    assert result == "http://evil.com/Mozi.m"

def test_normalize_url_lowercases_scheme_and_hostname_with_numbers():
    value = "HTTP://The4EVIL12.COM/Mozi.m"
    result = normalize_url(value)

    assert result == "http://the4evil12.com/Mozi.m"

def test_normalize_url_preserves_path_case():
    value = "https://example.com/Mozi.M"
    result = normalize_url(value)

    assert result == value

def test_normalize_url_preserves_query_and_fragment():
    value = "https://Example.com/A?x=1#frag"
    result = normalize_url(value)

    assert result == "https://example.com/A?x=1#frag"

@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com/file",
        "ssh://example.com/",
    ],
)
def test_normalize_url_rejects_unsupported_scheme(value):
    with pytest.raises(ValueError):
        normalize_url(value)

@pytest.mark.parametrize(
    "value",
    [
        "https:///path",
        "http://",
    ],
)
def test_normalize_url_requires_hostname(value):
    with pytest.raises(ValueError):
        normalize_url(value)

def test_normalize_url_accepts_ip_hostname():
    value = "http://192.168.1.1:8080/Mozi.m"
    result = normalize_url(value)

    assert result == value

def test_normalize_url_rejects_invalid_ip_hostname():
    with pytest.raises(ValueError):
        normalize_url("http://999.1.1.1:8080/file")

@pytest.mark.parametrize(
    "value",
    [
        "http://example.com:0/",
        "http://example.com:65535/",
    ],
)
def test_normalize_url_accepts_port_limits(value):
    assert normalize_url(value) == value

@pytest.mark.parametrize(
    "value",
    [
        "http://example.com:65536/",
        "http://example.com:-1/",
    ],
)
def test_normalize_url_rejects_invalid_port(value):
    with pytest.raises(ValueError):
        normalize_url(value)

@pytest.mark.parametrize(
    "value",
    [
        "http://example.com:80/",
        "https://example.com:443/",
    ],
)
def test_normalize_url_preserves_explicit_default_port(value):
    assert normalize_url(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "http://-evil.com/file",
        "http://evil_.com/file",
        "http://singlelabel/file",
    ],
)
def test_normalize_url_rejects_invalid_domain_hostname(value):
    with pytest.raises(ValueError):
        normalize_url(value)

def test_normalize_url_normalizes_port_leading_zeroes():
    assert normalize_url("http://example.com:0080/file") == \
           "http://example.com:80/file"

@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://[2001:db8::1]/file", "https://[2001:db8::1]/file"),
        ("https://[2001:0DB8:0:0:0:0:0:1]/file", "https://[2001:db8::1]/file"),
        ("https://[2001:0DB8:0:0:0:0:0:1]:0443/A", "https://[2001:db8::1]:443/A")
    ],
)
def test_normalize_url_ipv6(value, expected):
    assert expected == normalize_url(value)

def test_normalize_url_invalid_ipv6_raises_error():
    with pytest.raises(ValueError):
        normalize_url("https://[2001:db8::::1]")

@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://alice@example.com/file", "https://alice@example.com/file"),
        ("https://alice:secret@example.com/file", "https://alice:secret@example.com/file"),
        ("https://alice:@example.com/file", "https://alice:@example.com/file"),
        ("https://:secret@example.com/file", "https://:secret@example.com/file"),
        ("https://@example.com/file", "https://@example.com/file")
    ],
)
def test_normalize_url_userinfo(value, expected):
    assert expected == normalize_url(value)

def test_normalize_url_preserves_userinfo_case():
    value = "HTTPS://Alice:SeCrEt@EXAMPLE.COM/File"

    assert normalize_url(value) == \
        "https://Alice:SeCrEt@example.com/File"

def test_normalize_url_userinfo_ipv6_and_port():
    value = "https://alice:secret@[2001:0DB8:0:0:0:0:0:1]:08443/File"

    assert normalize_url(value) == \
        "https://alice:secret@[2001:db8::1]:8443/File"