import pytest
from threatintel.models import IOCType
from threatintel.parser import parse_ioc, parse_iocs

def test_parse_valid_domain():
    dict_ioc = {
        "type": "domain",
        "value": "EVIL.COM.",
        "source": "feed_a",
    }

    result = parse_ioc(dict_ioc)
    assert result.type == IOCType.DOMAIN
    assert result.value == "EVIL.COM."
    assert result.sources == {"feed_a"}

def test_parse_valid_IP():
    dict_ioc = {
        "type": "ip",
        "value": "192.168.1.1",
        "source": "feed_a",
    }

    result = parse_ioc(dict_ioc)
    assert result.type == IOCType.IP
    assert result.value == "192.168.1.1"
    assert result.sources == {"feed_a"}

def test_parse_valid_sha256():
    dict_ioc = {
        "type": "sha256",
        "value": "a" * 64,
        "source": "feed_a",
    }

    result = parse_ioc(dict_ioc)
    assert result.type == IOCType.SHA256
    assert result.value == "a" * 64
    assert result.sources == {"feed_a"}

def test_parse_unknown_ioctype():
    dict_ioc = {
        "type": "banana",
        "value": "a" * 64,
        "source": "feed_a",
    }
    with pytest.raises(ValueError):
        parse_ioc(dict_ioc)
    
def test_parse_missing_field():
    dict_ioc = {
        "type": "sha256",
        "value": "a" * 64,        
    }
    with pytest.raises(ValueError):
        parse_ioc(dict_ioc)

def test_parse_field_type_error():
    dict_ioc = {
        "type": 123,
        "value": "192.168.1.1",
        "source": "feed_a",
    }
    with pytest.raises(ValueError):
        parse_ioc(dict_ioc)

def test_parse_field_type_error2():
    dict_ioc = {
        "type": "domain",
        "value": "evil.com",
        "source": 123
    }
    with pytest.raises(ValueError):
        parse_ioc(dict_ioc)

def test_parse_no_error_more_fields():
    dict_ioc = {
        "type": "domain",
        "value": "evil.com",
        "source": "feed_a",
        "extra": 42
    }

    result = parse_ioc(dict_ioc)
    assert result.type == IOCType.DOMAIN
    assert result.value == "evil.com"
    assert result.sources == {"feed_a"}

def test_parse_empty_list():
    result = parse_iocs([])
    
    assert result == []

def test_parse_two_valid_entries():
    list_iocs = [
    {
        "type": "domain",
        "value": "evil.com",
        "source": "feed_a",
        "extra": 42
    },
    {
        "type": "ip",
        "value": "192.168.1.1",
        "source": "feed_a",
    }]
    
    result = parse_iocs(list_iocs)    
    
    assert len(result) == 2
    assert result[0].type == IOCType.DOMAIN
    assert result[1].type == IOCType.IP

def test_parse_one_invalid_entry():
    list_iocs = [
    {
        "type": "domain",
        "value": "evil.com",
        "source": "feed_a",
        "extra": 42
    },
    {
        "type": "ip",
        "value": "192.168.1.1",
        "source": 1,
    }]
    
    with pytest.raises(ValueError):
        parse_iocs(list_iocs)