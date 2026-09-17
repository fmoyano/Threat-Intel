import pytest

from threatintel.feeds.threatfox_adapter import threatfox_adapt_ioc_list
from threatintel.models import IOCType


def test_valid_domain():
    tf_data = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "evil.example",
                "ioc_type": "domain",
                "malware": "win.something"
            }
        ]
    }

    result = threatfox_adapt_ioc_list(tf_data)
    assert len(result) == 1
    assert result[0].type == IOCType.DOMAIN
    assert result[0].value == "evil.example"
    assert result[0].sources == {"threatfox"}

def test_two_domains():
    tf_data = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "evil.example",
                "ioc_type": "domain",
                "malware": "win.something"
            },
            {
                "ioc": "evil2.example",
                "ioc_type": "domain",
                "malware": "linux.something"
            }
        ]
    }

    result = threatfox_adapt_ioc_list(tf_data)
    assert len(result) == 2
    assert result[0].type == IOCType.DOMAIN
    assert result[0].value == "evil.example"
    assert result[0].sources == {"threatfox"}
    assert result[1].type == IOCType.DOMAIN
    assert result[1].value == "evil2.example"
    assert result[1].sources == {"threatfox"}

def test_ignore_url():
    tf_data = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "evil.example",
                "ioc_type": "url",
                "url_value": "http://example.com"
            }            
        ]
    }

    result = threatfox_adapt_ioc_list(tf_data)
    assert len(result) == 0


def test_url_domain():
    tf_data = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "evil.example",
                "ioc_type": "domain",
                "malware": "win.something"
            },
            {
                "ioc": "evil2.example",
                "ioc_type": "url",
                "url_value": "http://example.com"
            }
        ]
    }

    result = threatfox_adapt_ioc_list(tf_data)
    assert len(result) == 1
    assert result[0].type == IOCType.DOMAIN
    assert result[0].value == "evil.example"
    assert result[0].sources == {"threatfox"}

def test_keeps_domain_value():
    tf_data = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "EVIL.COM.",
                "ioc_type": "domain",
                "malware": "win.something"
            }
        ]
    }

    result = threatfox_adapt_ioc_list(tf_data)
    assert len(result) == 1
    assert result[0].type == IOCType.DOMAIN
    assert result[0].value == "EVIL.COM."
    assert result[0].sources == {"threatfox"}

def test_sha256():
    tf_data = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "A" * 64,
                "ioc_type": "sha256_hash",
                "malware": "win.something"
            }
        ]
    }

    result = threatfox_adapt_ioc_list(tf_data)
    assert len(result) == 1
    assert result[0].type == IOCType.SHA256
    assert result[0].value == "A" * 64
    assert result[0].sources == {"threatfox"}


def test_empty_input():
    with pytest.raises(ValueError):
        threatfox_adapt_ioc_list({})

def test_query_status_error():
    tf_data = {
        "query_status": "not_ok",
        "data": [
            {
                "ioc": "evil.example",
                "ioc_type": "domain",
                "malware": "win.something"
            },
            {
                "ioc": "evil2.example",
                "ioc_type": "url",
                "url_value": "http://example.com"
            }
        ]
    }

    with pytest.raises(ValueError):
        threatfox_adapt_ioc_list(tf_data)

def test_query_missing_query_status():
    tf_data = {
        "data": [
            {
                "ioc": "evil.example",
                "ioc_type": "domain",
                "malware": "win.something"
            },
            {
                "ioc": "evil2.example",
                "ioc_type": "url",
                "url_value": "http://example.com"
            }
        ]
    }

    with pytest.raises(ValueError):
        threatfox_adapt_ioc_list(tf_data)

def test_missing_data():
    tf_data = {
        "query_status": "ok"        
    }

    with pytest.raises(TypeError):
        threatfox_adapt_ioc_list(tf_data)

def test_empty_data():
    tf_data = {
        "query_status": "ok",
        "data":[]
    }
    
    result = threatfox_adapt_ioc_list(tf_data)
    assert len(result) == 0


def test_missing_ioc_type():
    tf_data = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "evil.example",
                "malware": "win.something"
            }
        ]
    }

    with pytest.raises(ValueError):
        threatfox_adapt_ioc_list(tf_data)    

def test_missing_ioc():
    tf_data = {
        "query_status": "ok",
        "data": [
            {               
                "ioc_type": "domain",
                "malware": "win.something"
            }
        ]
    }

    with pytest.raises(ValueError):
        threatfox_adapt_ioc_list(tf_data)

def test_wrong_input_type():
    with pytest.raises(ValueError):
        threatfox_adapt_ioc_list([])

def test_wrong_data_type():
    tf_data = {
        "query_status": "ok",
        "data": {}
    }
    
    with pytest.raises(TypeError):
        threatfox_adapt_ioc_list(tf_data)

def test_wrong_data_list_type():
    tf_data = {
        "query_status": "ok",
        "data": ["hola"]
    }
    
    with pytest.raises(TypeError):
        threatfox_adapt_ioc_list(tf_data)

def test_wrong_ioc_type_type():
    tf_data = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "evil.example",
                "ioc_type": 123,
                "malware": "win.something"
            }
        ]
    }

    with pytest.raises(TypeError):
        threatfox_adapt_ioc_list(tf_data)

def test_url_without_ioc():
    tf_data = {
        "query_status": "ok",
        "data": [
            {                
                "ioc_type": "url",
                "malware": "win.something"
            }
        ]
    }

    result = threatfox_adapt_ioc_list(tf_data)
    assert result == []

def test_ip_port():
    tf_data = {
        "query_status": "ok",
        "data": [
            {
                "ioc_type": "ip:port",
                "ioc": "128.1.1.1:0080"
            }
        ]
    }

    result = threatfox_adapt_ioc_list(tf_data)
    assert len(result) == 1
    assert result[0].value == "128.1.1.1:0080"
    assert result[0].type == IOCType.IP_PORT
    assert result[0].sources == {"threatfox"}