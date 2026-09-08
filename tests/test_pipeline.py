import pytest
from threatintel.models import IOC, IOCType
from threatintel.pipeline import process_iocs

def test_pipeline_same_ioc():
    iocs = [IOC(IOCType.DOMAIN, "EVIL.COM.", {"feed_a"}),
            IOC(IOCType.DOMAIN, "evil.com", {"feed_b"})]

    result = process_iocs(iocs)
    
    assert len(result) == 1
    assert result[0].value == "evil.com"
    assert result[0].sources == {"feed_a", "feed_b"}


def test_pipeline_three_valid_iocs():
    domain = "EVIL.COM."
    ip = "192.168.1.10"
    sha256 = "A" * 64

    iocs = [IOC(IOCType.DOMAIN, domain, {"feed_a"}),
            IOC(IOCType.IP, ip, {"feed_b"}),
            IOC(IOCType.SHA256, sha256, {"feed_c"})]

    result = process_iocs(iocs)
    result_by_type = {ioc.type: ioc for ioc in result}

    assert len(result) == 3
    assert result_by_type[IOCType.DOMAIN].value == "evil.com"
    assert result_by_type[IOCType.IP].value == ip
    assert result_by_type[IOCType.SHA256].value == sha256.lower()

def test_pipeline_value_error():
    iocs = [IOC(IOCType.DOMAIN, "evil.com", {"feed_a"}),
            IOC(IOCType.IP, "999.999.999.999", {"feed_b"}),
            IOC(IOCType.SHA256, "a" * 64, {"feed_c"})]
    
    with pytest.raises(ValueError):
        process_iocs(iocs)