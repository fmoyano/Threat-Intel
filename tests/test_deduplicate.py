from threatintel.models import IOC, IOCType
from threatintel.deduplicate import deduplicate_iocs


def test_empty_list():
    result = deduplicate_iocs([])

    assert result == []

def test_different_iocs():
    ioc1 = IOC(IOCType.DOMAIN, "evil.com", {"feed_a"})
    ioc2 = IOC(IOCType.IP, "203.0.113.42", {"feed_a"})
    result = deduplicate_iocs([ioc1, ioc2])

    assert len(result) == 2

def test_duplicates_combine_sources():
    ioc1 = IOC(IOCType.DOMAIN, "evil.com", {"feed_a"})
    ioc2 = IOC(IOCType.DOMAIN, "evil.com", {"feed_b"})
    result = deduplicate_iocs([ioc1, ioc2])

    assert len(result) == 1
    assert result[0].sources == {"feed_a", "feed_b"}

def test_input_not_change():
    ioc1 = IOC(IOCType.DOMAIN, "evil.com", {"feed_a"})
    ioc2 = IOC(IOCType.DOMAIN, "evil.com", {"feed_b"})
    result = deduplicate_iocs([ioc1, ioc2])

    assert ioc1.sources == {"feed_a"}
    assert ioc2.sources == {"feed_b"}

def test_three_same_iocs():
    ioc1 = IOC(IOCType.DOMAIN, "evil.com", {"feed_a"})
    ioc2 = IOC(IOCType.DOMAIN, "evil.com", {"feed_b"})
    ioc3 = IOC(IOCType.DOMAIN, "evil.com", {"feed_c"})
    result = deduplicate_iocs([ioc1, ioc2, ioc3])

    assert len(result) == 1
    assert result[0].sources == {"feed_a", "feed_b", "feed_c"}