import json

from threatintel.models import IOC, IOCType
from threatintel.ingest import load_iocs_from_json
from threatintel.pipeline import process_iocs
from threatintel.stats import compute_stats

def test_stats_end_to_end(tmp_path):
    data = [
        {
            "type": "domain",
            "value": "EVIL.COM.",
            "source": "feed_a",
        },
        {
            "type": "domain",
            "value": "evil.com",
            "source": "feed_b",
        },
        {
            "type": "ip",
            "value": "192.168.1.10",
            "source": "feed_a",
        },
        {
            "type": "sha256",
            "value": "A" * 64,
            "source": "feed_c",
        }
    ]

    path = tmp_path / "iocs.json"

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file)

    unprocessed_result = load_iocs_from_json(path)
    processed_result = process_iocs(unprocessed_result)
    stats = compute_stats(unprocessed_result, processed_result)

    assert stats.indicators_processed == 4
    assert stats.unique_indicators == 3
    assert stats.duplicates == 1
    assert stats.count_by_type[IOCType.DOMAIN] == 1
    assert stats.count_by_type[IOCType.IP] == 1
    assert stats.count_by_type[IOCType.SHA256] == 1

def test_stats_empty_lists():
    stats = compute_stats([], [])
    assert stats.indicators_processed == 0
    assert stats.unique_indicators == 0
    assert stats.duplicates == 0

    for ioc_type in IOCType:
        assert stats.count_by_type[ioc_type] == 0    

def test_stats_one_duplicate():
    list_unprocessed_iocs = [
        IOC(IOCType.DOMAIN, "EVIL.COM.", {"feed_a"}),
        IOC(IOCType.DOMAIN, "evil.com", {"feed_b"}),
        IOC(IOCType.IP, "192.168.1.1", {"feed_c"}),
        IOC(IOCType.SHA256, "A" * 64, {"feed_b"}),
    ]

    list_processed_iocs = [
        IOC(IOCType.DOMAIN, "evil.com", {"feed_a", "feed_b"}),        
        IOC(IOCType.IP, "192.168.1.1", {"feed_c"}),
        IOC(IOCType.SHA256, "a" * 64, {"feed_b"}),
    ]

    stats = compute_stats(list_unprocessed_iocs, list_processed_iocs)
    assert stats.indicators_processed == 4
    assert stats.unique_indicators == 3
    assert stats.duplicates == 1
    assert stats.count_by_type[IOCType.DOMAIN] == 1
    assert stats.count_by_type[IOCType.IP] == 1
    assert stats.count_by_type[IOCType.SHA256] == 1