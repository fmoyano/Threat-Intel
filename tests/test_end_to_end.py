import json

from threatintel.models import IOCType
from threatintel.ingest import load_iocs_from_json
from threatintel.pipeline import process_iocs

def test_end_to_end_json_processing(tmp_path):
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
    result = process_iocs(unprocessed_result)
    result_by_type = {ioc.type: ioc for ioc in result}

    assert len(unprocessed_result) == 4
    assert len(result) == 3
    assert result_by_type[IOCType.DOMAIN].value == "evil.com"
    assert result_by_type[IOCType.DOMAIN].sources == {"feed_a", "feed_b"}
    assert result_by_type[IOCType.IP].value == "192.168.1.10"
    assert result_by_type[IOCType.IP].sources == {"feed_a"}
    assert result_by_type[IOCType.SHA256].value == "a" * 64
    assert result_by_type[IOCType.SHA256].sources == {"feed_c"}

    
