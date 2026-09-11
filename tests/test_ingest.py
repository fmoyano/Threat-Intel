import json

from threatintel.ingest import load_iocs_from_json
from threatintel.models import IOCType

def test_load_iocs_from_json(tmp_path):
    data = [
        {
            "type": "domain",
            "value": "EVIL.COM.",
            "source": "feed_a",
        },
        {
            "type": "ip",
            "value": "192.168.1.1",
            "source": "feed_b",
        },
    ]

    path = tmp_path / "iocs.json"

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file)

    result = load_iocs_from_json(path)

    assert len(result) == 2
    assert result[0].type == IOCType.DOMAIN
    assert result[0].value == "EVIL.COM."
    assert result[1].type == IOCType.IP