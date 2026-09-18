import json

from threatintel.feeds import threatfox_client
from threatintel.feeds.threatfox_adapter import threatfox_adapt_ioc_list
from threatintel.feeds.threatfox_client import fetch_recent_iocs
from threatintel.ingest import load_iocs_from_json
from threatintel.models import IOCType
from threatintel.pipeline import process_iocs


class FakeResponse:
    def raise_for_status(self):
        pass
        
    def json(self) -> dict:        
        return {
                "query_status": "ok",
                "data": [
                    {
                        "ioc": "EVIL.COM.",
                        "ioc_type": "domain"
                    },
                    {
                        "ioc": "evil.com",
                        "ioc_type": "domain"
                    },                 
                    {
                        "ioc": "A" * 64,
                        "ioc_type": "sha256_hash"
                    },

                    {
                        "ioc": "http://example.com/File",
                        "ioc_type": "url"
                    }
                ]}

def fake_post(url: str, headers: dict, json: dict, timeout: int) -> FakeResponse:
    return FakeResponse()

def test_deduplicates_iocs_across_sources(tmp_path, monkeypatch):
    # From ThreatFox   
    monkeypatch.setattr(threatfox_client.requests, "post", fake_post)
    
    result = fetch_recent_iocs("test_key", 1)
    adapted_threatfox_list = threatfox_adapt_ioc_list(result)
    
    # From local
    local_data = [  
                    {
                        "value": "EVIL.COM.",
                        "type": "domain",
                        "source": "local_feed"
                    },
                    {
                        "value": "evil.com",
                        "type": "domain",
                        "source": "local_feed"
                    },                 
                    {
                        "value": "A" * 64,
                        "type": "sha256",
                        "source": "local_feed"
                    }
                ]

    path = tmp_path / "iocs.json"
    with open(path, "w", encoding="utf-8") as file:
        json.dump(local_data, file)

    local_list = load_iocs_from_json(path)

    # Create full list from local data and threatfox adapted data
    full_list = adapted_threatfox_list + local_list

    final_list = process_iocs(full_list)
    assert len(final_list) == 3

    final_list_by_type = {ioc.type: ioc for ioc in final_list}
    assert final_list_by_type[IOCType.DOMAIN].value == "evil.com"
    assert final_list_by_type[IOCType.DOMAIN].sources == {"threatfox", "local_feed"}
    assert final_list_by_type[IOCType.SHA256].value == "a" * 64
    assert final_list_by_type[IOCType.SHA256].sources == {"threatfox", "local_feed"}
    assert final_list_by_type[IOCType.URL].value == "http://example.com/File"
    assert final_list_by_type[IOCType.URL].sources == {"threatfox"}