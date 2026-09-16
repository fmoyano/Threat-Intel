from threatintel.feeds import threatfox_client
from threatintel.feeds.threatfox_adapter import threatfox_adapt_ioc_list
from threatintel.feeds.threatfox_client import fetch_recent_iocs
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
                        "ioc": "http:example.com",
                        "ioc_type": "url"
                    },
                ]}

def fake_post(url: str, headers: dict, json: dict, timeout: int) -> FakeResponse:
    return FakeResponse()

def test_threatfox_integration(monkeypatch):   
    monkeypatch.setattr(threatfox_client.requests, "post", fake_post)
    
    result = fetch_recent_iocs("test-key", 1)
    assert result["query_status"] == "ok"

    adapted_list = threatfox_adapt_ioc_list(result)
    assert len(adapted_list) == 3

    final_list = process_iocs(adapted_list)    
    assert len(final_list) == 2

    final_list_by_type = {ioc.type: ioc for ioc in final_list}
    assert final_list_by_type[IOCType.DOMAIN].value == "evil.com"
    assert final_list_by_type[IOCType.DOMAIN].sources == {"threatfox"}
    assert final_list_by_type[IOCType.SHA256].value == "a" * 64
    assert final_list_by_type[IOCType.SHA256].sources == {"threatfox"}