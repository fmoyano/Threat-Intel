import pytest
from threatintel.feeds import threatfox_orchestrator
from threatintel.feeds.threatfox_orchestrator import get_threatfox_iocs
from threatintel.models import IOC, IOCType

def test_threatfox_orchestrator_happy_path(monkeypatch):

    days_passed_as_argument = 3

    fake_client_response = {
            "query_status": "ok",
            "data":[
                {
                    "ioc_type": "domain",
                    "ioc": "EVIL.COM."
                },
                {
                    "ioc_type": "url",
                    "ioc": "http://example.com"
                }
            ]
        }

    expected_iocs = [IOC(IOCType.DOMAIN, "EVIL.COM.", {"threatfox"})]

    def fake_get_auth_key() -> str:
        return "fake-key"

    def fake_fetch_recent_iocs(auth_key: str, days: int = 1) -> dict:
        assert auth_key == "fake-key"
        assert days == days_passed_as_argument
        return fake_client_response

    def fake_adapt_ioc_list(data: dict) -> list[IOC]:
        assert data == fake_client_response
        return expected_iocs

    monkeypatch.setattr(threatfox_orchestrator, "get_threatfox_auth_key", fake_get_auth_key)
    monkeypatch.setattr(threatfox_orchestrator, "fetch_recent_iocs", fake_fetch_recent_iocs)
    monkeypatch.setattr(threatfox_orchestrator, "threatfox_adapt_ioc_list", fake_adapt_ioc_list)

    result = get_threatfox_iocs(days_passed_as_argument)
    assert len(result) == 1

    # orchestrator must return without alteration what the adapter returns
    assert result is expected_iocs 


def test_threatfox_orchestrator_propagates_config_error(monkeypatch):

    def fake_get_auth_key() -> str:
        raise RuntimeError("ThreatFox key not configured/found.")

    def fake_fetch_recent_iocs(auth_key: str, days: int = 1) -> dict:
        raise AssertionError("fetch should not be called after RuntimeError")

    def fake_adapt_ioc_list(data: dict) -> list[IOC]:
        raise AssertionError("adapter should not be called after RuntimeError")

    monkeypatch.setattr(threatfox_orchestrator, "get_threatfox_auth_key", fake_get_auth_key)
    monkeypatch.setattr(threatfox_orchestrator, "fetch_recent_iocs", fake_fetch_recent_iocs)
    monkeypatch.setattr(threatfox_orchestrator, "threatfox_adapt_ioc_list", fake_adapt_ioc_list)

    with pytest.raises(RuntimeError):
        get_threatfox_iocs(3)


def test_threatfox_orchestrator_propagates_client_error(monkeypatch):

    days_passed_as_argument = 3

    def fake_get_auth_key() -> str:
        return "test-key"

    class FakeClientError(Exception):
        pass

    def fake_fetch_recent_iocs(auth_key: str, days: int = 1) -> dict:
        assert auth_key == "test-key"        
        assert days == days_passed_as_argument
        raise FakeClientError()

    def fake_adapt_ioc_list(data: dict) -> list[IOC]:
        raise AssertionError("adapter should not be called after timeout")

    monkeypatch.setattr(threatfox_orchestrator, "get_threatfox_auth_key", fake_get_auth_key)
    monkeypatch.setattr(threatfox_orchestrator, "fetch_recent_iocs", fake_fetch_recent_iocs)
    monkeypatch.setattr(threatfox_orchestrator, "threatfox_adapt_ioc_list", fake_adapt_ioc_list)

    with pytest.raises(FakeClientError):
        get_threatfox_iocs(days_passed_as_argument)