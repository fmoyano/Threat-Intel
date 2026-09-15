import pytest
from typing import Callable
from requests import HTTPError, Timeout
from threatintel.feeds import threatfox_client
from threatintel.feeds.threatfox_client import THREATFOX_API_URL, fetch_recent_iocs

def test_0days_fails():
    with pytest.raises(ValueError):
        fetch_recent_iocs("", 0)

def test_8days_fails():
    with pytest.raises(ValueError):
        fetch_recent_iocs("", 8)

class FakeResponse:
    def __init__(self, simulate_http_error: bool = False, simulate_json_error: bool = False):
        self.raise_for_status_called = False
        self.simulate_http_error = simulate_http_error
        self.simulate_json_error = simulate_json_error

    def raise_for_status(self):
        self.raise_for_status_called = True
        if self.simulate_http_error:
            raise threatfox_client.requests.HTTPError()

    def json(self) -> dict:
        if self.simulate_json_error:
            raise ValueError()

        return {"query_status": "ok", "data": []}

def make_fake_post(expected_days: int, expected_auth_key: str,
    fake_response: FakeResponse, simulate_timeout: bool = False) -> Callable:
    def fake_post(url: str, headers: dict, json: dict, timeout: int):

        if simulate_timeout:
            raise threatfox_client.requests.Timeout()

        assert url == THREATFOX_API_URL
        assert headers["Auth-Key"] == expected_auth_key
        assert json["query"] == "get_iocs"
        assert json["days"] == expected_days
        assert timeout > 0
        return fake_response

    return fake_post

def test_1day_ok(monkeypatch):
    days = 1
    auth_key = "test_key"
    fake_response = FakeResponse()

    monkeypatch.setattr(threatfox_client.requests, "post", make_fake_post(days, auth_key, fake_response))
    result = fetch_recent_iocs(auth_key, days)
    
    assert fake_response.raise_for_status_called
    assert result == {"query_status": "ok", "data": []}


def test_7days_ok(monkeypatch):
    days = 7
    auth_key = "test_key"
    fake_response = FakeResponse()

    monkeypatch.setattr(threatfox_client.requests, "post", make_fake_post(days, auth_key, fake_response))
    result = fetch_recent_iocs(auth_key, days)
    
    assert fake_response.raise_for_status_called
    assert result == {"query_status": "ok", "data": []}


def test_happy_path(monkeypatch):
    days = 3
    auth_key = "test_key"    
    fake_response = FakeResponse()
    
    monkeypatch.setattr(threatfox_client.requests, "post", make_fake_post(days, auth_key, fake_response))
    result = fetch_recent_iocs(auth_key, days)
    
    assert fake_response.raise_for_status_called
    assert result == {"query_status": "ok", "data": []}

def test_default_days(monkeypatch):
    auth_key = "test_key"    
    fake_response = FakeResponse()
    
    monkeypatch.setattr(threatfox_client.requests, "post", make_fake_post(1, auth_key, fake_response))
    result = fetch_recent_iocs(auth_key)
    
    assert fake_response.raise_for_status_called
    assert result == {"query_status": "ok", "data": []}

def test_http_error(monkeypatch):
    days = 3
    auth_key = "test_key"    
    fake_response = FakeResponse(simulate_http_error=True)
    
    monkeypatch.setattr(threatfox_client.requests, "post", make_fake_post(days, auth_key, fake_response))
    
    with pytest.raises(HTTPError):
        fetch_recent_iocs(auth_key, days)

def test_timeout(monkeypatch):
    days = 3
    auth_key = "test_key"    
    fake_response = FakeResponse()
    
    monkeypatch.setattr(threatfox_client.requests, "post", make_fake_post(days, auth_key, fake_response, True))
    
    with pytest.raises(Timeout):
        fetch_recent_iocs(auth_key, days)

def test_json_error(monkeypatch):
    days = 3
    auth_key = "test_key"    
    fake_response = FakeResponse(simulate_json_error=True)
    
    monkeypatch.setattr(threatfox_client.requests, "post", make_fake_post(days, auth_key, fake_response))
    
    with pytest.raises(ValueError):
        fetch_recent_iocs(auth_key, days)

    assert fake_response.raise_for_status_called
    