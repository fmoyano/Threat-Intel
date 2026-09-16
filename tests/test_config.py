import pytest
from threatintel.config import get_threatfox_auth_key

def test_defined_variable(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "123456")
    assert get_threatfox_auth_key() == "123456"

def test_undefined_variable(monkeypatch):
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)
    with pytest.raises(RuntimeError):
        get_threatfox_auth_key()    

def test_empty_variable_value(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "")
    with pytest.raises(RuntimeError):
        get_threatfox_auth_key()
