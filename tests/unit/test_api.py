import os
import sys

import pytest
from fastapi.testclient import TestClient

# Ensure the agent source directory is on the path when running tests outside Docker
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src", "agent"))

from main import app, _validate_http_url  # noqa: E402

client = TestClient(app)

def test_dashboard_200_ok():
    """
    Simulates a web request to the root dashboard endpoint to ensure
    the Jinja2 templates compile correctly and the route doesn't crash.
    This runs without triggering the lifespan background loops!
    """
    response = client.get("/")
    assert response.status_code == 200
    assert "NetWatch AI" in response.text
    assert "Discovered Endpoints" in response.text


class TestValidateHttpUrl:
    """Tests for the _validate_http_url helper function."""

    def test_local_url_accepted_without_allowlist(self, monkeypatch):
        """Without ALLOWED_LLM_HOSTS any valid http(s) URL should be accepted."""
        monkeypatch.delenv("ALLOWED_LLM_HOSTS", raising=False)
        result = _validate_http_url("http://127.0.0.1:11434")
        assert result == "http://127.0.0.1:11434"

    def test_private_network_url_accepted_without_allowlist(self, monkeypatch):
        """Private-network Ollama hosts must be accepted when no allowlist is set."""
        monkeypatch.delenv("ALLOWED_LLM_HOSTS", raising=False)
        result = _validate_http_url("http://192.168.1.100:11434")
        assert result == "http://192.168.1.100:11434"

    def test_https_url_accepted_without_allowlist(self, monkeypatch):
        monkeypatch.delenv("ALLOWED_LLM_HOSTS", raising=False)
        result = _validate_http_url("https://ollama.example.com")
        assert result == "https://ollama.example.com:443"

    def test_url_with_trailing_slash_normalized(self, monkeypatch):
        monkeypatch.delenv("ALLOWED_LLM_HOSTS", raising=False)
        result = _validate_http_url("http://127.0.0.1:11434/")
        assert result == "http://127.0.0.1:11434"

    def test_invalid_scheme_rejected(self, monkeypatch):
        monkeypatch.delenv("ALLOWED_LLM_HOSTS", raising=False)
        with pytest.raises(ValueError, match="http"):
            _validate_http_url("ftp://127.0.0.1:11434")

    def test_missing_hostname_rejected(self, monkeypatch):
        monkeypatch.delenv("ALLOWED_LLM_HOSTS", raising=False)
        with pytest.raises(ValueError):
            _validate_http_url("http://")

    def test_allowlist_match_accepted(self, monkeypatch):
        monkeypatch.setenv("ALLOWED_LLM_HOSTS", "http://192.168.1.50:11434")
        result = _validate_http_url("http://192.168.1.50:11434")
        assert result == "http://192.168.1.50:11434"

    def test_allowlist_no_match_rejected(self, monkeypatch):
        monkeypatch.setenv("ALLOWED_LLM_HOSTS", "http://192.168.1.50:11434")
        with pytest.raises(ValueError, match="allowed"):
            _validate_http_url("http://192.168.1.99:11434")
