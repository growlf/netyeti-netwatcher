import os
import sys

from fastapi.testclient import TestClient

# Ensure the agent source directory is on the path when running tests outside Docker
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src", "agent"))

from main import app  # noqa: E402

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
