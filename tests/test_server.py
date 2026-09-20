"""
Tests for server.py — API routes, authentication, lifespan, and Pydantic validation.
"""

import os
import pytest
from starlette.testclient import TestClient
from server import app

client = TestClient(app)


def test_health_check():
    """Verify /api/health returns properly structured status JSON."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert "configured" in data
    assert "gemini_key" in data
    assert "panos_key" in data
    assert "firewall_reachable" in data
    assert "firewall_ip" in data
    assert "mode" in data
    assert "fleet" in data


def test_liveness_and_readiness_probes():
    """Verify /healthz and /readyz Kubernetes-standard health probes."""
    # Liveness probe
    live_resp = client.get("/healthz")
    assert live_resp.status_code == 200
    assert live_resp.json() == {"status": "alive"}

    # Readiness probe
    ready_resp = client.get("/readyz")
    assert ready_resp.status_code == 200
    rdata = ready_resp.json()
    assert rdata["status"] == "ready"
    assert "mode" in rdata
    assert "gemini_authenticated" in rdata
    assert "playbooks_loaded" in rdata
    assert "tools_loaded" in rdata
    assert "fleet" in rdata


def test_auth_middleware_blocks_unauthorized():
    """Protected endpoints like /api/devices must return 401 without X-API-Key."""
    # Temporarily ensure API_ACCESS_KEY is present
    old_key = os.environ.get("API_ACCESS_KEY")
    os.environ["API_ACCESS_KEY"] = "test-secret-key-12345"
    try:
        response = client.get("/api/devices")
        assert response.status_code == 401
    finally:
        if old_key is not None:
            os.environ["API_ACCESS_KEY"] = old_key
        else:
            os.environ.pop("API_ACCESS_KEY", None)


def test_auth_middleware_permits_authorized():
    """Protected endpoints allow access when valid X-API-Key is provided."""
    old_key = os.environ.get("API_ACCESS_KEY")
    test_key = "test-secret-key-12345"
    os.environ["API_ACCESS_KEY"] = test_key
    try:
        response = client.get("/api/devices", headers={"X-API-Key": test_key})
        # Should succeed (200) and return firewalls dict
        assert response.status_code == 200
        assert "firewalls" in response.json()
    finally:
        if old_key is not None:
            os.environ["API_ACCESS_KEY"] = old_key
        else:
            os.environ.pop("API_ACCESS_KEY", None)


def test_pydantic_validation_chat_empty():
    """POST /api/chat with empty or missing payload should return 422 Unprocessable Entity."""
    test_key = os.environ.get("API_ACCESS_KEY", "default-key")
    response = client.post(
        "/api/chat",
        headers={"X-API-Key": test_key},
        json={}  # missing 'message' field
    )
    assert response.status_code == 422


def test_pydantic_validation_schedule_update():
    """POST /api/cards/schedule with missing required fields should return 422."""
    test_key = os.environ.get("API_ACCESS_KEY", "default-key")
    response = client.post(
        "/api/cards/schedule",
        headers={"X-API-Key": test_key},
        json={"invalid_field": 123}  # missing 'card_key'
    )
    assert response.status_code == 422


def test_setup_unauthorized_reconfiguration_blocked():
    """If API_ACCESS_KEY already exists, setup without valid key should be rejected with 403."""
    old_key = os.environ.get("API_ACCESS_KEY")
    os.environ["API_ACCESS_KEY"] = "already-configured-secret"
    try:
        response = client.post(
            "/api/setup",
            json={
                "backend_type": "dotenv",
                "firewall_ip": "10.0.0.1",
                "panos_key": "some-key",
                "gemini_key": "some-key"
            }
        )
        assert response.status_code == 403
        data = response.json()
        assert data["success"] is False
        assert "already configured" in data["error"].lower()
    finally:
        if old_key is not None:
            os.environ["API_ACCESS_KEY"] = old_key
        else:
            os.environ.pop("API_ACCESS_KEY", None)


def test_card_run_missing_key():
    """POST /api/cards/run with non-existent card returns 404 cleanly without raising 500."""
    test_key = os.environ.get("API_ACCESS_KEY", "default-key")
    response = client.post(
        "/api/cards/run",
        headers={"X-API-Key": test_key},
        json={"card_key": "non_existent_card_xyz_123"}
    )
    assert response.status_code == 404
    data = response.json()
    assert data["success"] is False
    assert "not found" in data["error"].lower()
