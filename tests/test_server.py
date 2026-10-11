"""
Tests for server.py â€” API routes, authentication, lifespan, and Pydantic validation.
"""

import os
import pytest
from starlette.testclient import TestClient
from server import app

client = TestClient(app)


def test_health_check():
    """Verify /api/health returns properly structured status JSON and vends access_token on loopback dev."""
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
    # TestClient connects as 'testclient' on loopback in development mode
    if os.getenv("API_ACCESS_KEY"):
        assert data.get("access_token") == os.getenv("API_ACCESS_KEY")


def test_health_check_auto_auth_disabled(monkeypatch):
    """Verify /api/health omits access_token when DEV_AUTO_AUTH is explicitly false."""
    monkeypatch.setenv("DEV_AUTO_AUTH", "false")
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert "access_token" not in data


def test_health_check_production_environment(monkeypatch):
    """Verify /api/health omits access_token when ENVIRONMENT is production."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert "access_token" not in data


def test_health_check_proxy_header_blocks_auto_auth():
    """Verify /api/health omits access_token when incoming request has proxy forwarding headers."""
    response = client.get("/api/health", headers={"X-Forwarded-For": "203.0.113.195"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" not in data


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


def test_pydantic_validation_export_doc_missing_trace():
    """POST /api/export/google-doc with missing required fields should return 422."""
    test_key = os.environ.get("API_ACCESS_KEY", "default-key")
    response = client.post(
        "/api/export/google-doc",
        headers={"X-API-Key": test_key},
        json={"invalid_field": 123}  # missing 'trace_id'
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




def test_investigation_receipts_endpoint():
    """GET /api/investigations/{trace_id}/receipts returns 404 on missing, 200 on cached."""
    test_key = os.environ.get("API_ACCESS_KEY", "default-key")
    headers = {"X-API-Key": test_key}

    # 1. Non-existent trace
    resp = client.get("/api/investigations/non-existent-trace/receipts", headers=headers)
    assert resp.status_code == 404

    # 2. Seed cache directly
    from server import _cache_investigation
    _cache_investigation("trace-test-123", "Test query", "Test verdict", [{"tool": "test_routing_fib", "duration_ms": 12.5}])

    resp = client.get("/api/investigations/trace-test-123/receipts", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["trace_id"] == "trace-test-123"
    assert data["query"] == "Test query"
    assert data["verdict"] == "Test verdict"
    assert len(data["receipts"]) == 1
    assert data["receipts"][0]["tool"] == "test_routing_fib"


def test_export_google_doc_endpoint():
    """POST /api/export/google-doc returns 404 on missing, 200 on cached, and formats report."""
    test_key = os.environ.get("API_ACCESS_KEY", "default-key")
    headers = {"X-API-Key": test_key}

    # 1. Non-existent trace
    resp = client.post("/api/export/google-doc", headers=headers, json={"trace_id": "non-existent-trace"})
    assert resp.status_code == 404

    # 2. Seed cache directly
    from server import _cache_investigation
    _cache_investigation("trace-export-test", "Why is DMZ down?", "Security rule Deny-All dropped it", [{"tool": "test_security_policy", "duration_ms": 30.0}])

    # 3. Successful export
    resp = client.post("/api/export/google-doc", headers=headers, json={"trace_id": "trace-export-test"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "markdown" in data
    assert "Why is DMZ down?" in data["markdown"]
    assert "Deny-All" in data["markdown"]
