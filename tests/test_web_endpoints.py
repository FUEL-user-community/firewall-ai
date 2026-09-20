"""
Tests for Layer 6 Web UI assets, StaticFiles serving, and Frontend API route contracts.
"""

import os
import pytest
from starlette.testclient import TestClient
from server import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def ensure_auth_key():
    """Ensure API_ACCESS_KEY is consistently set for tests."""
    old_key = os.environ.get("API_ACCESS_KEY")
    os.environ["API_ACCESS_KEY"] = "web-test-key-999"
    yield "web-test-key-999"
    if old_key is not None:
        os.environ["API_ACCESS_KEY"] = old_key
    else:
        os.environ.pop("API_ACCESS_KEY", None)


def test_static_index_html():
    """Root GET / and /index.html should serve the main dashboard HTML."""
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert "text/html" in res_root.headers.get("content-type", "")
    assert "Core Defense" in res_root.text

    res_index = client.get("/index.html")
    assert res_index.status_code == 200
    assert "Core Defense" in res_index.text
    assert 'src="app.js' in res_index.text
    # SOC modern elements
    assert 'id="cardSearch"' in res_index.text
    assert 'id="deviceFilter"' in res_index.text
    assert 'id="deckEmpty"' in res_index.text
    assert 'id="toastContainer"' in res_index.text
    assert 'id="chatCardContext"' in res_index.text


def test_static_range_html():
    """GET /range.html should serve the range simulation view and link to range.js."""
    res = client.get("/range.html")
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")
    assert "Range" in res.text
    assert 'src="range.js' in res.text
    assert 'id="deviceSelect"' in res.text
    assert 'id="scenarioPresets"' in res.text
    assert 'id="canvasError"' in res.text


def test_static_js_and_css_assets():
    """GET /app.js, /range.js, and /styles.css must be directly accessible."""
    res_app = client.get("/app.js")
    assert res_app.status_code == 200
    assert "function esc" in res_app.text
    assert "function showToast" in res_app.text
    assert "function renderFilteredDeck" in res_app.text

    res_range = client.get("/range.js")
    assert res_range.status_code == 200
    assert "function esc" in res_range.text
    assert "function extractRangePayload" in res_range.text
    assert "function sanitizeMermaid" in res_range.text
    assert "/api/range/simulate" in res_range.text

    res_css = client.get("/styles.css")
    assert res_css.status_code == 200
    assert "body" in res_css.text
    assert "toast-container" in res_css.text


def test_api_cards_endpoints(ensure_auth_key):
    """Authenticated calls to /api/cards and /api/cards/schedule return expected structures."""
    headers = {"X-API-Key": ensure_auth_key}

    # Cards list
    res_cards = client.get("/api/cards", headers=headers)
    assert res_cards.status_code == 200
    data = res_cards.json()
    assert "cards" in data
    assert "counts" in data

    # Schedule list
    res_sched = client.get("/api/cards/schedule", headers=headers)
    assert res_sched.status_code == 200
    assert "schedule" in res_sched.json()

    # Card Registry
    res_reg = client.get("/api/cards/registry", headers=headers)
    assert res_reg.status_code == 200
    reg_data = res_reg.json()
    assert "cards" in reg_data
    assert "total" in reg_data
    assert isinstance(reg_data["cards"], list)


def test_api_drift_timeline(ensure_auth_key):
    """GET /api/drift/timeline returns a timeline list."""
    headers = {"X-API-Key": ensure_auth_key}
    res = client.get("/api/drift/timeline", headers=headers)
    assert res.status_code == 200
    assert "timeline" in res.json()


def test_range_simulate_validation(ensure_auth_key):
    """POST /api/range/simulate validates payload presence and device parameters."""
    headers = {"X-API-Key": ensure_auth_key}

    # Missing message field -> 422
    res_missing = client.post("/api/range/simulate", headers=headers, json={})
    assert res_missing.status_code == 422

    # Whitespace message -> 400
    res_empty = client.post("/api/range/simulate", headers=headers, json={"message": "   "})
    assert res_empty.status_code == 400
    assert "Empty message" in res_empty.json().get("error", "")

    # Valid payload with explicit device parameter schema check
    from server import RangeSimulateRequest
    req = RangeSimulateRequest(message="Test scenario", device="fw-hq")
    assert req.device == "fw-hq"
    assert req.message == "Test scenario"


def test_nonexistent_card_actions(ensure_auth_key):
    """Actions on nonexistent card IDs return 404."""
    headers = {"X-API-Key": ensure_auth_key}
    card_id = "nonexistent-uuid-0000"

    res_get = client.get(f"/api/cards/{card_id}", headers=headers)
    assert res_get.status_code == 404

    res_audit = client.get(f"/api/cards/{card_id}/audit", headers=headers)
    assert res_audit.status_code == 404

    res_logprobs = client.get(f"/api/cards/{card_id}/logprobs", headers=headers)
    assert res_logprobs.status_code == 404

    res_approve = client.post(f"/api/cards/{card_id}/approve", headers=headers)
    assert res_approve.status_code == 404

    res_deny = client.post(f"/api/cards/{card_id}/deny", headers=headers)
    assert res_deny.status_code == 404

    res_mute = client.post(f"/api/cards/{card_id}/mute", headers=headers, json={"hours": 12})
    assert res_mute.status_code == 404
