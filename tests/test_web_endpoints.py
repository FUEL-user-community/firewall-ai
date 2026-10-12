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
    # Clean elements
    assert 'id="deviceFilter"' in res_index.text
    assert 'id="toastContainer"' in res_index.text
    assert 'id="messages"' in res_index.text
    assert 'id="input"' in res_index.text
    assert 'id="hitlTextPopup"' in res_index.text
    assert 'id="perimeterStatusChip"' in res_index.text
    assert 'id="btnModeDiag"' in res_index.text
    assert 'id="btnModeAdvisor"' in res_index.text


def test_static_range_html():
    """GET /range.html should serve the range simulation view and link to range.js."""
    res = client.get("/range.html")
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")
    assert "Range" in res.text
    assert 'src="range.js' in res.text
    assert 'id="deviceSelect"' in res.text
    assert 'id="cliForm"' in res.text
    assert 'id="canvasError"' in res.text


def test_static_js_and_css_assets():
    """GET /app.js, /range.js, and /styles.css must be directly accessible."""
    res_app = client.get("/app.js")
    assert res_app.status_code == 200
    assert "function esc" in res_app.text
    assert "function showToast" in res_app.text
    assert "function toggleReceiptsDrawer" in res_app.text
    assert "function bindModeSelector" in res_app.text
    assert "function setMode" in res_app.text
    assert "function renderPostReportPrompt" in res_app.text

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
    assert "mode-selector-bar" in res_css.text
    assert "post-report-prompt" in res_css.text
    assert "action-chip" in res_css.text


def test_active_telemetry_endpoints(ensure_auth_key):
    """Authenticated calls to active telemetry and device endpoints return expected structures."""
    headers = {"X-API-Key": ensure_auth_key}

    # Fleet registry
    res_devices = client.get("/api/devices", headers=headers)
    assert res_devices.status_code == 200
    data = res_devices.json()
    assert "firewalls" in data
    assert len(data["firewalls"]) > 0

    # Receipts 404 for unknown trace
    res_receipts = client.get("/api/investigations/unknown-trace-id-999/receipts", headers=headers)
    assert res_receipts.status_code == 404

    # Real-time telemetry endpoint contract check
    res_telem = client.get("/api/telemetry?device=default", headers=headers)
    assert res_telem.status_code == 200
    telem_data = res_telem.json()
    assert "success" in telem_data
    assert "active_sessions" in telem_data
    assert "mgmt_cpu" in telem_data


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
