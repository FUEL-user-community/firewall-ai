import os
import unittest.mock as mock
import pytest
from core.panos.client import PanOSClient
from core.panos.interceptors import CommandRouter, CommandType
from core.panos.logs import (
    execute_log_query,
    execute_report_query,
    execute_report_discovery,
    execute_live_app_analytics,
)
from core.panos.metrics import MetricsLogger
from core.panos.research import search_live_docs


# ═══════════════════════════════════════════════════════════════
# 1. PanOSClient Tests (Log & Report Alignment with pan-os-python)
# ═══════════════════════════════════════════════════════════════

def test_client_execute_log_passes_log_type_and_timeout():
    """Verify execute_log passes log_type, filter, nlogs, and timeout to pan-os-python xapi."""
    client = PanOSClient(device_name="test-fw", hostname="127.0.0.1", api_key="secret-key", verify_ssl=False)
    mock_xapi = mock.MagicMock()
    mock_xapi.xml_result.return_value = "<log><entry><app>threat-app</app></entry></log>"
    client.fw._xapi_private = mock_xapi

    status, result = client.execute_log(
        log_type="threat",
        query="( action eq deny )",
        nlogs=25,
        timeout=15
    )

    assert status == 200
    mock_xapi.log.assert_called_once_with(
        log_type="threat",
        nlogs=25,
        skip=0,
        filter="( action eq deny )",
        timeout=15
    )


def test_client_execute_report_uses_native_report_api():
    """Verify execute_report uses pan-os-python xapi.report rather than xapi.op."""
    client = PanOSClient(device_name="test-fw", hostname="127.0.0.1", api_key="secret-key", verify_ssl=False)
    mock_xapi = mock.MagicMock()
    mock_xapi.xml_result.return_value = "<report><entry><app>ssl</app></entry></report>"
    client.fw._xapi_private = mock_xapi

    status, result = client.execute_report(
        report_name="top-applications",
        report_type="predefined",
        timeout=12
    )

    assert status == 200
    mock_xapi.report.assert_called_once_with(
        reporttype="predefined",
        reportname="top-applications",
        timeout=12
    )

    # Empty report name should return 400 immediately
    err_status, err_result = client.execute_report(report_name="   ")
    assert err_status == 400

    # Empty report name should return 400 immediately
    err_status, err_result = client.execute_report(report_name="   ")
    assert err_status == 400


# ═══════════════════════════════════════════════════════════════
# 2. Logs Module Tests (execute_log_query & live_app_analytics)
# ═══════════════════════════════════════════════════════════════

@mock.patch("core.panos.logs._get_pool")
def test_execute_log_query_passes_log_type(mock_get_pool):
    """Verify execute_log_query forwards the requested log_type to the client."""
    mock_pool = mock.MagicMock()
    mock_client = mock.MagicMock()
    mock_client.execute_log.return_value = (200, "<log><entry>data</entry></log>")
    mock_pool.get_client.return_value = mock_client
    mock_get_pool.return_value = mock_pool

    res = execute_log_query(log_type="system", filter_query="( eventid eq commit )")
    mock_client.execute_log.assert_called_once_with(
        log_type="system",
        query="( eventid eq commit )",
        nlogs=20
    )
    assert isinstance(res, str)


@mock.patch("core.panos.logs._get_pool")
def test_execute_live_app_analytics_xml_parsing(mock_get_pool):
    """Verify execute_live_app_analytics parses active sessions and handles errors."""
    mock_pool = mock.MagicMock()
    mock_client = mock.MagicMock()
    mock_pool.get_client.return_value = mock_client
    mock_get_pool.return_value = mock_pool

    # 1. Success case with sessions
    sample_xml = """
    <response status="success">
        <result>
            <entry><application>web-browsing</application></entry>
            <entry><application>ssl</application></entry>
            <entry><application>web-browsing</application></entry>
        </result>
    </response>
    """
    mock_client.execute_op.return_value = (200, sample_xml)
    res = execute_live_app_analytics()
    assert "web-browsing" in res
    assert "Total Sessions Analyzed: 3" in res

    # 2. Empty sessions case
    mock_client.execute_op.return_value = (200, "<response status='success'><result></result></response>")
    empty_res = execute_live_app_analytics()
    assert "0 sessions" in empty_res

    # 3. Firewall error envelope case
    error_xml = "<response status='error'><msg><line>Session table lock failed</line></msg></response>"
    mock_client.execute_op.return_value = (200, error_xml)
    err_res = execute_live_app_analytics()
    assert "Live Analytics Failed: Session table lock failed" in err_res


# ═══════════════════════════════════════════════════════════════
# 3. CommandRouter Tests (Interceptors)
# ═══════════════════════════════════════════════════════════════

def test_command_router_case_insensitivity():
    """Verify CommandRouter routes commands regardless of casing."""
    router = CommandRouter()

    # Uppercase log command
    r1 = router.route("SHOW LOG TRAFFIC")
    assert r1.type == CommandType.LOG_QUERY
    assert r1.args["log_type"] == "TRAFFIC"

    # Mixed case report command
    r2 = router.route("show Report top-applications")
    assert r2.type == CommandType.REPORT_QUERY
    assert r2.args["report_type"] == "top-applications"

    # Uppercase session analytics
    r3 = router.route("SHOW SESSION ANALYTICS")
    assert r3.type == CommandType.LIVE_ANALYTICS

    # Operational command fallthrough
    r4 = router.route("show system info")
    assert r4.type == CommandType.OPERATIONAL
    assert r4.args["cmd"] == "show system info"

    # Empty command fallthrough
    r5 = router.route("")
    assert r5.type == CommandType.OPERATIONAL


def test_command_router_extracts_filter_expression():
    """Verify CommandRouter extracts both log type and filter expressions."""
    router = CommandRouter()

    # Plain log query without filter
    r1 = router.route("show log traffic")
    assert r1.type == CommandType.LOG_QUERY
    assert r1.args["log_type"] == "traffic"
    assert r1.args.get("filter_query") is None

    # Log query with complex filter expression
    r2 = router.route("show log traffic ( addr.src in 10.0.0.5 ) and ( action eq deny )")
    assert r2.type == CommandType.LOG_QUERY
    assert r2.args["log_type"] == "traffic"
    assert r2.args["filter_query"] == "( addr.src in 10.0.0.5 ) and ( action eq deny )"

    # Backward direction query
    r3 = router.route("show log system direction equal backward")
    assert r3.type == CommandType.LOG_QUERY
    assert r3.args["log_type"] == "system"
    assert r3.args["filter_query"] == "direction equal backward"


# ═══════════════════════════════════════════════════════════════
# 4. Research & Metrics Tests
# ═══════════════════════════════════════════════════════════════

def test_research_validation_and_headers():
    """Verify search_live_docs input validation and header handling."""
    # Empty query guard
    assert "cannot be empty" in search_live_docs("   ")

    # Unconfigured API guard
    with mock.patch.dict(os.environ, {"GOOGLE_SEARCH_API_KEY": "", "GOOGLE_CSE_ID": ""}):
        assert "not configured" in search_live_docs("CVE-2024-3400")

    # Mocked successful request
    with mock.patch.dict(os.environ, {"GOOGLE_SEARCH_API_KEY": "dummy", "GOOGLE_CSE_ID": "dummy"}):
        with mock.patch("requests.get") as mock_get:
            mock_resp = mock.MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "items": [
                    {"title": "Palo Alto App-ID", "link": "https://docs.paloaltonetworks.com/appid", "snippet": "App-ID guide"}
                ]
            }
            mock_get.return_value = mock_resp

            res = search_live_docs("App-ID")
            assert "Palo Alto App-ID" in res
            # Check User-Agent header passed
            call_kwargs = mock_get.call_args[1]
            assert "User-Agent" in call_kwargs["headers"]


def test_metrics_logger_defensive():
    """Verify MetricsLogger handles empty, None, and non-numeric stats gracefully."""
    logger = MetricsLogger.get_instance()
    # Should not raise on None or invalid types
    logger.log("test_cmd", None)
    logger.log("test_cmd", {})
    logger.log("test_cmd", {"reduction_pct": "invalid"})
    logger.log("test_cmd", {"reduction_pct": 42.5})
