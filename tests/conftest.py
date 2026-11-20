"""Shared pytest fixtures."""

import pytest


@pytest.fixture(autouse=True)
def _isolate_audit_log(tmp_path, monkeypatch):
    """Keep the hash-chained provenance log out of the operator's real ~/.neo/audit during tests."""
    monkeypatch.setenv("NEO_AUDIT_LOG", str(tmp_path / "neo_audit_test.jsonl"))
    yield
