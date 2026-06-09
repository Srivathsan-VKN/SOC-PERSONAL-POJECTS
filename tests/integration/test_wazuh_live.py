"""
Live integration tests for WazuhConnector.

These hit your REAL Wazuh Indexer. They are marked with @pytest.mark.integration
so they don't run during normal `pytest` — only with `pytest -m integration`.

Prerequisites:
- Your Ubuntu VM is running with Wazuh Indexer reachable on the configured host/port
- .env has correct credentials
"""
import os

import pytest

from triage_assistant.connectors import WazuhConnector


# Skip these tests entirely if the integration flag isn't set
pytestmark = pytest.mark.integration


def test_can_connect_to_real_wazuh():
    connector = WazuhConnector()
    assert connector.test_connection() is True


def test_can_fetch_alerts_from_real_wazuh():
    connector = WazuhConnector()
    # Fetch up to 5 alerts from the last 24 hours, any level
    alerts = list(connector.fetch_alerts(max_results=5))
    # We don't assert len > 0 because the indexer might be empty (your lab)
    assert isinstance(alerts, list)
    # If we did get alerts, verify they're real Wazuh shape
    for alert in alerts:
        assert "rule" in alert or "agent" in alert  # Some Wazuh field is present