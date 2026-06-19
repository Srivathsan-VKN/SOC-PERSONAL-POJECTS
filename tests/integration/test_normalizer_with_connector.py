"""
Integration test: connector → normalizer pipeline.

Fetches real alerts from the live Wazuh indexer and pipes each through
the normalizer. Skipped if the indexer is empty.
"""
import pytest

from triage_assistant.connectors import WazuhConnector
from triage_assistant.normalizer import WazuhNormalizer
from triage_assistant.models import NormalizedAlert

pytestmark = pytest.mark.integration


def test_real_alerts_pipe_through_normalizer():
    connector = WazuhConnector()
    normalizer = WazuhNormalizer()

    alerts = list(connector.fetch_alerts(max_results=5))
    if not alerts:
        pytest.skip("Wazuh indexer has no alerts — generate some to test against")

    for raw_alert in alerts:
        normalized = normalizer.normalize(raw_alert)
        assert isinstance(normalized, NormalizedAlert)
        assert normalized.source_siem == "wazuh"
        assert normalized.alert_id != "unknown"
        assert normalized.rule.id  # has some rule ID