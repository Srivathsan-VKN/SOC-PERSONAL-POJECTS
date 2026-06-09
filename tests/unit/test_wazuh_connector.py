"""
Unit tests for WazuhConnector.

Strategy: mock the OpenSearch client entirely. These tests verify our
connector's LOGIC — query construction, error translation, iteration —
without needing a live Wazuh instance.
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from opensearchpy.exceptions import (
    AuthenticationException,
    ConnectionError as OSConnectionError,
    RequestError,
)

from triage_assistant.connectors import (
    AuthenticationError,
    ConnectionError,
    QueryError,
    WazuhConnector,
)


# --------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------- #


@pytest.fixture
def mock_opensearch():
    """Patch the OpenSearch client used inside WazuhConnector."""
    with patch("triage_assistant.connectors.wazuh.OpenSearch") as mock_cls:
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def connector(mock_opensearch):
    """A WazuhConnector with a mocked OpenSearch client."""
    return WazuhConnector(
        host="fake-host",
        port=9200,
        username="admin",
        password="fake-password",
        verify_tls=False,
    )


# --------------------------------------------------------------------- #
# test_connection
# --------------------------------------------------------------------- #


def test_test_connection_returns_true_on_success(connector, mock_opensearch):
    mock_opensearch.info.return_value = {
        "cluster_name": "wazuh-cluster",
        "version": {"number": "2.13.0"},
    }
    assert connector.test_connection() is True
    mock_opensearch.info.assert_called_once()


def test_test_connection_raises_auth_error_on_bad_creds(connector, mock_opensearch):
    mock_opensearch.info.side_effect = AuthenticationException(
        401, "unauthorized", {}
    )
    with pytest.raises(AuthenticationError):
        connector.test_connection()


def test_test_connection_raises_connection_error_when_host_unreachable(
    connector, mock_opensearch
):
    mock_opensearch.info.side_effect = OSConnectionError("N/A", "connection refused", None)
    with pytest.raises(ConnectionError):
        connector.test_connection()


# --------------------------------------------------------------------- #
# fetch_alerts — query construction
# --------------------------------------------------------------------- #


def test_fetch_alerts_builds_correct_query(connector, mock_opensearch):
    mock_opensearch.search.return_value = {
        "hits": {"hits": [], "total": {"value": 0}}
    }

    since = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    list(connector.fetch_alerts(since=since, min_level=7, max_results=50))

    # Verify the search call
    mock_opensearch.search.assert_called_once()
    call_kwargs = mock_opensearch.search.call_args.kwargs
    assert call_kwargs["index"] == "wazuh-alerts-*"

    body = call_kwargs["body"]
    assert body["size"] == 50
    assert body["sort"] == [{"timestamp": {"order": "desc"}}]

    filters = body["query"]["bool"]["filter"]
    assert {"range": {"rule.level": {"gte": 7}}} in filters
    assert any("timestamp" in f.get("range", {}) for f in filters)


def test_fetch_alerts_defaults_to_last_hour_when_since_is_none(
    connector, mock_opensearch
):
    mock_opensearch.search.return_value = {
        "hits": {"hits": [], "total": {"value": 0}}
    }

    list(connector.fetch_alerts(min_level=0))

    body = mock_opensearch.search.call_args.kwargs["body"]
    filters = body["query"]["bool"]["filter"]
    time_filter = next(f for f in filters if "timestamp" in f.get("range", {}))
    # Just verify it set SOME timestamp — exact value depends on now()
    assert "gte" in time_filter["range"]["timestamp"]


# --------------------------------------------------------------------- #
# fetch_alerts — iteration & yielding
# --------------------------------------------------------------------- #


def test_fetch_alerts_yields_source_documents(connector, mock_opensearch):
    fake_alert_1 = {"rule": {"id": "60122", "level": 10}, "agent": {"id": "001"}}
    fake_alert_2 = {"rule": {"id": "550", "level": 7}, "agent": {"id": "001"}}

    mock_opensearch.search.return_value = {
        "hits": {
            "hits": [
                {"_source": fake_alert_1, "_id": "abc"},
                {"_source": fake_alert_2, "_id": "def"},
            ],
            "total": {"value": 2},
        }
    }

    results = list(connector.fetch_alerts())

    assert len(results) == 2
    assert results[0] == fake_alert_1
    assert results[1] == fake_alert_2


def test_fetch_alerts_yields_nothing_when_no_hits(connector, mock_opensearch):
    mock_opensearch.search.return_value = {
        "hits": {"hits": [], "total": {"value": 0}}
    }
    assert list(connector.fetch_alerts()) == []


# --------------------------------------------------------------------- #
# fetch_alerts — error translation
# --------------------------------------------------------------------- #


def test_fetch_alerts_raises_query_error_on_bad_dsl(connector, mock_opensearch):
    mock_opensearch.search.side_effect = RequestError(
        400, "parse_exception", {"error": "bad query"}
    )
    with pytest.raises(QueryError):
        list(connector.fetch_alerts())


def test_fetch_alerts_raises_auth_error_when_creds_revoked(connector, mock_opensearch):
    mock_opensearch.search.side_effect = AuthenticationException(401, "denied", {})
    with pytest.raises(AuthenticationError):
        list(connector.fetch_alerts())
