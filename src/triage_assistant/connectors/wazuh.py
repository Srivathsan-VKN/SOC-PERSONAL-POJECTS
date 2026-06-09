"""
WazuhConnector — fetches alerts from the Wazuh Indexer (OpenSearch) _search API.

Architecture note: per the research, alert DOCUMENTS live in the Wazuh INDEXER
(OpenSearch on port 9200), NOT in the manager API on port 55000. The manager
API is for management (agents, rules, config) — not alert retrieval.

Index pattern: `wazuh-alerts-*`
Time field:    `timestamp`
Default sort:  most recent first
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional

import urllib3
from opensearchpy import OpenSearch
from opensearchpy.exceptions import (
    AuthenticationException,
    ConnectionError as OSConnectionError,
    RequestError,
    TransportError,
)

from ..config import get_logger, get_settings
from .base import BaseSIEMConnector
from .exceptions import (
    AuthenticationError,
    ConnectionError,
    QueryError,
    ResponseError,
    ConnectorError,
)

log = get_logger(__name__)


class WazuhConnector(BaseSIEMConnector):
    """Pulls Wazuh alerts via the Indexer (OpenSearch) _search API."""

    INDEX_PATTERN = "wazuh-alerts-*"
    TIME_FIELD = "timestamp"

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_tls: Optional[bool] = None,
    ):
        """
        Args default to settings from .env. Override if needed (e.g. tests).
        """
        s = get_settings()
        self.host = host or s.wazuh_indexer_host
        self.port = port or s.wazuh_indexer_port
        self.username = username or s.wazuh_indexer_user
        self.password = password or s.wazuh_indexer_password
        self.verify_tls = verify_tls if verify_tls is not None else s.wazuh_verify_tls

        if not self.verify_tls:
            # Wazuh ships with self-signed certs by default.
            # In a home lab, this is expected. In production, supply a CA bundle.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.client = OpenSearch(
            hosts=[{"host": self.host, "port": self.port}],
            http_auth=(self.username, self.password),
            use_ssl=True,
            verify_certs=self.verify_tls,
            ssl_show_warn=self.verify_tls,
            timeout=30,
        )

        log.info(
            "wazuh_connector.initialized",
            host=self.host,
            port=self.port,
            verify_tls=self.verify_tls,
        )

    # ------------------------------------------------------------------ #
    # BaseSIEMConnector implementation
    # ------------------------------------------------------------------ #

    def test_connection(self) -> bool:
        """Verify host is reachable AND credentials work."""
        try:
            info = self.client.info()
            log.info(
                "wazuh_connector.connection_ok",
                cluster=info.get("cluster_name"),
                version=info.get("version", {}).get("number"),
            )
            return True
        except AuthenticationException as e:
            log.error("wazuh_connector.auth_failed", error=str(e))
            raise AuthenticationError(f"Wazuh auth failed: {e}") from e
        except OSConnectionError as e:
            log.error("wazuh_connector.connection_failed", error=str(e))
            raise ConnectionError(f"Cannot reach Wazuh at {self.host}:{self.port}: {e}") from e
        except TransportError as e:
            log.error("wazuh_connector.transport_error", error=str(e))
            raise ConnectorError (f"Wazuh transport error: {e}") from e

    def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        min_level: int = 0,
        max_results: int = 100,
    ) -> Iterator[dict]:
        """Yield raw Wazuh alert documents (each is the `_source` dict)."""
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(hours=1)

        # Cap at indexer's safe default to avoid deep-pagination heap pressure.
        # For >10k results we'd switch to search_after; not needed in V1.
        size = min(max_results, 10_000)

        query = {
            "size": size,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"rule.level": {"gte": min_level}}},
                        {"range": {self.TIME_FIELD: {"gte": since.isoformat()}}},
                    ]
                }
            },
            "sort": [{self.TIME_FIELD: {"order": "desc"}}],
        }

        log.info(
            "wazuh_connector.fetch_start",
            since=since.isoformat(),
            min_level=min_level,
            max_results=size,
        )

        try:
            response = self.client.search(index=self.INDEX_PATTERN, body=query)
        except AuthenticationException as e:
            raise AuthenticationError(f"Wazuh auth failed: {e}") from e
        except OSConnectionError as e:
            raise ConnectionError(f"Cannot reach Wazuh: {e}") from e
        except RequestError as e:
            raise QueryError(f"Wazuh rejected query: {e}") from e
        except TransportError as e:
            raise ConnectorError(f"Wazuh transport error: {e}") from e

        try:
            hits = response["hits"]["hits"]
            total = response["hits"]["total"]
            total_value = total["value"] if isinstance(total, dict) else total
        except (KeyError, TypeError) as e:
            raise ResponseError(f"Unexpected Wazuh response shape: {e}") from e

        log.info(
            "wazuh_connector.fetch_complete",
            returned=len(hits),
            total_matching=total_value,
        )

        for hit in hits:
            yield hit.get("_source", {})
