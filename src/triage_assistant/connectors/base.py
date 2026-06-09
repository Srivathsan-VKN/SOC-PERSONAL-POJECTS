"""
BaseSIEMConnector — the abstract interface every SIEM connector must implement.

The point of this class is architectural: downstream code (normalizer, enricher,
LLM) never imports WazuhConnector directly. It depends on this interface.
That means you can swap Wazuh for Splunk later by writing a new SplunkConnector
that inherits from this class — and nothing else in the codebase changes.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Iterator, Optional


class BaseSIEMConnector(ABC):
    """Abstract base class for all SIEM connectors."""

    @abstractmethod
    def test_connection(self) -> bool:
        """Return True if we can reach and authenticate to the SIEM."""
        ...

    @abstractmethod
    def fetch_alerts(
        self,
        since: Optional[datetime] = None,
        min_level: int = 0,
        max_results: int = 100,
    ) -> Iterator[dict]:
        """
        Yield raw alert documents from the SIEM.

        Args:
            since: Only return alerts after this UTC timestamp. None = last 1 hour.
            min_level: Only return alerts with severity >= this value.
                       (For Wazuh: rule.level, 0–15. For other SIEMs, mapped equivalents.)
            max_results: Cap on number of alerts to return per call.

        Yields:
            dict: A raw alert document as returned by the SIEM.
                  The shape is SIEM-specific; the normalizer converts it.
        """
        ...
