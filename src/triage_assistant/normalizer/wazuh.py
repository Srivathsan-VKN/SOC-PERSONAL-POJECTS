"""
WazuhNormalizer — converts raw Wazuh alerts into NormalizedAlert objects.

This is the SIEM-vendor-specific translation layer. It knows about Wazuh's
quirky field locations (Windows events in data.win.eventdata.*, FIM in
syscheck.*, firewall in data.srcip, Suricata in data.alert.*).

Downstream modules only ever consume NormalizedAlert — they don't care
that Wazuh was the source. To add Splunk support tomorrow, write a
SplunkNormalizer with the same interface. Nothing downstream changes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from ..config import get_logger
from ..models import (
    Agent,
    DestinationEndpoint,
    Host,
    MitreMapping,
    NormalizedAlert,
    RuleInfo,
    SourceEndpoint,
)

log = get_logger(__name__)


class WazuhNormalizer:
    """Converts raw Wazuh alert dicts into NormalizedAlert objects."""

    def normalize(self, raw: dict) -> NormalizedAlert:
        """Main entry point. Convert one raw Wazuh alert dict to NormalizedAlert.

        Args:
            raw: The full Wazuh alert document (the _source dict from the indexer).

        Returns:
            A NormalizedAlert object validated by Pydantic.

        Raises:
            pydantic.ValidationError: If `raw` is so malformed that even our
                defensive defaults can't produce a valid NormalizedAlert.
        """
        return NormalizedAlert(
            alert_id=self._extract_alert_id(raw),
            timestamp=self._extract_timestamp(raw),
            source_siem="wazuh",
            rule=self._extract_rule(raw),
            mitre=self._extract_mitre(raw),
            host=self._extract_host(raw),
            agent=self._extract_agent(raw),
            source=self._extract_source(raw),
            destination=self._extract_destination(raw),
            event_action=self._extract_event_action(raw),
            event_outcome=self._extract_event_outcome(raw),
            full_log=raw.get("full_log"),
            raw=raw,
        )

    # ------------------------------------------------------------------ #
    # Utility — safe nested dict access
    # ------------------------------------------------------------------ #

    @staticmethod
    def _safe_get(d: Any, *keys: str, default: Any = None) -> Any:
        """Safely walk a nested dict. _safe_get(d, 'a', 'b', 'c') = d['a']['b']['c'] or default.

        Returns default if ANY key in the chain is missing or any intermediate
        value isn't a dict. This is the difference between defensive code and
        code that crashes on the first weird alert.
        """
        for key in keys:
            if not isinstance(d, dict):
                return default
            d = d.get(key)
            if d is None:
                return default
        return d

    # ------------------------------------------------------------------ #
    # Per-field extractors
    # ------------------------------------------------------------------ #

    def _extract_alert_id(self, raw: dict) -> str:
        # Wazuh format: epoch.offset (e.g. "1717756200.123456")
        return str(raw.get("id") or "unknown")

    def _extract_timestamp(self, raw: dict) -> datetime:
        ts_str = raw.get("timestamp")
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            # Wazuh format: 2026-06-07T10:30:00.000+0000
            # Python 3.11+ fromisoformat handles trailing offsets natively
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError, TypeError):
            log.warning("normalizer.malformed_timestamp", value=str(ts_str))
            return datetime.now(timezone.utc)

    def _extract_rule(self, raw: dict) -> RuleInfo:
        rule = raw.get("rule") or {}
        return RuleInfo(
            id=str(rule.get("id", "unknown")),
            level=int(rule.get("level", 0)),
            description=rule.get("description") or "(no description)",
            groups=rule.get("groups") or [],
        )

    def _extract_mitre(self, raw: dict) -> MitreMapping:
        mitre = self._safe_get(raw, "rule", "mitre", default={}) or {}
        return MitreMapping(
            technique_ids=mitre.get("id") or [],
            technique_names=mitre.get("technique") or [],
            tactic_names=mitre.get("tactic") or [],
        )

    def _extract_agent(self, raw: dict) -> Agent:
        agent = raw.get("agent") or {}
        return Agent(id=agent.get("id"), name=agent.get("name"))

    def _extract_host(self, raw: dict) -> Host:
        # In Wazuh, the agent IS the monitored host.
        agent = raw.get("agent") or {}
        return Host(
            name=agent.get("name"),
            ip=agent.get("ip"),
            os=self._safe_get(raw, "agent", "os", "name"),
        )

    def _extract_source(self, raw: dict) -> SourceEndpoint:
        """Extract attacker / source endpoint info.

        Wazuh hides source IPs in three different places depending on log source:
          1. Linux/firewall logs: data.srcip
          2. Windows logon events: data.win.eventdata.ipAddress
          3. Suricata alerts: data.src_ip
        We check all three.
        """
        win_data = self._safe_get(raw, "data", "win", "eventdata") or {}
        data = raw.get("data") or {}

        src_ip = (
            data.get("srcip")
            or win_data.get("ipAddress")
            or data.get("src_ip")
        )
        src_port_raw = (
            data.get("srcport")
            or win_data.get("ipPort")
            or data.get("src_port")
        )
        src_port = self._safe_int(src_port_raw)
        src_user = data.get("srcuser")

        return SourceEndpoint(ip=src_ip, port=src_port, user=src_user)

    def _extract_destination(self, raw: dict) -> DestinationEndpoint:
        win_data = self._safe_get(raw, "data", "win", "eventdata") or {}
        data = raw.get("data") or {}

        dst_ip = data.get("dstip") or data.get("dest_ip")
        dst_port = self._safe_int(data.get("dstport") or data.get("dest_port"))
        # For Windows logon events, the TARGET user is the destination user.
        dst_user = data.get("dstuser") or win_data.get("targetUserName")

        return DestinationEndpoint(ip=dst_ip, port=dst_port, user=dst_user)

    def _extract_event_action(self, raw: dict) -> Optional[str]:
        """A short, human-readable label for what happened."""
        # FIM events → file-modified / file-added / file-deleted
        sc_event = self._safe_get(raw, "syscheck", "event")
        if sc_event:
            return f"file-{sc_event}"

        # Windows event IDs we recognize
        win_event = self._safe_get(raw, "data", "win", "system", "eventID")
        if win_event == "4625":
            return "logon-failed"
        if win_event == "4624":
            return "logon-success"
        if win_event == "1":  # Sysmon process creation
            return "process-created"

        # Firewall actions
        action = self._safe_get(raw, "data", "action")
        if action:
            return str(action).lower()

        return None

    def _extract_event_outcome(self, raw: dict) -> Optional[str]:
        """success / failure / unknown."""
        win_event = self._safe_get(raw, "data", "win", "system", "eventID")
        if win_event == "4625":
            return "failure"
        if win_event == "4624":
            return "success"
        return None

    # ------------------------------------------------------------------ #
    # Utility — safe int conversion
    # ------------------------------------------------------------------ #

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """Convert to int if possible, else None. Wazuh sometimes returns ports as strings."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
