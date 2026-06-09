"""
Smoke test: run the WazuhConnector against the real Indexer and print results.

Usage:
    python scripts\smoke_wazuh_connector.py

Not a pytest — just a quick "does this work right now" script.
"""
import json
import sys
from datetime import datetime, timedelta, timezone

from triage_assistant.config import configure_logging
from triage_assistant.connectors import (
    AuthenticationError,
    ConnectionError,
    WazuhConnector,
)


def main():
    configure_logging("INFO")
    connector = WazuhConnector()

    print("=" * 60)
    print("Testing connection to Wazuh Indexer...")
    print("=" * 60)
    try:
        connector.test_connection()
        print(" :) Connection OK\n")
    except (AuthenticationError, ConnectionError) as e:
        print(f" :( Connection failed: {e}")
        sys.exit(1)

    print("=" * 60)
    print("Fetching alerts from the last 24 hours (any level, max 3)...")
    print("=" * 60)
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    alerts = list(connector.fetch_alerts(since=since, min_level=0, max_results=3))

    print(f"\nFound {len(alerts)} alert(s).\n")

    for i, alert in enumerate(alerts, 1):
        print(f"--- Alert {i} ---")
        # Print only key fields, not the giant raw blob
        summary = {
            "timestamp": alert.get("timestamp"),
            "rule_id": alert.get("rule", {}).get("id"),
            "rule_level": alert.get("rule", {}).get("level"),
            "description": alert.get("rule", {}).get("description"),
            "agent": alert.get("agent", {}).get("name"),
            "mitre": alert.get("rule", {}).get("mitre", {}),
        }
        print(json.dumps(summary, indent=2, default=str))
        print()


if __name__ == "__main__":
    main()