"""
Smoke test: fetch real Wazuh alerts and show them after normalization.

Usage:
    python scripts\smoke_normalizer.py
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
from triage_assistant.normalizer import WazuhNormalizer


def main():
    configure_logging("INFO")
    connector = WazuhConnector()
    normalizer = WazuhNormalizer()

    print("=" * 60)
    print("Connecting to Wazuh Indexer...")
    print("=" * 60)
    try:
        connector.test_connection()
        print(" Connected\n")
    except (AuthenticationError, ConnectionError) as e:
        print(f" Connection failed: {e}")
        sys.exit(1)

    print("=" * 60)
    print("Fetching alerts (last 24h, max 3)...")
    print("=" * 60)
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    raw_alerts = list(connector.fetch_alerts(since=since, max_results=3))

    if not raw_alerts:
        print("\n No alerts in indexer. This is expected for a quiet lab.")
        print("The normalizer is fully tested against fixtures — see tests.")
        print("In Phase 3+ we'll generate real alerts (attacks or sample data).")
        return

    print(f"\nFound {len(raw_alerts)} alert(s). Normalizing each...\n")

    for i, raw in enumerate(raw_alerts, 1):
        print(f"--- Alert {i} (normalized) ---")
        try:
            normalized = normalizer.normalize(raw)
            print(normalized.model_dump_json(indent=2))
        except Exception as e:
            print(f" Normalization failed: {e}")
            print("Raw was:")
            print(json.dumps(raw, indent=2, default=str)[:500])
        print()


if __name__ == "__main__":
    main()
