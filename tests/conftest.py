"""
conftest.py — shared pytest fixtures.

Anything defined here is automatically available to any test.
"""
import pytest


@pytest.fixture
def sample_wazuh_brute_force_alert():
    """A realistic Wazuh alert for a Windows failed-logon brute force (rule 60122)."""
    return {
        "timestamp": "2026-06-07T10:30:00.000+0000",
        "id": "1717756200.123456",
        "rule": {
            "id": "60122",
            "level": 10,
            "description": "Multiple Windows logon failures.",
            "firedtimes": 5,
            "mail": False,
            "groups": ["windows", "authentication_failed"],
            "mitre": {
                "id": ["T1110"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"]
            }
        },
        "agent": {"id": "001", "name": "Win-user", "ip": "192.168.1.8"},
        "manager": {"name": "wazuh-manager"},
        "data": {
            "win": {
                "system": {
                    "eventID": "4625",
                    "channel": "Security",
                    "providerName": "Microsoft-Windows-Security-Auditing"
                },
                "eventdata": {
                    "targetUserName": "Administrator",
                    "ipAddress": "192.168.1.9",
                    "ipPort": "52341",
                    "logonType": "3",
                    "status": "0xc000006d",
                    "subStatus": "0xc000006a"
                }
            }
        },
        "location": "EventChannel"
    }
