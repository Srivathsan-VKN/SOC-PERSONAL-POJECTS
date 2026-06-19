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

@pytest.fixture
def sample_wazuh_fim_alert():
    """A Wazuh File Integrity Monitoring alert — file modified on disk.

    FIM data lives under `syscheck.*` (NOT under `data.*` — Wazuh quirk).
    """
    return {
        "timestamp": "2026-06-07T11:45:00.000+0000",
        "id": "1717760700.789012",
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed.",
            "groups": ["ossec", "syscheck", "syscheck_entry_modified"],
            "mitre": {
                "id": ["T1565"],
                "tactic": ["Impact"],
                "technique": ["Data Manipulation"]
            }
        },
        "agent": {"id": "001", "name": "Win-user", "ip": "192.168.1.8"},
        "manager": {"name": "wazuh-manager"},
        "syscheck": {
            "path": "C:\\SensitiveData\\confidential.txt",
            "mode": "realtime",
            "event": "modified",
            "size_before": "1024",
            "size_after": "2048",
            "sha256_after": "a1b2c3d4e5f6",
            "uname_after": "Administrator"
        },
        "location": "syscheck"
    }


@pytest.fixture
def sample_wazuh_sysmon_alert():
    """A Wazuh alert from Sysmon — suspicious PowerShell process creation.

    Sysmon events use the Windows channel structure (data.win.*) but with
    Sysmon-specific fields like commandLine, parentImage.
    """
    return {
        "timestamp": "2026-06-07T12:00:00.000+0000",
        "id": "1717761600.345678",
        "rule": {
            "id": "61603",
            "level": 8,
            "description": "Sysmon - Suspicious process creation (PowerShell encoded command)",
            "groups": ["windows", "sysmon", "sysmon_event_1"],
            "mitre": {
                "id": ["T1059", "T1059.001"],
                "tactic": ["Execution"],
                "technique": ["Command and Scripting Interpreter", "PowerShell"]
            }
        },
        "agent": {"id": "001", "name": "Win-user", "ip": "192.168.1.8"},
        "data": {
            "win": {
                "system": {
                    "eventID": "1",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "providerName": "Microsoft-Windows-Sysmon"
                },
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAA=",
                    "parentImage": "C:\\Windows\\explorer.exe",
                    "user": "WIN-USER\\Administrator",
                    "processGuid": "{abc-123}"
                }
            }
        },
        "location": "EventChannel"
    }


@pytest.fixture
def sample_wazuh_sparse_alert():
    """A minimal Wazuh alert — most fields missing.

    Real Wazuh alerts in the wild often have sparse data (custom rules,
    low-level system messages). We test that the normalizer handles this
    gracefully instead of crashing on KeyError.
    """
    return {
        "timestamp": "2026-06-07T13:00:00.000+0000",
        "rule": {
            "id": "1002",
            "level": 2,
            "description": "Unknown problem"
        }
    }
