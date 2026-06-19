"""
Unit tests for WazuhNormalizer.

Strategy: feed real-shaped Wazuh alerts (from conftest fixtures) into
the normalizer and assert that the output NormalizedAlert has the
expected field values.
"""
from datetime import datetime

import pytest
from pydantic import ValidationError

from triage_assistant.models import NormalizedAlert
from triage_assistant.normalizer import WazuhNormalizer


@pytest.fixture
def normalizer():
    return WazuhNormalizer()


# ===================================================================== #
# Brute force alert (Windows Event 4625)
# ===================================================================== #


class TestBruteForceAlert:

    def test_returns_normalized_alert_instance(
        self, normalizer, sample_wazuh_brute_force_alert
    ):
        result = normalizer.normalize(sample_wazuh_brute_force_alert)
        assert isinstance(result, NormalizedAlert)

    def test_extracts_alert_id(self, normalizer, sample_wazuh_brute_force_alert):
        result = normalizer.normalize(sample_wazuh_brute_force_alert)
        assert result.alert_id == "1717756200.123456"

    def test_source_siem_is_wazuh(self, normalizer, sample_wazuh_brute_force_alert):
        result = normalizer.normalize(sample_wazuh_brute_force_alert)
        assert result.source_siem == "wazuh"

    def test_extracts_rule_info(self, normalizer, sample_wazuh_brute_force_alert):
        result = normalizer.normalize(sample_wazuh_brute_force_alert)
        assert result.rule.id == "60122"
        assert result.rule.level == 10
        assert "logon failures" in result.rule.description.lower()
        assert "windows" in result.rule.groups

    def test_extracts_mitre_mapping(
        self, normalizer, sample_wazuh_brute_force_alert
    ):
        result = normalizer.normalize(sample_wazuh_brute_force_alert)
        assert "T1110" in result.mitre.technique_ids
        assert "Brute Force" in result.mitre.technique_names
        assert "Credential Access" in result.mitre.tactic_names

    def test_extracts_source_from_windows_event(
        self, normalizer, sample_wazuh_brute_force_alert
    ):
        # Windows logon events bury the attacker IP under data.win.eventdata.ipAddress
        result = normalizer.normalize(sample_wazuh_brute_force_alert)
        assert result.source.ip == "192.168.1.9"
        assert result.source.port == 52341

    def test_extracts_target_user_as_destination_user(
        self, normalizer, sample_wazuh_brute_force_alert
    ):
        result = normalizer.normalize(sample_wazuh_brute_force_alert)
        assert result.destination.user == "Administrator"

    def test_extracts_agent_and_host(
        self, normalizer, sample_wazuh_brute_force_alert
    ):
        result = normalizer.normalize(sample_wazuh_brute_force_alert)
        assert result.agent.id == "001"
        assert result.agent.name == "Win-user"
        assert result.host.name == "Win-user"
        assert result.host.ip == "192.168.1.8"

    def test_event_action_is_logon_failed(
        self, normalizer, sample_wazuh_brute_force_alert
    ):
        result = normalizer.normalize(sample_wazuh_brute_force_alert)
        assert result.event_action == "logon-failed"
        assert result.event_outcome == "failure"

    def test_preserves_raw_alert(self, normalizer, sample_wazuh_brute_force_alert):
        result = normalizer.normalize(sample_wazuh_brute_force_alert)
        assert result.raw == sample_wazuh_brute_force_alert


# ===================================================================== #
# FIM alert (Syscheck — file modified)
# ===================================================================== #


class TestFimAlert:

    def test_normalizes_successfully(self, normalizer, sample_wazuh_fim_alert):
        result = normalizer.normalize(sample_wazuh_fim_alert)
        assert isinstance(result, NormalizedAlert)

    def test_event_action_is_file_modified(
        self, normalizer, sample_wazuh_fim_alert
    ):
        result = normalizer.normalize(sample_wazuh_fim_alert)
        assert result.event_action == "file-modified"

    def test_mitre_mapping_present(self, normalizer, sample_wazuh_fim_alert):
        result = normalizer.normalize(sample_wazuh_fim_alert)
        assert "T1565" in result.mitre.technique_ids
        assert "Impact" in result.mitre.tactic_names

    def test_no_source_ip_for_fim_event(self, normalizer, sample_wazuh_fim_alert):
        # FIM is local — no source IP
        result = normalizer.normalize(sample_wazuh_fim_alert)
        assert result.source.ip is None

    def test_rule_level_correct(self, normalizer, sample_wazuh_fim_alert):
        result = normalizer.normalize(sample_wazuh_fim_alert)
        assert result.rule.level == 7


# ===================================================================== #
# Sysmon alert (process creation)
# ===================================================================== #


class TestSysmonAlert:

    def test_normalizes_successfully(self, normalizer, sample_wazuh_sysmon_alert):
        result = normalizer.normalize(sample_wazuh_sysmon_alert)
        assert isinstance(result, NormalizedAlert)

    def test_handles_subtechniques(self, normalizer, sample_wazuh_sysmon_alert):
        result = normalizer.normalize(sample_wazuh_sysmon_alert)
        assert "T1059" in result.mitre.technique_ids
        assert "T1059.001" in result.mitre.technique_ids  # Sub-technique
        assert "Execution" in result.mitre.tactic_names

    def test_event_action_process_created(
        self, normalizer, sample_wazuh_sysmon_alert
    ):
        result = normalizer.normalize(sample_wazuh_sysmon_alert)
        assert result.event_action == "process-created"


# ===================================================================== #
# Robustness — missing / malformed data
# ===================================================================== #


class TestRobustness:

    def test_sparse_alert_does_not_crash(
        self, normalizer, sample_wazuh_sparse_alert
    ):
        result = normalizer.normalize(sample_wazuh_sparse_alert)
        assert isinstance(result, NormalizedAlert)

    def test_sparse_alert_has_empty_mitre(
        self, normalizer, sample_wazuh_sparse_alert
    ):
        result = normalizer.normalize(sample_wazuh_sparse_alert)
        assert result.mitre.technique_ids == []
        assert result.mitre.tactic_names == []

    def test_sparse_alert_has_no_source_ip(
        self, normalizer, sample_wazuh_sparse_alert
    ):
        result = normalizer.normalize(sample_wazuh_sparse_alert)
        assert result.source.ip is None

    def test_empty_dict_does_not_crash(self, normalizer):
        # The most pathological input — completely empty alert
        result = normalizer.normalize({})
        assert isinstance(result, NormalizedAlert)
        assert result.rule.id == "unknown"
        assert result.rule.level == 0

    def test_malformed_timestamp_falls_back_to_now(self, normalizer):
        raw = {
            "timestamp": "not-actually-a-timestamp",
            "rule": {"id": "1", "level": 1, "description": "x"},
        }
        result = normalizer.normalize(raw)
        assert isinstance(result.timestamp, datetime)  # Got SOME timestamp

    def test_string_port_converts_to_int(self, normalizer):
        # Wazuh sometimes returns ports as strings
        raw = {
            "rule": {"id": "1", "level": 1, "description": "x"},
            "data": {"srcip": "10.0.0.1", "srcport": "8080"},
        }
        result = normalizer.normalize(raw)
        assert result.source.port == 8080
        assert isinstance(result.source.port, int)

    def test_garbage_port_becomes_none(self, normalizer):
        raw = {
            "rule": {"id": "1", "level": 1, "description": "x"},
            "data": {"srcip": "10.0.0.1", "srcport": "not-a-port"},
        }
        result = normalizer.normalize(raw)
        assert result.source.port is None
