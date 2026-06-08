"""
Smoke tests for the Pydantic models.

If these pass, the project is set up correctly and the schemas are valid.
"""
from datetime import datetime

from triage_assistant.models import (
    NormalizedAlert,
    RuleInfo,
    TriageResult,
    Verdict,
    Priority,
    SeverityBand,
)


def test_can_build_minimal_normalized_alert():
    alert = NormalizedAlert(
        alert_id="test-001",
        timestamp=datetime.utcnow(),
        rule=RuleInfo(id="60122", level=10, description="Multiple login failures"),
    )
    assert alert.source_siem == "wazuh"
    assert alert.rule.level == 10
    assert alert.mitre.technique_ids == []


def test_rule_level_must_be_in_range():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RuleInfo(id="x", level=99, description="bad")


def test_can_build_triage_result():
    result = TriageResult(
        verdict=Verdict.TRUE_POSITIVE,
        confidence=85,
        priority=Priority.P2,
        severity_band=SeverityBand.HIGH,
        attack_summary="Brute force attempt against Administrator account.",
        recommended_action="Block source IP 192.168.1.9 and reset Administrator password.",
    )
    assert result.verdict == "TRUE_POSITIVE"
    assert result.priority == "P2"