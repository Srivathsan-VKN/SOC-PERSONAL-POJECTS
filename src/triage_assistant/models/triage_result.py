"""
TriageResult — the output of the AI triage step (Module 3b).

This is the structured response we ask the LLM to produce.
The shape is inspired by CrowdStrike Charlotte AI: verdict + priority +
recommended action + confidence + reasoning.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"


class Priority(str, Enum):
    P1 = "P1"   # Critical / immediate
    P2 = "P2"   # High
    P3 = "P3"   # Medium
    P4 = "P4"   # Low / informational


class SeverityBand(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class TriageResult(BaseModel):
    """Structured triage decision from the LLM."""

    verdict: Verdict
    confidence: int = Field(ge=0, le=100)     # 0–100
    priority: Priority
    severity_band: SeverityBand

    attack_summary: str = Field(
        description="2–3 sentences in plain English describing what happened."
    )
    recommended_action: str = Field(
        description="The single most important next step for the analyst."
    )
    additional_actions: list[str] = Field(
        default_factory=list,
        description="Other immediate steps."
    )
    countermeasures: list[str] = Field(
        default_factory=list,
        description="Longer-term hardening recommendations."
    )

    # IDs the LLM claims are relevant — MUST be validated against MITRE/NVD
    # databases before being trusted (we do this in Phase 4).
    referenced_mitre_ids: list[str] = Field(default_factory=list)
    referenced_cve_ids: list[str] = Field(default_factory=list)

    reasoning: Optional[str] = Field(
        default=None,
        description="The LLM's chain-of-thought / explanation."
    )