"""
EnrichedTriage — the final, fully-decorated alert ready for reporting.

Bundles:
  - the normalized alert (Module 1.5 output)
  - MITRE/CVE enrichment we fetched ourselves (Module 3a)
  - the LLM's triage decision (Module 3b)
  - validation results (which LLM-claimed IDs were real)
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .normalized_alert import NormalizedAlert
from .triage_result import TriageResult


class MitreTechniqueDetail(BaseModel):
    technique_id: str          # e.g. "T1110"
    name: str                  # "Brute Force"
    tactic: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    is_validated: bool = True  # came from our DB, not LLM imagination


class CveDetail(BaseModel):
    cve_id: str
    cvss_score: Optional[float] = None
    severity: Optional[str] = None       # LOW / MEDIUM / HIGH / CRITICAL
    attack_vector: Optional[str] = None
    description: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    is_validated: bool = True


class EnrichedTriage(BaseModel):
    alert: NormalizedAlert
    mitre_details: list[MitreTechniqueDetail] = Field(default_factory=list)
    cve_details: list[CveDetail] = Field(default_factory=list)
    triage: TriageResult

    # Audit trail: things the LLM mentioned but we couldn't verify
    unvalidated_mitre_ids: list[str] = Field(default_factory=list)
    unvalidated_cve_ids: list[str] = Field(default_factory=list)