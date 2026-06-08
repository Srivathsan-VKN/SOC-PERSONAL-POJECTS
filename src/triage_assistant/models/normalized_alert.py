"""
NormalizedAlert — the internal alert format.

This is the schema EVERY downstream module sees.
Wazuh-specific fields are mapped here in the Normalizer (Module 1.5).
Future SIEM connectors (Splunk, Elastic) will produce this same shape,
so downstream code never changes.

Aligned with Elastic Common Schema (ECS) 9.4.0 conventions.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class Host(BaseModel):
    """The monitored endpoint (where the event happened)."""
    name: Optional[str] = None
    ip: Optional[str] = None
    os: Optional[str] = None


class Agent(BaseModel):
    """The Wazuh agent that reported the event."""
    id: Optional[str] = None
    name: Optional[str] = None


class SourceEndpoint(BaseModel):
    """The source of the action (often the attacker IP)."""
    ip: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None


class DestinationEndpoint(BaseModel):
    """The destination/target of the action."""
    ip: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None


class MitreMapping(BaseModel):
    """MITRE ATT&CK technique reference from the rule."""
    technique_ids: list[str] = Field(default_factory=list)   # e.g. ["T1110", "T1078"]
    technique_names: list[str] = Field(default_factory=list)
    tactic_names: list[str] = Field(default_factory=list)


class RuleInfo(BaseModel):
    """The detection rule that fired."""
    id: str
    level: int = Field(ge=0, le=15)        # Wazuh rule.level
    description: str
    groups: list[str] = Field(default_factory=list)


class NormalizedAlert(BaseModel):
    """The internal, SIEM-agnostic alert format."""
    # Identity
    alert_id: str
    timestamp: datetime
    source_siem: str = "wazuh"             # which SIEM produced this

    # The detection
    rule: RuleInfo
    mitre: MitreMapping = Field(default_factory=MitreMapping)

    # Who/where
    host: Host = Field(default_factory=Host)
    agent: Agent = Field(default_factory=Agent)
    source: SourceEndpoint = Field(default_factory=SourceEndpoint)
    destination: DestinationEndpoint = Field(default_factory=DestinationEndpoint)

    # Raw evidence (preserved for the LLM and the report)
    event_action: Optional[str] = None     # what happened, e.g. "logon-failed"
    event_outcome: Optional[str] = None    # "success" / "failure"
    full_log: Optional[str] = None         # original raw log line
    raw: dict = Field(default_factory=dict)  # complete original Wazuh alert
