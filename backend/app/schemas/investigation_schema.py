from pydantic import BaseModel, Field
from typing import List, Dict, Any, Literal
from app.schemas.email_schema import ParsedEmail
from app.ml.inference import MLTriageResult


class AgentFinding(BaseModel):
    agent_name: str
    status: Literal["clean", "suspicious", "malicious", "skipped"]
    findings: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)


class FinalVerdict(BaseModel):
    attack_classification: Literal[
        "Phishing",
        "Business Email Compromise (BEC)",
        "Spearphishing / Hybrid Attack",
        "Suspicious - Needs Review",
        "Legitimate",
    ]
    overall_risk_score: int = Field(ge=0, le=100)
    confidence_level: Literal["High", "Medium", "Low"]
    executive_summary: str
    verified_indicators: List[str] = Field(default_factory=list)
    heuristic_suspicions: List[str] = Field(default_factory=list)
    cited_policies_and_intel: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)


class FullInvestigationReport(BaseModel):
    parsed_email: ParsedEmail
    ml_triage: MLTriageResult
    agent_reports: List[AgentFinding]
    verdict: FinalVerdict