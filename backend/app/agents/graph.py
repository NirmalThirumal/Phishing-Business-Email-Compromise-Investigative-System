import json
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage

from app.core.config import settings
from app.schemas.email_schema import ParsedEmail
from app.ml.inference import MLTriageResult
from app.schemas.investigation_schema import AgentFinding, FinalVerdict, FullInvestigationReport
from app.rag.vector_store import ThreatIntelRAG
from app.agents.tools import (
    check_virustotal_url,
    check_google_safe_browsing,
    check_urlhaus_url,
    check_domain_age_whois,
    verify_identity_against_directory,
)


class InvestigationState(TypedDict):
    parsed_email: ParsedEmail
    ml_triage: MLTriageResult
    email_agent_report: AgentFinding
    url_agent_report: AgentFinding
    identity_agent_report: AgentFinding
    intel_agent_report: AgentFinding
    final_verdict: FinalVerdict


# Initialize shared RAG instance once
_rag_store = ThreatIntelRAG()


# ---------------------------------------------------------------------------
# Agent 1: Email & Header Analysis Agent
# ---------------------------------------------------------------------------
def email_analysis_node(state: InvestigationState) -> Dict[str, Any]:
    parsed = state["parsed_email"]
    findings: List[str] = []
    status = "clean"

    if parsed.display_name_contains_email:
        findings.append(
            f"Display name spoofing: '{parsed.sender_display_name}' embeds an email address that differs from '{parsed.sender_email}'."
        )
        status = "malicious"

    if parsed.reply_to_mismatch:
        findings.append(
            f"Reply-To mismatch: From domain is '{parsed.sender_domain}', while Reply-To is '{parsed.reply_to_email}'."
        )
        if status == "clean":
            status = "suspicious"

    if parsed.return_path_mismatch:
        findings.append(
            f"Return-Path mismatch: Bounce address '{parsed.return_path_email}' differs from sender domain '{parsed.sender_domain}'."
        )
        if status == "clean":
            status = "suspicious"

    for auth_note in parsed.auth_results.authentication_summary:
        findings.append(auth_note)
        if "fail" in auth_note.lower():
            status = "malicious" if status == "malicious" else "suspicious"

    for att in parsed.attachments:
        if att.is_executable_or_macro:
            findings.append(
                f"High-risk attachment detected: '{att.filename}' ({att.content_type}, SHA256: {att.sha256[:12]}...)."
            )
            status = "malicious"

    if not findings:
        findings.append("No header spoofing, authentication failures, or dangerous attachments detected.")

    return {
        "email_agent_report": AgentFinding(
            agent_name="Email & Header Analysis Agent",
            status=status,
            findings=findings,
            evidence={
                "spf": parsed.auth_results.spf_status,
                "dkim": parsed.auth_results.dkim_status,
                "dmarc": parsed.auth_results.dmarc_status,
                "reply_to_mismatch": parsed.reply_to_mismatch,
                "attachment_count": len(parsed.attachments),
            },
        )
    }


# ---------------------------------------------------------------------------
# Agent 2: URL & Domain Investigation Agent
# ---------------------------------------------------------------------------
def url_investigation_node(state: InvestigationState) -> Dict[str, Any]:
    parsed = state["parsed_email"]
    if not parsed.urls:
        return {
            "url_agent_report": AgentFinding(
                agent_name="URL & Domain Investigation Agent",
                status="clean",
                findings=["No embedded URLs found in the email body (characteristic of zero-payload BEC if other indicators exist)."],
                evidence={"url_count": 0},
            )
        }

    findings: List[str] = []
    status = "clean"
    url_evidence: List[Dict[str, Any]] = []

    raw_urls = [u.raw_url for u in parsed.urls]
    gsb_result = check_google_safe_browsing(raw_urls)
    if gsb_result.get("threat_count", 0) > 0:
        findings.append(f"Google Safe Browsing flagged {gsb_result['threat_count']} unsafe URL(s)!")
        status = "malicious"

    for u in parsed.urls:
        if u.is_ip_address:
            findings.append(f"Raw IP-address URL detected ('{u.raw_url}') — commonly used to bypass domain reputation filters.")
            status = "malicious"
        if u.is_shortened:
            findings.append(f"URL shortener detected ('{u.raw_url}') — obscures final destination.")
            if status == "clean":
                status = "suspicious"
        if u.mismatched_anchor:
            findings.append(
                f"Deceptive anchor text: Link displays '{u.anchor_text}' but actually points to '{u.raw_url}'."
            )
            status = "malicious"

        vt_res = check_virustotal_url(u.raw_url)
        if vt_res.get("malicious_votes", 0) > 0:
            findings.append(f"VirusTotal flagged '{u.raw_url}' ({vt_res['malicious_votes']} security vendors marked malicious).")
            status = "malicious"

        uh_res = check_urlhaus_url(u.raw_url)
        if uh_res.get("query_status") == "ok":
            findings.append(f"URLhaus database matched '{u.raw_url}' as active malware/phishing distribution.")
            status = "malicious"

        whois_res = check_domain_age_whois(u.domain)
        if whois_res.get("newly_registered"):
            findings.append(f"Domain '{u.domain}' was newly registered ({whois_res.get('age_days')} days ago).")
            if status == "clean":
                status = "suspicious"

        url_evidence.append({
            "url": u.raw_url,
            "domain": u.domain,
            "virustotal": vt_res,
            "urlhaus": uh_res,
            "whois": whois_res,
        })

    if not findings:
        findings.append(f"Inspected {len(parsed.urls)} URL(s); no malicious reputation hits found.")

    return {
        "url_agent_report": AgentFinding(
            agent_name="URL & Domain Investigation Agent",
            status=status,
            findings=findings,
            evidence={"google_safe_browsing": gsb_result, "inspected_urls": url_evidence},
        )
    }


# ---------------------------------------------------------------------------
# Agent 3: Identity & Impersonation Verification Agent
# ---------------------------------------------------------------------------
def identity_verification_node(state: InvestigationState) -> Dict[str, Any]:
    parsed = state["parsed_email"]
    dir_check = verify_identity_against_directory(
        sender_name=parsed.sender_display_name,
        sender_email=parsed.sender_email,
        sender_domain=parsed.sender_domain,
        reply_to_email=parsed.reply_to_email,
    )

    findings = list(dir_check["findings"])
    sender_whois = check_domain_age_whois(parsed.sender_domain)
    if sender_whois.get("newly_registered"):
        findings.append(
            f"Sender domain '{parsed.sender_domain}' is newly registered ({sender_whois.get('age_days')} days old)."
        )

    status = "clean"
    if dir_check["impersonated_executive"] or dir_check["domain_typosquat_target"]:
        status = "malicious"
    elif findings:
        status = "suspicious"
    else:
        findings.append("Sender identity and domain show no impersonation against the internal corporate directory.")

    return {
        "identity_agent_report": AgentFinding(
            agent_name="Identity & Impersonation Agent",
            status=status,
            findings=findings,
            evidence={
                "directory_check": dir_check,
                "sender_domain_whois": sender_whois,
            },
        )
    }


# ---------------------------------------------------------------------------
# Agent 4: Threat Intelligence RAG Agent
# ---------------------------------------------------------------------------
def threat_intel_rag_node(state: InvestigationState) -> Dict[str, Any]:
    parsed = state["parsed_email"]
    query_text = f"{parsed.subject} {parsed.body_text[:400]}".strip()
    retrieved_docs = _rag_store.retrieve(query_text, top_k=3)

    findings: List[str] = []
    for doc in retrieved_docs:
        snippet = doc["content"].splitlines()[0].replace("#", "").strip()
        findings.append(
            f"Matched [{doc['source']}] (similarity: {doc['relevance_score']}): {snippet}"
        )

    return {
        "intel_agent_report": AgentFinding(
            agent_name="Threat Intelligence RAG Agent",
            status="suspicious" if retrieved_docs else "clean",
            findings=findings,
            evidence={"retrieved_passages": retrieved_docs},
        )
    }


# ---------------------------------------------------------------------------
# Agent 5: Risk Assessment & Reporting Agent (Gemini LLM + Resilient Fallback)
# ---------------------------------------------------------------------------
def _candidate_gemini_models() -> List[str]:
    ordered = [settings.GEMINI_MODEL] + list(getattr(settings, "GEMINI_FALLBACK_MODELS", []))
    seen: List[str] = []
    for model_name in ordered:
        if model_name and model_name not in seen:
            seen.append(model_name)
    return seen


def _deterministic_verdict_fallback(
    parsed: ParsedEmail, ml: MLTriageResult, reports: List[AgentFinding]
) -> FinalVerdict:
    """Fallback evidence synthesizer if Gemini API is unavailable or rate-limited."""
    verified: List[str] = []
    suspicions: List[str] = []
    citations: List[str] = []

    for r in reports:
        if r.agent_name == "Threat Intelligence RAG Agent":
            for doc in r.evidence.get("retrieved_passages", []):
                citations.append(doc["source"])
        elif r.status in {"malicious", "suspicious"}:
            for f in r.findings:
                if r.status == "malicious":
                    verified.append(f)
                else:
                    suspicions.append(f)

    body_and_subj = f"{parsed.subject} {parsed.body_text}".lower()
    exec_or_finance_lure = (
        any(k in body_and_subj for k in ["wire transfer", "beneficiary", "escrow", "gift card", "confidential board"])
        and any(k in body_and_subj for k in ["ceo", "cfo", "vikram mehta", "ananya nair", "urgent"])
        and parsed.sender_domain != "acmecorp.com"
    )

    if exec_or_finance_lure and "External sender impersonating executive authority or requesting urgent financial transfer." not in verified:
        verified.append("External sender impersonating executive authority or requesting urgent financial transfer.")

    is_bec = (
        len(parsed.urls) == 0
        and (
            exec_or_finance_lure
            or any("impersonation" in v.lower() or "lookalike" in v.lower() for v in verified)
            or parsed.reply_to_mismatch
        )
    )
    has_malicious_url = any(
        r.agent_name == "URL & Domain Investigation Agent" and r.status == "malicious"
        for r in reports
    )

    if is_bec:
        classification = "Business Email Compromise (BEC)"
    elif has_malicious_url:
        classification = "Phishing"
    elif ml.combined_ml_risk_score >= 65 and suspicions:
        classification = "Suspicious - Needs Review"
    else:
        classification = "Legitimate"

    if classification in {"Phishing", "Business Email Compromise (BEC)"}:
        score = min(100, int(max(ml.combined_ml_risk_score, 85)))
    elif classification == "Suspicious - Needs Review":
        score = min(74, int(ml.combined_ml_risk_score))
    else:
        score = min(35, int(ml.combined_ml_risk_score * 0.4))

    return FinalVerdict(
        attack_classification=classification,
        overall_risk_score=score,
        confidence_level="High" if verified else "Medium",
        executive_summary=(
            f"Automated multi-agent investigation classified this message from '{parsed.sender_email}' "
            f"as {classification} (Risk Score: {score}/100) based on {len(verified)} verified technical indicators "
            f"and an ML risk score of {ml.combined_ml_risk_score}/100."
        ),
        verified_indicators=verified or ["No high-confidence malicious indicators detected."],
        heuristic_suspicions=suspicions,
        cited_policies_and_intel=list(dict.fromkeys(citations)),
        recommended_actions=(
            [
                "Quarantine the email immediately pending SOC analyst verification.",
                "Do not reply to the sender or click any embedded links.",
                "Verify any financial transfer or credential request out-of-band via an internally registered phone number.",
            ]
            if classification != "Legitimate"
            else ["No containment required; standard delivery permitted."]
        ),
    )


def risk_assessment_node(state: InvestigationState) -> Dict[str, Any]:
    parsed = state["parsed_email"]
    ml = state["ml_triage"]
    reports = [
        state["email_agent_report"],
        state["url_agent_report"],
        state["identity_agent_report"],
        state["intel_agent_report"],
    ]

    if not settings.GOOGLE_API_KEY:
        return {"final_verdict": _deterministic_verdict_fallback(parsed, ml, reports)}

    system_prompt = (
        "You are a Senior SOC Cybersecurity Incident Responder analyzing a suspicious email. "
        "Synthesize the ML triage scores and the 4 specialized agent investigation reports into a clear, "
        "evidence-grounded FinalVerdict. "
        "CRITICAL RULES:\n"
        "1. Distinguish strictly between 'verified_indicators' (hard technical facts like failed SPF/DMARC, "
        "mismatched HTML hrefs, executive email mismatch, or Threat Intel hits) and 'heuristic_suspicions' "
        "(behavioral cues like urgent payment language or secrecy).\n"
        "2. Classify Business Email Compromise (BEC) accurately when an attacker impersonates an executive/vendor "
        "or requests an urgent financial/wire transfer even if zero URLs are present.\n"
        "3. Cite the exact RAG sources (e.g., 'mitre_attack/t1566_phishing.md', 'cisa_advisories/bec_guidance.md', "
        "'org_policies/wire_transfer_and_exec_policy.md') in 'cited_policies_and_intel'.\n"
        "4. Always frame recommendations as Human-in-the-Loop actions for a SOC analyst."
    )

    investigation_context = {
        "email_metadata": {
            "subject": parsed.subject,
            "from_display": parsed.sender_display_name,
            "from_email": parsed.sender_email,
            "reply_to": parsed.reply_to_email,
            "recipients": parsed.recipients,
            "body_excerpt": parsed.body_text[:1000],
        },
        "ml_triage": ml.model_dump(),
        "agent_findings": [r.model_dump() for r in reports],
    }

    for model_name in _candidate_gemini_models():
        try:
            llm = ChatGoogleGenerativeAI(
                model=model_name,
                google_api_key=settings.GOOGLE_API_KEY,
                temperature=0.1,
                max_retries=0,
            )
            structured_llm = llm.with_structured_output(FinalVerdict)
            verdict: FinalVerdict = structured_llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=f"Investigate and synthesize this evidence:\n{json.dumps(investigation_context, indent=2)}"),
            ])
            return {"final_verdict": verdict}
        except Exception as exc:
            err_name = type(exc).__name__
            err_msg = str(exc)
            print(f"[Warning] Model '{model_name}' unavailable ({err_name}), trying fallback...")
            if any(token in err_msg for token in ("429", "RESOURCE_EXHAUSTED", "Quota", "quota")):
                break

    return {"final_verdict": _deterministic_verdict_fallback(parsed, ml, reports)}


# ---------------------------------------------------------------------------
# Compile the LangGraph Workflow
# ---------------------------------------------------------------------------
def build_investigation_graph():
    workflow = StateGraph(InvestigationState)

    workflow.add_node("email_agent", email_analysis_node)
    workflow.add_node("url_agent", url_investigation_node)
    workflow.add_node("identity_agent", identity_verification_node)
    workflow.add_node("intel_agent", threat_intel_rag_node)
    workflow.add_node("risk_agent", risk_assessment_node)

    workflow.set_entry_point("email_agent")
    workflow.add_edge("email_agent", "url_agent")
    workflow.add_edge("url_agent", "identity_agent")
    workflow.add_edge("identity_agent", "intel_agent")
    workflow.add_edge("intel_agent", "risk_agent")
    workflow.add_edge("risk_agent", END)

    return workflow.compile()


investigation_graph = build_investigation_graph()


def run_full_investigation(parsed: ParsedEmail, ml_triage: MLTriageResult) -> FullInvestigationReport:
    initial_state: InvestigationState = {
        "parsed_email": parsed,
        "ml_triage": ml_triage,
        "email_agent_report": None,  # type: ignore
        "url_agent_report": None,    # type: ignore
        "identity_agent_report": None,  # type: ignore
        "intel_agent_report": None,  # type: ignore
        "final_verdict": None,       # type: ignore
    }

    final_state = investigation_graph.invoke(initial_state)

    return FullInvestigationReport(
        parsed_email=parsed,
        ml_triage=ml_triage,
        agent_reports=[
            final_state["email_agent_report"],
            final_state["url_agent_report"],
            final_state["identity_agent_report"],
            final_state["intel_agent_report"],
        ],
        verdict=final_state["final_verdict"],
    )