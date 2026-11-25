from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from app.parsers.email_parser import parse_eml_bytes
from app.ml.inference import DualMLPredictor
from app.agents.graph import run_full_investigation
from app.core.storage import (
    save_investigation,
    list_investigations,
    get_investigation,
    update_analyst_decision,
)

router = APIRouter(prefix="/api", tags=["Investigations"])
predictor = DualMLPredictor()


class AnalystDecisionRequest(BaseModel):
    decision: str  # "Quarantine Email", "Mark as Phishing / BEC", "Mark as Legitimate", "Escalate to Tier-2"
    notes: str = ""


@router.get("/health")
def health_check():
    return {"status": "online", "system": "Phishing & Business Email Compromise Investigative System"}


@router.post("/investigate/upload")
async def investigate_eml_upload(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Please upload a valid .eml file.")

    raw_bytes = await file.read()
    parsed = parse_eml_bytes(raw_bytes, check_live_dns=False)
    ml_result = predictor.predict(parsed, org_domain="acmecorp.com")
    full_report = run_full_investigation(parsed, ml_result)

    saved_record = save_investigation(
        report_dict=full_report.model_dump(),
        filename=file.filename,
    )
    return saved_record


@router.get("/investigations")
def get_all_investigations():
    return list_investigations()


@router.get("/investigations/{inv_id}")
def get_single_investigation(inv_id: str):
    record = get_investigation(inv_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation ID not found.")
    return record


@router.post("/investigations/{inv_id}/decision")
def submit_analyst_decision(inv_id: str, payload: AnalystDecisionRequest):
    updated = update_analyst_decision(inv_id, payload.decision, payload.notes)
    if not updated:
        raise HTTPException(status_code=404, detail="Investigation ID not found.")
    return updated