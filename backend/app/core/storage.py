import os
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join("data", "processed", "investigations_store.json")


def _load_all() -> List[Dict[str, Any]]:
    if not os.path.exists(DB_PATH):
        return []
    with open(DB_PATH, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def _save_all(records: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


def save_investigation(report_dict: Dict[str, Any], filename: str = "uploaded_email.eml") -> Dict[str, Any]:
    records = _load_all()
    record = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "filename": filename,
        "analyst_decision": "Pending Review",
        "analyst_notes": "",
        "report": report_dict,
    }
    records.insert(0, record)
    _save_all(records)
    return record


def list_investigations() -> List[Dict[str, Any]]:
    return _load_all()


def get_investigation(inv_id: str) -> Optional[Dict[str, Any]]:
    for rec in _load_all():
        if rec["id"] == inv_id:
            return rec
    return None


def update_analyst_decision(inv_id: str, decision: str, notes: str = "") -> Optional[Dict[str, Any]]:
    records = _load_all()
    for rec in records:
        if rec["id"] == inv_id:
            rec["analyst_decision"] = decision
            rec["analyst_notes"] = notes
            rec["reviewed_at"] = datetime.now(timezone.utc).isoformat()
            _save_all(records)
            return rec
    return None