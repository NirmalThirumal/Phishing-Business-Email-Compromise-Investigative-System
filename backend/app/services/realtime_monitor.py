import sys
import os
import json
import time
import socket
import imaplib
from dotenv import load_dotenv

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
os.chdir(PROJECT_ROOT)

from app.parsers.email_parser import parse_eml_bytes
from app.ml.inference import DualMLPredictor
from app.agents.graph import run_full_investigation
from app.core.storage import save_investigation

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")
IMAP_USER = os.getenv("IMAP_USER", "")
IMAP_APP_PASSWORD = os.getenv("IMAP_APP_PASSWORD", "")
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "15"))
SEEN_STATE_FILE = os.path.join("data", "processed", "seen_imap_ids.json")


def _load_seen_uids() -> set:
    if not os.path.exists(SEEN_STATE_FILE):
        return set()
    try:
        with open(SEEN_STATE_FILE, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except Exception:
        return set()


def _save_seen_uids(uids: set) -> None:
    os.makedirs(os.path.dirname(SEEN_STATE_FILE), exist_ok=True)
    with open(SEEN_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(list(uids), f, indent=2)


def poll_mailbox_once(predictor: DualMLPredictor) -> int:
    """Checks both INBOX and [Gmail]/Spam for new emails, investigates them, and saves to dashboard DB."""
    if not IMAP_USER or not IMAP_APP_PASSWORD:
        raise ValueError("Set IMAP_USER and IMAP_APP_PASSWORD in your .env file to enable live monitoring.")

    socket.setdefaulttimeout(12)
    seen_uids = _load_seen_uids()
    processed_count = 0

    mail = imaplib.IMAP4_SSL(IMAP_HOST)
    try:
        mail.login(IMAP_USER, IMAP_APP_PASSWORD)

        # Check both INBOX and Spam (Gmail often routes test phishing/BEC emails to Spam)
        for folder in ["INBOX", "[Gmail]/Spam"]:
            status, _ = mail.select(f'"{folder}"', readonly=True)
            if status != "OK":
                continue

            # Fetch the 5 most recent emails in the folder using UIDs
            status, data = mail.uid("search", None, "ALL")
            if status != "OK" or not data[0]:
                continue

            recent_uids = data[0].split()[-5:]
            for uid_bytes in recent_uids:
                uid_key = f"{folder}:{uid_bytes.decode()}"
                if uid_key in seen_uids:
                    continue

                # Mark seen immediately so existing inbox history isn't re-scanned endlessly
                seen_uids.add(uid_key)
                _save_seen_uids(seen_uids)

                _, msg_data = mail.uid("fetch", uid_bytes, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        raw_bytes = response_part[1]
                        parsed = parse_eml_bytes(raw_bytes, check_live_dns=False)
                        print(f"[IMAP] Found new email in {folder}: '{parsed.subject}' from {parsed.sender_email}")

                        ml_res = predictor.predict(parsed, org_domain="acmecorp.com")
                        report = run_full_investigation(parsed, ml_res)

                        saved = save_investigation(
                            report_dict=report.model_dump(),
                            filename=f"LIVE_{folder.replace('[Gmail]/', '')}_{uid_bytes.decode()}.eml",
                        )
                        print(
                            f"[LIVE MONITOR] Investigated '{parsed.subject}' -> "
                            f"{report.verdict.attack_classification} (Score: {report.verdict.overall_risk_score}/100, ID: #{saved['id']})"
                        )
                        processed_count += 1
    finally:
        try:
            mail.logout()
        except Exception:
            pass

    return processed_count


if __name__ == "__main__":
    print(f"Starting Real-Time Email Security Monitor for {IMAP_USER} on {IMAP_HOST} (every {POLL_INTERVAL_SECONDS}s)...", flush=True)
    predictor = DualMLPredictor()
    while True:
        try:
            print(f"[{time.strftime('%H:%M:%S')}] Polling Gmail INBOX & Spam...", flush=True)
            count = poll_mailbox_once(predictor)
            if count == 0:
                print(f"[{time.strftime('%H:%M:%S')}] No new emails detected.", flush=True)
        except Exception as e:
            print(f"[Monitor Error] {e}", flush=True)
        time.sleep(POLL_INTERVAL_SECONDS)