import os
import sys
import json
import time
from typing import List, Dict, Any

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    confusion_matrix,
)

# Resolve project root and backend/ directory cleanly
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__)))
PROJECT_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
os.chdir(PROJECT_ROOT)

from app.parsers.email_parser import parse_eml_bytes
from app.ml.inference import DualMLPredictor
from app.rag.vector_store import ThreatIntelRAG
from app.agents.graph import run_full_investigation

REPORT_OUT_PATH = os.path.join("data", "processed", "component_evaluation_report.json")


# ---------------------------------------------------------------------------
# Labeled Ground-Truth Test Emails (Covers Phishing, BEC, Vendor Fraud, Clean)
# ---------------------------------------------------------------------------
GROUND_TRUTH_EMAILS: List[Dict[str, Any]] = [
    {
        "case_id": "GT-01_PHISH_IP_SPOOF",
        "expected_class": "Phishing",
        "expected_binary": 1,
        "expected_agents": {"email": "malicious", "url": "malicious", "identity": "suspicious"},
        "raw_eml": (
            b'Authentication-Results: mx.acmecorp.com; spf=fail; dkim=fail; dmarc=fail\r\n'
            b'From: "Microsoft 365 Security <support@microsoft.com>" <alert@office365-verify-login.com>\r\n'
            b'Reply-To: harvest-team@external-mail-drop.net\r\n'
            b'To: user@acmecorp.com\r\n'
            b'Subject: URGENT: Your Office 365 Password Expires in 2 Hours\r\n'
            b'Content-Type: text/html; charset="utf-8"\r\n\r\n'
            b'<html><body><p>Click <a href="http://198.51.100.42/auth/login">https://login.microsoftonline.com/verify</a> immediately.</p></body></html>'
        ),
    },
    {
        "case_id": "GT-02_BEC_EXEC_WIRE",
        "expected_class": "Business Email Compromise (BEC)",
        "expected_binary": 1,
        "expected_agents": {"email": "suspicious", "url": "clean", "identity": "malicious"},
        "raw_eml": (
            b'Authentication-Results: mx.acmecorp.com; spf=pass; dkim=none; dmarc=fail\r\n'
            b'From: "Vikram Mehta (CEO)" <vikram.mehta@acmec0rp.com>\r\n'
            b'Reply-To: v.mehta.exec@gmail.com\r\n'
            b'To: priya.sharma@acmecorp.com\r\n'
            b'Subject: Confidential - Urgent Vendor Wire Transfer Today\r\n'
            b'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
            b'Hi Priya, I am in a confidential board acquisition meeting and cannot take calls. Please wire transfer $48,500 immediately.'
        ),
    },
    {
        "case_id": "GT-03_BEC_GIFT_CARD_GMAIL",
        "expected_class": "Business Email Compromise (BEC)",
        "expected_binary": 1,
        "expected_agents": {"email": "clean", "url": "clean", "identity": "malicious"},
        "raw_eml": (
            b'Authentication-Results: mx.acmecorp.com; spf=pass; dkim=pass; dmarc=pass\r\n'
            b'From: "Vikram Mehta" <vikram.ceo.desk@gmail.com>\r\n'
            b'To: ananya.nair@acmecorp.com\r\n'
            b'Subject: Quick confidential favor\r\n'
            b'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
            b'Hi Ananya, I am in a confidential board session. Urgently purchase 10 Apple Gift Cards ($200 each) and email the codes. Vikram Mehta, CEO.'
        ),
    },
    {
        "case_id": "GT-04_VENDOR_BANK_CHANGE",
        "expected_class": "Business Email Compromise (BEC)",
        "expected_binary": 1,
        "expected_agents": {"email": "malicious", "url": "clean", "identity": "malicious"},
        "raw_eml": (
            b'Authentication-Results: mx.acmecorp.com; spf=softfail; dkim=none; dmarc=fail\r\n'
            b'From: "Apex Legal Partners Billing" <billing@apexlega1-partners.com>\r\n'
            b'Reply-To: settlements@apex-remittance-desk.com\r\n'
            b'To: finance@acmecorp.com\r\n'
            b'Subject: UPDATED BANKING DETAILS: Overdue Retainer Invoice #INV-2026-894\r\n'
            b'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
            b'Please route future invoice settlements to our updated beneficiary escrow account via urgent wire transfer today.'
        ),
    },
    {
        "case_id": "GT-05_PHISH_HR_BONUS",
        "expected_class": "Phishing",
        "expected_binary": 1,
        "expected_agents": {"email": "malicious", "url": "malicious", "identity": "suspicious"},
        "raw_eml": (
            b'Authentication-Results: mx.acmecorp.com; spf=fail; dkim=fail; dmarc=fail\r\n'
            b'From: "AcmeCorp HR & Payroll <hr@acmecorp.com>" <noreply@hr-benefits-portal-sync.com>\r\n'
            b'To: priya.sharma@acmecorp.com\r\n'
            b'Subject: Action Required: 2026 Annual Bonus & Tax Form W-2 Verification\r\n'
            b'Content-Type: text/html; charset="utf-8"\r\n\r\n'
            b'<html><body><p>Verify SSO within 24 hours: <a href="http://203.0.113.19/sso/login">https://hr.acmecorp.com/bonus</a></p></body></html>'
        ),
    },
    {
        "case_id": "GT-06_CLEAN_INTERNAL_SYNC",
        "expected_class": "Legitimate",
        "expected_binary": 0,
        "expected_agents": {"email": "clean", "url": "clean", "identity": "clean"},
        "raw_eml": (
            b'Authentication-Results: mx.acmecorp.com; spf=pass; dkim=pass; dmarc=pass\r\n'
            b'From: "Rahul Verma" <rahul.verma@acmecorp.com>\r\n'
            b'To: engineering@acmecorp.com\r\n'
            b'Subject: Notes from Q4 Architecture Sync & Sprint Planning\r\n'
            b'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
            b'Hi Team, Thanks for joining this morning Q4 architecture review. Here is our recap for Sprint 14 action items.'
        ),
    },
    {
        "case_id": "GT-07_CLEAN_VENDOR_UPDATE",
        "expected_class": "Legitimate",
        "expected_binary": 0,
        "expected_agents": {"email": "clean", "url": "clean", "identity": "clean"},
        "raw_eml": (
            b'Authentication-Results: mx.acmecorp.com; spf=pass; dkim=pass; dmarc=pass\r\n'
            b'From: "Vikram Mehta" <vikram.mehta@acmecorp.com>\r\n'
            b'To: all-staff@acmecorp.com\r\n'
            b'Subject: Q4 All-Hands Town Hall Recording & Slides\r\n'
            b'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
            b'Hello everyone, Thank you for a great quarter. Please find the town hall summary attached in the internal portal.'
        ),
    },
    {
        "case_id": "GT-08_CLEAN_IT_MAINTENANCE",
        "expected_class": "Legitimate",
        "expected_binary": 0,
        "expected_agents": {"email": "clean", "url": "clean", "identity": "clean"},
        "raw_eml": (
            b'Authentication-Results: mx.acmecorp.com; spf=pass; dkim=pass; dmarc=pass\r\n'
            b'From: "IT Operations" <it-ops@acmecorp.com>\r\n'
            b'To: engineering@acmecorp.com\r\n'
            b'Subject: Scheduled Weekend Maintenance Window - Staging Cluster\r\n'
            b'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
            b'Hi Team, Routine patching on the staging Kubernetes cluster will occur Saturday between 02:00 and 04:00 UTC. No action required.'
        ),
    },
]


# ---------------------------------------------------------------------------
# 1. Evaluate Email Parser & Feature Extraction Engine
# ---------------------------------------------------------------------------
def evaluate_parser() -> Dict[str, Any]:
    latencies_ms = []
    checks_passed = 0
    total_checks = 0

    for item in GROUND_TRUTH_EMAILS:
        t0 = time.perf_counter()
        parsed = parse_eml_bytes(item["raw_eml"], check_live_dns=False)
        latencies_ms.append((time.perf_counter() - t0) * 1000)
        pdata = parsed.model_dump()

        total_checks += 2
        if parsed.sender_email and "@" in parsed.sender_email:
            checks_passed += 1

        if item["case_id"] == "GT-01_PHISH_IP_SPOOF":
            has_ip = any(u.get("is_ip_address") for u in pdata.get("urls", []))
            if pdata.get("reply_to_mismatch") and has_ip:
                checks_passed += 1
        elif item["case_id"] == "GT-05_PHISH_HR_BONUS":
            has_mismatch = any(
                u.get("anchor_text_mismatch") or u.get("is_ip_address")
                for u in pdata.get("urls", [])
            )
            if has_mismatch:
                checks_passed += 1
        elif item["case_id"] == "GT-02_BEC_EXEC_WIRE":
            if pdata.get("reply_to_mismatch") and len(pdata.get("urls", [])) == 0:
                checks_passed += 1
        else:
            spf = pdata.get("auth_results", {}).get("spf_status", "")
            if spf in {"pass", "fail", "softfail", "none"}:
                checks_passed += 1

    return {
        "component": "1. Email Parsing & Feature Engine",
        "extraction_accuracy_pct": round((checks_passed / total_checks) * 100, 2),
        "assertions_passed": f"{checks_passed}/{total_checks}",
        "avg_latency_ms": round(float(np.mean(latencies_ms)), 3),
    }


# ---------------------------------------------------------------------------
# 2. Evaluate Dual ML Models (Track A: XGBoost NLP + Track B: Isolation Forest)
# ---------------------------------------------------------------------------
def evaluate_ml_models() -> Dict[str, Any]:
    corpus_path = os.path.join("data", "processed", "merged_training_corpus.csv")
    vec_path = os.path.join("data", "processed", "tfidf_vectorizer.joblib")
    xgb_path = os.path.join("data", "processed", "xgb_phishing_model.joblib")

    results: Dict[str, Any] = {}

    if os.path.exists(corpus_path) and os.path.exists(vec_path) and os.path.exists(xgb_path):
        df = pd.read_csv(corpus_path).dropna(subset=["text", "label"])
        _, X_test, _, y_test = train_test_split(
            df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
        )
        vec = joblib.load(vec_path)
        clf = joblib.load(xgb_path)

        t0 = time.perf_counter()
        X_test_vec = vec.transform(X_test)
        preds = clf.predict(X_test_vec)
        probs = clf.predict_proba(X_test_vec)[:, 1]
        infer_ms = ((time.perf_counter() - t0) * 1000) / len(X_test)

        acc = accuracy_score(y_test, preds)
        prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average="binary", zero_division=0)
        auc = roc_auc_score(y_test, probs)
        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        results["track_a_xgboost_nlp"] = {
            "test_samples": int(len(y_test)),
            "accuracy_pct": round(acc * 100, 2),
            "precision_pct": round(prec * 100, 2),
            "recall_pct": round(rec * 100, 2),
            "f1_score_pct": round(f1 * 100, 2),
            "roc_auc": round(float(auc), 4),
            "false_positive_rate_pct": round(fpr * 100, 2),
            "avg_latency_ms": round(infer_ms, 4),
        }
    else:
        results["track_a_xgboost_nlp"] = {"error": "Merged training corpus not found. Run upgrade_dataset_and_train.py first."}

    predictor = DualMLPredictor()
    y_true, y_pred_combined, anomaly_scores = [], [], []
    latencies = []

    for item in GROUND_TRUTH_EMAILS:
        parsed = parse_eml_bytes(item["raw_eml"], check_live_dns=False)
        t0 = time.perf_counter()
        ml_res = predictor.predict(parsed, org_domain="acmecorp.com")
        latencies.append((time.perf_counter() - t0) * 1000)

        y_true.append(item["expected_binary"])
        y_pred_combined.append(1 if ml_res.combined_ml_risk_score >= 50.0 else 0)
        anomaly_scores.append(ml_res.behavioral_anomaly_score)

    acc_c = accuracy_score(y_true, y_pred_combined)
    prec_c, rec_c, f1_c, _ = precision_recall_fscore_support(y_true, y_pred_combined, average="binary", zero_division=0)
    auc_iso = roc_auc_score(y_true, anomaly_scores)

    results["dual_ml_combined_triage"] = {
        "eval_emails": len(GROUND_TRUTH_EMAILS),
        "accuracy_pct": round(acc_c * 100, 2),
        "precision_pct": round(prec_c * 100, 2),
        "recall_pct": round(rec_c * 100, 2),
        "f1_score_pct": round(f1_c * 100, 2),
        "isolation_forest_roc_auc": round(float(auc_iso), 4),
        "avg_latency_ms": round(float(np.mean(latencies)), 2),
    }
    return results


# ---------------------------------------------------------------------------
# 3. Evaluate Threat Intelligence RAG Knowledge Base (Precision@3, Recall@3, MRR)
# ---------------------------------------------------------------------------
def evaluate_rag() -> Dict[str, Any]:
    rag_queries = [
        {
            "query": "Urgent CEO wire transfer request bypassing dual approval and callback verification",
            "expected_sources": {"org_policies/wire_transfer_and_exec_policy.md", "cisa_advisories/bec_guidance.md"},
        },
        {
            "query": "Credential harvesting link with deceptive HTML anchor href pointing to IP address",
            "expected_sources": {"mitre_attack/t1566_phishing.md"},
        },
        {
            "query": "Vendor banking account change notice on overdue invoice remittance",
            "expected_sources": {"org_policies/wire_transfer_and_exec_policy.md", "cisa_advisories/bec_guidance.md"},
        },
        {
            "query": "Lookalike typosquatted domain impersonating executive leadership",
            "expected_sources": {"cisa_advisories/bec_guidance.md", "org_policies/wire_transfer_and_exec_policy.md"},
        },
    ]

    rag = ThreatIntelRAG()
    k = 3

    # Dynamically detect the search/query method on ThreatIntelRAG
    search_fn = None
    for candidate in ("retrieve_relevant_intel", "search", "query", "retrieve", "get_relevant_documents"):
        if hasattr(rag, candidate) and callable(getattr(rag, candidate)):
            search_fn = getattr(rag, candidate)
            break

    precisions, recalls, reciprocal_ranks, latencies = [], [], [], []

    for q in rag_queries:
        t0 = time.perf_counter()
        if search_fn is not None:
            try:
                hits = search_fn(q["query"], top_k=k)
            except TypeError:
                try:
                    hits = search_fn(q["query"], k=k)
                except TypeError:
                    hits = search_fn(q["query"])
        elif hasattr(rag, "collection"):
            res = rag.collection.query(query_texts=[q["query"]], n_results=k)
            metas = (res.get("metadatas") or [[]])[0]
            hits = [{"source": m.get("source", "")} for m in metas]
        else:
            raise AttributeError(f"Could not find query method on ThreatIntelRAG: {dir(rag)}")

        latencies.append((time.perf_counter() - t0) * 1000)

        retrieved_sources = []
        for h in hits[:k]:
            if isinstance(h, dict):
                retrieved_sources.append(h.get("source") or h.get("metadata", {}).get("source", ""))
            elif hasattr(h, "metadata"):
                retrieved_sources.append(h.metadata.get("source", ""))

        relevant_retrieved = sum(1 for src in retrieved_sources if src in q["expected_sources"])
        unique_relevant_found = len(set(retrieved_sources).intersection(q["expected_sources"]))

        precisions.append(relevant_retrieved / k)
        recalls.append(unique_relevant_found / len(q["expected_sources"]))

        rr = 0.0
        for rank, src in enumerate(retrieved_sources, start=1):
            if src in q["expected_sources"]:
                rr = 1.0 / rank
                break
        reciprocal_ranks.append(rr)

    return {
        "component": "3. Threat Intel RAG Knowledge Base (ChromaDB)",
        "queries_evaluated": len(rag_queries),
        "precision_at_3_pct": round(float(np.mean(precisions)) * 100, 2),
        "recall_at_3_pct": round(float(np.mean(recalls)) * 100, 2),
        "mrr": round(float(np.mean(reciprocal_ranks)), 4),
        "avg_latency_ms": round(float(np.mean(latencies)), 2),
    }


# ---------------------------------------------------------------------------
# 4. Evaluate Individual LangGraph Agents & End-to-End Multi-Agent Pipeline
# ---------------------------------------------------------------------------
def evaluate_agents_and_pipeline() -> Dict[str, Any]:
    predictor = DualMLPredictor()
    agent_hits = {"email": 0, "url": 0, "identity": 0}
    total = len(GROUND_TRUTH_EMAILS)

    y_true_class, y_pred_class = [], []
    y_true_bin, y_pred_bin = [], []
    e2e_latencies = []

    for item in GROUND_TRUTH_EMAILS:
        t0 = time.perf_counter()
        parsed = parse_eml_bytes(item["raw_eml"], check_live_dns=False)
        ml_res = predictor.predict(parsed, org_domain="acmecorp.com")

        # Full end-to-end graph execution
        full_report = run_full_investigation(parsed, ml_res)
        e2e_latencies.append((time.perf_counter() - t0) * 1000)

        # Extract per-agent status from full_report.agent_reports
        for rep in full_report.agent_reports:
            name_lower = rep.agent_name.lower()
            if "email" in name_lower and rep.status == item["expected_agents"]["email"]:
                agent_hits["email"] += 1
            elif "url" in name_lower and rep.status == item["expected_agents"]["url"]:
                agent_hits["url"] += 1
            elif "identity" in name_lower and rep.status == item["expected_agents"]["identity"]:
                agent_hits["identity"] += 1

        pred_cls = full_report.verdict.attack_classification
        y_true_class.append(item["expected_class"])
        y_pred_class.append(pred_cls)

        y_true_bin.append(item["expected_binary"])
        y_pred_bin.append(0 if pred_cls == "Legitimate" else 1)

    e2e_acc = accuracy_score(y_true_class, y_pred_class)
    _, _, macro_f1, _ = precision_recall_fscore_support(y_true_class, y_pred_class, average="macro", zero_division=0)
    bin_prec, bin_rec, bin_f1, _ = precision_recall_fscore_support(y_true_bin, y_pred_bin, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true_bin, y_pred_bin).ravel()
    e2e_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "specialized_agents_accuracy": {
            "email_header_agent_pct": round((agent_hits["email"] / total) * 100, 2),
            "url_domain_agent_pct": round((agent_hits["url"] / total) * 100, 2),
            "identity_impersonation_agent_pct": round((agent_hits["identity"] / total) * 100, 2),
        },
        "end_to_end_pipeline": {
            "multiclass_accuracy_pct": round(e2e_acc * 100, 2),
            "multiclass_macro_f1_pct": round(macro_f1 * 100, 2),
            "threat_detection_precision_pct": round(bin_prec * 100, 2),
            "threat_detection_recall_pct": round(bin_rec * 100, 2),
            "threat_detection_f1_pct": round(bin_f1 * 100, 2),
            "false_positive_rate_pct": round(e2e_fpr * 100, 2),
            "avg_e2e_latency_ms": round(float(np.mean(e2e_latencies)), 2),
        },
    }


def main():
    print("=" * 84)
    print("PHISHGUARD AI — INDEPENDENT COMPONENT & END-TO-END ACCURACY BENCHMARK")
    print("=" * 84)

    parser_metrics = evaluate_parser()
    ml_metrics = evaluate_ml_models()
    rag_metrics = evaluate_rag()
    agent_metrics = evaluate_agents_and_pipeline()

    full_report = {
        "parser": parser_metrics,
        "ml_models": ml_metrics,
        "rag_knowledge_base": rag_metrics,
        "agents_and_pipeline": agent_metrics,
    }

    os.makedirs(os.path.dirname(REPORT_OUT_PATH), exist_ok=True)
    with open(REPORT_OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print("\n1. EMAIL PARSER & FEATURE EXTRACTION ENGINE")
    print(f"   Extraction Accuracy : {parser_metrics['extraction_accuracy_pct']}% ({parser_metrics['assertions_passed']})")
    print(f"   Avg Latency         : {parser_metrics['avg_latency_ms']} ms/email")

    if "accuracy_pct" in ml_metrics.get("track_a_xgboost_nlp", {}):
        xa = ml_metrics["track_a_xgboost_nlp"]
        print(f"\n2A. TRACK A — XGBOOST NLP CLASSIFIER (Holdout Test Set: n={xa['test_samples']})")
        print(f"   Accuracy            : {xa['accuracy_pct']}%")
        print(f"   Precision / Recall  : {xa['precision_pct']}% / {xa['recall_pct']}%")
        print(f"   F1-Score / ROC-AUC  : {xa['f1_score_pct']}% / {xa['roc_auc']}")
        print(f"   False Positive Rate : {xa['false_positive_rate_pct']}%")
        print(f"   Avg Latency         : {xa['avg_latency_ms']} ms/email")

    dm = ml_metrics["dual_ml_combined_triage"]
    print(f"\n2B. DUAL ML COMBINED TRIAGE & ISOLATION FOREST (Ground-Truth Suite: n={dm['eval_emails']})")
    print(f"   Combined Accuracy   : {dm['accuracy_pct']}% (F1: {dm['f1_score_pct']}%)")
    print(f"   IsolationForest AUC : {dm['isolation_forest_roc_auc']}")
    print(f"   Avg Latency         : {dm['avg_latency_ms']} ms/email")

    print(f"\n3. THREAT INTELLIGENCE RAG ENGINE (ChromaDB Top-3 Retrieval)")
    print(f"   Precision@3         : {rag_metrics['precision_at_3_pct']}%")
    print(f"   Recall@3            : {rag_metrics['recall_at_3_pct']}%")
    print(f"   Mean Reciprocal Rank: {rag_metrics['mrr']}")
    print(f"   Avg Latency         : {rag_metrics['avg_latency_ms']} ms/query")

    sa = agent_metrics["specialized_agents_accuracy"]
    e2e = agent_metrics["end_to_end_pipeline"]
    print("\n4. SPECIALIZED LANGGRAPH AGENTS (Individual Node Accuracy)")
    print(f"   Email & Header Agent: {sa['email_header_agent_pct']}%")
    print(f"   URL & Domain Agent  : {sa['url_domain_agent_pct']}%")
    print(f"   Identity Agent      : {sa['identity_impersonation_agent_pct']}%")

    print("\n5. END-TO-END MULTI-AGENT INVESTIGATIVE SYSTEM")
    print(f"   Multi-Class Accuracy: {e2e['multiclass_accuracy_pct']}% (Macro-F1: {e2e['multiclass_macro_f1_pct']}%)")
    print(f"   Threat Precision/Rec: {e2e['threat_detection_precision_pct']}% / {e2e['threat_detection_recall_pct']}% (F1: {e2e['threat_detection_f1_pct']}%)")
    print(f"   False Positive Rate : {e2e['false_positive_rate_pct']}%")
    print(f"   Avg E2E Latency     : {e2e['avg_e2e_latency_ms']} ms/email")
    print("=" * 84)
    print(f"Saved JSON benchmark report to: {REPORT_OUT_PATH}")


if __name__ == "__main__":
    main()