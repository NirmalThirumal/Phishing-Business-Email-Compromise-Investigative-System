import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.parsers.email_parser import parse_eml_file
from app.ml.inference import DualMLPredictor
from app.agents.graph import run_full_investigation

if __name__ == "__main__":
    predictor = DualMLPredictor()
    samples = [
        "data/sample_emls/sample_phishing.eml",
        "data/sample_emls/sample_bec.eml",
    ]

    for path in samples:
        print("=" * 80)
        print(f"RUNNING FULL MULTI-AGENT INVESTIGATION ON: {path}")
        print("=" * 80)
        parsed = parse_eml_file(path, check_live_dns=False)
        ml_res = predictor.predict(parsed, org_domain="acmecorp.com")
        report = run_full_investigation(parsed, ml_res)

        print("\n--- FINAL VERDICT (GEMINI SYNTHESIS) ---")
        print(report.verdict.model_dump_json(indent=2))
        print("\n--- INDIVIDUAL AGENT STATUSES ---")
        for ag in report.agent_reports:
            print(f"[{ag.status.upper()}] {ag.agent_name}:")
            for f in ag.findings:
                print(f"   - {f}")
        print()