import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.parsers.email_parser import parse_eml_file
from app.ml.inference import DualMLPredictor

if __name__ == "__main__":
    predictor = DualMLPredictor()
    samples = [
        "data/sample_emls/sample_phishing.eml",
        "data/sample_emls/sample_bec.eml",
    ]
    for path in samples:
        print("=" * 70)
        print(f"ML TRIAGE FOR: {path}")
        print("=" * 70)
        parsed = parse_eml_file(path, check_live_dns=False)
        result = predictor.predict(parsed, org_domain="acmecorp.com")
        print(result.model_dump_json(indent=2))