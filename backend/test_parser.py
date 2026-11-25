import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.parsers.email_parser import parse_eml_file

if __name__ == "__main__":
    samples = [
        "data/sample_emls/sample_phishing.eml",
        "data/sample_emls/sample_bec.eml",
    ]
    for path in samples:
        print("=" * 70)
        print(f"PARSING: {path}")
        print("=" * 70)
        parsed = parse_eml_file(path, check_live_dns=False)
        print(parsed.model_dump_json(indent=2))