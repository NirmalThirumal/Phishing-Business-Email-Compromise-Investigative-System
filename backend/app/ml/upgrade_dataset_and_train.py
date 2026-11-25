import os
import tarfile
import urllib.request
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

RAW_DIR = os.path.join("data", "raw")
MODEL_DIR = os.path.join("data", "processed")
os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

SPAMASSASSIN_ARCHIVES = {
    "easy_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "spam": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
}


def download_and_extract_spamassassin() -> pd.DataFrame:
    """Downloads official Apache SpamAssassin ham & spam archives and extracts email text."""
    rows = []

    for label_name, url in SPAMASSASSIN_ARCHIVES.items():
        archive_path = os.path.join(RAW_DIR, f"{label_name}.tar.bz2")
        extract_dir = os.path.join(RAW_DIR, label_name)

        if not os.path.exists(archive_path):
            print(f"Downloading {label_name} from SpamAssassin Public Corpus...")
            urllib.request.urlretrieve(url, archive_path)

        if not os.path.exists(extract_dir):
            print(f"Extracting {archive_path}...")
            with tarfile.open(archive_path, "r:bz2") as tar:
                tar.extractall(path=extract_dir)

        binary_label = 0 if label_name == "easy_ham" else 1
        count = 0
        for root, _, files in os.walk(extract_dir):
            for fname in files:
                if fname == "cmds":
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="latin-1") as f:
                        raw_text = f.read()
                    # Strip raw headers to extract subject + body cleanly
                    parts = raw_text.split("\n\n", 1)
                    body = parts[1] if len(parts) > 1 else parts[0]
                    clean_text = " ".join(body.split())[:3000]
                    if len(clean_text) > 40:
                        rows.append({"text": clean_text, "label": binary_label, "source": f"spamassassin_{label_name}"})
                        count += 1
                except Exception:
                    continue
        print(f"Loaded {count} emails from {label_name}.")

    return pd.DataFrame(rows)


def build_bec_scenarios() -> pd.DataFrame:
    """Generates varied Business Email Compromise (BEC) templates to augment public phishing corpora."""
    templates = [
        "Hi {name}, are you available at your desk? I'm in a confidential board meeting and need you to process an urgent wire transfer of ${amount} before 5 PM today.",
        "Please update our beneficiary banking instructions for {vendor}. All future invoice settlements must be routed to our new escrow account effective immediately.",
        "Confidential Request: Can you handle a time-sensitive vendor payment of ${amount} right now? Do not call as I am currently with legal counsel on an acquisition.",
        "URGENT: Your corporate Microsoft 365 password expires today. Confirm your credentials immediately via the security portal to avoid mailbox lockout.",
        "Hi Finance, attached is the revised remittance advice for overdue invoice #{inv}. Please confirm once the wire transfer has been initiated.",
        "I need you to purchase {qty} digital gift cards for an urgent client appreciation event and email me the redemption codes immediately. Keep this confidential.",
        "Security Alert: Unusual sign-in detected from an unrecognized IP address. Re-authenticate your SSO account immediately to prevent suspension.",
        "As discussed with the CEO, please expedite a same-day ACH/wire transfer of ${amount} to finalize our supplier agreement before COB.",
    ]

    names = ["Priya", "Ananya", "Rahul", "Finance Team", "Accounts Payable", "Karthik", "Sneha"]
    vendors = ["Apex Legal Partners", "CloudScale Ltd", "Global Logistics Corp", "Vertex Consulting"]
    amounts = ["24,500", "48,500", "75,000", "112,000", "18,900"]

    rows = []
    rng = np.random.default_rng(42)
    for i in range(400):
        tmpl = templates[i % len(templates)]
        msg = tmpl.format(
            name=rng.choice(names),
            vendor=rng.choice(vendors),
            amount=rng.choice(amounts),
            inv=rng.integers(1000, 9999),
            qty=rng.integers(5, 15),
        )
        rows.append({"text": msg, "label": 1, "source": "synthetic_bec"})

    return pd.DataFrame(rows)


def retrain_models():
    sa_df = download_and_extract_spamassassin()
    bec_df = build_bec_scenarios()

    full_df = pd.concat([sa_df, bec_df], ignore_index=True)
    full_df.to_csv(os.path.join(MODEL_DIR, "merged_training_corpus.csv"), index=False)
    print(f"\nTotal merged dataset size: {len(full_df)} emails (Legitimate: {(full_df['label']==0).sum()}, Malicious/BEC: {(full_df['label']==1).sum()})")

    X_train, X_test, y_train, y_test = train_test_split(
        full_df["text"], full_df["label"], test_size=0.2, random_state=42, stratify=full_df["label"]
    )

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        stop_words="english",
        sublinear_tf=True,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    clf = XGBClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
    )
    clf.fit(X_train_vec, y_train)

    preds = clf.predict(X_test_vec)
    print("\n=== REAL DATASET EVALUATION REPORT (SpamAssassin + BEC) ===")
    print(classification_report(y_test, preds, target_names=["Legitimate", "Phishing / BEC"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))

    joblib.dump(vectorizer, os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib"))
    joblib.dump(clf, os.path.join(MODEL_DIR, "xgb_phishing_model.joblib"))
    print("\nUpdated production ML models saved to data/processed/!")


if __name__ == "__main__":
    retrain_models()