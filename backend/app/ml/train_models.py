import os
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

MODEL_DIR = os.path.join("data", "processed")
os.makedirs(MODEL_DIR, exist_ok=True)


def build_bootstrap_dataset() -> pd.DataFrame:
    """
    Constructs a balanced bootstrap dataset of:
      0 = Legitimate business communications
      1 = Phishing & Business Email Compromise (BEC) attacks
    """
    legitimate_samples = [
        "Hi team, please find attached the minutes from today's sprint planning meeting. Let me know if any action items need updates.",
        "Reminder: Our quarterly all-hands town hall starts tomorrow at 10:00 AM in the main auditorium and on Zoom.",
        "Your monthly AWS billing statement for October is now available in the billing console.",
        "Hi Priya, thanks for sending over the Q3 marketing deck. I added a few comments on slide 8.",
        "Welcome to GitHub! Please confirm your email address if you recently created a new developer account.",
        "The IT maintenance window is scheduled for Sunday between 2:00 AM and 4:00 AM. No action is required on your part.",
        "Attached is the signed NDA from our legal team for your records. Best regards, Rahul.",
        "Can we reschedule our 1-on-1 sync from Thursday afternoon to Friday morning at 11 AM?",
        "Your flight itinerary and e-ticket receipt for next week's conference in Bengaluru are attached.",
        "Please submit your timesheets for the current pay period by Friday evening via the HR portal.",
        "Hi Finance, here is the approved expense report for last week's client visit with receipts attached.",
        "Thank you for your order. Your package has shipped and will arrive by Tuesday.",
    ] * 25  # 300 clean examples

    phishing_and_bec_samples = [
        "URGENT: Your Office 365 password expires in 2 hours. Verify your credentials immediately to avoid account suspension.",
        "We detected an unauthorized sign-in attempt on your corporate bank account. Click here to confirm your identity immediately.",
        "Are you at your desk? I am tied up in a confidential acquisition meeting. Process an urgent wire transfer of $48,500 before 6 PM today.",
        "Hi Finance Team, please update our beneficiary bank account details for today's supplier invoice settlement. Treat as strictly confidential.",
        "Your mailbox storage is 99% full. Sign in to the webmail portal now using your corporate password to upgrade quota.",
        "FINAL NOTICE: Your domain registration will be suspended today unless you complete immediate payment verification.",
        "I need you to purchase 10 Apple gift cards of $100 each for client appreciation and scratch off the codes right away. Do not call me, I am in a board meeting.",
        "Security Alert: Unusual login from unknown device. Reset your Single Sign-On credentials immediately via the secure link below.",
        "Please remit $72,000 via wire transfer to the updated escrow account by COB today so the merger agreement does not lapse.",
        "Your payroll direct deposit failed validation. Log in with your employee ID and password to re-verify your banking details.",
        "Attached is the encrypted remittance advice. Enable macros in the document to view the payment breakdown.",
        "CEO Request: Can you handle an urgent confidential wire payment right now? Reply back as soon as you receive this.",
    ] * 25  # 300 malicious examples

    texts = legitimate_samples + phishing_and_bec_samples
    labels = [0] * len(legitimate_samples) + [1] * len(phishing_and_bec_samples)
    return pd.DataFrame({"text": texts, "label": labels})


def train_nlp_classifier(df: pd.DataFrame):
    print("Training Track A: NLP Phishing & BEC Classifier (TF-IDF + XGBoost)...")
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=3000,
        stop_words="english",
        sublinear_tf=True,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    clf = XGBClassifier(
        n_estimators=150,
        max_depth=4,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
    )
    clf.fit(X_train_vec, y_train)

    preds = clf.predict(X_test_vec)
    print("\nNLP Classifier Evaluation Report:")
    print(classification_report(y_test, preds, target_names=["Legitimate", "Phishing/BEC"]))

    joblib.dump(vectorizer, os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib"))
    joblib.dump(clf, os.path.join(MODEL_DIR, "xgb_phishing_model.joblib"))
    print("Saved NLP model artifacts to data/processed/\n")


def train_anomaly_detector():
    print("Training Track B: Behavioral Anomaly Detector (Isolation Forest)...")
    rng = np.random.default_rng(42)

    # Simulate 500 normal corporate email feature vectors
    normal_data = np.column_stack([
        rng.uniform(0.0, 0.35, 500),      # unrelated external domain or exact internal match (0.0)
        np.zeros(500),                    # no reply-to mismatch
        rng.choice([0.0, 1.0], 500, p=[0.95, 0.05]),
        np.zeros(500),                    # no display-name email spoofing
        np.zeros(500),                    # SPF passes
        np.zeros(500),                    # DKIM passes
        np.zeros(500),                    # DMARC passes
        rng.integers(0, 3, 500),          # 0 to 2 normal links
        np.zeros(500),                    # no raw IP URLs
        np.zeros(500),                    # no mismatched anchor text
        np.zeros(500),                    # no dangerous executables/macros
        rng.integers(0, 2, 500),          # 0 or 1 routine business keyword
    ]).astype(np.float32)

    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=0.05,
        random_state=42,
    )
    iso_forest.fit(normal_data)

    joblib.dump(iso_forest, os.path.join(MODEL_DIR, "isolation_forest_anomaly.joblib"))
    print("Saved Anomaly Detection model to data/processed/\n")


if __name__ == "__main__":
    dataset = build_bootstrap_dataset()
    train_nlp_classifier(dataset)
    train_anomaly_detector()
    print("Phase 2 ML Training Complete!")