import os
import joblib
import numpy as np
from pydantic import BaseModel
from app.schemas.email_schema import ParsedEmail
from app.ml.feature_extractor import extract_behavioral_features

MODEL_DIR = os.path.join("data", "processed")


class MLTriageResult(BaseModel):
    nlp_phishing_probability: float   # 0.0 to 1.0
    behavioral_anomaly_score: float   # 0.0 (normal) to 1.0 (highly anomalous)
    is_anomalous: bool
    combined_ml_risk_score: float     # 0 to 100
    requires_agent_investigation: bool


class DualMLPredictor:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.vectorizer = joblib.load(os.path.join(model_dir, "tfidf_vectorizer.joblib"))
        self.nlp_model = joblib.load(os.path.join(model_dir, "xgb_phishing_model.joblib"))
        self.anomaly_model = joblib.load(os.path.join(model_dir, "isolation_forest_anomaly.joblib"))

    def predict(self, parsed: ParsedEmail, org_domain: str = "acmecorp.com") -> MLTriageResult:
        # 1. Track A: NLP Phishing Probability
        combined_text = f"{parsed.subject} {parsed.body_text}".strip()
        vec = self.vectorizer.transform([combined_text])
        phishing_prob = float(self.nlp_model.predict_proba(vec)[0][1])

        # 2. Track B: Behavioral & Header Anomaly Score
        features = extract_behavioral_features(parsed, org_domain=org_domain).reshape(1, -1)
        raw_decision = float(self.anomaly_model.decision_function(features)[0])
        is_anomalous = bool(self.anomaly_model.predict(features)[0] == -1)

        # Convert IsolationForest decision_function into a normalized 0.0 - 1.0 risk score
        normalized_anomaly = float(np.clip(0.5 - (raw_decision * 1.6), 0.0, 1.0))

        # Weighted ML risk score (0-100)
        combined_score = round((phishing_prob * 0.55 + normalized_anomaly * 0.45) * 100, 2)

        # Trigger LangGraph multi-agent investigation if score >= 35 or high domain similarity
        trigger_agents = bool(combined_score >= 35.0 or is_anomalous or features[0][0] >= 0.75)

        return MLTriageResult(
            nlp_phishing_probability=round(phishing_prob, 4),
            behavioral_anomaly_score=round(normalized_anomaly, 4),
            is_anomalous=is_anomalous,
            combined_ml_risk_score=combined_score,
            requires_agent_investigation=trigger_agents,
        )