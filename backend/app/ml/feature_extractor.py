import numpy as np
from rapidfuzz import fuzz
from app.schemas.email_schema import ParsedEmail

URGENCY_WORDS = {
    "urgent", "immediately", "asap", "suspend", "suspended", "verify",
    "expire", "expires", "restricted", "unauthorized", "action required",
    "confidential", "wire", "transfer", "beneficiary", "invoice", "overdue",
    "cob", "end of day", "password", "security alert"
}

FINANCIAL_WORDS = {
    "wire", "transfer", "bank", "account", "payment", "invoice",
    "beneficiary", "routing", "swift", "iban", "fund", "funds", "remittance"
}


def extract_behavioral_features(parsed: ParsedEmail, org_domain: str = "acmecorp.com") -> np.ndarray:
    """
    Converts a ParsedEmail object into a 12-dimensional numerical feature vector
    for unsupervised anomaly detection (Isolation Forest).
    """
    text_combined = f"{parsed.subject} {parsed.body_text}".lower()

    # 1. Domain similarity to internal organization domain (catches lookalikes like acmec0rp.com)
    domain_similarity = 0.0
    if parsed.sender_domain and parsed.sender_domain != org_domain:
        domain_similarity = fuzz.ratio(parsed.sender_domain, org_domain) / 100.0

    # 2. Header mismatch indicators
    reply_to_mismatch = 1.0 if parsed.reply_to_mismatch else 0.0
    return_path_mismatch = 1.0 if parsed.return_path_mismatch else 0.0
    display_name_spoof = 1.0 if parsed.display_name_contains_email else 0.0

    # 3. Authentication failure flags
    spf_fail = 1.0 if parsed.auth_results.spf_status in {"fail", "softfail"} else 0.0
    dkim_fail = 1.0 if parsed.auth_results.dkim_status == "fail" else 0.0
    dmarc_fail = 1.0 if parsed.auth_results.dmarc_status == "fail" else 0.0

    # 4. URL & Attachment risk indicators
    url_count = float(len(parsed.urls))
    has_ip_or_short_url = 1.0 if any(u.is_ip_address or u.is_shortened for u in parsed.urls) else 0.0
    has_mismatched_anchor = 1.0 if any(u.mismatched_anchor for u in parsed.urls) else 0.0
    has_risky_attachment = 1.0 if any(a.is_executable_or_macro for a in parsed.attachments) else 0.0

    # 5. Linguistic urgency & financial pressure density
    urgency_hits = sum(1 for w in URGENCY_WORDS if w in text_combined)
    financial_hits = sum(1 for w in FINANCIAL_WORDS if w in text_combined)

    features = np.array([
        domain_similarity,
        reply_to_mismatch,
        return_path_mismatch,
        display_name_spoof,
        spf_fail,
        dkim_fail,
        dmarc_fail,
        url_count,
        has_ip_or_short_url,
        has_mismatched_anchor,
        has_risky_attachment,
        float(urgency_hits + financial_hits),
    ], dtype=np.float32)

    return features