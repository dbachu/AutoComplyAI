# detector.py - simple heuristics + optional model
import re
import validators
import joblib
import os
from urllib.parse import urlparse
import pandas as pd

DETECTION_MODE = os.getenv("DETECTION_MODE", "single")

_ensemble_rf = None
_ensemble_lr = None

if DETECTION_MODE == "ensemble":
    try:
        _ensemble_rf = joblib.load(os.path.join("models", "rf_model.joblib"))
        _ensemble_lr = joblib.load(os.path.join("models", "lr_model.joblib"))
    except Exception:
        _ensemble_rf = None
        _ensemble_lr = None


MODEL_PATH = os.path.join('models', 'url_model.joblib')
_classifier = None
if os.path.exists(MODEL_PATH):
    try:
        _classifier = joblib.load(MODEL_PATH)
    except Exception:
        _classifier = None

def url_features(url: str) -> dict:
    parsed = urlparse(url)
    features = {}
    features['has_ip'] = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.netloc))
    features['length'] = len(url)
    features['count_dots'] = url.count('.')
    features['has_at'] = '@' in url
    features['suspicious_tld'] = parsed.netloc.endswith(('.ru', '.cn', '.tk', '.ml'))
    features['uses_https'] = parsed.scheme == 'https'
    features['num_digits'] = sum(c.isdigit() for c in url)
    return features

def analyze_url(url: str) -> dict:
    valid = validators.url(url)
    if not valid:
        return {"type": "url", "valid": False, "score": 0.0, "verdict": "invalid", "evidence": ["invalid URL format"]}

    feats = url_features(url)
    evidence = []
    score = 0.0

    if feats['has_ip']:
        evidence.append("URL uses IP address")
        score += 0.25
    if feats['count_dots'] > 4 or feats['length'] > 75:
        evidence.append("Very long / many subdomains")
        score += 0.2
    if feats['has_at']:
        evidence.append("Contains '@' symbol")
        score += 0.2
    if feats['suspicious_tld']:
        evidence.append("Suspicious TLD")
        score += 0.15
    if not feats['uses_https']:
        evidence.append("Not using HTTPS")
        score += 0.05

    # --- ML / Ensemble scoring ---
    if DETECTION_MODE == "ensemble" and _ensemble_rf and _ensemble_lr:
        try:
            feature_vector = extract_features(url)

            p1 = _ensemble_rf.predict_proba([feature_vector])[0][1]
            p2 = _ensemble_lr.predict_proba([feature_vector])[0][1]
            prob = round((p1 + p2) / 2, 3)

            score = max(score, prob)
            evidence.append(f"Ensemble ML probability: {prob:.3f}")
            mode = "ensemble"
        except Exception:
            mode = "ensemble-failed"

    elif _classifier is not None:
        try:
            df = pd.DataFrame([feats])
            prob = float(_classifier.predict_proba(df)[0][1])
            score = max(score, prob)
            evidence.append(f"ML model probability: {prob:.3f}")
            mode = "single"
        except Exception:
            mode = "single-failed"
    else:
        mode = "heuristic"


    verdict = "phishing" if score >= 0.5 else "suspicious" if score >= 0.3 else "legitimate"

    confidence = confidence_label(score)
    feature_explanations = explain_features(feats)

    return {
        "type": "url",
        "input": url,
        "valid": True,
        "features": feats,
        "score": round(score, 3),
        "verdict": verdict,
        "confidence": confidence,
        "mode": mode,
        "evidence": evidence,
        "explanations": feature_explanations
    }



def email_body_features(body: str) -> dict:
    feats = {}
    feats['has_urgent'] = bool(re.search(r'\burgent\b|\bimmediate action\b|\bverify\b', body, re.I))
    feats['has_links'] = bool(re.search(r'https?://', body))
    feats['has_attachments'] = bool(re.search(r'\battachment\b|\battached\b', body, re.I))
    feats['from_bank_terms'] = bool(re.search(r'bank|account|password|login|verify', body, re.I))
    feats['length'] = len(body)
    return feats

def analyze_email(body: str) -> dict:
    feats = email_body_features(body)
    score = 0.0
    evidence = []
    if feats['has_urgent']:
        score += 0.25
        evidence.append("Urgency language detected")
    if feats['has_links']:
        score += 0.25
        evidence.append("Contains links")
    if feats['has_attachments']:
        score += 0.15
        evidence.append("References attachments")
    if feats['from_bank_terms']:
        score += 0.2
        evidence.append("Bank/login terms present")
    if feats['length'] < 20:
        score += 0.1
        evidence.append("Very short message body")

    verdict = "phishing" if score >= 0.6 else "suspicious" if score >= 0.3 else "legitimate"
    return {"type": "email", "input_preview": body[:500], "features": feats, "score": round(score, 3), "verdict": verdict, "evidence": evidence}

# detector.py

import re
from urllib.parse import urlparse

def extract_features(input_text: str):
    """
    Extract numerical phishing features from a URL or text.
    Returns a list in fixed order for ML models.
    """

    text = input_text.lower()

    length = len(text)
    count_dots = text.count(".")
    has_ip = 1 if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text) else 0
    suspicious_tld = 1 if any(tld in text for tld in [".ru", ".cn", ".tk", ".ml", ".ga"]) else 0
    num_digits = sum(c.isdigit() for c in text)
    uses_https = 1 if text.startswith("https") else 0

    return [
        length,
        count_dots,
        has_ip,
        suspicious_tld,
        num_digits,
        uses_https
    ]

def confidence_label(score: float) -> str:
    if score >= 0.75:
        return "High"
    elif score >= 0.4:
        return "Medium"
    else:
        return "Low"

def explain_features(feats: dict) -> list:
    explanations = []

    if feats.get("has_ip"):
        explanations.append("URL contains an IP address, commonly used in phishing.")

    if feats.get("suspicious_tld"):
        explanations.append("Domain uses a suspicious top-level domain.")

    if feats.get("count_dots", 0) > 4:
        explanations.append("Excessive subdomains detected.")

    if not feats.get("uses_https", True):
        explanations.append("Connection is not secured with HTTPS.")

    if feats.get("num_digits", 0) > 6:
        explanations.append("Unusually high number of digits in URL.")

    return explanations
