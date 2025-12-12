# detector.py - simple heuristics + optional model
import re
import validators
import joblib
import os
from urllib.parse import urlparse
import pandas as pd

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

    if _classifier is not None:
        df = pd.DataFrame([feats])
        try:
            prob = float(_classifier.predict_proba(df)[0][1])
            score = max(score, prob)
            evidence.append(f"ML model probability: {prob:.3f}")
        except Exception:
            pass

    verdict = "phishing" if score >= 0.5 else "suspicious" if score >= 0.3 else "legitimate"
    return {"type": "url", "input": url, "valid": True, "features": feats, "score": round(score, 3), "verdict": verdict, "evidence": evidence}

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
