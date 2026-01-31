# models/ensemble.py

import joblib
import numpy as np

class EnsembleDetector:
    """
    Ensemble-based phishing detector aligned with base paper techniques.
    Uses soft voting across multiple classical ML models.
    """

    def __init__(self):
        self.rf = joblib.load("models/rf_model.joblib")
        self.lr = joblib.load("models/lr_model.joblib")

    def predict(self, features: np.ndarray):
        """
        Returns:
        - final_score: averaged probability
        - verdict: phishing / legitimate
        """
        rf_prob = self.rf.predict_proba([features])[0][1]
        lr_prob = self.lr.predict_proba([features])[0][1]

        final_score = round((rf_prob + lr_prob) / 2, 4)
        verdict = "phishing" if final_score > 0.6 else "legitimate"

        return final_score, verdict
