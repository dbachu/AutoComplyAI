# models/train_ensemble_model.py
# Phase 2: Ensemble training using runtime feature extraction

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from detector import extract_features   # now works

def train_ensemble():
    df = pd.read_csv("models/sample_urls.csv")

    # Expecting columns: input, label
    X = df["input"].apply(lambda x: extract_features(x)).tolist()
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    joblib.dump(rf, "models/rf_model.joblib")

    lr = LogisticRegression(max_iter=1000)
    lr.fit(X_train, y_train)
    joblib.dump(lr, "models/lr_model.joblib")

    print("✅ Phase 2 ensemble models trained successfully")

if __name__ == "__main__":
    train_ensemble()
