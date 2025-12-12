# train_model.py - train a synthetic URL phishing model
import os, joblib, random
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

MODEL_PATH = os.path.join('models','url_model.joblib')

def synth_row(phish: bool):
    if phish:
        return {
            'has_ip': random.choice([0,1]),
            'length': random.randint(60,200),
            'count_dots': random.randint(2,8),
            'has_at': random.choice([0,1,1]),
            'suspicious_tld': random.choice([0,1,1]),
            'uses_https': random.choice([0,0,1]),
            'num_digits': random.randint(3,30),
            'label': 1
        }
    else:
        return {
            'has_ip': 0,
            'length': random.randint(20,80),
            'count_dots': random.randint(1,3),
            'has_at': 0,
            'suspicious_tld': 0,
            'uses_https': 1,
            'num_digits': random.randint(0,6),
            'label': 0
        }

def make_dataset(n=1000):
    rows = []
    for _ in range(n//2):
        rows.append(synth_row(True))
        rows.append(synth_row(False))
    return pd.DataFrame(rows)

def train_and_save():
    df = make_dataset(1000)
    X = df.drop(columns=['label'])
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    print(classification_report(y_test, preds))
    joblib.dump(clf, MODEL_PATH)
    print(f"Saved model to {MODEL_PATH}")

if __name__ == '__main__':
    os.makedirs('models', exist_ok=True)
    train_and_save()
