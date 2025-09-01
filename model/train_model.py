# model/train_model.py
"""
Train a simple classifier on MobSF-derived features.
You must prepare a CSV where each row = sample, columns = FEATURE_ORDER + label.
label: 1 = fake/malicious, 0 = genuine banking.
"""
import csv
from pathlib import Path
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from utils.config import MODEL_PATH
from features.build_features import FEATURE_ORDER

def load_training_csv(csv_path: Path):
    X, y = [], []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            X.append([float(row.get(k, 0.0)) for k in FEATURE_ORDER])
            y.append(int(row["label"]))
    return X, y

def train(csv_path: str, out_path: Path = MODEL_PATH):
    X, y = load_training_csv(Path(csv_path))
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=300, max_depth=None, random_state=42, class_weight="balanced")
    clf.fit(Xtr, ytr)
    ypred = clf.predict(Xte)
    print(classification_report(yte, ypred, digits=4))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, out_path)
    print(f"Saved model -> {out_path}")

if __name__ == "__main__":
    # Example:
    # python -m model.train_model data/training/features.csv
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m model.train_model <features.csv>")
        raise SystemExit(1)
    train(sys.argv[1])
