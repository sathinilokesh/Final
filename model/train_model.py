# model/train_model.py
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import json

# Paths
DATASET = Path(__file__).resolve().parent.parent / "data" / "training" / "features.csv"
MODEL_PATH = Path(__file__).resolve().parent / "artifacts" / "apk_rf_model.pkl"
FEATURES_PATH = Path(__file__).resolve().parent / "artifacts" / "feature_names.json"

def train():
    if not DATASET.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET}. "
                                f"Run `python data/make_synthetic.py` first.")

    print(f"[*] Loading dataset: {DATASET}")
    df = pd.read_csv(DATASET)

    # Drop label and keep only numeric features
    y = df["label"]
    X = df.drop(columns=["label"])
    X = X.select_dtypes(include=["number", "bool"])  # keep only numeric/bool

    # Save feature names for inference
    FEATURES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(FEATURES_PATH, "w") as f:
        json.dump(list(X.columns), f)
    print(f"[+] Saved feature schema → {FEATURES_PATH}")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Model
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        n_jobs=-1
    )

    print("[*] Training RandomForest...")
    clf.fit(X_train, y_train)

    # Eval
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[+] Accuracy: {acc:.3f}")
    print(classification_report(y_test, y_pred))

    # Save model
    joblib.dump(clf, MODEL_PATH)
    print(f"[+] Model saved → {MODEL_PATH}")

if __name__ == "__main__":
    train()
