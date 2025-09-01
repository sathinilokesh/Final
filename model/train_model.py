import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
from utils.config import MODEL_PATH

def train(csv_path: str):
    df = pd.read_csv(csv_path)
    X = df.drop(columns=["label"])
    y = df["label"]
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    joblib.dump(clf, MODEL_PATH)
    print(f"[+] Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train("data/training/features.csv")
