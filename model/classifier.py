# model/classifier.py
import joblib
import numpy as np
import json
from pathlib import Path

FEATURES_PATH = Path(__file__).resolve().parent / "artifacts" / "feature_names.json"

class APKClassifier:
    def __init__(self, model_path):
        self.model = joblib.load(model_path)
        if FEATURES_PATH.exists():
            with open(FEATURES_PATH) as f:
                self.feature_names = json.load(f)
        else:
            self.feature_names = []

    def predict(self, features: dict):
        # Convert to ordered numeric vector
        row = []
        for fname in self.feature_names:
            val = features.get(fname, 0)
            if isinstance(val, (int, float, bool)):
                row.append(float(val))
            else:
                row.append(0.0)  # fallback for missing/non-numeric
        X = np.array([row])

        pred = self.model.predict(X)[0]
        prob_fake = None
        if hasattr(self.model, "predict_proba"):
            prob_fake = self.model.predict_proba(X)[0][1]

        return {
            "prediction": int(pred),
            "prob_fake": float(prob_fake) if prob_fake is not None else None,
        }
