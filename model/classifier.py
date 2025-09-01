# model/classifier.py
from pathlib import Path
import joblib
import numpy as np
from utils.config import MODEL_PATH
from features.build_features import vectorize

class APKClassifier:
    def __init__(self, model_path: Path = MODEL_PATH):
        self.model_path = model_path
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}. Train it first.")
        self.model = joblib.load(model_path)

    def predict(self, feature_dict: dict) -> dict:
        x = np.array([vectorize(feature_dict)])
        prob = float(self.model.predict_proba(x)[0][1]) if hasattr(self.model, "predict_proba") else None
        pred = int(self.model.predict(x)[0])
        return {"prediction": pred, "prob_fake": prob}
