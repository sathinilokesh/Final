import joblib
import numpy as np
from utils.config import MODEL_PATH

class APKClassifier:
    def __init__(self, model_path=MODEL_PATH):
        self.model = joblib.load(model_path)

    def predict(self, features: dict):
        X = np.array([list(features.values())])
        pred = self.model.predict(X)[0]
        prob = self.model.predict_proba(X)[0][1] if hasattr(self.model, "predict_proba") else None
        return {"prediction": int(pred), "prob_fake": float(prob) if prob is not None else None}
