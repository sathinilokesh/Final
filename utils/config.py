# utils/config.py
import os
from pathlib import Path

# Directories
BASE_DIR = Path(os.getenv("FAKE_APK_BASE_DIR", Path(__file__).resolve().parents[1]))
SAMPLES_DIR = BASE_DIR / "data" / "samples"
OUTPUT_DIR = BASE_DIR / "data" / "outputs"
REPORTS_DIR = OUTPUT_DIR / "reports"
MODELS_DIR = BASE_DIR / "model" / "artifacts"

# Ensure dirs exist
for d in [SAMPLES_DIR, OUTPUT_DIR, REPORTS_DIR, MODELS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# MobSF
MOBSF_URL = os.getenv("MOBSF_URL", "http://localhost:8000/")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "secret")  # set your key
MOBSF_TIMEOUT = int(os.getenv("MOBSF_TIMEOUT", "900"))   # 15 mins for heavy scans
MOBSF_DYNAMIC = os.getenv("MOBSF_DYNAMIC", "false").lower() == "true"

# Classifier
MODEL_PATH = MODELS_DIR / "apk_rf_model.pkl"

# Security / Upload limits
MAX_APK_MB = int(os.getenv("MAX_APK_MB", "200"))

# Optional: set to True if later you add VT back
ENABLE_VT = os.getenv("ENABLE_VT", "false").lower() == "true"

USE_MOBSF = False
