
# 🕵️ Fake Banking APK Detector

An automated pipeline to detect fake / malicious banking apps (APKs) by combining:

- **Static & Dynamic Analysis** via [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)  
- **Feature Extraction** from MobSF JSON reports  
- **Machine Learning Classification** (genuine vs fake)  
- **Reporting** in HTML (MobSF findings + ML verdict)  
- **REST API** (FastAPI) for easy integration  

---

## 📂 Architecture

```

📂 APK Collector
→  📦 Precheck (hash only)
→  🕵 MobSF Analysis (Static/Dynamic)
→  📊 Feature Builder (from MobSF JSON)
→  🤖 ML Classifier
→  📝 Report Generator (MobSF findings + Classifier output)
→  🌐 API (FastAPI endpoint)

````

---

## ⚙️ Requirements

- Python **3.10+**
- Docker (for MobSF container)

Install Python dependencies:

```bash
pip install -r requirements.txt
````

### Python dependencies

* fastapi
* uvicorn\[standard]
* requests
* joblib
* scikit-learn
* numpy
* pandas

---

## 🚀 Setup & Run

### 1. Start MobSF

Run MobSF via Docker (easiest way):

```bash
docker run -it --rm -p 8000:8000 -e MOBSF_ANALYZER_IDENTIFIER=emulator-5554  -e MOBSF_API_KEY=secret opensecurity/mobile-security-framework-mobsf:latest
```

Copy your `MOBSF_API_KEY` and update it in `utils/config.py` or set as env var:

```bash
export MOBSF_API_KEY=CHANGE_ME
```

---

### 2. Train Classifier

Prepare a CSV dataset with MobSF-extracted features + labels (`1=fake`, `0=genuine`).
Train and save the model:

```bash
python -m model.train_model data/training/features.csv
```

This saves a model into:

```
model/artifacts/bank_apk_classifier.joblib
```

---

### 3. Start API

Launch the FastAPI server:

```bash
uvicorn api.app:app --host 0.0.0.0 --port 9000 --reload
```

API Docs: [http://localhost:9000/docs](http://localhost:9000/docs)

---

### 4. Scan an APK

Upload an APK for scanning:

```bash
curl -F "file=@/path/to/app.apk" "http://localhost:9000/scan?dynamic=false"
```

Example response:

```json
{
  "apk": "sample.apk",
  "sha256": "d41d8cd98f00b204e9800998ecf8427e",
  "size_bytes": 3481192,
  "verdict": "fake",
  "prob_fake": 0.92,
  "features": {
    "looks_like_banking": 1.0,
    "dangerous_perm_count": 3.0,
    "exported_components": 5.0
  },
  "report_path": "data/outputs/reports/report_sample.html"
}
```

The **HTML report** contains:

* APK info
* Extracted features
* Classifier verdict
* MobSF static findings excerpt

---

## 📂 Project Structure

```
fake_apk_detector/
│
├── collector/           # APK collection (local or URL)
├── precheck/            # File hash, size
├── mobsf/               # MobSF client integration
├── features/            # Feature extraction from MobSF JSON
├── model/               # ML training + inference
├── reports/             # HTML report generation
├── api/                 # FastAPI endpoint
├── utils/               # Config & logging
├── data/                # Samples, outputs, reports
└── requirements.txt
```

---

## 🔍 Notes

* **MobSF Static Analysis** is the primary source of features.
* **Dynamic Analysis** can be enabled by setting `MOBSF_DYNAMIC=true` (requires emulator integration in MobSF).
* **VirusTotal integration** is optional (not included here due to API limits).
* The ML model improves as you collect more labeled APK samples (both genuine & fake).
