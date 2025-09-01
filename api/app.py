from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path
from utils.config import SAMPLES_DIR, MODEL_PATH, MAX_APK_MB
from utils.logger import get_logger
from precheck.precheck import precheck
from mobsf.mobsf_client import upload_and_scan, get_static_json
from features.build_features import extract_features
from model.classifier import APKClassifier
from reports.report_generator import generate_report

app = FastAPI(title="Fake Banking APK Detector")
log = get_logger("api")
_classifier = None

def get_classifier():
    global _classifier
    if _classifier is None:
        _classifier = APKClassifier(MODEL_PATH)
    return _classifier

@app.post("/scan")
async def scan_apk(file: UploadFile = File(...), dynamic: bool = False):
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Please upload an .apk file")

    content = await file.read()
    size_mb = len(content) / (1024 * 1024)
    if size_mb > MAX_APK_MB:
        raise HTTPException(status_code=400, detail=f"APK too large ({size_mb:.1f} MB > {MAX_APK_MB} MB)")

    dst = SAMPLES_DIR / file.filename
    with open(dst, "wb") as f:
        f.write(content)
    log.info(f"Received APK: {dst} ({size_mb:.2f} MB)")

    pc = precheck(dst)

    try:
        up = upload_and_scan(dst)
        scan_hash = up["hash"]
        static_json = get_static_json(scan_hash)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"MobSF error: {e}")

    feats = extract_features(static_json)
    clf = get_classifier()
    pred = clf.predict(feats)

    report_path = generate_report(
        apk_name=file.filename,
        sha256=pc["sha256"],
        verdict="fake" if pred["prediction"] == 1 else "genuine",
        prob=pred.get("prob_fake"),
        features=feats,
        mobsf_excerpt=None,
    )

    return JSONResponse({
        "apk": file.filename,
        "sha256": pc["sha256"],
        "size_bytes": pc["size"],
        "verdict": "fake" if pred["prediction"] == 1 else "genuine",
        "prob_fake": pred.get("prob_fake"),
        "features": feats,
        "report_path": str(report_path),
    })

@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": MODEL_PATH.exists()}
