# api/app.py
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path

from utils.config import SAMPLES_DIR, MODEL_PATH, MAX_APK_MB, USE_MOBSF
from utils.logger import get_logger
from precheck.precheck import precheck
from static_analysis.androguard_extractor import extract_features as androguard_features
from mobsf.mobsf_client import upload_and_scan, get_static_json, run_dynamic_if_enabled
from features.build_features import extract_features as mobsf_features
from model.classifier import APKClassifier
from reports.report_generator import generate_report

app = FastAPI(title="Fake Banking APK Detector")
log = get_logger("api")

_classifier = None


def get_classifier():
    """Lazy load the trained classifier."""
    global _classifier
    if _classifier is None:
        _classifier = APKClassifier(MODEL_PATH)
    return _classifier


@app.post("/scan")
async def scan_apk(file: UploadFile = File(...), dynamic: bool = False):
    # Validate file extension
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Please upload an .apk file")

    # Read file contents
    content = await file.read()
    size_mb = len(content) / (1024 * 1024)
    if size_mb > MAX_APK_MB:
        raise HTTPException(
            status_code=400,
            detail=f"APK too large ({size_mb:.1f} MB > {MAX_APK_MB} MB)",
        )

    # Save uploaded file to samples dir
    dst = SAMPLES_DIR / file.filename
    with open(dst, "wb") as f:
        f.write(content)
    log.info(f"[*] Received APK: {dst} ({size_mb:.2f} MB)")

    # Precheck step: hash, size
    pc = precheck(dst)

    # Analysis
    feats = None
    analysis_backend = None
    try:
        if USE_MOBSF:
            # MobSF pipeline
            up = upload_and_scan(dst)
            scan_hash = up["hash"]
            static_json = get_static_json(scan_hash)
            dynamic_json = run_dynamic_if_enabled(scan_hash) if dynamic else None
            feats = mobsf_features(static_json, dynamic_json)
            analysis_backend = "MobSF"
        else:
            # Androguard pipeline (default)
            feats = androguard_features(dst)
            analysis_backend = "Androguard"
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Analysis error: {e}")

    # Classification
    clf = get_classifier()
    pred = clf.predict(feats)

    # Report generation
    report_path = generate_report(
        apk_name=file.filename,
        sha256=pc["sha256"],
        verdict=pred["prediction"],
        prob=pred.get("prob_fake"),
        features=feats,
        mobsf_excerpt=None if analysis_backend == "Androguard" else {
            "app_info": static_json.get("app_info", {}),
            "manifest_summary": static_json.get("manifest_analysis", {}),
            "urls": static_json.get("urls", [])[:20],
            "permissions_sample": (
                static_json.get("permissions", {}).get("dangerous", []) or []
            )[:20],
        },
    )

    return JSONResponse({
        "apk": file.filename,
        "sha256": pc["sha256"],
        "size_bytes": pc["size"],
        "verdict": "fake" if pred["prediction"] == 1 else "genuine",
        "prob_fake": pred.get("prob_fake"),
        "features": feats,
        "analysis_backend": analysis_backend,
        "report_path": str(report_path),
    })


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": MODEL_PATH.exists(),
        "backend": "MobSF" if USE_MOBSF else "Androguard",
    }
