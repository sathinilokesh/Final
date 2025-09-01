# mobsf/mobsf_client.py
import time
from pathlib import Path
import requests
from utils.config import MOBSF_URL, MOBSF_API_KEY, MOBSF_TIMEOUT, MOBSF_DYNAMIC
from utils.logger import get_logger

log = get_logger("mobsf")

HEADERS = {"Authorization": MOBSF_API_KEY}

def _post(path: str, **kwargs):
    url = f"{MOBSF_URL.rstrip('/')}/{path.lstrip('/')}"
    r = requests.post(url, headers=HEADERS, timeout=MOBSF_TIMEOUT, **kwargs)
    if r.status_code >= 400:
        log.error(f"MobSF POST {url} failed: {r.status_code} {r.text}")
    r.raise_for_status()
    return r

def _get(path: str, **kwargs):
    url = f"{MOBSF_URL.rstrip('/')}/{path.lstrip('/')}"
    r = requests.get(url, headers=HEADERS, timeout=MOBSF_TIMEOUT, **kwargs)
    if r.status_code >= 400:
        log.error(f"MobSF GET {url} failed: {r.status_code} {r.text}")
    r.raise_for_status()
    return r

def upload_and_scan(apk_path: Path) -> dict:
    log.info(f"Uploading to MobSF: {apk_path}")
    files = {"file": (apk_path.name, open(apk_path, "rb"), "application/octet-stream")}
    resp = _post("upload", files=files).json()
    scan_hash = resp["hash"]
    log.info(f"Uploaded. Hash={scan_hash}. Triggering scan...")
    scan = _post("scan", data={"hash": scan_hash}).json()
    return {"hash": scan_hash, "scan": scan}

def get_static_json(scan_hash: str) -> dict:
    """Fetch static analysis JSON."""
    log.info("Fetching static report JSON from MobSF")
    return _post("report_json", data={"hash": scan_hash}).json()

# Optional: dynamic (only if you configured dynamic env in MobSF)
def run_dynamic_if_enabled(scan_hash: str) -> dict | None:
    if not MOBSF_DYNAMIC:
        log.info("MobSF dynamic disabled; skipping.")
        return None
    log.info("Starting MobSF dynamic analysis (beta; ensure emulator is configured in MobSF)")
    # This flow may vary by MobSF version; basic pattern:
    start = _post("dynamic/start", data={"hash": scan_hash}).json()
    # Poll status
    for _ in range(120):  # ~10-20 minutes polling window
        time.sleep(10)
        status = _get(f"dynamic/status?hash={scan_hash}").json()
        if status.get("status") == "finished":
            break
    # Fetch dynamic report (if available)
    try:
        dyn = _get(f"dynamic/report_json?hash={scan_hash}").json()
        return dyn
    except Exception as e:
        log.warning(f"No dynamic JSON available: {e}")
        return None
