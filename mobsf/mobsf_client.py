# mobsf/mobsf_client.py
"""
MobSF REST API client for APK scanning.
Handles upload, scan, static JSON retrieval, and dynamic analysis.
"""

import requests
from pathlib import Path
from utils.config import MOBSF_API_KEY, MOBSF_URL
from utils.logger import get_logger

log = get_logger("mobsf")

# Ensure MobSF URL ends with /api/v1/
BASE = MOBSF_URL.rstrip("/") + "/api/v1/"
HEADERS = {"Authorization": MOBSF_API_KEY}


def healthcheck():
    """Check if MobSF is running and reachable."""
    url = BASE + "healthcheck"
    r = requests.get(url, headers=HEADERS)
    r.raise_for_status()
    return r.json()


def upload_and_scan(apk_path: Path):
    """Upload APK to MobSF and start scan."""
    url = BASE + "upload"
    log.info(f"[MobSF] Uploading {apk_path}")
    with open(apk_path, "rb") as f:
        files = {"file": (apk_path.name, f, "application/vnd.android.package-archive")}
        r = requests.post(url, files=files, headers=HEADERS)
    r.raise_for_status()
    data = r.json()
    scan_hash = data.get("hash")
    if not scan_hash:
        raise RuntimeError(f"Upload failed, no hash returned: {data}")
    log.info(f"[MobSF] Uploaded. Hash={scan_hash}")

    # trigger scan
    scan_url = BASE + "scan"
    r2 = requests.post(scan_url, json={"hash": scan_hash}, headers=HEADERS)
    r2.raise_for_status()
    log.info("[MobSF] Scan triggered successfully")
    return data


def get_static_json(scan_hash: str):
    """Fetch static analysis results from MobSF."""
    url = BASE + "report_json"
    r = requests.post(url, json={"hash": scan_hash}, headers=HEADERS)
    r.raise_for_status()
    return r.json()


def run_dynamic_analysis(scan_hash: str):
    """Trigger dynamic analysis in MobSF and fetch results"""
    url = f"{MOBSF_URL}/api/v1/dynamic/report_json"
    headers = {"Authorization": MOBSF_API_KEY}
    params = {"hash": scan_hash}
    r = requests.get(url, headers=headers, params=params, timeout=300)
    r.raise_for_status()
    return r.json()
