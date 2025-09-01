# mobsf/mobsf_client.py
import requests
from utils.config import MOBSF_URL, MOBSF_API_KEY

headers = {"Authorization": MOBSF_API_KEY}

def upload_and_scan(apk_path: str) -> dict:
    """Upload APK to MobSF and trigger scan."""
    url = f"{MOBSF_URL}/api/v1/upload"
    files = {"file": open(apk_path, "rb")}
    r = requests.post(url, files=files, headers=headers)
    r.raise_for_status()
    return r.json()

def get_static_json(scan_hash: str) -> dict:
    """Fetch static analysis JSON."""
    url = f"{MOBSF_URL}/api/v1/report_json"
    r = requests.post(url, data={"hash": scan_hash}, headers=headers)
    r.raise_for_status()
    return r.json()

def run_dynamic_analysis(scan_hash: str) -> dict:
    """
    Stop dynamic analysis (if running) and fetch dynamic analysis JSON.
    """
    # Step 1: Stop dynamic analysis
    stop_url = f"{MOBSF_URL}/api/v1/dynamic/stop_analysis"
    r = requests.post(stop_url, data={"hash": scan_hash}, headers=headers)
    if r.status_code not in (200, 500):  # 500 sometimes if already stopped
        r.raise_for_status()

    # Step 2: Fetch dynamic JSON report
    report_url = f"{MOBSF_URL}/api/v1/dynamic/report_json"
    r = requests.post(report_url, data={"hash": scan_hash}, headers=headers)
    r.raise_for_status()
    return r.json()
