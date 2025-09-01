import requests
from utils.config import MOBSF_API_KEY, MOBSF_URL

def upload_and_scan(apk_path: str) -> dict:
    files = {"file": open(apk_path, "rb")}
    headers = {"Authorization": MOBSF_API_KEY}
    resp = requests.post(f"{MOBSF_URL}/api/v1/upload", files=files, headers=headers)
    resp.raise_for_status()
    return resp.json()

def get_static_json(scan_hash: str) -> dict:
    headers = {"Authorization": MOBSF_API_KEY}
    resp = requests.post(f"{MOBSF_URL}/api/v1/report_json", data={"hash": scan_hash}, headers=headers)
    resp.raise_for_status()
    return resp.json()
