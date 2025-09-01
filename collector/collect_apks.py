# collector/collect_apks.py
"""
Example collector:
- Copies APKs from a watched folder or downloads from URLs list.
- Stores into data/samples with normalized file names.
"""
from pathlib import Path
import shutil
import requests
from utils.config import SAMPLES_DIR
from utils.logger import get_logger

log = get_logger("collector")

def add_from_local(apk_path: str) -> Path:
    src = Path(apk_path)
    if not src.exists() or src.suffix.lower() != ".apk":
        raise FileNotFoundError(f"Not an APK: {apk_path}")
    dst = SAMPLES_DIR / src.name
    shutil.copy2(src, dst)
    log.info(f"Added APK -> {dst}")
    return dst

def add_from_url(url: str, filename: str = None) -> Path:
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    name = filename or url.split("/")[-1]
    if not name.endswith(".apk"):
        name += ".apk"
    dst = SAMPLES_DIR / name
    with open(dst, "wb") as f:
        f.write(r.content)
    log.info(f"Downloaded APK -> {dst}")
    return dst

if __name__ == "__main__":
    # quick demo
    # add_from_local("/path/to/app.apk")
    pass
