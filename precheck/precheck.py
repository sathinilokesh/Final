# precheck/precheck.py
import hashlib
from pathlib import Path
from utils.logger import get_logger

log = get_logger("precheck")

def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def precheck(file_path: Path) -> dict:
    if not file_path.exists():
        raise FileNotFoundError(file_path)
    sha256 = compute_sha256(file_path)
    size = file_path.stat().st_size
    log.info(f"Precheck: {file_path.name} | sha256={sha256} | size={size} bytes")
    return {"sha256": sha256, "size": size}
