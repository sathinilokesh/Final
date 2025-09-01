import hashlib
import os
from pathlib import Path

def compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash for an APK file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def precheck(file_path: str) -> dict:
    """Collect basic metadata (hash, size)."""
    sha256 = compute_sha256(file_path)
    size = os.path.getsize(file_path)
    return {"sha256": sha256, "size": size}

if __name__ == "__main__":
    sample = "../data/samples/sample.apk"
    print(precheck(sample))
