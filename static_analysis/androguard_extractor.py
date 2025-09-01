# static_analysis/androguard_extractor.py
from androguard.core.apk import APK
from pathlib import Path
import hashlib


def compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash of file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_features(apk_path: str):
    """
    Extract features from an APK using Androguard.
    Returns a dictionary ready for ML model input.
    """
    apk_path = Path(apk_path)
    apk = APK(str(apk_path))

    features = {}

    # Basic info
    features["apk_name"] = apk_path.name
    features["sha256"] = compute_sha256(str(apk_path))
    features["package_name"] = apk.get_package()
    features["version_code"] = apk.get_androidversion_code()
    features["version_name"] = apk.get_androidversion_name()

    # Permissions
    perms = apk.get_permissions() or []
    features["permission_count"] = len(perms)
    features["permissions_dangerous"] = sum(
        1 for p in perms if "WRITE_SMS" in p or "READ_SMS" in p or "RECORD_AUDIO" in p
    )
    features["permissions_network"] = sum(
        1 for p in perms if "INTERNET" in p or "ACCESS_NETWORK_STATE" in p
    )

    # Components
    features["activities_count"] = len(apk.get_activities() or [])
    features["services_count"] = len(apk.get_services() or [])
    features["receivers_count"] = len(apk.get_receivers() or [])
    features["providers_count"] = len(apk.get_providers() or [])

    # Certificate (signer info)
    certs = apk.get_certificates_der_v2() or apk.get_certificates_der_v3()
    features["certificates_count"] = len(certs) if certs else 0

    # APK size
    features["apk_size_bytes"] = apk_path.stat().st_size

    return features


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python androguard_extractor.py <apk_path>")
        sys.exit(1)

    apk_file = sys.argv[1]
    feats = extract_features(apk_file)
    print(json.dumps(feats, indent=2))
