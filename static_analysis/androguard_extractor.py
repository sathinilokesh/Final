import re
import zipfile
import hashlib
from pathlib import Path
from androguard.core.apk import APK
import xml.etree.ElementTree as ET


def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_urls(file_path: Path):
    urls = set()
    with zipfile.ZipFile(file_path, "r") as zf:
        for name in zf.namelist():
            if name.endswith((".xml", ".txt", ".html", ".js", ".smali")):
                try:
                    data = zf.read(name).decode("utf-8", errors="ignore")
                    found = re.findall(r"https?://[^\s\"'>]+", data)
                    urls.update(found)
                except Exception:
                    continue
    return list(urls)


def count_exported_components(manifest_xml, tag):
    """
    Count exported components based on Android rules:
    - exported="true" => exported
    - exported="false" => not exported
    - exported missing and has intent-filter => exported
    """
    total = 0
    ns = {"android": "http://schemas.android.com/apk/res/android"}  # Usually the android namespace

    for elem in manifest_xml.findall(f".//{tag}"):
        exported = elem.get("{http://schemas.android.com/apk/res/android}exported")
        if exported == "true":
            total += 1
        elif exported == "false":
            continue
        else:
            # Check if intent-filter exists
            if elem.find("intent-filter") is not None:
                total += 1
    return total


def extract_features(file_path: str):
    apk = APK(file_path)
    sha256 = compute_sha256(Path(file_path))

    # Permissions
    perms = apk.get_permissions()
    dangerous_perms = [
        p for p in perms if "READ_SMS" in p or "RECORD_AUDIO" in p or "WRITE_SMS" in p
    ]

    # Parse manifest XML for exported components counting
    try:
        manifest_xml_str = apk.get_android_manifest_xml().toxml()
        manifest_xml = ET.fromstring(manifest_xml_str)
    except Exception:
        manifest_xml = None

    exported_activities = count_exported_components(manifest_xml, "activity") if manifest_xml else 0

    # Debuggable flag
    debuggable = 1 if apk.is_debuggable() else 0

    # Cleartext traffic flag
    # Search for the android:usesCleartextTraffic attribute in application tag
    uses_cleartext = 0
    if manifest_xml is not None:
        application = manifest_xml.find("application")
        if application is not None:
            cleartext = application.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
            if cleartext == "true":
                uses_cleartext = 1

    # Cert validity (get the first cert, parse dates)
    cert_days = -1
    try:
        from cryptography import x509
        certs = apk.get_certificates_der_v2() or apk.get_certificates_der_v1() or apk.get_certificates_der_v3()
        if certs:
            cert = x509.load_der_x509_certificate(certs[0])
            delta = cert.not_valid_after - cert.not_valid_before
            cert_days = delta.days
    except Exception:
        pass

    # URLs
    urls = extract_urls(Path(file_path))

    return {
        "apk": Path(file_path).name,
        "sha256": sha256,
        "size_bytes": Path(file_path).stat().st_size,
        "looks_like_banking": 1 if "bank" in apk.get_package().lower() else 0,
        "dangerous_perm_count": len(dangerous_perms),
        "exported_components": exported_activities,
        "hardcoded_urls": len(urls),
        "debuggable": debuggable,
        "uses_cleartext": uses_cleartext,
        "certificate_validity_days": cert_days,
    }


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python androguard_extractor.py <apk>")
        sys.exit(1)

    feats = extract_features(sys.argv[1])
    print(json.dumps(feats, indent=2))
