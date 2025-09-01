# features/build_features.py
"""
Turn MobSF JSON into ML features.
We keep features simple & robust to schema variance across MobSF versions.
"""
from __future__ import annotations
from typing import Dict, Any, List, Set
import re

def _safe_len(container) -> int:
    try:
        return len(container or [])
    except Exception:
        return 0

DANGEROUS_PERM_PREFIXES = (
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_PHONE_STATE",
    "android.permission.USE_FINGERPRINT",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
)

BANKING_KEYWORDS = ("bank", "upi", "payment", "wallet", "finance", "pay", "card", "upi://", "ifsc")

def extract_features(mobsf_json: Dict[str, Any],
                     dynamic_json: Dict[str, Any] | None = None) -> Dict[str, float]:
    perms_raw = mobsf_json.get("permissions", {}) or {}
    # Some MobSF versions expose permissions in different buckets.
    # Merge all into a single set:
    perm_sets: List[Set[str]] = []
    for key in ("dangerous", "normal", "signature", "unknown", "all"):
        p = perms_raw.get(key)
        if isinstance(p, list):
            perm_sets.append(set(p))
    permissions: Set[str] = set().union(*perm_sets) if perm_sets else set(perms_raw if isinstance(perms_raw, list) else [])

    activities = mobsf_json.get("activities", {}) or {}
    exported_acts = activities.get("exported", []) or []
    providers = mobsf_json.get("providers", {}) or {}
    services = mobsf_json.get("services", {}) or {}
    receivers = mobsf_json.get("receivers", {}) or {}

    # Certificate / signing
    cert = mobsf_json.get("certificate", {}) or {}
    cert_valid = 1.0 if cert.get("is_valid", cert.get("valid", False)) else 0.0
    cert_issuer = (cert.get("issuer", "") or "").lower()
    cert_subject = (cert.get("subject", "") or "").lower()
    cert_self_signed = 1.0 if cert_issuer and cert_issuer == cert_subject else 0.0

    # URLs
    urls = mobsf_json.get("urls", []) or []
    hardcoded_bankish_urls = sum(1 for u in urls if any(k in u.lower() for k in BANKING_KEYWORDS))

    # Manifest flags
    manifest = mobsf_json.get("manifest_analysis", {}) or {}
    debuggable = 1.0 if manifest.get("is_debuggable") or manifest.get("debuggable") else 0.0
    backup_enabled = 1.0 if manifest.get("allow_backup") or manifest.get("backup_enabled") else 0.0

    # Heuristic: banking-like app indicators (package/label)
    app_info = mobsf_json.get("app_info", {}) or {}
    pkg = (app_info.get("packagename") or app_info.get("package_name") or "").lower()
    app_label = (app_info.get("label") or app_info.get("app_name") or "").lower()
    looks_like_banking = 1.0 if any(k in pkg or k in app_label for k in BANKING_KEYWORDS) else 0.0

    # Dangerous permissions count
    dangerous_count = sum(1 for p in permissions if p in DANGEROUS_PERM_PREFIXES)

    # Exported components (attack surface)
    exported_components = _safe_len(exported_acts) \
        + _safe_len(providers.get("exported", [])) \
        + _safe_len(services.get("exported", [])) \
        + _safe_len(receivers.get("exported", []))

    # Dynamic signals (optional)
    dyn_net_domains = 0
    dyn_suspicious_calls = 0
    if dynamic_json:
        net = (dynamic_json.get("network") or {}).get("domains") or []
        dyn_net_domains = _safe_len(net)
        calls = dynamic_json.get("api_calls") or []
        # crude suspicious call match
        suspicious_patterns = (r"sendTextMessage", r"getDeviceId|getImei", r"Cipher\.getInstance", r"execHttpRequest")
        for c in calls:
            s = str(c).lower()
            if any(re.search(pat, s, re.I) for pat in suspicious_patterns):
                dyn_suspicious_calls += 1

    features = {
        "looks_like_banking": looks_like_banking,
        "dangerous_perm_count": float(dangerous_count),
        "exported_components": float(exported_components),
        "hardcoded_bankish_urls": float(hardcoded_bankish_urls),
        "debuggable": float(debuggable),
        "backup_enabled": float(backup_enabled),
        "cert_valid": float(cert_valid),
        "cert_self_signed": float(cert_self_signed),
        "dyn_net_domains": float(dyn_net_domains),
        "dyn_suspicious_calls": float(dyn_suspicious_calls),
    }
    return features

FEATURE_ORDER = [
    "looks_like_banking",
    "dangerous_perm_count",
    "exported_components",
    "hardcoded_bankish_urls",
    "debuggable",
    "backup_enabled",
    "cert_valid",
    "cert_self_signed",
    "dyn_net_domains",
    "dyn_suspicious_calls",
]

def vectorize(features: Dict[str, float]) -> list[float]:
    return [float(features.get(k, 0.0)) for k in FEATURE_ORDER]
