def extract_features(static_json: dict, dynamic_json: dict = None) -> dict:
    """Extract numeric features from MobSF JSON (without debuggable)."""
    manifest = static_json.get("manifest_analysis", {})
    perms = static_json.get("permissions", {})

    features = {
        "dangerous_perm_count": len(perms.get("dangerous", [])),
        "total_permissions": sum(len(v) for v in perms.values()),
        "exported_activities": len(manifest.get("exported_activities", [])),
        "services": len(manifest.get("services", [])),
        "receivers": len(manifest.get("receivers", [])),
        "urls_count": len(static_json.get("urls", [])),
    }

    if dynamic_json:
        net = dynamic_json.get("network_calls", [])
        features["network_calls"] = len(net)

    return features
