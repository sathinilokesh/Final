def extract_features(static_json: dict, dynamic_json: dict = None) -> dict:
    """Extract numeric features from MobSF JSON (without debuggable)."""
    manifest = static_json.get("manifest_analysis", {}) or {}
    perms = static_json.get("permissions", {}) or {}

    features = {
        "dangerous_perm_count": len(perms.get("dangerous", [])),
        "total_permissions": sum(len(v) for v in perms.values()),
        "exported_activities": len(manifest.get("exported_activities", [])),
        "services": len(manifest.get("services", [])),
        "receivers": len(manifest.get("receivers", [])),
        "urls_count": len(static_json.get("urls", [])),
    }

    if dynamic_json:
        # Different MobSF versions use different keys
        net_calls = (
            dynamic_json.get("network_calls")
            or dynamic_json.get("network_request")
            or dynamic_json.get("network_analysis")
            or []
        )
        features["network_calls"] = len(net_calls)

        api_calls = dynamic_json.get("api_calls", [])
        features["api_calls"] = len(api_calls)

    return features
