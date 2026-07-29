"""
manifest_loader.py — loads ace-manifest.yaml explicit RPM->GPM mappings.
Returns a dict of {service_name: role_arn} for the matcher to check first.
"""

from pathlib import Path
import yaml


def load_manifest(manifest_path: str) -> dict[str, str]:
    """
    Loads ace-manifest.yaml and returns {service_name: role_arn}.
    Returns empty dict if file doesn't exist or has no mappings.
    Never raises — missing manifest = fall back to fuzzy matching.
    """
    path = Path(manifest_path)
    if not path.exists():
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception:
        return {}

    if not data or "mappings" not in data:
        return {}

    result = {}
    for entry in data.get("mappings", []):
        service = entry.get("service", "").strip()
        role_arn = entry.get("role_arn", "").strip()
        if service and role_arn:
            result[service] = role_arn

    return result