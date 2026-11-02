from functools import lru_cache

from app.services.attack_cache import get_attack_objects


def _get_attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _get_attack_url(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


@lru_cache(maxsize=1)
def build_technique_index() -> dict:
    index = {}

    for obj in get_attack_objects():
        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        attack_id = _get_attack_id(obj)

        if not attack_id:
            continue

        index[attack_id] = {
            "id": attack_id,
            "stix_id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description", ""),
            "url": _get_attack_url(obj),
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "kill_chain_phases": obj.get("kill_chain_phases", []),
        }

    return index


def lookup_technique(attack_id: str) -> dict | None:
    return build_technique_index().get(attack_id)