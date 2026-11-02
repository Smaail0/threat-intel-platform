from app.services.attack_lookup import lookup_technique


def enrich_techniques(technique_ids: list[str]) -> list[dict]:
    enriched = []

    for technique_id in technique_ids:
        technique = lookup_technique(technique_id)

        if not technique:
            continue

        tactics = [
            phase.get("phase_name")
            for phase in technique.get("kill_chain_phases", [])
        ]

        enriched.append({
            "id": technique["id"],
            "name": technique["name"],
            "description": technique["description"],
            "url": technique["url"],
            "tactics": tactics,
            "platforms": technique["platforms"],
            "is_subtechnique": technique["is_subtechnique"]
        })

    return enriched


def build_attack_chain(techniques: list[dict]) -> list[str]:
    ordered_tactics = []

    for technique in techniques:
        for tactic in technique.get("tactics", []):

            normalized = tactic.replace("-", " ").title()

            if normalized not in ordered_tactics:
                ordered_tactics.append(normalized)

    return ordered_tactics