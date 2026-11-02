def _indicator_key(item: dict) -> str:
    return f"{item.get('type')}:{item.get('indicator')}"


def deduplicate_virustotal_items(items: list[dict]) -> list[dict]:
    unique = {}

    for item in items:
        key = _indicator_key(item)

        if key not in unique:
            unique[key] = item
            continue

        existing = unique[key]

        existing_malicious = existing.get("malicious") or 0
        item_malicious = item.get("malicious") or 0

        if item_malicious > existing_malicious:
            unique[key] = item

    return list(unique.values())


def calculate_ioc_risk(item: dict) -> dict:
    malicious = item.get("malicious") or 0
    suspicious = item.get("suspicious") or 0
    reputation = item.get("reputation") or 0

    score = 0
    reasons = []

    if malicious >= 10:
        score += 10
        reasons.append("Detected as malicious by 10 or more engines")
    elif malicious >= 5:
        score += 8
        reasons.append("Detected as malicious by 5 or more engines")
    elif malicious >= 1:
        score += 5
        reasons.append("Detected as malicious by at least one engine")

    if suspicious >= 1:
        score += 2
        reasons.append("Marked suspicious by VirusTotal engines")

    if reputation < 0:
        score += 2
        reasons.append("Negative reputation score")

    score = min(score, 10)

    if score >= 8:
        severity = "HIGH"
    elif score >= 4:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    enriched = dict(item)
    enriched["ioc_score"] = score
    enriched["ioc_severity"] = severity
    enriched["ioc_reasons"] = reasons

    return enriched


def correlate_session_intelligence(
    virustotal_items: list[dict],
    attack_chain: list[str],
    mitre_techniques: list[dict],
    abuseipdb: dict | None = None
) -> dict:

    deduped_items = deduplicate_virustotal_items(virustotal_items)

    scored_iocs = [
        calculate_ioc_risk(item)
        for item in deduped_items
    ]

    scored_iocs.sort(
        key=lambda item: item.get("ioc_score", 0),
        reverse=True
    )

    highest_ioc_score = max(
        [item.get("ioc_score", 0) for item in scored_iocs],
        default=0
    )

    abuse_score = 0
    if abuseipdb:
        abuse_score = abuseipdb.get("abuse_confidence_score") or 0

    attack_chain_score = 0
    if len(attack_chain) >= 3:
        attack_chain_score = 8
    elif len(attack_chain) == 2:
        attack_chain_score = 6
    elif len(attack_chain) == 1:
        attack_chain_score = 4

    abuse_normalized = min(int(abuse_score / 10), 10)

    session_risk_score = max(
        highest_ioc_score,
        attack_chain_score,
        abuse_normalized
    )

    if session_risk_score >= 8:
        session_risk = "HIGH"
    elif session_risk_score >= 4:
        session_risk = "MEDIUM"
    else:
        session_risk = "LOW"

    return {
        "session_risk_score": session_risk_score,
        "session_risk": session_risk,
        "top_iocs": scored_iocs[:10],
        "ioc_count": len(scored_iocs),
        "attack_chain_length": len(attack_chain),
        "mitre_technique_count": len(mitre_techniques),
    }