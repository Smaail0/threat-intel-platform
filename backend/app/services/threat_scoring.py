def calculate_threat_score(event: dict) -> dict:
    eventid = event.get("eventid", "")
    command = (event.get("input", "") or "").lower()

    score = 0
    reasons = []

    if eventid == "cowrie.login.failed":
        score += 2
        reasons.append("Failed login attempt")

    if eventid == "cowrie.login.success":
        score += 5
        reasons.append("Successful login into honeypot")

    if eventid == "cowrie.command.input":
        score += 3
        reasons.append("Command execution detected")

    dangerous_keywords = {
        "wget": "File download using wget",
        "curl": "File download using curl",
        "chmod": "Permission modification command",
        "sh": "Shell script execution",
        "bash": "Bash execution",
        "nc": "Netcat usage",
        "base64": "Possible encoded payload",
        "/tmp": "Use of temporary execution directory"
    }

    for keyword, reason in dangerous_keywords.items():
        if keyword in command:
            score += 4
            reasons.append(reason)

    if eventid == "cowrie.session.file_download":
        score += 8
        reasons.append("File download captured by honeypot")

    score = min(score, 10)

    if score >= 7:
        severity = "HIGH"
    elif score >= 4:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons
    }