def generate_session_summary(ip: str, service: str, score: int, reasons: list[str]) -> str:
    if score >= 7:
        level = "High-risk"
    elif score >= 4:
        level = "Medium-risk"
    else:
        level = "Low-risk"

    if reasons:
        unique_reasons = list(dict.fromkeys(reasons))
        reason_text = ", ".join(unique_reasons[:3])
        return f"{level} {service.upper()} session from {ip}: {reason_text}."

    return f"{level} {service.upper()} session from {ip}: no suspicious behavior detected."