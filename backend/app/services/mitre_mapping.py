def map_event_to_mitre(event: dict) -> list[dict]:
    eventid = event.get("eventid", "")
    command = (event.get("input", "") or "").lower()

    techniques = []

    if eventid == "cowrie.session.file_download" or "wget" in command or "curl" in command:
        techniques.append({
            "id": "T1105",
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control"
        })

    if "sh" in command or "bash" in command or eventid == "cowrie.command.input":
        techniques.append({
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution"
        })

    if "chmod" in command:
        techniques.append({
            "id": "T1222",
            "name": "File and Directory Permissions Modification",
            "tactic": "Defense Evasion"
        })

    return techniques