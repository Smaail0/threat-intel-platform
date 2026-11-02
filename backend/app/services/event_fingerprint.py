import hashlib
import json


def generate_event_hash(event: dict, session_uuid: str) -> str:
    fingerprint_data = {
        "session_id": session_uuid,
        "eventid": event.get("eventid"),
        "timestamp": event.get("timestamp"),
        "input": event.get("input"),
        "message": event.get("message"),
        "src_ip": event.get("src_ip"),
    }

    normalized = json.dumps(
        fingerprint_data,
        sort_keys=True,
        ensure_ascii=False
    )

    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()