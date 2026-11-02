import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AttackSession, SessionEvent

from app.services.behavior_mapper import enrich_techniques, build_attack_chain

from app.services.threat_scoring import calculate_threat_score

from app.services.session_summary import generate_session_summary

from app.services.mitre_mapping import map_event_to_mitre

from app.services.event_fingerprint import generate_event_hash

from app.services.geoip_service import enrich_ip

from app.tasks.enrichment_tasks import enrich_event_task

from app.services.ioc_extractor import extract_iocs

router = APIRouter()


@router.post("/ingest")
async def ingest_event(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    events = data if isinstance(data, list) else [data]

    inserted = 0
    seen_sessions = set()
    event_ids_to_enrich = []

    for event in events:
        eventid = event.get("eventid", "unknown")
        session = event.get("session")
        src_ip = event.get("src_ip")
        geo = enrich_ip(src_ip)
        event["geo"] = geo
        event["iocs"] = extract_iocs(event)
        src_port = event.get("src_port")
        sensor = event.get("sensor", "unknown-node")
        protocol = event.get("protocol", "ssh")

        timestamp_raw = event.get("timestamp")
        if timestamp_raw:
            timestamp = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
        else:
            timestamp = datetime.now(timezone.utc)

        session_uuid = uuid.uuid5(
            uuid.NAMESPACE_DNS,
            session or f"{src_ip}-{timestamp_raw}"
        )

        if session_uuid not in seen_sessions:
            existing_session = db.get(AttackSession, session_uuid)

            if not existing_session:
                db.add(AttackSession(
                    id=session_uuid,
                    honeypot_node=sensor,
                    service=protocol,
                    attacker_ip=src_ip,
                    attacker_port=src_port,
                    timestamp=timestamp,
                    threat_score=0,
                    ip_type=geo.get("type"),
                    country=geo.get("country"),
                    country_iso=geo.get("country_iso"),
                    city=geo.get("city"),
                    latitude=geo.get("latitude"),
                    longitude=geo.get("longitude"),
                    asn=geo.get("asn"),
                    organization=geo.get("organization"),
                ))
                db.flush()

            seen_sessions.add(session_uuid)

        threat = calculate_threat_score(event)
        event["geo"] = enrich_ip(src_ip)
        event["threat_score"] = threat["score"]
        event["severity"] = threat["severity"]
        event["threat_reasons"] = threat["reasons"]
        event["mitre_techniques"] = map_event_to_mitre(event)
        
        technique_ids = [
            technique["id"]
            for technique in event.get("mitre_techniques", [])
        ]

        enriched_techniques = enrich_techniques(technique_ids)
        event["mitre_techniques"] = enriched_techniques
                
        session_obj = db.get(AttackSession, session_uuid)

        if session_obj:
            current_score = session_obj.threat_score or 0
            session_obj.threat_score = max(current_score, threat["score"])

            existing_techniques = session_obj.mitre_techniques or []

            combined_techniques = {
                technique["id"]: technique
                for technique in existing_techniques
            }

            for technique in enriched_techniques:
                combined_techniques[technique["id"]] = technique

            session_obj.mitre_techniques = list(combined_techniques.values())
            session_obj.attack_chain = build_attack_chain(session_obj.mitre_techniques)

            reasons = event.get("threat_reasons", [])

            if reasons:
                session_obj.ai_summary = generate_session_summary(
                    ip=src_ip,
                    service=protocol,
                    score=session_obj.threat_score,
                    reasons=reasons
                )

        event_hash = generate_event_hash(event, str(session_uuid))

        existing_event = (
            db.query(SessionEvent)
            .filter(SessionEvent.event_hash == event_hash)
            .first()
        )

        if existing_event:
            continue

        session_event = SessionEvent(
            session_id=session_uuid,
            event_type=eventid,
            timestamp=timestamp,
            payload=event,
            event_hash=event_hash
        )

        db.add(session_event)
        db.flush()

        event_ids_to_enrich.append(session_event.id)

        inserted += 1

    db.commit()
    
    for event_id in event_ids_to_enrich:
        enrich_event_task.delay(event_id)

    return {
        "status": "stored",
        "inserted": inserted
    }