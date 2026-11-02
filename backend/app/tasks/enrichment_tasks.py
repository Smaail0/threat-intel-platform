from datetime import datetime

from app.worker import celery_app
from app.database import SessionLocal
from app.models import SessionEvent, AttackSession
from app.services.abuseipdb_service import check_ip_reputation
from app.services.virustotal_service import enrich_iocs_with_virustotal
from sqlalchemy.orm.attributes import flag_modified
from app.services.session_behavior_service import refresh_session_behaviors


@celery_app.task(name="enrich_event_task")
def enrich_event_task(event_id: int):
    db = SessionLocal()

    try:
        event = db.get(SessionEvent, event_id)

        if not event:
            return {
                "status": "not_found",
                "event_id": event_id
            }
            
        payload = event.payload or {}

        geo = payload.get("geo", {})
        ip = payload.get("src_ip")

        if geo.get("is_public") and ip:
            abuse = check_ip_reputation(ip)

            payload["abuseipdb"] = abuse
            event.payload = payload
            flag_modified(event, "payload")

            session = db.get(AttackSession, event.session_id)

            if session and abuse.get("enabled") and not abuse.get("error"):
                session.abuse_confidence_score = abuse.get("abuse_confidence_score")
                session.abuse_total_reports = abuse.get("total_reports")
                session.abuse_usage_type = abuse.get("usage_type")
                session.abuse_isp = abuse.get("isp")
                session.abuse_domain = abuse.get("domain")

                last_reported = abuse.get("last_reported_at")
                if last_reported:
                    session.abuse_last_reported_at = datetime.fromisoformat(
                        last_reported.replace("Z", "+00:00")
                    )

        iocs = payload.get("iocs", {})

        if iocs and (
            iocs.get("domains") or
            iocs.get("urls") or
            iocs.get("hashes")
        ):
            payload["virustotal"] = enrich_iocs_with_virustotal(iocs)
            
            event.payload = payload
            flag_modified(event, "payload")
            
        db.commit()
        
        refresh_session_behaviors(db, event.session_id)

        return {
            "status": "enriched",
            "event_id": event_id,
            "abuseipdb_checked": bool(geo.get("is_public") and ip),
            "virustotal_checked": bool(payload.get("virustotal"))
        }

    finally:
        db.close()