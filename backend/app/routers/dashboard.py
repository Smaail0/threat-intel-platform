from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from uuid import UUID

from app.database import get_db
from app.models import AttackSession, SessionEvent

from app.services.intelligence_correlation import correlate_session_intelligence

from app.services.behavior_correlation import analyze_session_behaviors

from app.services.session_behavior_service import save_session_behaviors

from app.models import AttackSession, SessionEvent, SessionBehavior

from app.services.session_behavior_service import refresh_session_behaviors

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/events")
def get_events(limit: int = 50, db: Session = Depends(get_db)):
    events = db.query(SessionEvent).order_by(desc(SessionEvent.id)).limit(limit).all()

    return [
        {
            "id": event.id,
            "session_id": str(event.session_id),
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "payload": event.payload,
        }
        for event in events
    ]


@router.get("/sessions")
def get_sessions(limit: int = 50, db: Session = Depends(get_db)):
    sessions = db.query(AttackSession).order_by(desc(AttackSession.timestamp)).limit(limit).all()

    return [
        {
            "id": str(session.id),
            "attacker_ip": str(session.attacker_ip),
            "service": session.service,
            "timestamp": session.timestamp,
            "threat_score": session.threat_score,
            "ai_summary": session.ai_summary,

            "geo": {
                "ip_type": session.ip_type,
                "country": session.country,
                "country_iso": session.country_iso,
                "city": session.city,
                "latitude": session.latitude,
                "longitude": session.longitude,
                "asn": session.asn,
                "organization": session.organization,
            }
        }
        for session in sessions
    ]

@router.get("/sessions/{session_id}/intelligence")
def get_session_intelligence(session_id: UUID, db: Session = Depends(get_db)):
    
    session = db.get(AttackSession, session_id)
    
    if not session:
        return {
            "error": "session_not_found"
        }

    events = (
        db.query(SessionEvent)
        .filter(SessionEvent.session_id == session_id)
        .order_by(SessionEvent.timestamp.asc())
        .all()
    )
    
    stored_behaviors = (
        db.query(SessionBehavior)
        .filter(SessionBehavior.session_id == session_id)
        .order_by(SessionBehavior.created_at.asc())
        .all()
    )

    if not stored_behaviors:
        behavior_analysis = analyze_session_behaviors(events)
        save_session_behaviors(db, session.id, behavior_analysis)

        stored_behaviors = (
            db.query(SessionBehavior)
            .filter(SessionBehavior.session_id == session_id)
            .order_by(SessionBehavior.created_at.asc())
            .all()
        )

    behavior_analysis = {
        "commands_analyzed": len(events),
        "behaviors": [
            {
                "behavior_name": behavior.behavior_name,
                "stage": behavior.stage,
                "severity": behavior.severity,
                "description": behavior.description,
                "confidence": behavior.confidence,
                "mitre_techniques": behavior.mitre_techniques or [],
                "detected_sequence": behavior.detected_sequence or [],
            }
            for behavior in stored_behaviors
        ],
        "attack_timeline": list(
            dict.fromkeys(
                behavior.stage
                for behavior in stored_behaviors
                if behavior.stage
            )
        ),
        "overall_behavior_severity": (
            "HIGH"
            if any(b.severity == "HIGH" for b in stored_behaviors)
            else "MEDIUM"
            if any(b.severity == "MEDIUM" for b in stored_behaviors)
            else "LOW"
        ),
        "summary": (
            "Detected attacker behavior timeline: "
            + " → ".join(
                list(
                    dict.fromkeys(
                        behavior.stage
                        for behavior in stored_behaviors
                        if behavior.stage
                    )
                )
            )
            if stored_behaviors
            else "No significant multi-step attacker behavior detected."
        ),
    }

    urls = set()
    domains = set()
    hashes = set()
    ips = set()

    virustotal_items = []

    for event in events:
        payload = event.payload or {}

        iocs = payload.get("iocs", {})

        urls.update(iocs.get("urls", []))
        domains.update(iocs.get("domains", []))
        hashes.update(iocs.get("hashes", []))
        ips.update(iocs.get("ips", []))

        vt = payload.get("virustotal")
        if vt:
            virustotal_items.extend(vt.get("domains", []))
            virustotal_items.extend(vt.get("urls", []))
            virustotal_items.extend(vt.get("hashes", []))
        
    abuseipdb = {
        "abuse_confidence_score": session.abuse_confidence_score,
        "total_reports": session.abuse_total_reports,
        "usage_type": session.abuse_usage_type,
        "isp": session.abuse_isp,
        "domain": session.abuse_domain,
        "last_reported_at": session.abuse_last_reported_at,
    }

    correlation = correlate_session_intelligence(
        virustotal_items=virustotal_items,
        attack_chain=session.attack_chain or [],
        mitre_techniques=session.mitre_techniques or [],
        abuseipdb=abuseipdb
    )

    return {
        "session_id": str(session.id),
        "attacker_ip": str(session.attacker_ip),
        "threat_score": session.threat_score,
        "summary": session.ai_summary,
        "attack_chain": session.attack_chain or [],
        "mitre_techniques": session.mitre_techniques or [],
        "behavior_analysis": behavior_analysis,
        "abuseipdb": {
            "abuse_confidence_score": session.abuse_confidence_score,
            "total_reports": session.abuse_total_reports,
            "usage_type": session.abuse_usage_type,
            "isp": session.abuse_isp,
            "domain": session.abuse_domain,
            "last_reported_at": session.abuse_last_reported_at,
        },
        "iocs": {
            "urls": sorted(urls),
            "domains": sorted(domains),
            "hashes": sorted(hashes),
            "ips": sorted(ips),
        },
        "virustotal": virustotal_items,
        "correlation": correlation,
    }


@router.get("/stats/overview")
def get_overview(db: Session = Depends(get_db)):
    total_sessions = db.query(func.count(AttackSession.id)).scalar()
    total_events = db.query(func.count(SessionEvent.id)).scalar()
    unique_attackers = db.query(func.count(func.distinct(AttackSession.attacker_ip))).scalar()

    successful_logins = db.query(func.count(SessionEvent.id)).filter(
        SessionEvent.event_type == "cowrie.login.success"
    ).scalar()

    failed_logins = db.query(func.count(SessionEvent.id)).filter(
        SessionEvent.event_type == "cowrie.login.failed"
    ).scalar()

    return {
        "total_sessions": total_sessions,
        "total_events": total_events,
        "unique_attackers": unique_attackers,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
    }


@router.get("/stats/commands")
def get_top_commands(limit: int = 10, db: Session = Depends(get_db)):
    rows = (
        db.query(
            SessionEvent.payload["input"].astext.label("command"),
            func.count(SessionEvent.id).label("count")
        )
        .filter(SessionEvent.event_type == "cowrie.command.input")
        .group_by("command")
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )

    return [
        {
            "command": row.command,
            "count": row.count,
        }
        for row in rows
    ]


@router.get("/stats/logins")
def get_login_attempts(db: Session = Depends(get_db)):
    rows = (
        db.query(
            SessionEvent.event_type,
            func.count(SessionEvent.id).label("count")
        )
        .filter(SessionEvent.event_type.in_([
            "cowrie.login.success",
            "cowrie.login.failed"
        ]))
        .group_by(SessionEvent.event_type)
        .all()
    )

    return [
        {
            "event_type": row.event_type,
            "count": row.count,
        }
        for row in rows
    ]
    
@router.get("/stats/timeline")
def get_event_timeline(db: Session = Depends(get_db)):

    rows = (
        db.query(
            func.date_trunc("minute", SessionEvent.timestamp).label("minute"),
            func.count(SessionEvent.id).label("count")
        )
        .group_by("minute")
        .order_by("minute")
        .limit(60)
        .all()
    )

    return [
        {
            "time": row.minute.isoformat(),
            "count": row.count
        }
        for row in rows
    ]

@router.get("/stats/top_ips")
def get_top_ips(limit: int = 10, db: Session = Depends(get_db)):

    rows = (
        db.query(
            AttackSession.attacker_ip,
            func.count(AttackSession.id).label("count")
        )
        .group_by(AttackSession.attacker_ip)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )

    return [
        {
            "ip": str(row.attacker_ip),
            "count": row.count
        }
        for row in rows
    ]
    
@router.get("/sessions/high-risk")
def get_high_risk_sessions(limit: int = 10, db: Session = Depends(get_db)):

    sessions = (
        db.query(AttackSession)
        .filter(AttackSession.threat_score >= 7)
        .order_by(desc(AttackSession.threat_score), desc(AttackSession.timestamp))
        .limit(limit)
        .all()
    )

    return [
        {
            "id": str(session.id),
            "attacker_ip": str(session.attacker_ip),
            "service": session.service,
            "timestamp": session.timestamp,
            "threat_score": session.threat_score,
            "ai_summary": session.ai_summary,

            "geo": {
                "ip_type": session.ip_type,
                "country": session.country,
                "country_iso": session.country_iso,
                "city": session.city,
                "latitude": session.latitude,
                "longitude": session.longitude,
                "asn": session.asn,
                "organization": session.organization,
            },
            
            "abuseipdb": {
                "abuse_confidence_score": session.abuse_confidence_score,
                "total_reports": session.abuse_total_reports,
                "usage_type": session.abuse_usage_type,
                "isp": session.abuse_isp,
                "domain": session.abuse_domain,
                "last_reported_at": session.abuse_last_reported_at,
            }
        }
        for session in sessions
    ]
    
@router.get("/sessions/{session_id}/events")
def get_session_events(session_id: UUID, db: Session = Depends(get_db)):

    events = (
        db.query(SessionEvent)
        .filter(SessionEvent.session_id == session_id)
        .order_by(SessionEvent.timestamp.asc())
        .all()
    )

    return [
        {
            "id": event.id,
            "session_id": str(event.session_id),
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "payload": event.payload,
        }
        for event in events
    ]
    
@router.get("/stats/countries")
def get_top_countries(limit: int = 10, db: Session = Depends(get_db)):

    rows = (
        db.query(
            AttackSession.country_iso,
            AttackSession.country,
            func.count(AttackSession.id).label("count")
        )
        .filter(AttackSession.country_iso.isnot(None))
        .group_by(AttackSession.country_iso, AttackSession.country)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )

    return [
        {
            "country_iso": row.country_iso,
            "country": row.country,
            "count": row.count
        }
        for row in rows
    ]
    
@router.get("/stats/asns")
def get_top_asns(limit: int = 10, db: Session = Depends(get_db)):

    rows = (
        db.query(
            AttackSession.asn,
            AttackSession.organization,
            func.count(AttackSession.id).label("count")
        )
        .filter(AttackSession.asn.isnot(None))
        .group_by(AttackSession.asn, AttackSession.organization)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )

    return [
        {
            "asn": row.asn,
            "organization": row.organization,
            "count": row.count
        }
        for row in rows
    ]
    
@router.get("/map/attack-locations")
def get_attack_locations(db: Session = Depends(get_db)):

    sessions = (
        db.query(AttackSession)
        .filter(AttackSession.latitude.isnot(None))
        .filter(AttackSession.longitude.isnot(None))
        .all()
    )

    return [
        {
            "session_id": str(session.id),
            "attacker_ip": str(session.attacker_ip),
            "country": session.country,
            "country_iso": session.country_iso,
            "city": session.city,
            "latitude": session.latitude,
            "longitude": session.longitude,
            "asn": session.asn,
            "organization": session.organization,
            "threat_score": session.threat_score,
        }
        for session in sessions
    ]
    
@router.get("/stats/behaviors")
def get_top_behaviors(limit: int = 10, db: Session = Depends(get_db)):
    rows = (
        db.query(
            SessionBehavior.behavior_name,
            func.count(SessionBehavior.id).label("count")
        )
        .group_by(SessionBehavior.behavior_name)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )

    return [
        {
            "behavior": row.behavior_name,
            "count": row.count,
        }
        for row in rows
    ]
    
@router.get("/stats/behavior-stages")
def get_behavior_stages(db: Session = Depends(get_db)):
    rows = (
        db.query(
            SessionBehavior.stage,
            func.count(SessionBehavior.id).label("count")
        )
        .filter(SessionBehavior.stage.isnot(None))
        .group_by(SessionBehavior.stage)
        .order_by(desc("count"))
        .all()
    )

    return [
        {
            "stage": row.stage,
            "count": row.count,
        }
        for row in rows
    ]
    
@router.get("/stats/high-severity-behaviors")
def get_high_severity_behaviors(db: Session = Depends(get_db)):
    count = (
        db.query(func.count(SessionBehavior.id))
        .filter(SessionBehavior.severity == "HIGH")
        .scalar()
    )

    return {
        "high_severity_behaviors": count
    }
    
@router.get("/behaviors/{behavior_name}/sessions")
def get_sessions_by_behavior(
    behavior_name: str,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    rows = (
        db.query(AttackSession, SessionBehavior)
        .join(SessionBehavior, SessionBehavior.session_id == AttackSession.id)
        .filter(SessionBehavior.behavior_name == behavior_name)
        .order_by(desc(AttackSession.timestamp))
        .limit(limit)
        .all()
    )

    return [
        {
            "session_id": str(session.id),
            "attacker_ip": str(session.attacker_ip),
            "service": session.service,
            "timestamp": session.timestamp,
            "threat_score": session.threat_score,
            "behavior": {
                "name": behavior.behavior_name,
                "stage": behavior.stage,
                "severity": behavior.severity,
                "confidence": behavior.confidence,
                "mitre_techniques": behavior.mitre_techniques or [],
            },
        }
        for session, behavior in rows
    ]
    
@router.get("/behavior-stages/{stage}/sessions")
def get_sessions_by_behavior_stage(
    stage: str,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    rows = (
        db.query(AttackSession, SessionBehavior)
        .join(SessionBehavior, SessionBehavior.session_id == AttackSession.id)
        .filter(SessionBehavior.stage == stage)
        .order_by(desc(AttackSession.timestamp))
        .limit(limit)
        .all()
    )

    return [
        {
            "session_id": str(session.id),
            "attacker_ip": str(session.attacker_ip),
            "service": session.service,
            "timestamp": session.timestamp,
            "threat_score": session.threat_score,
            "behavior": {
                "name": behavior.behavior_name,
                "stage": behavior.stage,
                "severity": behavior.severity,
                "confidence": behavior.confidence,
                "mitre_techniques": behavior.mitre_techniques or [],
            },
        }
        for session, behavior in rows
    ]