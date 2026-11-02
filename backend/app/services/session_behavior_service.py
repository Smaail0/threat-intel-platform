from app.models import SessionBehavior, SessionEvent
from app.services.behavior_correlation import analyze_session_behaviors

def save_session_behaviors(db, session_id, behavior_analysis):
    """
    Replace existing stored behaviors for a session with latest analysis.
    """

    db.query(SessionBehavior).filter(
        SessionBehavior.session_id == session_id
    ).delete()

    behaviors = behavior_analysis.get("behaviors", [])

    for behavior in behaviors:
        db_behavior = SessionBehavior(
            session_id=session_id,
            behavior_name=behavior.get("behavior_name"),
            stage=behavior.get("stage"),
            severity=behavior.get("severity"),
            description=behavior.get("description"),
            confidence=behavior.get("confidence"),
            mitre_techniques=behavior.get("mitre_techniques", []),
            detected_sequence=[
            {
                **step,
                "timestamp": (
                    step["timestamp"].isoformat()
                    if step.get("timestamp")
                    else None
                ),
            }
            for step in behavior.get("detected_sequence", [])
            ],
        )

        db.add(db_behavior)

    db.commit()
    
def refresh_session_behaviors(db, session_id):
    events = (
        db.query(SessionEvent)
        .filter(SessionEvent.session_id == session_id)
        .order_by(SessionEvent.timestamp.asc())
        .all()
    )

    behavior_analysis = analyze_session_behaviors(events)

    save_session_behaviors(db, session_id, behavior_analysis)

    return behavior_analysis