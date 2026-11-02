import uuid

from sqlalchemy import Column, String, Integer, BigInteger, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.types import TIMESTAMP, Float
from sqlalchemy.sql import func
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class AttackSession(Base):
    __tablename__ = "attack_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    ip_type = Column(String(30))
    country = Column(String(100))
    country_iso = Column(String(10))
    city = Column(String(100))
    latitude = Column(Float)
    longitude = Column(Float)
    asn = Column(Integer)
    organization = Column(String(255))

    honeypot_node = Column(String(50))
    service = Column(String(20))

    attacker_ip = Column(INET)
    attacker_port = Column(Integer)
    
    abuse_confidence_score = Column(Integer)
    abuse_total_reports = Column(Integer)

    abuse_usage_type = Column(String(100))
    abuse_isp = Column(String(255))
    abuse_domain = Column(String(255))

    abuse_last_reported_at = Column(DateTime(timezone=True))

    timestamp = Column(
        TIMESTAMP(timezone=True),
        server_default=func.now()
    )
    
    behaviors = relationship(
        "SessionBehavior",
        back_populates="session",
        cascade="all, delete-orphan",
    )

    ai_summary = Column(String)
    threat_score = Column(Integer)
    
    mitre_techniques = Column(JSONB, default=list)
    attack_chain = Column(JSONB, default=list)


class SessionEvent(Base):
    __tablename__ = "session_events"
    

    id = Column(BigInteger, primary_key=True)

    session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("attack_sessions.id", ondelete="CASCADE")
    )

    event_type = Column(String(50))
    event_hash = Column(String(64), unique=True, index=True)

    timestamp = Column(
        TIMESTAMP(timezone=True),
        server_default=func.now()
    )

    payload = Column(JSONB)
    

class SessionBehavior(Base):
    __tablename__ = "session_behaviors"

    id = Column(Integer, primary_key=True, index=True)

    session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("attack_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    behavior_name = Column(String, nullable=False)
    stage = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    description = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)

    mitre_techniques = Column(JSONB, nullable=True)
    detected_sequence = Column(JSONB, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    session = relationship("AttackSession", back_populates="behaviors")