from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any
from datetime import datetime


class HoneypotEvent(BaseModel):

    model_config = ConfigDict(extra="allow")

    eventid: str

    session: Optional[str] = None

    src_ip: Optional[str] = None
    src_port: Optional[int] = None

    timestamp: datetime

    sensor: Optional[str] = None

    protocol: Optional[str] = "ssh"

    payload: Optional[Dict[str, Any]] = {}