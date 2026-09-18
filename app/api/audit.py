from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services.authentication import get_current_user

router = APIRouter(prefix="/api/audit", tags=["Audit"])


class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    actor: str
    actor_type: str
    event: str
    device_id: Optional[int]
    device_name: Optional[str]
    ip_address: Optional[str]
    status: str
    metadata_json: Optional[str]

    class Config:
        from_attributes = True


@router.get("", response_model=List[AuditLogResponse])
def get_audit_logs(
    event: Optional[str] = None,
    actor_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve immutable audit log records.
    Audit records cannot be edited or deleted through the API or UI.
    """
    query = db.query(AuditLog)

    if event:
        query = query.filter(AuditLog.event == event)
    if actor_type:
        query = query.filter(AuditLog.actor_type == actor_type.upper())
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (AuditLog.actor.like(search_term)) |
            (AuditLog.event.like(search_term)) |
            (AuditLog.device_name.like(search_term)) |
            (AuditLog.ip_address.like(search_term)) |
            (AuditLog.metadata_json.like(search_term))
        )

    return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
