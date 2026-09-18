from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

from app.database.database import get_db
from app.services.authentication import get_current_user, get_current_admin_user
from app.services.web_filter_service import WebFilterService
from app.models.user import User
from app.models.web_policy import WebFilterRule, WebActivityLog, VpnRestrictionPolicy
from app.websocket.manager import ws_manager
from app.websocket.events import SystemEvent, EventType

router = APIRouter(prefix="/web-filter", tags=["Web Filtering & Policies"])


# Schemas
class RuleCreateRequest(BaseModel):
    domain_pattern: str
    category: str = "General"
    action: str = "BLOCK"
    description: Optional[str] = None
    is_active: bool = True


class RuleUpdateRequest(BaseModel):
    domain_pattern: Optional[str] = None
    category: Optional[str] = None
    action: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None


class VpnPolicyUpdateRequest(BaseModel):
    block_all_vpns: Optional[bool] = None
    block_wireguard: Optional[bool] = None
    block_openvpn: Optional[bool] = None
    terminate_vpn_processes: Optional[bool] = None
    custom_blocked_adapters: Optional[str] = None


class ActivityItem(BaseModel):
    domain: str
    remote_ip: Optional[str] = None
    process_name: Optional[str] = None
    is_vpn: bool = False


class ActivityReportBatch(BaseModel):
    mac_address: Optional[str] = None
    ip_address: Optional[str] = None
    activities: List[ActivityItem]


@router.get("/rules")
def get_rules(
    active_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rules = WebFilterService.get_rules(db, active_only=active_only)
    return [
        {
            "id": r.id,
            "domain_pattern": r.domain_pattern,
            "category": r.category,
            "action": r.action,
            "description": r.description,
            "is_active": r.is_active,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in rules
    ]


@router.post("/rules")
async def create_rule(
    req: RuleCreateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin_user),
):
    rule = WebFilterService.create_rule(
        db=db,
        domain_pattern=req.domain_pattern,
        category=req.category,
        action=req.action,
        description=req.description,
        is_active=req.is_active,
    )

    # Broadcast policy update event to all connected dashboard and clients
    await ws_manager.broadcast_event(
        SystemEvent.create(
            EventType.WEB_POLICY_UPDATED,
            {"rule_id": rule.id, "domain_pattern": rule.domain_pattern, "action": rule.action},
        )
    )

    return {
        "id": rule.id,
        "domain_pattern": rule.domain_pattern,
        "category": rule.category,
        "action": rule.action,
        "description": rule.description,
        "is_active": rule.is_active,
    }


@router.put("/rules/{rule_id}")
async def update_rule(
    rule_id: int,
    req: RuleUpdateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin_user),
):
    rule = WebFilterService.update_rule(
        db=db,
        rule_id=rule_id,
        domain_pattern=req.domain_pattern,
        category=req.category,
        action=req.action,
        description=req.description,
        is_active=req.is_active,
    )
    if not rule:
        raise HTTPException(status_code=404, detail="Filter rule not found")

    await ws_manager.broadcast_event(
        SystemEvent.create(
            EventType.WEB_POLICY_UPDATED,
            {"rule_id": rule.id, "domain_pattern": rule.domain_pattern},
        )
    )

    return {"message": "Rule updated", "id": rule.id}


@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin_user),
):
    success = WebFilterService.delete_rule(db, rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Filter rule not found")

    await ws_manager.broadcast_event(
        SystemEvent.create(
            EventType.WEB_POLICY_UPDATED,
            {"rule_id": rule_id, "action": "DELETED"},
        )
    )
    return {"message": "Rule deleted"}


@router.get("/activity")
def get_activity(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    device_id: Optional[int] = None,
    action_taken: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(WebActivityLog)
    if device_id is not None:
        q = q.filter(WebActivityLog.device_id == device_id)
    if action_taken:
        q = q.filter(WebActivityLog.action_taken == action_taken.upper())
    if search:
        s = f"%{search}%"
        q = q.filter(
            (WebActivityLog.domain.ilike(s))
            | (WebActivityLog.process_name.ilike(s))
            | (WebActivityLog.ip_address.ilike(s))
        )

    total = q.count()
    items = q.order_by(WebActivityLog.timestamp.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "items": [
            {
                "id": a.id,
                "device_id": a.device_id,
                "hostname": a.device.hostname if a.device else "Unknown",
                "mac_address": a.mac_address,
                "ip_address": a.ip_address,
                "domain": a.domain,
                "remote_ip": a.remote_ip,
                "process_name": a.process_name,
                "action_taken": a.action_taken,
                "category": a.category,
                "matched_rule": a.matched_rule,
                "is_vpn_traffic": a.is_vpn_traffic,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            }
            for a in items
        ],
    }


@router.post("/activity")
async def report_activity_batch(
    batch: ActivityReportBatch,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Monitored client endpoint to report detected web endpoints and VPN status.
    Can be invoked by registered client daemons.
    """
    client_ip = batch.ip_address or (request.client.host if request.client else "127.0.0.1")
    recorded = []
    blocked_count = 0

    for act in batch.activities:
        log_entry = WebFilterService.record_activity_entry(
            db=db,
            domain=act.domain,
            mac_address=batch.mac_address,
            ip_address=client_ip,
            remote_ip=act.remote_ip,
            process_name=act.process_name,
            is_vpn=act.is_vpn,
        )
        if log_entry.action_taken == "BLOCK":
            blocked_count += 1
        recorded.append(log_entry.id)

    # Broadcast live alert to admin dashboard if any blocked traffic
    if blocked_count > 0:
        await ws_manager.broadcast_event(
            SystemEvent.create(
                EventType.WEB_FILTER_VIOLATION,
                {
                    "client_ip": client_ip,
                    "mac_address": batch.mac_address,
                    "blocked_count": blocked_count,
                    "timestamp": batch.activities[0].domain if batch.activities else "",
                },
            )
        )

    return {"status": "ok", "recorded_count": len(recorded), "blocked_count": blocked_count}


@router.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return WebFilterService.get_stats(db)


@router.get("/client-policy")
def get_client_policy(
    db: Session = Depends(get_db),
):
    """
    Publicly accessible to enrolled clients to pull latest block rules and anti-VPN directives.
    """
    active_rules = WebFilterService.get_rules(db, active_only=True)
    vpn_policy = WebFilterService.get_vpn_policy(db)

    return {
        "blocked_domains": [
            {
                "pattern": r.domain_pattern,
                "category": r.category,
                "action": r.action,
            }
            for r in active_rules
        ],
        "vpn_policy": {
            "block_all_vpns": vpn_policy.block_all_vpns,
            "block_wireguard": vpn_policy.block_wireguard,
            "block_openvpn": vpn_policy.block_openvpn,
            "terminate_vpn_processes": vpn_policy.terminate_vpn_processes,
            "blocked_adapter_substrings": [
                s.strip().lower()
                for s in (vpn_policy.custom_blocked_adapters or "").split(",")
                if s.strip()
            ],
        },
    }


@router.get("/policy/vpn")
def get_vpn_policy_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    p = WebFilterService.get_vpn_policy(db)
    return {
        "id": p.id,
        "block_all_vpns": p.block_all_vpns,
        "block_wireguard": p.block_wireguard,
        "block_openvpn": p.block_openvpn,
        "terminate_vpn_processes": p.terminate_vpn_processes,
        "custom_blocked_adapters": p.custom_blocked_adapters,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


@router.post("/policy/vpn")
async def update_vpn_policy_endpoint(
    req: VpnPolicyUpdateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin_user),
):
    p = WebFilterService.update_vpn_policy(
        db=db,
        block_all_vpns=req.block_all_vpns,
        block_wireguard=req.block_wireguard,
        block_openvpn=req.block_openvpn,
        terminate_vpn_processes=req.terminate_vpn_processes,
        custom_blocked_adapters=req.custom_blocked_adapters,
    )

    await ws_manager.broadcast_event(
        SystemEvent.create(
            EventType.WEB_POLICY_UPDATED,
            {"block_all_vpns": p.block_all_vpns},
        )
    )

    return {"message": "VPN policy updated", "block_all_vpns": p.block_all_vpns}
