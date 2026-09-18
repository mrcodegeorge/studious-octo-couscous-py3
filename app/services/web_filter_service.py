import re
import fnmatch
import datetime
import logging
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.models.web_policy import WebFilterRule, WebActivityLog, VpnRestrictionPolicy
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.device import Device

logger = logging.getLogger(__name__)


class WebFilterService:
    @staticmethod
    def get_rules(db: Session, active_only: bool = False) -> List[WebFilterRule]:
        q = db.query(WebFilterRule)
        if active_only:
            q = q.filter(WebFilterRule.is_active == True)
        return q.order_by(WebFilterRule.created_at.desc()).all()

    @staticmethod
    def get_rule_by_id(db: Session, rule_id: int) -> Optional[WebFilterRule]:
        return db.query(WebFilterRule).filter(WebFilterRule.id == rule_id).first()

    @staticmethod
    def create_rule(
        db: Session,
        domain_pattern: str,
        category: str = "General",
        action: str = "BLOCK",
        description: Optional[str] = None,
        is_active: bool = True,
    ) -> WebFilterRule:
        domain_pattern = domain_pattern.strip().lower()
        existing = db.query(WebFilterRule).filter(WebFilterRule.domain_pattern == domain_pattern).first()
        if existing:
            existing.category = category
            existing.action = action
            existing.description = description
            existing.is_active = is_active
            db.commit()
            db.refresh(existing)
            return existing

        rule = WebFilterRule(
            domain_pattern=domain_pattern,
            category=category,
            action=action,
            description=description,
            is_active=is_active,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return rule

    @staticmethod
    def update_rule(
        db: Session,
        rule_id: int,
        domain_pattern: Optional[str] = None,
        category: Optional[str] = None,
        action: Optional[str] = None,
        description: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> Optional[WebFilterRule]:
        rule = db.query(WebFilterRule).filter(WebFilterRule.id == rule_id).first()
        if not rule:
            return None

        if domain_pattern is not None:
            rule.domain_pattern = domain_pattern.strip().lower()
        if category is not None:
            rule.category = category
        if action is not None:
            rule.action = action
        if description is not None:
            rule.description = description
        if is_active is not None:
            rule.is_active = is_active

        db.commit()
        db.refresh(rule)
        return rule

    @staticmethod
    def delete_rule(db: Session, rule_id: int) -> bool:
        rule = db.query(WebFilterRule).filter(WebFilterRule.id == rule_id).first()
        if not rule:
            return False
        db.delete(rule)
        db.commit()
        return True

    @staticmethod
    def match_domain(domain: str, rules: List[WebFilterRule]) -> Tuple[bool, Optional[WebFilterRule]]:
        """
        Matches a domain against a list of WebFilterRule objects.
        Supports wildcards:
          - "*.tiktok.com" matches "v16.tiktok.com", "tiktok.com"
          - "facebook.com" matches "facebook.com", "www.facebook.com"
          - "*vpn*" matches anything containing vpn
        """
        dom = domain.strip().lower()
        for r in rules:
            if not r.is_active:
                continue
            pat = r.domain_pattern.strip().lower()

            # Exact match
            if dom == pat:
                return True, r

            # Standard fnmatch (e.g. *.domain.com)
            if fnmatch.fnmatch(dom, pat):
                return True, r

            # Check if pattern starts with *. and dom matches base domain
            if pat.startswith("*."):
                base = pat[2:]
                if dom == base or dom.endswith("." + base):
                    return True, r

            # Check subdomain matching if pat has no wildcard
            if not pat.startswith("*") and dom.endswith("." + pat):
                return True, r

        return False, None

    @staticmethod
    def record_activity_entry(
        db: Session,
        domain: str,
        mac_address: Optional[str] = None,
        ip_address: Optional[str] = None,
        remote_ip: Optional[str] = None,
        process_name: Optional[str] = None,
        is_vpn: bool = False,
    ) -> WebActivityLog:
        """
        Evaluates domain against active filter rules, persists WebActivityLog,
        and generates alerts/audits if blocked.
        """
        clean_domain = domain.strip().lower()
        active_rules = WebFilterService.get_rules(db, active_only=True)
        is_match, matched_rule = WebFilterService.match_domain(clean_domain, active_rules)

        # Lookup device_id if mac provided
        device_id = None
        device = None
        if mac_address:
            device = db.query(Device).filter(Device.mac_address == mac_address).first()
            if device:
                device_id = device.id

        action_taken = "ALLOWED"
        category = "General"
        rule_pat = None

        if is_match and matched_rule:
            action_taken = matched_rule.action  # "BLOCK" or "ALERT"
            category = matched_rule.category
            rule_pat = matched_rule.domain_pattern

            if action_taken == "BLOCK":
                # Create Alert
                dev_label = device.hostname if device else (ip_address or mac_address or "Client")
                alert = Alert(
                    device_id=device_id,
                    alert_type="POLICY_VIOLATION",
                    severity="WARNING",
                    title="Restricted Site Access Blocked",
                    message=f"Access to '{clean_domain}' blocked for {dev_label} (Process: {process_name or 'Unknown'}). Matched rule: {rule_pat}",
                )
                db.add(alert)

                # Create AuditLog
                import json
                audit = AuditLog(
                    actor=dev_label,
                    actor_type="CLIENT",
                    event="WEB_FILTER_BLOCK",
                    device_id=device_id,
                    device_name=dev_label,
                    ip_address=ip_address,
                    status="DENIED",
                    metadata_json=json.dumps({
                        "domain": clean_domain,
                        "remote_ip": remote_ip,
                        "process": process_name,
                        "rule": rule_pat,
                        "is_vpn": is_vpn,
                    }),
                )
                db.add(audit)

        log_entry = WebActivityLog(
            device_id=device_id,
            mac_address=mac_address,
            ip_address=ip_address,
            domain=clean_domain,
            remote_ip=remote_ip,
            process_name=process_name,
            action_taken=action_taken,
            category=category,
            matched_rule=rule_pat,
            is_vpn_traffic=is_vpn,
            timestamp=datetime.datetime.utcnow(),
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry

    @staticmethod
    def get_vpn_policy(db: Session) -> VpnRestrictionPolicy:
        policy = db.query(VpnRestrictionPolicy).first()
        if not policy:
            policy = VpnRestrictionPolicy(
                block_all_vpns=True,
                block_wireguard=True,
                block_openvpn=True,
                terminate_vpn_processes=True,
                custom_blocked_adapters="wintun,wireguard,tap0901,nordlynx,openvpn,proton",
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
        return policy

    @staticmethod
    def update_vpn_policy(
        db: Session,
        block_all_vpns: Optional[bool] = None,
        block_wireguard: Optional[bool] = None,
        block_openvpn: Optional[bool] = None,
        terminate_vpn_processes: Optional[bool] = None,
        custom_blocked_adapters: Optional[str] = None,
    ) -> VpnRestrictionPolicy:
        policy = WebFilterService.get_vpn_policy(db)
        if block_all_vpns is not None:
            policy.block_all_vpns = block_all_vpns
        if block_wireguard is not None:
            policy.block_wireguard = block_wireguard
        if block_openvpn is not None:
            policy.block_openvpn = block_openvpn
        if terminate_vpn_processes is not None:
            policy.terminate_vpn_processes = terminate_vpn_processes
        if custom_blocked_adapters is not None:
            policy.custom_blocked_adapters = custom_blocked_adapters

        policy.updated_at = datetime.datetime.utcnow()
        db.commit()
        db.refresh(policy)
        return policy

    @staticmethod
    def get_stats(db: Session) -> Dict[str, Any]:
        since = datetime.datetime.utcnow() - datetime.timedelta(hours=24)

        total_24h = db.query(WebActivityLog).filter(WebActivityLog.timestamp >= since).count()
        blocked_24h = (
            db.query(WebActivityLog)
            .filter(WebActivityLog.timestamp >= since, WebActivityLog.action_taken == "BLOCK")
            .count()
        )
        vpn_detections = (
            db.query(WebActivityLog)
            .filter(WebActivityLog.timestamp >= since, WebActivityLog.is_vpn_traffic == True)
            .count()
        )
        active_rules_count = db.query(WebFilterRule).filter(WebFilterRule.is_active == True).count()

        # Top 10 domains
        top_domains_raw = (
            db.query(WebActivityLog.domain, func.count(WebActivityLog.id).label("count"))
            .filter(WebActivityLog.timestamp >= since)
            .group_by(WebActivityLog.domain)
            .order_by(desc("count"))
            .limit(10)
            .all()
        )
        top_domains = [{"domain": r[0], "count": r[1]} for r in top_domains_raw]

        # Top blocked domains
        top_blocked_raw = (
            db.query(WebActivityLog.domain, func.count(WebActivityLog.id).label("count"))
            .filter(WebActivityLog.timestamp >= since, WebActivityLog.action_taken == "BLOCK")
            .group_by(WebActivityLog.domain)
            .order_by(desc("count"))
            .limit(5)
            .all()
        )
        top_blocked = [{"domain": r[0], "count": r[1]} for r in top_blocked_raw]

        return {
            "total_activities_24h": total_24h,
            "blocked_attempts_24h": blocked_24h,
            "vpn_detections_24h": vpn_detections,
            "active_rules_count": active_rules_count,
            "top_domains": top_domains,
            "top_blocked": top_blocked,
        }
