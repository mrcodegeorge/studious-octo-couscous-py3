import logging
from app.database.database import engine, Base, SessionLocal
from app.models import User, SystemSetting
from app.config import settings

logger = logging.getLogger(__name__)


def init_db():
    """Create all database tables and seed default system settings."""
    logger.info("Initializing NETSENTRY database schema...")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        # Default system settings if missing
        default_settings = [
            ("scan_interval", str(settings.SCAN_INTERVAL), "Network background scan interval in seconds"),
            ("camera_session_max_minutes", str(settings.CAMERA_SESSION_MAX_MINUTES), "Maximum camera session duration in minutes"),
            ("authorized_subnet", settings.AUTHORIZED_SUBNET, "Admin configured authorized subnet CIDR"),
            ("demo_mode", "true" if settings.DEMO_MODE else "false", "Simulation mode for controlled evaluations"),
            ("system_version", "1.0.0", "NETSENTRY platform version"),
        ]

        for key, val, desc in default_settings:
            existing = db.query(SystemSetting).filter(SystemSetting.key == key).first()
            if not existing:
                setting = SystemSetting(key=key, value=val, description=desc)
                db.add(setting)

        # Seed default web filter rules if none exist
        from app.models.web_policy import WebFilterRule, VpnRestrictionPolicy
        if db.query(WebFilterRule).count() == 0:
            default_rules = [
                ("*.tiktok.com", "Social Media", "BLOCK", "Block TikTok short videos"),
                ("*.facebook.com", "Social Media", "BLOCK", "Block Facebook portal and CDN"),
                ("*.instagram.com", "Social Media", "BLOCK", "Block Instagram photo/reels"),
                ("*.bet365.com", "Gambling", "BLOCK", "Block online gambling portal"),
                ("*.roblox.com", "Gaming", "BLOCK", "Block Roblox gaming traffic"),
                ("*.nordvpn.com", "VPN/Proxy", "BLOCK", "Block commercial VPN portal"),
                ("*.protonvpn.com", "VPN/Proxy", "BLOCK", "Block ProtonVPN endpoint"),
                ("*.expressvpn.com", "VPN/Proxy", "BLOCK", "Block ExpressVPN gateway"),
            ]
            for dom, cat, act, desc in default_rules:
                db.add(WebFilterRule(domain_pattern=dom, category=cat, action=act, description=desc, is_active=True))

        # Seed default VPN restriction policy if none exists
        if db.query(VpnRestrictionPolicy).count() == 0:
            vpn_pol = VpnRestrictionPolicy(
                block_all_vpns=True,
                block_wireguard=True,
                block_openvpn=True,
                terminate_vpn_processes=True,
                custom_blocked_adapters="wintun,wireguard,tap0901,nordlynx,openvpn,proton"
            )
            db.add(vpn_pol)

        db.commit()
        logger.info("Database schema, default settings, and web filter policies initialized successfully.")
    except Exception as e:
        db.rollback()
        logger.error(f"Error during database initialization: {e}")
        raise
    finally:
        db.close()


def is_initial_setup_needed() -> bool:
    """Returns True if no administrator accounts exist in the database."""
    db = SessionLocal()
    try:
        count = db.query(User).filter(User.role == "admin").count()
        return count == 0
    finally:
        db.close()
