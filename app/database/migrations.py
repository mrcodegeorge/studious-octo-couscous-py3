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

        db.commit()
        logger.info("Database schema and default settings initialized successfully.")
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
