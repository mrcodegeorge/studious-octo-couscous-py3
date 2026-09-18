import sys
import argparse
import uvicorn
from app.config import settings
from app.database.database import SessionLocal
from app.database.migrations import init_db
from app.models.user import User
from app.services.authentication import hash_password


def setup_admin_cli(username: str, password: str, email: str = None):
    """Command-line setup for administrator credentials."""
    init_db()
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            print(f"[!] User '{username}' already exists. Updating password...")
            existing.hashed_password = hash_password(password)
            existing.failed_logins = 0
            existing.locked_until = None
            db.commit()
            print(f"[+] Administrator '{username}' password successfully updated.")
            return

        admin = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role="admin",
            is_active=True
        )
        db.add(admin)
        db.commit()
        print(f"[+] Administrator '{username}' successfully created!")
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="NETSENTRY - Local Network Monitoring & Consent Camera Server")
    parser.add_argument("--host", default=settings.HOST, help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=settings.PORT, help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    parser.add_argument("--setup-admin", nargs=2, metavar=("USERNAME", "PASSWORD"), help="Create or reset an administrator account")
    parser.add_argument("--demo", action="store_true", help="Launch in Demonstration Mode")

    args = parser.parse_args()

    if args.demo:
        settings.DEMO_MODE = True
        print("[*] Launching NETSENTRY in DEMONSTRATION MODE.")

    if args.setup_admin:
        setup_admin_cli(args.setup_admin[0], args.setup_admin[1])
        sys.exit(0)

    print(f"[*] Starting NETSENTRY server on http://{args.host}:{args.port}")
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
