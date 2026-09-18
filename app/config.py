import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

DATA_DIR.mkdir(exist_ok=True, parents=True)
LOGS_DIR.mkdir(exist_ok=True, parents=True)


class Settings(BaseSettings):
    APP_NAME: str = "NETSENTRY"
    DEBUG: bool = False
    SECRET_KEY: str = "netsentry-default-secret-key-replace-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    DATABASE_URL: str = f"sqlite:///{DATA_DIR / 'netsentry.db'}"

    NETWORK_INTERFACE: str = ""
    AUTHORIZED_SUBNET: str = ""
    SCAN_INTERVAL: int = 10

    CAMERA_SESSION_MAX_MINUTES: int = 10
    CAMERA_FRAME_RATE: int = 15

    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    REGISTRATION_CODE_EXPIRE_MINUTES: int = 15

    DEMO_MODE: bool = False

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
