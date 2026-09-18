import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from app.config import settings, LOGS_DIR, BASE_DIR
from app.database.migrations import init_db
from app.services.device_monitor import device_monitor

# Configure logging
log_file = LOGS_DIR / "netsentry.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(str(log_file), encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("netsentry")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing NETSENTRY platform...")
    init_db()
    # Start initial background scan
    await device_monitor.trigger_single_scan()
    # Optionally start periodic monitoring
    await device_monitor.start()
    logger.info("NETSENTRY backend operational.")
    yield
    # Shutdown
    logger.info("Shutting down NETSENTRY services...")
    await device_monitor.stop()
    logger.info("Shutdown complete.")


app = FastAPI(
    title="NETSENTRY Local Network Monitoring & Consent-Based Remote Camera System",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
from app.api.auth import router as auth_router
from app.api.devices import router as devices_router
from app.api.network import router as network_router
from app.api.camera import router as camera_router
from app.api.alerts import router as alerts_router
from app.api.audit import router as audit_router
from app.api.reports import router as reports_router
from app.api.client_api import router as client_router
from app.api.websocket_endpoints import router as ws_router

app.include_router(auth_router)
app.include_router(devices_router)
app.include_router(network_router)
app.include_router(camera_router)
app.include_router(alerts_router)
app.include_router(audit_router)
app.include_router(reports_router)
app.include_router(client_router)
app.include_router(ws_router)

# Mount Frontend Static Assets
frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    # Serve HTML pages directly
    @app.get("/")
    async def serve_index():
        return FileResponse(str(frontend_dir / "index.html"))

    @app.get("/{page_name}.html")
    async def serve_page(page_name: str):
        page_path = frontend_dir / f"{page_name}.html"
        if page_path.exists():
            return FileResponse(str(page_path))
        return JSONResponse(status_code=404, content={"detail": "Page not found"})
