import asyncio
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.config import settings
from app.database.database import SessionLocal
from app.models.network_scan import NetworkScan
from app.services.network_scanner import scanner
from app.services.device_detector import process_scan_results
from app.websocket.manager import ws_manager
from app.websocket.events import SystemEvent, EventType

logger = logging.getLogger(__name__)


class DeviceMonitorService:
    def __init__(self):
        self._is_running = False
        self._task: asyncio.Task | None = None
        self._interval_seconds = settings.SCAN_INTERVAL

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def interval(self) -> int:
        return self._interval_seconds

    def set_interval(self, seconds: int):
        self._interval_seconds = max(5, seconds)
        logger.info(f"Monitor interval adjusted to {self._interval_seconds}s")

    async def start(self):
        """Start the background network monitoring loop."""
        if self._is_running:
            logger.warning("Device monitor service is already running.")
            return

        self._is_running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info(f"Device monitor background service started with interval {self._interval_seconds}s.")

    async def stop(self):
        """Stop the background network monitoring loop."""
        if not self._is_running:
            return

        self._is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Device monitor background service stopped.")

    async def trigger_single_scan(self) -> dict:
        """Trigger an immediate one-off scan and process results."""
        start_time = datetime.now(timezone.utc)
        db: Session = SessionLocal()
        try:
            # Broadcast scan started
            await ws_manager.broadcast_event(
                SystemEvent.create(
                    event_type=EventType.SCAN_STARTED,
                    data={"subnet": scanner.subnet_cidr, "timestamp": start_time.isoformat()},
                    message="Network discovery scan started"
                )
            )

            scan_record = NetworkScan(
                started_at=start_time,
                subnet=scanner.subnet_cidr,
                scan_type="DEMO" if settings.DEMO_MODE else "ARP",
                status="RUNNING"
            )
            db.add(scan_record)
            db.commit()

            # Run network scanner in thread pool to avoid blocking the event loop
            loop = asyncio.get_running_loop()
            devices = await loop.run_in_executor(None, scanner.scan_network)

            # Process discovered devices
            stats = await process_scan_results(db, devices)

            # Complete scan record
            completed_time = datetime.now(timezone.utc)
            duration = (completed_time - start_time).total_seconds()
            scan_record.completed_at = completed_time
            scan_record.duration_seconds = duration
            scan_record.devices_found = len(devices)
            scan_record.new_devices = stats.get("new", 0)
            scan_record.status = "COMPLETED"
            db.commit()

            # Broadcast scan completed
            await ws_manager.broadcast_event(
                SystemEvent.create(
                    event_type=EventType.SCAN_COMPLETED,
                    data={
                        "devices_found": len(devices),
                        "duration_seconds": duration,
                        "stats": stats,
                    },
                    message="Network scan completed"
                )
            )

            return {
                "status": "COMPLETED",
                "devices_found": len(devices),
                "duration_seconds": duration,
                "stats": stats,
                "subnet": scanner.subnet_cidr,
            }
        except Exception as e:
            db.rollback()
            logger.error(f"Error during network scan: {e}")
            return {"status": "FAILED", "error": str(e)}
        finally:
            db.close()

    async def _monitor_loop(self):
        """Infinite loop periodically executing network scans."""
        while self._is_running:
            try:
                await self.trigger_single_scan()
            except Exception as e:
                logger.error(f"Error in monitor loop iteration: {e}")

            try:
                await asyncio.sleep(self._interval_seconds)
            except asyncio.CancelledError:
                break


device_monitor = DeviceMonitorService()
