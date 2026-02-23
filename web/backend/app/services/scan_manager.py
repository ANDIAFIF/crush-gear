"""Scan orchestration and WebSocket broadcast management."""

import asyncio
import sys
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from fastapi import WebSocket
from sqlalchemy.orm import Session

# Add project root to path for importing crushgear modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

from app import models
from app.services.crushgear_callbacks import DatabaseCallbacks
from app.database import SessionLocal

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScanManager:
    """Manages scan execution and WebSocket connections."""

    def __init__(self):
        self.active_scans: Dict[int, asyncio.Task] = {}
        self.websocket_clients: Dict[int, List[WebSocket]] = {}

    async def start_scan(
        self,
        db: Session,
        scan_id: int,
        target: str,
        options: dict
    ) -> None:
        """Run crushgear scan in background and persist results."""
        logger.info(f"🚀 Starting scan {scan_id} for target: {target}")
        started_at = None

        # Create a new database session for this async task
        # The original session will be closed after the HTTP request ends
        db_task = SessionLocal()

        try:
            # Update scan status to RUNNING
            scan = db_task.query(models.Scan).get(scan_id)
            if not scan:
                logger.error(f"❌ Scan {scan_id} not found in database")
                raise ValueError(f"Scan {scan_id} not found")

            logger.info(f"📝 Setting scan {scan_id} status to RUNNING")
            scan.status = "RUNNING"
            started_at = datetime.now()
            scan.started_at = started_at
            db_task.commit()

            # Import crushgear modules
            logger.info(f"📦 Importing CrushGear module")
            from crushgear import CrushGear

            # Create DatabaseCallbacks instance
            logger.info(f"🔗 Creating DatabaseCallbacks")
            callbacks = DatabaseCallbacks(db_task, scan_id, self)

            # Initialize CrushGear
            logger.info(f"⚙️  Initializing CrushGear with target: {target}")
            crusher = CrushGear(
                target=target,
                tools=options.get("tools"),
                username=options.get("username"),
                password=options.get("password"),
                lhost=options.get("lhost"),
                lport=options.get("lport"),
            )

            # Build tool wrappers
            logger.info(f"🔧 Preparing tool wrappers")
            crusher._prepare()
            logger.info(f"✅ Tool wrappers prepared: Phase0={len(crusher.phase0_wrappers)}, Phase1={len(crusher.phase1_wrappers)}")

            # Set output directory in scan
            scan.output_dir = str(crusher.output_dir)
            db_task.commit()
            logger.info(f"📁 Output directory: {crusher.output_dir}")

            # Run crushgear with callbacks
            logger.info(f"🚀 Starting phased execution")
            from core.runner import run_phased

            results = await run_phased(
                phase0_wrappers=crusher.phase0_wrappers,
                phase1_wrappers=crusher.phase1_wrappers,
                phase2_factory=crusher.phase2_factory,
                phase3_factory=crusher.phase3_factory,
                output_dir=crusher.output_dir,
                cfg_timeouts=crusher.config.get("timeouts", {}),
                callbacks=callbacks,
            )

            # Update scan status to COMPLETED
            completed_at = datetime.now()
            scan.status = "COMPLETED"
            scan.completed_at = completed_at
            scan.total_duration = (completed_at - started_at).total_seconds()
            db_task.commit()
            logger.info(f"✅ Scan {scan_id} completed in {scan.total_duration:.1f}s")

            # Broadcast completion
            await self.broadcast(scan_id, {
                "type": "scan_complete",
                "scan_id": scan_id,
                "status": "COMPLETED",
                "total_duration": scan.total_duration
            })

        except Exception as exc:
            logger.error(f"❌ Scan {scan_id} failed with error: {exc}", exc_info=True)

            # Update scan status to ERROR
            try:
                scan = db_task.query(models.Scan).get(scan_id)
                if scan:
                    scan.status = "ERROR"
                    scan.error_message = str(exc)
                    completed_at = datetime.now()
                    scan.completed_at = completed_at
                    if started_at:
                        scan.total_duration = (completed_at - started_at).total_seconds()
                    db_task.commit()
                    logger.info(f"📝 Scan {scan_id} status updated to ERROR")
            except Exception as db_exc:
                logger.error(f"❌ Failed to update scan status: {db_exc}")

            # Broadcast error
            try:
                await self.broadcast(scan_id, {
                    "type": "scan_error",
                    "scan_id": scan_id,
                    "error": str(exc)
                })
            except Exception as ws_exc:
                logger.error(f"❌ Failed to broadcast error: {ws_exc}")

        finally:
            # Cleanup
            logger.info(f"🧹 Cleaning up scan {scan_id}")
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
            # Close the task database session
            db_task.close()

    async def broadcast(self, scan_id: int, message: dict):
        """Send message to all WebSocket clients for this scan."""
        clients = self.websocket_clients.get(scan_id, [])
        disconnected = []

        for ws in clients:
            try:
                await ws.send_json(message)
            except Exception:
                # Mark for removal if send fails
                disconnected.append(ws)

        # Remove disconnected clients
        for ws in disconnected:
            clients.remove(ws)

    def add_websocket_client(self, scan_id: int, websocket: WebSocket):
        """Register WebSocket client for scan updates."""
        if scan_id not in self.websocket_clients:
            self.websocket_clients[scan_id] = []
        self.websocket_clients[scan_id].append(websocket)

    def remove_websocket_client(self, scan_id: int, websocket: WebSocket):
        """Unregister WebSocket client."""
        if scan_id in self.websocket_clients:
            clients = self.websocket_clients[scan_id]
            if websocket in clients:
                clients.remove(websocket)
            # Clean up empty lists
            if not clients:
                del self.websocket_clients[scan_id]


# Global singleton instance
scan_manager = ScanManager()
