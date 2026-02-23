"""Scan orchestration and WebSocket broadcast management."""

import asyncio
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from fastapi import WebSocket
from sqlalchemy.orm import Session

# Add project root to path for importing crushgear modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

from app import models
from app.services.crushgear_callbacks import DatabaseCallbacks


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
        try:
            # Update scan status to RUNNING
            scan = db.query(models.Scan).get(scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            scan.status = "RUNNING"
            scan.started_at = datetime.now()
            db.commit()

            # Import crushgear modules
            from crushgear import CrushGear

            # Create DatabaseCallbacks instance
            callbacks = DatabaseCallbacks(db, scan_id, self)

            # Initialize CrushGear
            crusher = CrushGear(
                target=target,
                tools=options.get("tools"),
                username=options.get("username"),
                password=options.get("password"),
                lhost=options.get("lhost"),
                lport=options.get("lport"),
            )

            # Build tool wrappers
            crusher._prepare()

            # Set output directory in scan
            scan.output_dir = str(crusher.output_dir)
            db.commit()

            # Run crushgear with callbacks
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
            scan.status = "COMPLETED"
            scan.completed_at = datetime.now()
            scan.total_duration = (scan.completed_at - scan.started_at).total_seconds()
            db.commit()

            # Broadcast completion
            await self.broadcast(scan_id, {
                "type": "scan_complete",
                "scan_id": scan_id,
                "status": "COMPLETED",
                "total_duration": scan.total_duration
            })

        except Exception as exc:
            # Update scan status to ERROR
            scan = db.query(models.Scan).get(scan_id)
            if scan:
                scan.status = "ERROR"
                scan.error_message = str(exc)
                scan.completed_at = datetime.now()
                if scan.started_at:
                    scan.total_duration = (scan.completed_at - scan.started_at).total_seconds()
                db.commit()

            # Broadcast error
            await self.broadcast(scan_id, {
                "type": "scan_error",
                "scan_id": scan_id,
                "error": str(exc)
            })

            raise

        finally:
            # Cleanup
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]

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
