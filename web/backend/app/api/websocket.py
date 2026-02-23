"""WebSocket API endpoint for real-time updates."""

import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.scan_manager import scan_manager

router = APIRouter()


@router.websocket("/scans/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: int):
    """
    WebSocket endpoint for real-time scan updates.

    Client connects to receive live updates:
    - tool_start: Tool begins execution
    - tool_output: Real-time stdout lines
    - tool_complete: Tool finished
    - phase_complete: Phase finished
    - scan_complete: Scan finished
    """
    await websocket.accept()

    # Register client with ScanManager
    scan_manager.add_websocket_client(scan_id, websocket)

    try:
        # Send connection confirmation
        await websocket.send_json({
            "type": "connected",
            "scan_id": scan_id,
            "message": "WebSocket connected - ready to receive real-time updates"
        })

        # Keep connection alive with timeout to detect dead connections
        while True:
            try:
                # Wait for client messages with 30 second timeout
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                # Handle client messages (ping/pong, etc.)
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                # Send ping to check if connection is still alive
                try:
                    await websocket.send_json({"type": "ping"})
                except:
                    # Connection is dead, break out of loop
                    break

    except WebSocketDisconnect:
        print(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        print(f"WebSocket error for scan {scan_id}: {e}")
    finally:
        # Unregister client from ScanManager
        scan_manager.remove_websocket_client(scan_id, websocket)
