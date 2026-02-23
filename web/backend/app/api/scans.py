"""Scan CRUD API endpoints."""

import asyncio
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional
from app import crud, schemas
from app.database import get_db
from app.services.scan_manager import scan_manager

router = APIRouter()


@router.get("/scans", response_model=schemas.ScanListResponse)
async def list_scans(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Max number of records to return"),
    status: Optional[str] = Query(None, description="Filter by status"),
    target: Optional[str] = Query(None, description="Filter by target (partial match)"),
    db: Session = Depends(get_db)
):
    """
    List all scans with pagination and filtering.

    - **skip**: Number of records to skip (for pagination)
    - **limit**: Maximum number of records to return (1-100)
    - **status**: Filter by scan status (PENDING, RUNNING, COMPLETED, ERROR)
    - **target**: Filter by target string (partial match)
    """
    scans, total = crud.get_scans(db, skip=skip, limit=limit, status=status, target=target)
    return {"scans": scans, "total": total}


@router.get("/scans/{scan_id}", response_model=schemas.ScanDetail)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Get detailed scan information by ID.

    Returns scan metadata, tool executions, and feed data.
    """
    scan = crud.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@router.post("/scans/start", response_model=schemas.ScanResponse, status_code=201)
async def start_scan(
    scan_data: schemas.ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start a new scan.

    Creates a scan record with PENDING status and triggers background execution
    via ScanManager. The scan will run asynchronously and update the database
    with results via DatabaseCallbacks.

    - **target**: Target IP/domain/URL/CIDR (required)
    - **tools**: Comma-separated tool names (optional, defaults to all tools)
    - **lhost**: LHOST for reverse shells (optional, auto-detected if not provided)
    - **lport**: LPORT for reverse shells (optional, defaults to 4444)
    - **username**: Username for credentials (optional)
    - **password**: Password for credentials (optional)
    """
    # Create scan record
    scan = crud.create_scan(db, scan_data)

    # Prepare options for ScanManager
    options = {
        "tools": scan_data.tools,
        "lhost": scan_data.lhost,
        "lport": scan_data.lport,
        "username": scan_data.username,
        "password": scan_data.password,
    }

    # Trigger background scan execution
    # Create new event loop task to avoid blocking
    task = asyncio.create_task(
        scan_manager.start_scan(db, scan.id, scan_data.target, options)
    )
    scan_manager.active_scans[scan.id] = task

    return scan


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Delete a scan and all related data.

    This will cascade delete:
    - Tool executions
    - Tool outputs
    - Hosts and ports
    - URLs
    - Vulnerabilities
    """
    success = crud.delete_scan(db, scan_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return {"success": True, "message": f"Scan {scan_id} deleted"}
