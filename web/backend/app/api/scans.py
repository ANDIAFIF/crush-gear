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


@router.get("/scans/{scan_id}/tool-outputs", response_model=schemas.ScanToolOutputsResponse)
async def get_scan_tool_outputs(
    scan_id: int,
    tool_name: Optional[str] = Query(None, description="Filter by specific tool name"),
    skip: int = Query(0, ge=0, description="Number of lines to skip"),
    limit: int = Query(1000, ge=1, le=5000, description="Max number of lines to return"),
    db: Session = Depends(get_db)
):
    """
    Get tool output lines for a scan.
    
    Can filter by tool_name or retrieve all outputs.
    Returns output lines with line numbers for terminal display.
    """
    # Verify scan exists
    scan = crud.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    # Get all tool executions for this scan
    tool_execs = scan.tool_executions
    
    # Filter by tool_name if specified
    if tool_name:
        tool_execs = [te for te in tool_execs if te.tool_name == tool_name]
    
    # Collect all outputs from matching tool executions
    all_outputs = []
    for tool_exec in tool_execs:
        outputs, _ = crud.get_tool_outputs(db, tool_exec.id, skip=0, limit=10000)
        for output in outputs:
            all_outputs.append({
                "line_num": output.line_num,
                "line_text": f"[{tool_exec.tool_name}] {output.line_text}",
                "tool_name": tool_exec.tool_name,
                "timestamp": output.timestamp.isoformat() if output.timestamp else None
            })
    
    # Sort by line_num
    all_outputs.sort(key=lambda x: x["line_num"])
    
    # Apply pagination
    paginated_outputs = all_outputs[skip:skip + limit]
    
    return {
        "outputs": paginated_outputs,
        "total": len(all_outputs),
        "skip": skip,
        "limit": limit
    }
