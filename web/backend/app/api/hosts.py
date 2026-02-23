"""Host API endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import crud, schemas
from app.database import get_db

router = APIRouter()


@router.get("/scans/{scan_id}/hosts", response_model=schemas.HostListResponse)
async def get_scan_hosts(scan_id: int, db: Session = Depends(get_db)):
    """
    Get all hosts discovered in a scan.

    Returns hosts with ports, services, and products.
    """
    # Verify scan exists
    scan = crud.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    hosts = crud.get_hosts_by_scan(db, scan_id)
    return {"hosts": hosts}
