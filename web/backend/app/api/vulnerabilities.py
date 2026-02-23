"""Vulnerability API endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app import crud, schemas
from app.database import get_db

router = APIRouter()


@router.get("/scans/{scan_id}/vulnerabilities", response_model=schemas.VulnerabilityListResponse)
async def get_scan_vulnerabilities(scan_id: int, db: Session = Depends(get_db)):
    """
    Get all vulnerabilities found in a scan.

    Returns CVE findings from nuclei with severity, hosts, and Metasploit module mappings.
    Results are ordered by severity (critical → high → medium → low → info).
    """
    # Verify scan exists
    scan = crud.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    vulnerabilities = crud.get_vulnerabilities_by_scan(db, scan_id)
    return {"vulnerabilities": vulnerabilities}
