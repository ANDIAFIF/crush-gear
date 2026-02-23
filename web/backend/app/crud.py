"""CRUD operations for database models."""

from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc
from typing import Optional, List
from app import models, schemas
from datetime import datetime


# ===== Scan CRUD =====

def get_scans(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    target: Optional[str] = None
) -> tuple[List[models.Scan], int]:
    """Get list of scans with pagination and filtering."""
    query = db.query(models.Scan)

    if status:
        query = query.filter(models.Scan.status == status)
    if target:
        query = query.filter(models.Scan.target.contains(target))

    total = query.count()
    scans = query.order_by(desc(models.Scan.started_at)).offset(skip).limit(limit).all()

    return scans, total


def get_scan_by_id(db: Session, scan_id: int) -> Optional[models.Scan]:
    """Get scan by ID with all related data."""
    return db.query(models.Scan).options(
        joinedload(models.Scan.tool_executions)
    ).filter(models.Scan.id == scan_id).first()


def create_scan(db: Session, scan_data: schemas.ScanCreate) -> models.Scan:
    """Create new scan record."""
    scan = models.Scan(
        target=scan_data.target,
        status="PENDING",
        started_at=datetime.now()
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def update_scan_status(
    db: Session,
    scan_id: int,
    status: str,
    completed_at: Optional[datetime] = None,
    total_duration: Optional[float] = None,
    error_message: Optional[str] = None
) -> Optional[models.Scan]:
    """Update scan status and completion info."""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if scan:
        scan.status = status
        if completed_at:
            scan.completed_at = completed_at
        if total_duration is not None:
            scan.total_duration = total_duration
        if error_message:
            scan.error_message = error_message
        db.commit()
        db.refresh(scan)
    return scan


def delete_scan(db: Session, scan_id: int) -> bool:
    """Delete scan and all related data (cascade)."""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if scan:
        db.delete(scan)
        db.commit()
        return True
    return False


# ===== Host CRUD =====

def get_hosts_by_scan(db: Session, scan_id: int) -> List[models.Host]:
    """Get all hosts for a scan with ports."""
    return db.query(models.Host).options(
        joinedload(models.Host.ports)
    ).filter(models.Host.scan_id == scan_id).all()


def create_host(db: Session, scan_id: int, host_data: dict) -> models.Host:
    """Create new host record."""
    host = models.Host(scan_id=scan_id, **host_data)
    db.add(host)
    db.commit()
    db.refresh(host)
    return host


# ===== Vulnerability CRUD =====

def get_vulnerabilities_by_scan(db: Session, scan_id: int) -> List[models.Vulnerability]:
    """Get all vulnerabilities for a scan."""
    return db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id == scan_id
    ).order_by(
        models.Vulnerability.severity.desc()
    ).all()


def create_vulnerability(db: Session, scan_id: int, vuln_data: dict) -> models.Vulnerability:
    """Create new vulnerability record."""
    vuln = models.Vulnerability(scan_id=scan_id, **vuln_data)
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


# ===== URL CRUD =====

def get_urls_by_scan(db: Session, scan_id: int) -> List[models.URL]:
    """Get all URLs for a scan."""
    return db.query(models.URL).filter(models.URL.scan_id == scan_id).all()


def create_url(db: Session, scan_id: int, url_data: dict) -> models.URL:
    """Create new URL record."""
    url = models.URL(scan_id=scan_id, **url_data)
    db.add(url)
    db.commit()
    db.refresh(url)
    return url


# ===== ToolExecution CRUD =====

def get_tool_execution(db: Session, tool_exec_id: int) -> Optional[models.ToolExecution]:
    """Get tool execution by ID."""
    return db.query(models.ToolExecution).filter(
        models.ToolExecution.id == tool_exec_id
    ).first()


def create_tool_execution(db: Session, exec_data: dict) -> models.ToolExecution:
    """Create new tool execution record."""
    tool_exec = models.ToolExecution(**exec_data)
    db.add(tool_exec)
    db.commit()
    db.refresh(tool_exec)
    return tool_exec


def update_tool_execution(db: Session, tool_exec_id: int, update_data: dict) -> Optional[models.ToolExecution]:
    """Update tool execution record."""
    tool_exec = db.query(models.ToolExecution).filter(
        models.ToolExecution.id == tool_exec_id
    ).first()
    if tool_exec:
        for key, value in update_data.items():
            setattr(tool_exec, key, value)
        db.commit()
        db.refresh(tool_exec)
    return tool_exec


# ===== ToolOutput CRUD =====

def get_tool_outputs(
    db: Session,
    tool_exec_id: int,
    skip: int = 0,
    limit: int = 1000
) -> tuple[List[models.ToolOutput], int]:
    """Get tool output lines with pagination."""
    query = db.query(models.ToolOutput).filter(
        models.ToolOutput.tool_execution_id == tool_exec_id
    ).order_by(models.ToolOutput.line_num)

    total = query.count()
    outputs = query.offset(skip).limit(limit).all()

    return outputs, total


def create_tool_output(db: Session, output_data: dict) -> models.ToolOutput:
    """Create new tool output line."""
    output = models.ToolOutput(**output_data)
    db.add(output)
    db.commit()
    db.refresh(output)
    return output
