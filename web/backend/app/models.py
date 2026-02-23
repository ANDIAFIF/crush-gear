"""SQLAlchemy database models for CrushGear web dashboard."""

from sqlalchemy import (
    Column, Integer, String, Float, Text, Boolean,
    DateTime, ForeignKey, JSON, Index
)
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class Scan(Base):
    """Scan metadata and overall status."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=False)
    target_type = Column(String(20))  # 'ip', 'domain', 'url', 'cidr'
    status = Column(String(20), index=True)  # 'PENDING', 'RUNNING', 'COMPLETED', 'ERROR'
    started_at = Column(DateTime, default=datetime.now, index=True)
    completed_at = Column(DateTime, nullable=True)
    total_duration = Column(Float, nullable=True)
    output_dir = Column(String(500), nullable=True)  # path to results/target_timestamp/
    feed_data = Column(JSON, nullable=True)  # complete feed dict from all phases
    error_message = Column(Text, nullable=True)

    # Relationships
    tool_executions = relationship("ToolExecution", back_populates="scan", cascade="all, delete-orphan")
    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")
    urls = relationship("URL", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class ToolExecution(Base):
    """Per-tool execution tracking."""
    __tablename__ = "tool_executions"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_name = Column(String(50))  # 'nmap', 'amass', 'httpx', etc.
    phase = Column(Integer)  # 0, 1, 2, 3
    status = Column(String(20), index=True)  # 'PENDING', 'RUNNING', 'DONE', 'ERROR', 'SKIPPED'
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)
    returncode = Column(Integer, nullable=True)
    output_file = Column(String(500), nullable=True)  # path to results/{tool}.txt or .json
    command = Column(Text, nullable=True)  # full command executed

    # Relationships
    scan = relationship("Scan", back_populates="tool_executions")
    outputs = relationship("ToolOutput", back_populates="tool_execution", cascade="all, delete-orphan")


class Host(Base):
    """Discovered hosts from nmap."""
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    ip = Column(String(45), index=True)  # IPv4 or IPv6
    hostname = Column(String(255), nullable=True)
    os_guess = Column(String(255), nullable=True)
    is_windows = Column(Boolean, default=False)
    is_dc = Column(Boolean, default=False)  # Domain Controller
    services_json = Column(JSON, nullable=True)  # {port: service} from nmap
    products_json = Column(JSON, nullable=True)  # {port: product} from nmap

    # Relationships
    scan = relationship("Scan", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")


class Port(Base):
    """Port/service details for each host."""
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    port_num = Column(Integer, index=True)
    protocol = Column(String(10))  # 'tcp', 'udp'
    state = Column(String(20))  # 'open', 'closed', 'filtered'
    service = Column(String(100), nullable=True)
    product = Column(String(255), nullable=True)

    # Relationships
    host = relationship("Host", back_populates="ports")


class URL(Base):
    """HTTP endpoints from httpx."""
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(500))
    status_code = Column(Integer, nullable=True)
    title = Column(String(500), nullable=True)
    is_live = Column(Boolean, default=True)
    metadata_json = Column(JSON, nullable=True)  # full httpx JSON output

    # Relationships
    scan = relationship("Scan", back_populates="urls")


class Vulnerability(Base):
    """Vulnerability findings from nuclei."""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(String(50), index=True, nullable=True)
    host = Column(String(255))
    template_id = Column(String(100), nullable=True)
    severity = Column(String(20), index=True)  # 'critical', 'high', 'medium', 'low', 'info'
    msf_module = Column(String(255), nullable=True)  # mapped Metasploit module
    msf_payload = Column(String(255), nullable=True)  # mapped payload
    metadata_json = Column(JSON, nullable=True)  # full nuclei JSON output

    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")


class ToolOutput(Base):
    """Real-time tool output lines."""
    __tablename__ = "tool_outputs"

    id = Column(Integer, primary_key=True, index=True)
    tool_execution_id = Column(Integer, ForeignKey("tool_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    line_num = Column(Integer)
    line_text = Column(Text)
    timestamp = Column(DateTime, default=datetime.now)

    # Relationships
    tool_execution = relationship("ToolExecution", back_populates="outputs")
