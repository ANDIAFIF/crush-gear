"""Pydantic schemas for request/response validation."""

from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List, Dict, Any
import json


# ===== Scan Schemas =====

class ScanCreate(BaseModel):
    """Request schema for creating a new scan."""
    target: str = Field(..., description="Target IP/domain/URL/CIDR")
    tools: Optional[str] = Field(None, description="Comma-separated tool names")
    lhost: Optional[str] = Field(None, description="LHOST for reverse shells")
    lport: Optional[int] = Field(None, description="LPORT for reverse shells")
    username: Optional[str] = Field(None, description="Username for credentials")
    password: Optional[str] = Field(None, description="Password for credentials")


class ScanBase(BaseModel):
    """Base scan fields."""
    id: int
    target: str
    target_type: Optional[str]
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    total_duration: Optional[float]

    class Config:
        from_attributes = True


class ScanResponse(ScanBase):
    """Response schema for scan list."""
    pass


class ScanDetail(ScanBase):
    """Detailed scan response with tool executions."""
    output_dir: Optional[str]
    feed_data: Optional[Dict[str, Any]]
    error_message: Optional[str]
    tool_executions: List["ToolExecutionResponse"] = []

    @field_validator('feed_data', mode='before')
    @classmethod
    def parse_json_field(cls, v):
        """Parse JSON string fields to dict."""
        if v is None:
            return None
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return {}
        return v

    class Config:
        from_attributes = True


# ===== ToolExecution Schemas =====

class ToolExecutionResponse(BaseModel):
    """Response schema for tool execution."""
    id: int
    tool_name: str
    phase: int
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration: Optional[float]
    returncode: Optional[int]
    output_file: Optional[str]
    command: Optional[str]

    class Config:
        from_attributes = True


# ===== Host & Port Schemas =====

class PortResponse(BaseModel):
    """Response schema for port."""
    id: int
    port_num: int
    protocol: Optional[str]
    state: str
    service: Optional[str]
    product: Optional[str]

    class Config:
        from_attributes = True


class HostResponse(BaseModel):
    """Response schema for host."""
    id: int
    ip: str
    hostname: Optional[str]
    os_guess: Optional[str]
    is_windows: bool
    is_dc: bool
    services_json: Optional[Dict[str, str]]
    products_json: Optional[Dict[str, str]]
    ports: List[PortResponse] = []

    @field_validator('services_json', 'products_json', mode='before')
    @classmethod
    def parse_json_field(cls, v):
        """Parse JSON string fields to dict."""
        if v is None:
            return None
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return {}
        return v

    class Config:
        from_attributes = True


# ===== URL Schemas =====

class URLResponse(BaseModel):
    """Response schema for URL."""
    id: int
    url: str
    status_code: Optional[int]
    title: Optional[str]
    is_live: bool
    metadata_json: Optional[Dict[str, Any]]

    @field_validator('metadata_json', mode='before')
    @classmethod
    def parse_json_field(cls, v):
        """Parse JSON string fields to dict."""
        if v is None:
            return None
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return {}
        return v

    class Config:
        from_attributes = True


# ===== Vulnerability Schemas =====

class VulnerabilityResponse(BaseModel):
    """Response schema for vulnerability."""
    id: int
    cve_id: Optional[str]
    host: str
    template_id: Optional[str]
    severity: str
    msf_module: Optional[str]
    msf_payload: Optional[str]
    metadata_json: Optional[Dict[str, Any]]

    @field_validator('metadata_json', mode='before')
    @classmethod
    def parse_json_field(cls, v):
        """Parse JSON string fields to dict."""
        if v is None:
            return None
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return {}
        return v

    class Config:
        from_attributes = True


# ===== ToolOutput Schemas =====

class ToolOutputResponse(BaseModel):
    """Response schema for tool output line."""
    id: int
    line_num: int
    line_text: str
    timestamp: datetime

    class Config:
        from_attributes = True


# ===== List Response Schemas =====

class ScanListResponse(BaseModel):
    """Response for scan list with pagination."""
    scans: List[ScanResponse]
    total: int


class HostListResponse(BaseModel):
    """Response for host list."""
    hosts: List[HostResponse]


class VulnerabilityListResponse(BaseModel):
    """Response for vulnerability list."""
    vulnerabilities: List[VulnerabilityResponse]


class ToolOutputListResponse(BaseModel):
    """Response for tool output list."""
    lines: List[ToolOutputResponse]
    total: int


class ToolOutputLine(BaseModel):
    """Single tool output line with tool name."""
    line_num: int
    line_text: str
    tool_name: str
    timestamp: Optional[str]


class ScanToolOutputsResponse(BaseModel):
    """Response for scan tool outputs endpoint."""
    outputs: List[ToolOutputLine]
    total: int
    skip: int
    limit: int


# Update forward references
ScanDetail.model_rebuild()
