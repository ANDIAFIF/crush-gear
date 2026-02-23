"""Database callbacks for CrushGear execution.

Implements ExecutionCallbacks protocol to persist scan execution
to database and broadcast WebSocket updates.
"""

from sqlalchemy.orm import Session
from datetime import datetime
import json
from pathlib import Path

from app import models, crud


class DatabaseCallbacks:
    """Persist scan execution to database and broadcast WebSocket updates."""

    def __init__(self, db: Session, scan_id: int, scan_manager):
        self.db = db
        self.scan_id = scan_id
        self.scan_manager = scan_manager
        self.tool_exec_ids: dict[str, int] = {}
        self.line_nums: dict[str, int] = {}

    async def on_tool_start(self, tool: str, phase: int, command: list[str]):
        """Called when a tool starts execution."""
        # Create tool_execution record
        tool_exec = models.ToolExecution(
            scan_id=self.scan_id,
            tool_name=tool,
            phase=phase,
            status="RUNNING",
            started_at=datetime.now(),
            command=" ".join(str(c) for c in command)
        )
        self.db.add(tool_exec)
        self.db.commit()
        self.tool_exec_ids[tool] = tool_exec.id
        self.line_nums[tool] = 0

        # Broadcast WebSocket
        await self.scan_manager.broadcast(self.scan_id, {
            "type": "tool_start",
            "tool": tool,
            "phase": phase,
            "timestamp": datetime.now().isoformat()
        })

    async def on_tool_output(self, tool: str, line: str, line_num: int):
        """Called for each output line from a tool."""
        # Store output line (batched writes for performance)
        tool_exec_id = self.tool_exec_ids.get(tool)
        if tool_exec_id:
            output = models.ToolOutput(
                tool_execution_id=tool_exec_id,
                line_num=line_num,
                line_text=line,
                timestamp=datetime.now()
            )
            self.db.add(output)

            # Commit every 50 lines for performance
            if line_num % 50 == 0:
                self.db.commit()

        # Broadcast WebSocket (real-time)
        await self.scan_manager.broadcast(self.scan_id, {
            "type": "tool_output",
            "tool": tool,
            "line": line,
            "line_num": line_num,
            "timestamp": datetime.now().isoformat()
        })

    async def on_tool_complete(self, tool: str, result):
        """Called when a tool completes (success or error)."""
        # Commit any pending outputs
        self.db.commit()

        # Update tool_execution record
        tool_exec_id = self.tool_exec_ids.get(tool)
        if tool_exec_id:
            tool_exec = self.db.query(models.ToolExecution).get(tool_exec_id)
            if tool_exec:
                tool_exec.status = result.status
                tool_exec.completed_at = datetime.now()
                tool_exec.duration = result.duration
                tool_exec.returncode = result.returncode
                tool_exec.output_file = result.output_file
                self.db.commit()

        # Broadcast WebSocket
        await self.scan_manager.broadcast(self.scan_id, {
            "type": "tool_complete",
            "tool": tool,
            "status": result.status,
            "duration": result.duration,
            "returncode": result.returncode
        })

    async def on_phase_complete(self, phase: int, feed: dict):
        """Called after a phase completes and feed is collected."""
        # Parse and persist structured data
        if phase == 0:  # nmap completed
            self._persist_nmap_data(feed)
        elif phase == 1:  # amass + httpx completed
            self._persist_urls(feed)
        elif phase == 2:  # nuclei completed
            self._persist_vulnerabilities(feed)

        # Update scan feed_data
        scan = self.db.query(models.Scan).get(self.scan_id)
        if scan:
            scan.feed_data = json.dumps(feed)
            self.db.commit()

        # Broadcast WebSocket
        feed_summary = {
            "hosts": len(feed.get("hosts", [])),
            "smb_hosts": len(feed.get("smb_hosts", [])),
            "urls": len(feed.get("urls", [])),
            "findings": len(feed.get("findings", []))
        }
        await self.scan_manager.broadcast(self.scan_id, {
            "type": "phase_complete",
            "phase": phase,
            "feed_summary": feed_summary
        })

    def _persist_nmap_data(self, feed: dict):
        """Parse nmap feed and create Host + Port records."""
        nmap_data = feed.get("nmap", {})
        for ip, data in nmap_data.items():
            # Create host record
            host = models.Host(
                scan_id=self.scan_id,
                ip=ip,
                hostname=data.get("hostname"),
                os_guess=data.get("os_guess"),
                is_windows=ip in feed.get("windows_hosts", []),
                is_dc=ip in feed.get("dc_hosts", []),
                services_json=json.dumps(data.get("services", {})),
                products_json=json.dumps(data.get("products", {}))
            )
            self.db.add(host)
            self.db.flush()

            # Create port records
            for port_num in data.get("ports", []):
                port = models.Port(
                    host_id=host.id,
                    port_num=port_num,
                    protocol="tcp",
                    state="open",
                    service=data.get("services", {}).get(str(port_num)),
                    product=data.get("products", {}).get(str(port_num))
                )
                self.db.add(port)

        self.db.commit()

    def _persist_urls(self, feed: dict):
        """Parse httpx feed and create URL records."""
        # Get httpx results from feed
        urls_data = feed.get("urls", [])
        
        # Try to read httpx.json from output_dir if available
        scan = self.db.query(models.Scan).get(self.scan_id)
        if scan and scan.output_dir:
            httpx_file = Path(scan.output_dir) / "httpx.json"
            if httpx_file.exists():
                try:
                    with open(httpx_file, "r") as f:
                        for line in f:
                            httpx_data = json.loads(line.strip())
                            url = models.URL(
                                scan_id=self.scan_id,
                                url=httpx_data.get("url"),
                                status_code=httpx_data.get("status_code"),
                                title=httpx_data.get("title"),
                                is_live=True,
                                metadata_json=json.dumps(httpx_data)
                            )
                            self.db.add(url)
                except Exception as e:
                    print(f"Warning: Failed to parse httpx.json: {e}")

        # Also create records for URLs in feed (if not from file)
        for url_str in urls_data:
            # Check if URL already exists
            existing = self.db.query(models.URL).filter(
                models.URL.scan_id == self.scan_id,
                models.URL.url == url_str
            ).first()
            if not existing:
                url = models.URL(
                    scan_id=self.scan_id,
                    url=url_str,
                    is_live=True
                )
                self.db.add(url)

        self.db.commit()

    def _persist_vulnerabilities(self, feed: dict):
        """Parse nuclei feed and create Vulnerability records."""
        findings = feed.get("findings", [])
        for finding in findings:
            vuln = models.Vulnerability(
                scan_id=self.scan_id,
                cve_id=finding.get("cve"),
                host=finding.get("host"),
                template_id=finding.get("template_id"),
                severity=finding.get("severity"),
                msf_module=finding.get("msf_module"),
                msf_payload=finding.get("msf_payload"),
                metadata_json=json.dumps(finding)
            )
            self.db.add(vuln)
        self.db.commit()
