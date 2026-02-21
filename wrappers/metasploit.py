import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetType
from core.feed import build_msf_rc


class MetasploitTool(BaseTool):
    name = "metasploit"
    _rc_path: str = ""
    _post_rc_path: str = ""

    def __init__(self, *args, lhost: str = "0.0.0.0", lport: int = 4444, **kwargs):
        super().__init__(*args, **kwargs)
        self.lhost = lhost
        self.lport = lport

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target
        rhosts = t.cidr if t.type == TargetType.CIDR else t.host

        nmap_data = self.feed.get("nmap", {})
        nuclei_findings = self.feed.get("findings", [])

        extra_cve_map = self.feed.get("extra_cve_map", {})

        rc_content, post_rc_path = build_msf_rc(
            rhosts=rhosts,
            nuclei_findings=nuclei_findings,
            nmap_data=nmap_data if nmap_data else None,
            lhost=self.lhost,
            lport=self.lport,
            extra_cve_map=extra_cve_map if extra_cve_map else None,
            username=self.username,
            password=self.password,
        )

        # post_rc_path is already written by build_msf_rc
        self._post_rc_path = post_rc_path

        # Write main RC
        import os
        rc_fd, rc_path = tempfile.mkstemp(prefix="crushgear_msf_", suffix=".rc")
        os.close(rc_fd)
        rc_file = Path(rc_path)
        rc_file.write_text(rc_content)
        self._rc_path = str(rc_file)

        return [self.binary, "-q", "-r", str(rc_file)]
