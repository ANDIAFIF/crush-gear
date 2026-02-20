import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetInfo, TargetType


class NucleiTool(BaseTool):
    name = "nuclei"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target

        # Priority: httpx live URLs > amass hosts > nmap web URLs > original target
        httpx_urls = self.feed.get("urls", [])
        amass_hosts = self.feed.get("hosts", [])

        if httpx_urls:
            url_file = Path(tempfile.mktemp(prefix="crushgear_nuclei_", suffix=".txt"))
            url_file.write_text("\n".join(httpx_urls) + "\n")
            target_args = ["-list", str(url_file)]
        elif amass_hosts:
            # Build URLs from discovered hosts
            urls = []
            for h in amass_hosts:
                urls.append(f"http://{h}")
                urls.append(f"https://{h}")
            url_file = Path(tempfile.mktemp(prefix="crushgear_nuclei_", suffix=".txt"))
            url_file.write_text("\n".join(urls) + "\n")
            target_args = ["-list", str(url_file)]
        elif t.type == TargetType.CIDR:
            urls = [f"http://{ip}" for ip in t.hosts[:254]]
            url_file = Path(tempfile.mktemp(prefix="crushgear_nuclei_", suffix=".txt"))
            url_file.write_text("\n".join(urls) + "\n")
            target_args = ["-list", str(url_file)]
        elif t.type == TargetType.URL:
            target_args = ["-u", t.url]
        else:
            target_args = ["-u", f"http://{t.host}", "-u", f"https://{t.host}"]

        return [
            self.binary,
            *target_args,
            "-severity", "critical,high,medium",
            "-tags",     "cve,rce,sqli,xss,ssrf,lfi,xxe,auth-bypass,default-login",
            "-jsonl",
            "-silent",
            "-c",        "50",   # concurrent targets
        ]
