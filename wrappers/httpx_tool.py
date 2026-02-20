import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetInfo, TargetType


class HttpxTool(BaseTool):
    name = "httpx"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target

        # Prefer nmap-discovered web URLs, then amass hosts, then original target
        nmap_web_urls = self.feed.get("urls", [])
        amass_hosts = self.feed.get("hosts", [])

        if nmap_web_urls:
            # Write to temp file for -list
            url_file = Path(tempfile.mktemp(prefix="crushgear_httpx_", suffix=".txt"))
            url_file.write_text("\n".join(nmap_web_urls) + "\n")
            target_args = ["-list", str(url_file)]
        elif amass_hosts:
            url_file = Path(tempfile.mktemp(prefix="crushgear_httpx_", suffix=".txt"))
            # Add http/https for each discovered host
            urls = []
            for h in amass_hosts:
                urls.append(f"http://{h}")
                urls.append(f"https://{h}")
            url_file.write_text("\n".join(urls) + "\n")
            target_args = ["-list", str(url_file)]
        elif t.type == TargetType.CIDR:
            urls = [f"http://{ip}" for ip in t.hosts[:254]]
            url_file = Path(tempfile.mktemp(prefix="crushgear_httpx_", suffix=".txt"))
            url_file.write_text("\n".join(urls) + "\n")
            target_args = ["-list", str(url_file)]
        elif t.type == TargetType.URL:
            target_args = ["-u", t.url]
        else:
            target_args = ["-u", f"http://{t.host}", "-u", f"https://{t.host}"]

        return [
            self.binary,
            *target_args,
            "-title",
            "-status-code",
            "-tech-detect",
            "-web-server",
            "-content-length",
            "-follow-redirects",
            "-json",
            "-silent",
            "-threads", "50",
        ]
