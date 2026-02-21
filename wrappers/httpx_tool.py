import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetType


class HttpxTool(BaseTool):
    name = "httpx"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target

        # Phase 1 runs in parallel with amass, after nmap.
        # Feed may be empty here — fall back to probing target directly.
        nmap_web_urls = self.feed.get("urls", [])
        amass_hosts   = self.feed.get("hosts", [])

        if nmap_web_urls:
            url_file = Path(tempfile.mktemp(prefix="crushgear_httpx_", suffix=".txt"))
            url_file.write_text("\n".join(nmap_web_urls) + "\n")
            target_args = ["-l", str(url_file)]

        elif amass_hosts:
            lines = []
            for h in amass_hosts:
                lines += [f"http://{h}", f"https://{h}"]
            url_file = Path(tempfile.mktemp(prefix="crushgear_httpx_", suffix=".txt"))
            url_file.write_text("\n".join(lines) + "\n")
            target_args = ["-l", str(url_file)]

        elif t.type == TargetType.CIDR:
            # Probe each host on common web ports
            lines = []
            for ip in t.hosts[:254]:
                lines += [
                    f"http://{ip}",
                    f"https://{ip}",
                    f"http://{ip}:8080",
                    f"http://{ip}:8443",
                ]
            url_file = Path(tempfile.mktemp(prefix="crushgear_httpx_", suffix=".txt"))
            url_file.write_text("\n".join(lines) + "\n")
            target_args = ["-l", str(url_file)]

        elif t.type == TargetType.URL:
            target_args = ["-u", t.url]

        else:
            # IP or DOMAIN — probe http, https, and common alt-ports
            host = t.host
            lines = [
                f"http://{host}",
                f"https://{host}",
                f"http://{host}:8080",
                f"http://{host}:8443",
                f"http://{host}:8888",
                f"http://{host}:9090",
            ]
            url_file = Path(tempfile.mktemp(prefix="crushgear_httpx_", suffix=".txt"))
            url_file.write_text("\n".join(lines) + "\n")
            target_args = ["-l", str(url_file)]

        return [
            self.binary,
            *target_args,

            # ── Probes ───────────────────────────────────────────────
            # NOTE: httpx v1.2+ renamed flags:
            #   -threads      → -c  (old flag removed in newer builds)
            #   -status-code  → -sc
            #   -tech-detect  → -td
            #   -web-server   → -server
            #   -content-length→ -cl
            #   -follow-redirects → -fr
            #   -json / -jsonl → -j  (stable alias)
            "-title",
            "-sc",          # status code
            "-td",          # tech detection (Wappalyzer)
            "-server",      # web server banner
            "-cl",          # content length
            "-ip",          # resolved IP
            "-cdn",         # CDN detection
            "-fr",          # follow redirects
            "-maxr", "5",   # max redirects

            # ── Output ───────────────────────────────────────────────
            "-j",           # JSONL output (stable across versions)
            "-silent",

            # ── Performance ─────────────────────────────────────────
            "-c",      "50",    # concurrency (-threads is DEPRECATED)
            "-timeout", "10",
            "-retries", "2",
            "-random-agent",
        ]
