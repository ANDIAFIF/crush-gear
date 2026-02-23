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
                    f"http://{ip}:8888",
                    f"http://{ip}:9090",
                    f"http://{ip}:3000",
                    f"http://{ip}:5000",
                ]
            url_file = Path(tempfile.mktemp(prefix="crushgear_httpx_", suffix=".txt"))
            url_file.write_text("\n".join(lines) + "\n")
            target_args = ["-l", str(url_file)]

        elif t.type == TargetType.URL:
            url_file = Path(tempfile.mktemp(prefix="crushgear_httpx_", suffix=".txt"))
            url_file.write_text(t.url + "\n")
            target_args = ["-l", str(url_file)]

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
                f"http://{host}:3000",
                f"http://{host}:5000",
                f"http://{host}:10000",
            ]
            url_file = Path(tempfile.mktemp(prefix="crushgear_httpx_", suffix=".txt"))
            url_file.write_text("\n".join(lines) + "\n")
            target_args = ["-l", str(url_file)]

        return [
            self.binary,
            *target_args,

            # ── Service Discovery ────────────────────────────────────
            "-title",            # page title
            "-sc",               # HTTP status code
            "-td",               # tech detection (Wappalyzer fingerprint)
            "-server",           # web server banner (Apache, nginx, IIS, etc.)
            "-cl",               # content length
            "-ct",               # content type
            "-ip",               # resolved IP address
            "-cdn",              # CDN detection (Cloudflare, Akamai, etc.)
            "-cname",            # CNAME record (useful for subdomain takeover)
            "-probe",            # HTTP/HTTPS probe status for each URL
            "-favicon",          # favicon MMH3 hash (identifies tech/framework)
            "-hash", "md5",      # page body MD5 hash (detect duplicates)
            "-jarm",             # JARM TLS fingerprint (identify TLS stack)
            "-tls-probe",        # probe HTTPS even if 443 not in URL

            # ── Request handling ─────────────────────────────────────
            "-fr",               # follow HTTP redirects
            "-maxr", "5",        # max redirects to follow
            "-random-agent",     # rotate user-agent per request

            # ── Output ───────────────────────────────────────────────
            "-j",                # JSONL output (one JSON object per line)
            "-silent",           # suppress banner/info messages

            # ── Performance ─────────────────────────────────────────
            "-threads", "50",    # concurrency (threads)
            "-timeout", "10",    # per-request timeout in seconds
            "-retries", "2",     # retry failed requests
        ]
