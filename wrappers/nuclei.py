import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetType


def _find_template_dir() -> str:
    """
    Detect nuclei templates directory.
    Returns the first valid path with >100 .yaml files, or empty string.
    Covers nuclei v3 default paths across distributions.
    """
    candidates = [
        Path.home() / ".local" / "nuclei-templates",          # nuclei v3 default (most common)
        Path.home() / ".local" / "share" / "nuclei-templates", # XDG compliant path
        Path.home() / "nuclei-templates",                      # older / manual install
        Path.home() / ".config" / "nuclei" / "templates",      # some v3 variants
        Path("/usr/share/nuclei-templates"),                    # system-wide install
        Path("/opt/nuclei-templates"),                          # custom install
    ]
    best: tuple[str, int] = ("", 0)
    for d in candidates:
        if d.exists() and d.is_dir():
            count = sum(1 for _ in d.rglob("*.yaml"))
            if count > best[1]:
                best = (str(d), count)
    return best[0]

# ─────────────────────────────────────────────────────────────────────────────
# Tags validated against nuclei-templates TEMPLATES-STATS.md (Feb 2026)
# Reference: https://github.com/projectdiscovery/nuclei-templates
# ─────────────────────────────────────────────────────────────────────────────

# Core vulnerability classes
VULN_TAGS = ",".join([
    "cve",              # 3960 templates — all CVE-assigned findings
    "kev",              # 480  — CISA Known Exploited Vulnerabilities (highest priority)
    "vkev",             # 1644 — VulnCheck KEV (broader KEV list)
    "vuln",             # 6572 — general vulnerability (largest single tag)
    "rce",              # 898  — Remote Code Execution
    "lfi",              # 817  — Local File Inclusion
    "sqli",             # 542  — SQL Injection
    "xss",              # 1380 — Cross-Site Scripting
    "ssrf",             # 173  — Server-Side Request Forgery
    "xxe",              # 46   — XML External Entity
    "ssti",             # 50   — Server-Side Template Injection
    "auth-bypass",      # 248  — Authentication Bypass
    "injection",        # 51   — Generic injection
    "deserialization",  # 69   — Java/PHP deserialization
    "oast",             # 334  — Out-of-band (interactsh-based detection)
    "file-upload",      # 101  — Unrestricted file upload
    "redirect",         # 170  — Open redirect
    "traversal",        # 58   — Path traversal
    "crlf",             # 14   — CRLF injection
    "log4j",            # 48   — Log4Shell variants
])

# Discovery & exposure
DISCOVERY_TAGS = ",".join([
    "exposure",         # 1366 — sensitive data/file exposure
    "misconfig",        # 933  — misconfiguration
    "panel",            # 1400 — admin/login panels
    "default-login",    # 300  — default credentials
    "unauth",           # 540  — unauthenticated access
    "token-spray",      # 247  — API token enumeration
    "takeover",         # 82   — subdomain takeover
    "top-200",          # 235  — community top-priority templates
    "api",              # 55   — API endpoint detection
    "disclosure",       # 152  — info disclosure
    "debug",            # 97   — debug endpoints left exposed
    "backup",           # 31   — backup files
    "config",           # 313  — config file exposure
    "keys",             # 158  — API key/secret exposure
    "cloud",            # 715  — cloud misconfigs (AWS/GCP/Azure)
    "devops",           # 752  — CI/CD, Docker, K8s
])

# Network-level service tags (used with ip:port targets from nmap)
# NOTE: 'mssql' and 'elasticsearch' are NOT real tags in templates-stats.
#       Use 'microsoft'/'sql' and 'elastic' instead.
NETWORK_TAGS = ",".join([
    "network",          # 374  — network protocol templates
    "tcp",              # 269  — raw TCP service checks
    "ftp",              # 136  — FTP checks
    "ssh",              # 54   — SSH checks
    "smtp",             # 18   — SMTP checks
    "smb",              # 18   — SMB/Samba checks
    "dns",              # 44   — DNS misconfiguration
    "ssl",              # 44   — SSL/TLS checks
    "mysql",            # 20   — MySQL checks
    "redis",            # 20   — Redis unauthenticated / default config
    "mongodb",          # 14   — MongoDB open access
    "postgresql",       # 41   — PostgreSQL checks
    "elastic",          # 11   — Elasticsearch (correct tag, not 'elasticsearch')
    "rdp",              # RDP detection templates
    "vnc",              # VNC checks
    "snmp",             # SNMP enumeration
    "ldap",             # 12   — LDAP checks
    "iot",              # 203  — IoT / embedded device checks
    "router",           # 135  — router vulnerabilities
])

# Combine all tag groups (deduplication not needed — nuclei handles it)
ALL_TAGS = ",".join([VULN_TAGS, DISCOVERY_TAGS, NETWORK_TAGS])

# Network services to scan: map port → protocol label
NETWORK_PORTS = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    110:   "pop3",
    143:   "imap",
    161:   "snmp",
    389:   "ldap",
    445:   "smb",
    1433:  "mssql",
    1521:  "oracle",
    3306:  "mysql",
    3389:  "rdp",
    5432:  "postgres",
    5900:  "vnc",
    6379:  "redis",
    8009:  "ajp",
    9200:  "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


def _build_network_targets(nmap_data: dict) -> list[str]:
    """
    Build ip:port targets for network-level nuclei scanning
    based on open ports discovered by nmap.
    """
    targets = []
    for ip, info in nmap_data.items():
        for port in info.get("ports", []):
            if port in NETWORK_PORTS:
                targets.append(f"{ip}:{port}")
    return targets


class NucleiTool(BaseTool):
    name = "nuclei"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target
        httpx_urls  = self.feed.get("urls", [])
        amass_hosts = self.feed.get("hosts", [])
        nmap_data   = self.feed.get("nmap", {})

        # ── Web targets ──────────────────────────────────────────────
        # Source priority: httpx live URLs → amass hosts → raw IPs from target
        web_targets: list[str] = []

        if httpx_urls:
            # httpx already confirmed these URLs are alive — best source
            web_targets = httpx_urls[:100]
        elif amass_hosts:
            for h in amass_hosts[:50]:
                web_targets += [f"http://{h}", f"https://{h}"]
        elif t.type == TargetType.URL:
            web_targets = [t.url]
        elif t.type == TargetType.CIDR:
            # Probe common web ports on each host in the subnet
            for ip in t.hosts[:254]:
                web_targets += [
                    f"http://{ip}",
                    f"https://{ip}",
                    f"http://{ip}:8080",
                    f"https://{ip}:8443",
                    f"http://{ip}:8888",
                    f"http://{ip}:9090",
                ]
        else:
            # Single IP or domain — probe common web ports
            h = t.host
            web_targets = [
                f"http://{h}",
                f"https://{h}",
                f"http://{h}:8080",
                f"https://{h}:8443",
                f"http://{h}:8888",
                f"http://{h}:9090",
            ]

        # ── Network targets (ip:port) ────────────────────────────────
        # Source priority: nmap-confirmed open ports → fallback common ports.
        # ip:port format triggers nuclei NETWORK templates (SMB, RDP, SSH, etc.)
        # This is what makes nuclei work for non-web infrastructure scans.
        net_targets: list[str] = []

        if nmap_data:
            # Best: use only ports nmap confirmed open (faster, no wasted scans)
            net_targets = _build_network_targets(nmap_data)
        else:
            # Fallback: if nmap hasn't run yet, probe ALL common network ports
            # on every host so nuclei still runs network templates automatically
            hosts: list[str] = []
            if t.type == TargetType.CIDR:
                hosts = [str(ip) for ip in t.hosts[:254]]
            elif t.type != TargetType.URL:
                hosts = [t.host]

            for h in hosts:
                for port in NETWORK_PORTS:          # NETWORK_PORTS is a dict: port→label
                    net_targets.append(f"{h}:{port}")

        # Merge: web targets first, then network ip:port targets
        all_targets = web_targets + net_targets
        target_file = Path(tempfile.mktemp(prefix="crushgear_nuclei_", suffix=".txt"))
        target_file.write_text("\n".join(all_targets) + "\n")

        # ── Template directory ───────────────────────────────────────
        # CRITICAL: -t must come FIRST before -tags / -etags so nuclei knows
        # WHERE to load templates from before applying tag filters.
        template_dir = _find_template_dir()

        cmd = [self.binary, "-list", str(target_file)]

        # ── Template directory (CRITICAL — must be explicit) ─────────
        # WARNING: flag -as (auto-scan) overrides -t and relies on Wappalyzer
        # tech-detection. If the target has WAF/firewall (very common), Wappalyzer
        # gets blocked → 0 technology detected → 0 templates loaded (templates:0 bug).
        # FIX: Never use -as. Always load templates via -t + -tags explicitly.
        if template_dir:
            cmd += ["-t", template_dir]
        # If no explicit template dir found, nuclei will use its own default.
        # Either way, -tags below guarantees the right templates are selected.

        cmd += [
            # ── Template selection ────────────────────────────────────
            # -tags: select templates by tag — always works regardless of tech detection.
            # -etags: exclude destructive tags (dos, bruteforce, fuzz).
            # -severity: skip informational to reduce noise.
            "-tags",        ALL_TAGS,
            "-etags",       "dos,bruteforce,fuzz",
            "-severity",    "critical,high,medium,low",

            # ── Output ───────────────────────────────────────────────
            "-jsonl",                # one JSON object per finding
            "-silent",               # suppress nuclei banner/logo

            # ── Progress ─────────────────────────────────────────────
            "-stats",
            "-stats-interval", "30",

            # ── Performance ──────────────────────────────────────────
            "-c",              "25", # concurrent template execution
            "-bulk-size",      "25", # targets per batch
            "-rate-limit",    "100", # req/sec (conservative for external targets)
            "-ss",    "host-spray",  # all templates per host (memory efficient)

            # ── Reliability ───────────────────────────────────────────
            "-retries",         "2",
            "-timeout",        "10", # seconds per request
            "-max-host-error", "30", # skip host after 30 consecutive errors

            # ── Misc ─────────────────────────────────────────────────
            "-fr",                   # follow HTTP redirects
            "-duc",                  # disable update-check during scan
        ]

        return cmd
