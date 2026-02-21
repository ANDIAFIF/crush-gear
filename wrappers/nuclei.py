import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetType

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

        # ── Build web targets ────────────────────────────────────────
        web_targets: list[str] = []

        if httpx_urls:
            web_targets = httpx_urls
        elif amass_hosts:
            for h in amass_hosts:
                web_targets.append(f"http://{h}")
                web_targets.append(f"https://{h}")
        elif t.type == TargetType.CIDR:
            for ip in t.hosts[:254]:
                web_targets.append(f"http://{ip}")
                web_targets.append(f"https://{ip}")
        elif t.type == TargetType.URL:
            web_targets = [t.url]
        else:
            web_targets = [f"http://{t.host}", f"https://{t.host}"]

        # ── Build network targets from nmap open ports ───────────────
        net_targets = _build_network_targets(nmap_data)

        # Merge: web first, then network-level ip:port
        all_targets = web_targets + net_targets

        target_file = Path(tempfile.mktemp(prefix="crushgear_nuclei_", suffix=".txt"))
        target_file.write_text("\n".join(all_targets) + "\n")

        return [
            self.binary,
            "-list",        str(target_file),

            # ── Template selection ───────────────────────────────────
            # -as: Wappalyzer tech detection → auto-selects matching
            #      templates (WordPress → wp-plugin templates, etc.)
            #      Works additively with -tags (union of both sets).
            "-as",

            # -etags: exclude destructive / noisy categories explicitly.
            # .nuclei-ignore excludes these by default but explicit is safer.
            "-etags",       "dos,bruteforce,fuzz",

            # Severity: include low (misconfigs/exposures are often low)
            "-severity",    "critical,high,medium,low",

            # All validated tags (see constants above)
            "-tags",        ALL_TAGS,

            # ── Output ──────────────────────────────────────────────
            "-jsonl",                # one JSON per line (required by feed parser)
            "-silent",               # suppress banner/info messages
            "-ot",                   # omit base64 template blob (~40% smaller output)

            # ── Progress ─────────────────────────────────────────────
            "-stats",                # show live scan statistics
            "-stats-interval", "30", # update every 30s

            # ── Performance ─────────────────────────────────────────
            "-c",              "30", # concurrent templates
            "-bulk-size",      "25", # targets per template batch
            "-rate-limit",    "150", # max requests/sec
            "-ss",    "host-spray",  # run all templates per host (better mem mgmt)

            # ── Reliability ─────────────────────────────────────────
            "-retries",         "2", # retry failed requests
            "-timeout",        "10", # seconds per request
            "-max-host-error", "30", # skip host after N errors

            # ── Accuracy ────────────────────────────────────────────
            "-fr",                   # follow HTTP redirects
            "-duc",                  # disable auto update-check during scan
        ]
