import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetType

# Wordlist search order: prefer smaller/faster lists first.
# raft-small (~18k) gives the best speed/coverage ratio.
# The medium wordlist (220k) is too large for automated multi-target runs.
WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",       # ~18k best
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",      # ~30k
    "/opt/homebrew/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",                       # ~4.7k
    "/usr/share/wordlists/dirb/common.txt",                                       # ~4.6k
    "/opt/homebrew/share/dirb/wordlists/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",               # ~220k last resort
]

# Hard cap feroxbuster scan time from inside feroxbuster itself.
# Separate from runner timeout — feroxbuster exits gracefully vs SIGKILL.
FEROX_TIME_LIMIT = "10m"

# File extensions to probe alongside directories.
# Covers common web stacks: PHP, ASP.NET, Java, Node, Python, plus backup/config files.
EXTENSIONS = (
    "php,asp,aspx,jsp,jspx,"        # server-side scripts
    "html,htm,xhtml,"               # static pages
    "js,json,xml,yaml,yml,"         # data/config files
    "txt,md,csv,"                   # text files
    "bak,old,orig,backup,"          # backup files
    "config,conf,cfg,ini,"          # configuration files
    "env,env.bak,.env.local,"       # environment files
    "log,logs,"                     # log files
    "sql,db,"                       # database dumps
    "zip,tar,gz,7z,"                # archives (often contain source/secrets)
    "key,pem,crt,pfx,p12"          # certificate / key files
)

# HTTP status codes that indicate non-content (exclude to reduce noise)
FILTER_CODES = "404,400,410,503,502"


def find_wordlist() -> str:
    """Find the best available wordlist, fallback to bundled one."""
    for candidate in WORDLIST_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    bundled = Path(__file__).parent.parent / "wordlists" / "common.txt"
    if bundled.exists():
        return str(bundled)
    return ""


class FeroxbusterTool(BaseTool):
    name = "feroxbuster"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target
        wordlist = find_wordlist()
        wordlist_args = ["-w", wordlist] if wordlist else []

        # ── Common flags ─────────────────────────────────────────────
        # --no-state       : skip resume state file (cleaner for automation)
        # --depth 3        : recurse 3 levels deep (realistic pentest depth)
        # --threads 25     : concurrent requests (balanced for LAN)
        # --timeout 7      : per-request timeout (seconds)
        # --time-limit 10m : hard stop after N minutes (prevents infinite runs)
        # --auto-tune      : auto-reduce rate on 429/503/rate-limit responses
        # --filter-status  : exclude noise status codes
        # --extensions     : file extensions to probe (critical for real web enum)
        # --random-agent   : rotate user-agent per request (evade simple WAF rules)
        # --redirects      : follow HTTP redirects (finds hidden paths)
        # --insecure       : ignore TLS certificate errors (self-signed certs common in labs)
        # --scan-limit 4   : max concurrent directory scans (prevent memory explosion)
        # --rate-limit 200 : max requests/sec (prevents overloading target)
        common_flags = [
            *wordlist_args,
            "--no-state",
            "--depth",          "3",
            "--threads",        "25",
            "--timeout",        "7",
            "--time-limit",     FEROX_TIME_LIMIT,
            "--auto-tune",
            "--filter-status",  FILTER_CODES,
            "--extensions",     EXTENSIONS,
            "--random-agent",
            "--redirects",
            "--insecure",
            "--scan-limit",     "4",
            "--rate-limit",     "200",
        ]

        # Get live URLs from httpx feed (most reliable targets for web enum)
        httpx_urls = self.feed.get("urls", [])

        if httpx_urls:
            # Use --input-file so stdin remains a TTY (pipe breaks Scan Mgmt Menu)
            url_file = Path(tempfile.mktemp(prefix="crushgear_ferox_", suffix=".txt"))
            url_file.write_text("\n".join(httpx_urls[:30]) + "\n")   # cap at 30 targets
            return [
                self.binary,
                "--input-file", str(url_file),
                *common_flags,
            ]

        # Fallback: single URL from original target
        if t.type == TargetType.URL:
            url = t.url
        elif t.type == TargetType.CIDR:
            # Pick first live host as fallback (httpx should have given us URLs)
            url = f"http://{t.hosts[0]}" if t.hosts else None
        else:
            url = f"http://{t.host}"

        if not url:
            return []

        return [
            self.binary,
            "--url", url,
            *common_flags,
        ]
