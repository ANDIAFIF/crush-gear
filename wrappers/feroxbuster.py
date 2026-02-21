import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetInfo, TargetType

# Wordlist search order: prefer smaller/faster lists first.
# raft-small (~18k) or common (~4.7k) are realistic for automated scans.
# The medium wordlist (220k) is too large for automated multi-target runs.
WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",     # ~18k
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",    # ~30k
    "/opt/homebrew/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",                     # ~4.7k
    "/usr/share/wordlists/dirb/common.txt",                                     # ~4.6k
    "/opt/homebrew/share/dirb/wordlists/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    # dirbuster medium is last resort — 220k entries, very slow
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]

# Hard cap feroxbuster scan time from inside feroxbuster itself.
# This is separate from the runner timeout and is more reliable because
# feroxbuster can clean up gracefully (vs SIGKILL from asyncio timeout).
FEROX_TIME_LIMIT = "8m"


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

        # Common flags for all invocations
        # --no-state          skip saving resume state (cleaner for automation)
        # --depth 2           directory recursion depth
        # --threads 10        concurrent requests (low enough to avoid WAF/rate-limit)
        # --timeout 7         per-request timeout in seconds
        # --time-limit Xm     hard stop the entire feroxbuster process after X minutes
        #                     → prevents the 1200s+ hang we saw when wordlist is large
        # --auto-tune         automatically reduce rate on 429/503 responses
        # --filter-status ... exclude common non-content codes to reduce noise
        common_flags = [
            *wordlist_args,
            "--no-state",
            "--depth",       "2",
            "--threads",     "10",
            "--timeout",     "7",
            "--time-limit",  FEROX_TIME_LIMIT,
            "--auto-tune",
        ]

        # Get live URLs from httpx feed (most reliable targets)
        httpx_urls = self.feed.get("urls", [])

        if httpx_urls:
            # Use --input-file so stdin remains a TTY (pipe breaks Scan Mgmt Menu)
            url_file = Path(tempfile.mktemp(prefix="crushgear_ferox_", suffix=".txt"))
            url_file.write_text("\n".join(httpx_urls[:20]) + "\n")  # cap at 20
            return [
                self.binary,
                "--input-file", str(url_file),
                *common_flags,
            ]

        # Fallback: single URL from original target
        if t.type == TargetType.URL:
            url = t.url
        elif t.type == TargetType.CIDR:
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

