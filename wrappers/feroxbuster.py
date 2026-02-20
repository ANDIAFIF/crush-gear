import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetInfo, TargetType

# Wordlist search order: seclists > dirbuster > dirb > bundled
WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/opt/homebrew/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/opt/homebrew/share/dirb/wordlists/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
]


def find_wordlist() -> str:
    """Find the best available wordlist, fallback to bundled one."""
    for candidate in WORDLIST_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    # Fallback: bundled wordlist in project
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

        # Get live URLs from httpx feed (most reliable targets)
        httpx_urls = self.feed.get("urls", [])

        if httpx_urls:
            # feroxbuster supports --stdin; pipe all live URLs
            url_file = Path(tempfile.mktemp(prefix="crushgear_ferox_", suffix=".txt"))
            url_file.write_text("\n".join(httpx_urls[:20]) + "\n")  # cap at 20 URLs
            return [
                "bash", "-c",
                f"cat {url_file} | {self.binary} --stdin "
                f"{' '.join(wordlist_args)} "
                f"--silent --no-state --depth 2 --threads 10",
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
            "--url",     url,
            *wordlist_args,
            "--silent",
            "--no-state",
            "--depth",   "2",
            "--threads", "10",
        ]

