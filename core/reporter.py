import re as _re
import time
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

TOOL_COLORS = {
    "netexec":     "bright_green",
    "smbmap":      "cyan",
    "amass":       "bright_blue",
    "httpx":       "bright_yellow",
    "nuclei":      "bright_red",
    "feroxbuster": "magenta",
    "metasploit":  "bright_white",
}

STATUS_COLORS = {
    "RUNNING": "yellow",
    "DONE":    "green",
    "ERROR":   "red",
    "SKIPPED": "dim",
}


def print_banner():
    banner = """
  ██████╗██████╗ ██╗   ██╗███████╗██╗  ██╗ ██████╗ ███████╗ █████╗ ██████╗
 ██╔════╝██╔══██╗██║   ██║██╔════╝██║  ██║██╔════╝ ██╔════╝██╔══██╗██╔══██╗
 ██║     ██████╔╝██║   ██║███████╗███████║██║  ███╗█████╗  ███████║██████╔╝
 ██║     ██╔══██╗██║   ██║╚════██║██╔══██║██║   ██║██╔══╝  ██╔══██║██╔══██╗
 ╚██████╗██║  ██║╚██████╔╝███████║██║  ██║╚██████╔╝███████╗██║  ██║██║  ██║
  ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
    """
    console.print(Panel(
        Text(banner, style="bold bright_red"),
        subtitle="[dim]All-in-One Pentest Automation[/dim]",
        border_style="red",
        padding=(0, 2),
    ))


def print_tool_line(tool_name: str, line: str):
    color = TOOL_COLORS.get(tool_name, "white")
    prefix = Text(f"[{tool_name.upper():>12}] ", style=f"bold {color}")
    content = Text(line)
    console.print(prefix + content)


def print_summary(results: list[dict]):
    table = Table(
        title="[bold]Scan Summary[/bold]",
        border_style="bright_white",
        show_lines=True,
    )
    table.add_column("Tool", style="bold", min_width=14)
    table.add_column("Status", min_width=8)
    table.add_column("Duration", justify="right", min_width=10)
    table.add_column("Output File", style="dim")

    for r in results:
        status = r.get("status", "UNKNOWN")
        color = STATUS_COLORS.get(status, "white")
        duration = r.get("duration", 0.0)
        table.add_row(
            f"[{TOOL_COLORS.get(r['tool'], 'white')}]{r['tool']}[/]",
            f"[{color}]{status}[/]",
            f"{duration:.1f}s",
            r.get("output_file", "-"),
        )

    console.print()
    console.print(table)


CRED_PATTERNS = [
    _re.compile(r'\[\+\]', _re.IGNORECASE),
    _re.compile(r'credential was successful', _re.IGNORECASE),
    _re.compile(r'Login Successful', _re.IGNORECASE),
    _re.compile(r'PWNED!', _re.IGNORECASE),
    _re.compile(r'Success:\s+\S+', _re.IGNORECASE),
]


def parse_credentials(output_dir: Path) -> list[dict]:
    """Parse successful credentials/logins from all tool output files."""
    found = []
    scan_files = {
        "metasploit": output_dir / "metasploit.txt",
        "netexec":    output_dir / "netexec.txt",
        "smbmap":     output_dir / "smbmap.txt",
        "nmap":       output_dir / "nmap.txt",
    }
    for tool, path in scan_files.items():
        if not path.exists():
            continue
        for line in path.read_text(errors="replace").splitlines():
            for pat in CRED_PATTERNS:
                if pat.search(line):
                    found.append({"tool": tool, "line": line.strip()})
                    break
    return found


def print_credential_summary(output_dir: Path):
    """Print a highlighted panel of all found credentials/successes."""
    creds = parse_credentials(output_dir)
    if not creds:
        return

    console.print()
    tbl = Table(
        title="[bold bright_green]Credentials & Successes Found[/bold bright_green]",
        border_style="bright_green",
        show_lines=True,
    )
    tbl.add_column("Tool",    style="bold", min_width=12)
    tbl.add_column("Finding", style="bright_white")

    seen: set[str] = set()
    for c in creds:
        key = f"{c['tool']}|{c['line']}"
        if key not in seen:
            seen.add(key)
            color = TOOL_COLORS.get(c["tool"], "white")
            tbl.add_row(f"[{color}]{c['tool']}[/]", c["line"])

    console.print(tbl)
    console.print(
        f"[bold bright_green]  → {len(seen)} finding(s) total[/bold bright_green]\n"
    )


def write_result_file(output_dir: Path, tool_name: str, lines: list[str]):
    ext_map = {
        "httpx":   "json",
        "nuclei":  "json",
    }
    ext = ext_map.get(tool_name, "txt")
    out_file = output_dir / f"{tool_name}.{ext}"
    out_file.write_text("\n".join(lines) + "\n")
    return str(out_file)
