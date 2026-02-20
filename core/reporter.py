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


def write_result_file(output_dir: Path, tool_name: str, lines: list[str]):
    ext_map = {
        "httpx":   "json",
        "nuclei":  "json",
    }
    ext = ext_map.get(tool_name, "txt")
    out_file = output_dir / f"{tool_name}.{ext}"
    out_file.write_text("\n".join(lines) + "\n")
    return str(out_file)
