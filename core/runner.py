import asyncio
import time
from pathlib import Path
from typing import Optional, Protocol

from core.reporter import print_tool_line, write_result_file, console
from core.feed import collect_all_feed, parse_nmap, get_all_hosts

TOOL_COLORS = {
    "nmap":        "bright_cyan",
    "netexec":     "bright_green",
    "smbmap":      "cyan",
    "amass":       "bright_blue",
    "httpx":       "bright_yellow",
    "nuclei":      "bright_red",
    "feroxbuster": "magenta",
    "metasploit":  "bright_white",
}

# Default per-tool timeouts (seconds) — overridden by config
TOOL_TIMEOUTS: dict[str, int] = {
    "nmap":        900,
    "amass":       1800,
    "nuclei":      900,
    "feroxbuster": 600,
    "metasploit":  600,
    "httpx":       300,
    "netexec":     300,
    "smbmap":      300,
}


class ToolResult:
    def __init__(self, tool_name: str):
        self.tool = tool_name
        self.status = "PENDING"
        self.duration = 0.0
        self.output_file = ""
        self.lines: list[str] = []
        self.returncode: Optional[int] = None


class ExecutionCallbacks(Protocol):
    """Protocol for execution event callbacks."""

    async def on_tool_start(
        self, tool: str, phase: int, command: list[str]
    ) -> None:
        """Called when a tool starts execution."""
        ...

    async def on_tool_output(
        self, tool: str, line: str, line_num: int
    ) -> None:
        """Called for each output line from a tool."""
        ...

    async def on_tool_complete(
        self, tool: str, result: ToolResult
    ) -> None:
        """Called when a tool completes (success or error)."""
        ...

    async def on_phase_complete(
        self, phase: int, feed: dict
    ) -> None:
        """Called after a phase completes and feed is collected."""
        ...


def resolve_timeout(tool_name: str, cfg_timeouts: dict) -> int:
    return cfg_timeouts.get(tool_name) or TOOL_TIMEOUTS.get(tool_name) or cfg_timeouts.get("default", 300)


async def run_tool(
    wrapper,
    output_dir: Path,
    timeout: int,
    results_map: dict[str, ToolResult],
    callbacks: ExecutionCallbacks | None = None,
    phase: int = 0,
):
    tool_name = wrapper.name
    result = results_map[tool_name]
    result.status = "RUNNING"
    start = time.monotonic()

    cmd = wrapper.build_command()
    if not cmd:
        result.status = "SKIPPED"
        result.duration = 0.0
        color = TOOL_COLORS.get(tool_name, "white")
        console.print(
            f"[bold {color}][{tool_name.upper():>12}][/] [dim]SKIPPED[/dim]"
        )
        return result

    color = TOOL_COLORS.get(tool_name, "white")
    console.print(
        f"[bold {color}][{tool_name.upper():>12}][/] [dim]→[/dim] {' '.join(str(c) for c in cmd[:6])}"
        + (" [dim]...[/dim]" if len(cmd) > 6 else "")
    )

    # CALLBACK: Tool start
    if callbacks:
        await callbacks.on_tool_start(tool_name, phase, cmd)

    try:
        proc = await asyncio.create_subprocess_exec(
            *[str(c) for c in cmd],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        async def read_stream():
            assert proc.stdout
            line_num = 0
            async for raw_line in proc.stdout:
                line = raw_line.decode(errors="replace").rstrip()
                result.lines.append(line)
                print_tool_line(tool_name, line)

                # CALLBACK: Tool output
                if callbacks:
                    await callbacks.on_tool_output(tool_name, line, line_num)
                line_num += 1

        try:
            await asyncio.wait_for(read_stream(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            result.status = "ERROR"
            msg = f"[TIMEOUT after {timeout}s]"
            result.lines.append(msg)
            print_tool_line(tool_name, f"[red]{msg}[/red]")

        await proc.wait()
        result.returncode = proc.returncode
        if result.status != "ERROR":
            result.status = "DONE" if proc.returncode == 0 else "ERROR"

    except FileNotFoundError:
        result.status = "ERROR"
        result.lines.append(f"Binary not found: {cmd[0]}")
        print_tool_line(tool_name, f"[red]Binary not found: {cmd[0]}[/red]")
    except Exception as exc:
        result.status = "ERROR"
        result.lines.append(str(exc))
        print_tool_line(tool_name, f"[red]Exception: {exc}[/red]")

    result.duration = time.monotonic() - start
    result.output_file = write_result_file(output_dir, tool_name, result.lines)

    # CALLBACK: Tool complete
    if callbacks:
        await callbacks.on_tool_complete(tool_name, result)

    return result


def _log_feed_summary(feed: dict):
    if feed.get("hosts"):
        console.print(
            f"  [bold bright_blue][FEED][/] amass/nmap → "
            f"[bright_blue]{len(feed['hosts'])} hosts[/] discovered"
        )
        for h in feed["hosts"][:8]:
            console.print(f"           [dim]· {h}[/dim]")
        if len(feed["hosts"]) > 8:
            console.print(f"           [dim]  … +{len(feed['hosts'])-8} more[/dim]")

    if feed.get("smb_hosts"):
        console.print(
            f"  [bold cyan][FEED][/] nmap SMB   → "
            f"[cyan]{len(feed['smb_hosts'])} SMB hosts[/] (port 445 open)"
        )

    _proto_map = [
        ("windows_hosts", "Windows hosts", "bright_white"),
        ("dc_hosts",      "Domain Controllers", "bright_magenta"),
        ("winrm_hosts",   "WinRM hosts",    "bright_green"),
        ("mssql_hosts",   "MSSQL hosts",    "bright_yellow"),
        ("rdp_hosts",     "RDP hosts",      "bright_blue"),
        ("ssh_hosts",     "SSH hosts",      "bright_cyan"),
        ("ldap_hosts",    "LDAP hosts",     "bright_red"),
    ]
    for key, label, color in _proto_map:
        hosts = feed.get(key, [])
        if hosts:
            console.print(
                f"  [bold {color}][FEED][/] nmap {label:<18} → "
                f"[{color}]{len(hosts)} host(s)[/]: "
                + ", ".join(hosts[:4])
                + (" …" if len(hosts) > 4 else "")
            )

    if feed.get("urls"):
        console.print(
            f"  [bold bright_yellow][FEED][/] httpx      → "
            f"[bright_yellow]{len(feed['urls'])} live URLs[/]"
        )
        for u in feed["urls"][:5]:
            console.print(f"           [dim]· {u}[/dim]")
        if len(feed["urls"]) > 5:
            console.print(f"           [dim]  … +{len(feed['urls'])-5} more[/dim]")

    if feed.get("findings"):
        console.print(
            f"  [bold bright_red][FEED][/] nuclei     → "
            f"[bright_red]{len(feed['findings'])} vulns[/] → MSF module mapping"
        )
        seen: set[str] = set()
        for f in feed["findings"]:
            cve = f.get("cve", "")
            if cve and cve not in seen:
                seen.add(cve)
                console.print(f"           [dim]· {cve} on {f.get('host','')}[/dim]")


async def run_phase(
    phase_num: int,
    phase_name: str,
    wrappers: list,
    output_dir: Path,
    cfg_timeouts: dict,
    results_map: dict[str, ToolResult],
    callbacks: ExecutionCallbacks | None = None,
):
    if not wrappers:
        console.print(f"[dim]Phase {phase_num} ({phase_name}): no tools to run, skipping.[/dim]")
        return
    console.rule(f"[bold]Phase {phase_num} — {phase_name}[/bold]")
    tasks = [
        run_tool(w, output_dir, resolve_timeout(w.name, cfg_timeouts), results_map, callbacks, phase_num)
        for w in wrappers
    ]
    await asyncio.gather(*tasks)


async def run_phased(
    phase0_wrappers: list,   # nmap
    phase1_wrappers: list,   # amass, httpx  (no feed needed, use nmap data)
    phase2_factory,           # callable(feed) → [nxc, smbmap, nuclei, ferox]
    phase3_factory,           # callable(feed) → [metasploit]
    output_dir: Path,
    cfg_timeouts: dict | None = None,
    callbacks: ExecutionCallbacks | None = None,
) -> list[dict]:
    cfg_timeouts = cfg_timeouts or {}
    results_map: dict[str, ToolResult] = {}

    def register(wrappers):
        for w in wrappers:
            if w.name not in results_map:
                results_map[w.name] = ToolResult(w.name)

    register(phase0_wrappers)
    register(phase1_wrappers)

    # ── Phase 0: Port Scan ───────────────────────────────────────────
    await run_phase(0, "Port Scanning (nmap)", phase0_wrappers, output_dir, cfg_timeouts, results_map, callbacks)

    # Collect nmap feed
    feed = collect_all_feed(output_dir)
    if callbacks:
        await callbacks.on_phase_complete(0, feed)
    if feed.get("hosts") or feed.get("smb_hosts") or feed.get("urls"):
        console.print()
        _log_feed_summary(feed)
        console.print()

    # ── Phase 1: Reconnaissance ──────────────────────────────────────
    await run_phase(1, "Reconnaissance (amass + httpx)", phase1_wrappers, output_dir, cfg_timeouts, results_map, callbacks)

    # Update feed with httpx results
    feed = collect_all_feed(output_dir)
    if callbacks:
        await callbacks.on_phase_complete(1, feed)
    console.print()
    _log_feed_summary(feed)
    console.print()

    # ── Phase 2: Scanning ────────────────────────────────────────────
    phase2 = phase2_factory(feed)
    register(phase2)
    await run_phase(2, "Scanning & Enumeration", phase2, output_dir, cfg_timeouts, results_map, callbacks)

    # Update feed with nuclei results
    feed = collect_all_feed(output_dir)
    if callbacks:
        await callbacks.on_phase_complete(2, feed)
    console.print()
    _log_feed_summary(feed)
    console.print()

    # ── Phase 3: Exploitation ────────────────────────────────────────
    phase3 = phase3_factory(feed)
    register(phase3)
    await run_phase(3, "Exploitation (metasploit)", phase3, output_dir, cfg_timeouts, results_map, callbacks)

    # Collect final feed and notify completion
    if callbacks:
        final_feed = collect_all_feed(output_dir)
        await callbacks.on_phase_complete(3, final_feed)

    return [
        {
            "tool":        r.tool,
            "status":      r.status,
            "duration":    r.duration,
            "output_file": r.output_file,
            "returncode":  r.returncode,
        }
        for r in results_map.values()
    ]
