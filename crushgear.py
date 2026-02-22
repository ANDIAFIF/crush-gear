#!/usr/bin/env python3

import argparse
import asyncio
import json
import shutil
import socket
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns

from core.reporter import print_banner, print_summary, console
from core.runner import run_phased
from core.target import parse_target
from core.updater import (
    startup_check,
    print_startup_notification,
    check_tool_versions,
    print_version_table,
    update_cve_mapping,
    update_tool_sources,
    get_full_cve_map,
    ensure_nuclei_templates,
    check_script_update,
    update_script,
)

from wrappers.nmap import NmapTool
from wrappers.amass import AmassTool
from wrappers.httpx_tool import HttpxTool
from wrappers.netexec import NetExecTool
from wrappers.smbmap import SmbmapTool
from wrappers.nuclei import NucleiTool
from wrappers.feroxbuster import FeroxbusterTool
from wrappers.metasploit import MetasploitTool

CONFIG_FILE = Path(__file__).parent / "config.json"
RESULTS_DIR = Path(__file__).parent / "results"
PARENT_DIR  = Path(__file__).parent.parent   # source root

ALL_TOOLS = ["nmap", "amass", "httpx", "netexec", "smbmap", "nuclei", "feroxbuster", "metasploit"]

BINARY_KEY_MAP = {
    "nmap":        "nmap",
    "nxc":         "netexec",
    "smbmap":      "smbmap",
    "amass":       "amass",
    "httpx":       "httpx",
    "nuclei":      "nuclei",
    "feroxbuster": "feroxbuster",
    "msfconsole":  "metasploit",
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {"binaries": {}, "timeouts": {}, "lhost": "0.0.0.0", "lport": 4444}
    with open(CONFIG_FILE) as f:
        return json.load(f)


def resolve_binary(tool_name: str, cfg_binaries: dict) -> str:
    project_dir = CONFIG_FILE.parent
    for cfg_key, tname in BINARY_KEY_MAP.items():
        if tname == tool_name:
            path = cfg_binaries.get(cfg_key, "")
            if path:
                p = Path(path)
                # If relative, resolve from project dir
                if not p.is_absolute():
                    p = project_dir / p
                if p.exists():
                    return str(p)
            return shutil.which(cfg_key) or ""
    return ""


def detect_lhost() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def get_all_local_ips() -> list[tuple[str, str]]:
    """Return list of (interface, ip) for all non-loopback IPv4 interfaces."""
    results: list[tuple[str, str]] = []
    try:
        import subprocess
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show"],
            stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                ip    = parts[3].split("/")[0]
                if not ip.startswith("127."):
                    results.append((iface, ip))
    except Exception:
        # Fallback: macOS / BSD
        try:
            import subprocess
            out = subprocess.check_output(
                ["ifconfig"], stderr=subprocess.DEVNULL, text=True
            )
            current_iface = ""
            for line in out.splitlines():
                if line and not line[0].isspace():
                    current_iface = line.split(":")[0]
                elif "inet " in line and "127.0.0.1" not in line:
                    ip = line.strip().split()[1]
                    results.append((current_iface, ip))
        except Exception:
            pass
    return results


def fetch_public_ip() -> str:
    """Try to get public IP via HTTP (best-effort, may fail on isolated nets)."""
    import urllib.request
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=4) as r:
                return r.read().decode().strip()
        except Exception:
            pass
    return ""


def ask_lhost() -> str:
    """
    Tanyakan ke user apakah jaringan 1 segment atau tidak,
    lalu pilih LHOST yang sesuai.

    Pilihan:
      1 → Sama segment  → gunakan IP lokal (auto-detect)
      2 → Beda segment  → masukkan IP Publik atau IP VPN/Tunnel
    """
    auto_ip   = detect_lhost()
    local_ips = get_all_local_ips()

    console.print()
    console.print(Panel(
        "[bold yellow]Pertanyaan: Apakah jaringan target 1 segment dengan mesin ini?[/bold yellow]\n\n"
        "  [cyan][1][/cyan] Ya, [bold]sama segment[/bold]  "
        f"→ gunakan IP lokal  [bright_white]{auto_ip}[/bright_white]\n"
        "  [cyan][2][/cyan] Tidak, [bold]beda segment[/bold]  "
        "→ masukkan IP Publik / VPN / Tunnel",
        title="[bold]LHOST Selection[/bold]",
        border_style="yellow",
    ))

    # Tampilkan semua IP lokal yang terdeteksi
    if local_ips:
        tbl = Table(show_header=True, header_style="bold dim", border_style="dim")
        tbl.add_column("Interface", style="cyan")
        tbl.add_column("IP Address", style="bright_white")
        for iface, ip in local_ips:
            tbl.add_row(iface, ip)
        console.print(tbl)

    while True:
        try:
            choice = input("\n  Pilihan [1/2]: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]Dibatalkan, pakai IP auto-detect.[/yellow]")
            return auto_ip

        if choice == "1":
            # Kalau ada lebih dari 1 IP lokal, tanyakan lagi
            if len(local_ips) > 1:
                console.print("\n  [dim]IP lokal yang tersedia:[/dim]")
                for idx, (iface, ip) in enumerate(local_ips, 1):
                    console.print(f"    [cyan][{idx}][/cyan] {iface}  {ip}")
                console.print(f"    [cyan][0][/cyan] Auto ({auto_ip})")
                while True:
                    try:
                        sub = input("  Pilih nomor interface: ").strip()
                    except (EOFError, KeyboardInterrupt):
                        return auto_ip
                    if sub == "0":
                        return auto_ip
                    if sub.isdigit() and 1 <= int(sub) <= len(local_ips):
                        chosen = local_ips[int(sub) - 1][1]
                        console.print(f"  [green]✔[/green] LHOST = [bright_white]{chosen}[/bright_white]")
                        return chosen
                    console.print("  [red]Pilihan tidak valid.[/red]")
            else:
                console.print(f"  [green]✔[/green] LHOST = [bright_white]{auto_ip}[/bright_white]")
                return auto_ip

        elif choice == "2":
            # Coba fetch public IP sebagai hint
            console.print("  [dim]Mengambil IP publik...[/dim]", end="")
            pub = fetch_public_ip()
            if pub:
                console.print(f" [dim]{pub}[/dim]")
            else:
                console.print(" [dim](gagal, jaringan terisolasi)[/dim]")

            console.print(
                "\n  Masukkan IP yang bisa di-reach oleh target:\n"
                "  [dim](IP Publik, IP VPN/tun0, IP reverse proxy, dll)[/dim]"
            )
            if pub:
                console.print(f"  [dim]Contoh IP publik terdeteksi: {pub}[/dim]")

            while True:
                try:
                    raw = input("  LHOST → ").strip()
                except (EOFError, KeyboardInterrupt):
                    console.print("\n[yellow]Dibatalkan, pakai IP auto-detect.[/yellow]")
                    return auto_ip

                # Validasi format IP
                parts = raw.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    console.print(f"  [green]✔[/green] LHOST = [bright_white]{raw}[/bright_white]")
                    return raw
                # Cek apakah hostname/domain (untuk kasus ngrok, tunneling)
                if raw and all(c.isalnum() or c in "-._" for c in raw):
                    console.print(f"  [green]✔[/green] LHOST = [bright_white]{raw}[/bright_white]")
                    return raw
                console.print("  [red]Format IP tidak valid, coba lagi.[/red]")
        else:
            console.print("  [red]Pilihan tidak valid. Masukkan 1 atau 2.[/red]")


# ─────────────────────────────────────────────────────────────────────────────
# Help system
# ─────────────────────────────────────────────────────────────────────────────

def print_help():
    print_banner()

    console.print(Panel(
        "[bold]CrushGear[/bold] adalah all-in-one pentest automation tool yang menjalankan\n"
        "7 tools secara paralel dengan alur otomatis: [cyan]Recon → Scan → Exploit[/cyan]\n\n"
        "Setiap fase [yellow]memakan output fase sebelumnya[/yellow] sebagai input:\n"
        "  nmap → amass/httpx → netexec/smbmap/nuclei/ferox → metasploit",
        title="[bold cyan]Tentang CrushGear[/bold cyan]",
        border_style="cyan",
    ))

    # ── Execution Flow ─────────────────────────────────────────────────
    flow = Table(title="[bold]Alur Eksekusi (4 Fase)[/bold]", show_lines=True, border_style="bright_cyan")
    flow.add_column("Fase",  style="bold",          min_width=8)
    flow.add_column("Tools",                         min_width=30)
    flow.add_column("Input",  style="dim",           min_width=20)
    flow.add_column("Output → Feed ke")

    flow.add_row(
        "[bright_cyan]Phase 0[/bright_cyan]",
        "[bright_cyan]nmap[/bright_cyan]",
        "Target (IP/CIDR/domain)",
        "Port terbuka, services → Phase 1 & 2",
    )
    flow.add_row(
        "[bright_blue]Phase 1[/bright_blue]",
        "[bright_blue]amass[/bright_blue]  [bright_yellow]httpx[/bright_yellow]",
        "Domain + nmap web ports",
        "Subdomains → Phase 2\nLive URLs → Phase 2",
    )
    flow.add_row(
        "[bright_green]Phase 2[/bright_green]",
        "[bright_green]netexec[/bright_green]  [cyan]smbmap[/cyan]\n[bright_red]nuclei[/bright_red]  [magenta]feroxbuster[/magenta]",
        "Hosts (amass)\nLive URLs (httpx)\nSMB hosts (nmap port 445)",
        "CVE findings → Phase 3",
    )
    flow.add_row(
        "[bright_white]Phase 3[/bright_white]",
        "[bright_white]metasploit[/bright_white]",
        "CVEs dari nuclei\nServices dari nmap",
        "Shell + auto post-exploit\n(hashdump, credential dump, etc.)",
    )
    console.print(flow)

    # ── Command Reference ──────────────────────────────────────────────
    console.print()
    cmd_table = Table(
        title="[bold]Command Reference[/bold]",
        show_lines=True,
        border_style="bright_white",
    )
    cmd_table.add_column("Command",     style="bold bright_yellow", min_width=45)
    cmd_table.add_column("Keterangan")

    cmd_table.add_row("python3 crushgear.py -t <target>",          "Jalankan semua tools (4 fase)")
    cmd_table.add_row("python3 crushgear.py -t <target> -u admin -p pass",
                                                                     "Dengan kredensial (SMB/NXC)")
    cmd_table.add_row("python3 crushgear.py -t <target> --tools amass,httpx,nuclei",
                                                                     "Pilih tools spesifik saja")
    cmd_table.add_row("python3 crushgear.py -t <target> --lhost 10.0.0.1 --lport 9001",
                                                                     "Set IP/port reverse shell MSF")
    cmd_table.add_row("", "")
    cmd_table.add_row("python3 crushgear.py --setup",               "Build semua tools dari source")
    cmd_table.add_row("python3 crushgear.py --check",               "Cek status binary + timeout")
    cmd_table.add_row("python3 crushgear.py --check-updates",       "Bandingkan versi installed vs GitHub")
    cmd_table.add_row("python3 crushgear.py --update-cves",         "Update CVE→MSF mapping dari GitHub")
    cmd_table.add_row("python3 crushgear.py --update-tools",        "git pull semua source tools")
    cmd_table.add_row("python3 crushgear.py --update-script",          "Update CrushGear script (git pull)")
    cmd_table.add_row("python3 crushgear.py --update-cves --github-token TOKEN",
                                                                     "Update CVE (lebih cepat, rate limit↑)")
    cmd_table.add_row("", "")
    cmd_table.add_row("python3 crushgear.py --help-full",           "Tampilkan help lengkap ini")

    console.print(cmd_table)

    # ── Target Types ───────────────────────────────────────────────────
    console.print()
    tgt = Table(title="[bold]Tipe Target yang Didukung[/bold]", show_lines=True, border_style="green")
    tgt.add_column("Tipe",   style="bold", min_width=10)
    tgt.add_column("Contoh", style="bright_yellow")
    tgt.add_column("Catatan")

    tgt.add_row("IP",     "192.168.1.1",       "Single host")
    tgt.add_row("Domain", "example.com",        "DNS di-resolve otomatis")
    tgt.add_row("URL",    "http://target.com",  "HTTP/HTTPS, host diekstrak")
    tgt.add_row("CIDR",   "192.168.1.0/24",    "Seluruh network range")
    console.print(tgt)

    # ── Tool Overview ──────────────────────────────────────────────────
    console.print()
    tool_tbl = Table(title="[bold]Daftar Tools & Fungsinya[/bold]", show_lines=True, border_style="magenta")
    tool_tbl.add_column("Tool",       style="bold", min_width=14)
    tool_tbl.add_column("Fase",       min_width=8)
    tool_tbl.add_column("Fungsi")
    tool_tbl.add_column("GitHub", style="dim")

    tool_tbl.add_row("[bright_cyan]nmap[/bright_cyan]",          "0",
                     "Port scan + service/OS detection",
                     "nmap.org (system pkg)")
    tool_tbl.add_row("[bright_blue]amass[/bright_blue]",         "1",
                     "Subdomain enumeration + DNS intel",
                     "owasp-amass/amass")
    tool_tbl.add_row("[bright_yellow]httpx[/bright_yellow]",     "1",
                     "HTTP probing: status, title, tech, redirect",
                     "projectdiscovery/httpx")
    tool_tbl.add_row("[bright_green]netexec[/bright_green]",     "2",
                     "SMB/SSH/LDAP enumeration, share+user listing",
                     "Pennyw0rth/NetExec")
    tool_tbl.add_row("[cyan]smbmap[/cyan]",                      "2",
                     "SMB share browsing + permission check",
                     "ShawnDEvans/smbmap")
    tool_tbl.add_row("[bright_red]nuclei[/bright_red]",          "2",
                     "Template-based vuln scanner (CVE, RCE, SQLi, dll)",
                     "projectdiscovery/nuclei")
    tool_tbl.add_row("[magenta]feroxbuster[/magenta]",           "2",
                     "Directory & endpoint brute-force",
                     "epi052/feroxbuster")
    tool_tbl.add_row("[bright_white]metasploit[/bright_white]",  "3",
                     "Auto-exploit berdasarkan CVE dari nuclei + post-exploit",
                     "rapid7/metasploit-framework")
    console.print(tool_tbl)

    # ── CVE Info ───────────────────────────────────────────────────────
    console.print()
    cfg = load_config()
    static_count = 188
    extra_count  = len(cfg.get("discovered_cves", {}))
    last_update  = cfg.get("_cve_last_update", "Belum pernah diupdate")[:10]
    console.print(Panel(
        f"  Static CVE mapping : [bold]{static_count}[/bold] entries\n"
        f"  Discovered (auto)  : [bold]{extra_count}[/bold] entries\n"
        f"  [bold]Total coverage     : {static_count + extra_count} CVEs → MSF modules[/bold]\n"
        f"  Last update        : [dim]{last_update}[/dim]\n\n"
        f"  Sumber:\n"
        f"    • [dim]nuclei-templates (projectdiscovery/nuclei-templates)[/dim]\n"
        f"    • [dim]metasploit-framework (rapid7/metasploit-framework)[/dim]\n\n"
        f"  Update: [bold yellow]python3 crushgear.py --update-cves[/bold yellow]",
        title="[bold red]CVE → Metasploit Mapping[/bold red]",
        border_style="red",
    ))

    # ── Results ────────────────────────────────────────────────────────
    console.print()
    console.print(Panel(
        "  Output per-tool disimpan di:\n"
        "  [bold]results/{target}_{timestamp}/[/bold]\n\n"
        "  ├── nmap.txt\n"
        "  ├── amass.txt\n"
        "  ├── httpx.json\n"
        "  ├── netexec.txt\n"
        "  ├── smbmap.txt\n"
        "  ├── nuclei.json\n"
        "  ├── feroxbuster.txt\n"
        "  └── metasploit.txt",
        title="[bold]Output Files[/bold]",
        border_style="dim",
    ))
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Check tools status
# ─────────────────────────────────────────────────────────────────────────────

def check_tools(cfg: dict):
    console.print("\n[bold]Tool Status Check[/bold]\n")
    table = Table(show_lines=True)
    table.add_column("Tool",        style="bold",    min_width=14)
    table.add_column("Binary Key",                   min_width=12)
    table.add_column("Timeout",     justify="right", min_width=8)
    table.add_column("Path")
    table.add_column("Status",                       min_width=12)

    timeouts = cfg.get("timeouts", {})
    project_dir = CONFIG_FILE.parent
    for cfg_key, tool_name in BINARY_KEY_MAP.items():
        path = cfg["binaries"].get(cfg_key, "")
        if path:
            p = Path(path)
            if not p.is_absolute():
                p = project_dir / p
            if not p.exists():
                path = shutil.which(cfg_key) or ""
            else:
                path = str(p)
        else:
            path = shutil.which(cfg_key) or ""
        ok     = bool(path and Path(path).exists())
        status = "[green]  OK[/green]" if ok else "[red]MISSING[/red]"
        t      = timeouts.get(tool_name, timeouts.get("default", 300))
        table.add_row(tool_name, cfg_key, f"{t}s", path or "-", status)

    console.print(table)
    console.print(f"\n[dim]LHOST (auto): {detect_lhost()}[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# Main scan
# ─────────────────────────────────────────────────────────────────────────────

async def _run(args: argparse.Namespace):
    print_banner()

    cfg      = load_config()
    binaries = cfg.get("binaries", {})
    token    = args.github_token or ""

    # ── Startup update notification (cached, non-blocking) ──────────
    outdated, script_upd = await asyncio.gather(
        startup_check(binaries, token=token),
        check_script_update(),
    )
    extra_cves = cfg.get("discovered_cves", {})
    last_cve   = cfg.get("_cve_last_update", "")
    total_cves = 188 + len(extra_cves)
    print_startup_notification(outdated, total_cves, last_cve, script_upd)

    cfg_timeouts = cfg.get("timeouts", {})
    lport = args.lport or cfg.get("lport", 4444)

    # Jika --lhost tidak di-set eksplisit → tanya user (segment check)
    if args.lhost:
        lhost = args.lhost
    elif cfg.get("lhost") and cfg["lhost"] != "0.0.0.0":
        lhost = cfg["lhost"]
    else:
        lhost = ask_lhost()

    target = parse_target(args.target)
    console.print(
        f"\n[bold]Target:[/bold] [bright_yellow]{target.raw}[/bright_yellow]  "
        f"[dim]type={target.type.value}  host={target.host}  ip={target.ip or 'N/A'}[/dim]"
    )
    console.print(
        f"[dim]LHOST: {lhost}  LPORT: {lport}  "
        f"CVE map: {total_cves} entries[/dim]\n"
    )

    requested: set[str] = set(args.tools.split(",")) if args.tools else set(ALL_TOOLS)

    def binary(tool_name: str) -> str:
        return resolve_binary(tool_name, binaries) if tool_name in requested else ""

    username = args.username or ""
    password = args.password or ""

    # Output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe      = target.raw.replace("/", "_").replace(":", "_").replace(".", "_")
    output_dir = RESULTS_DIR / f"{safe}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[dim]Results: {output_dir}[/dim]\n")

    # Full CVE map (static + discovered)
    full_cve_map = get_full_cve_map(CONFIG_FILE)

    # ── Auto-ensure nuclei templates (download/update if needed) ─────
    if "nuclei" in requested:
        nuclei_bin = resolve_binary("nuclei", binaries)
        if nuclei_bin:
            await ensure_nuclei_templates(nuclei_bin)
        else:
            console.print("[dim]Nuclei binary not found — skipping template check[/dim]")

    # ── Phase 0 ─────────────────────────────────────────────────────
    phase0 = []
    if "nmap" in requested:
        phase0.append(NmapTool(target=target, binary=binary("nmap"),
                               username=username, password=password))

    # ── Phase 1 ─────────────────────────────────────────────────────
    phase1 = []
    if "amass" in requested:
        phase1.append(AmassTool(target=target, binary=binary("amass"),
                                username=username, password=password))
    if "httpx" in requested:
        phase1.append(HttpxTool(target=target, binary=binary("httpx"),
                                username=username, password=password))

    # ── Phase 2 factory ─────────────────────────────────────────────
    def make_phase2(feed: dict) -> list:
        kw = dict(target=target, username=username, password=password, feed=feed)
        w  = []
        if "netexec"     in requested: w.append(NetExecTool    (binary=binary("netexec"),     **kw))
        if "smbmap"      in requested: w.append(SmbmapTool     (binary=binary("smbmap"),      **kw))
        if "nuclei"      in requested: w.append(NucleiTool     (binary=binary("nuclei"),      **kw))
        if "feroxbuster" in requested: w.append(FeroxbusterTool(binary=binary("feroxbuster"), **kw))
        return w

    # ── Phase 3 factory ─────────────────────────────────────────────
    def make_phase3(feed: dict) -> list:
        if "metasploit" not in requested:
            return []
        return [MetasploitTool(
            target=target, binary=binary("metasploit"),
            username=username, password=password,
            feed={**feed, "extra_cve_map": full_cve_map},
            lhost=lhost, lport=lport,
        )]

    results = await run_phased(
        phase0_wrappers=phase0,
        phase1_wrappers=phase1,
        phase2_factory=make_phase2,
        phase3_factory=make_phase3,
        output_dir=output_dir,
        cfg_timeouts=cfg_timeouts,
    )

    print_summary(results)
    console.print(f"\n[dim]All output saved to: {output_dir}[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CrushGear - All-in-One Pentest Automation",
        add_help=False,  # We provide our own --help
    )

    # ── Scan options ─────────────────────────────────────────────────
    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("-t", "--target",   help="Target: IP / domain / URL / CIDR")
    scan.add_argument("-u", "--username", default="", help="Username (NetExec / SMBMap)")
    scan.add_argument("-p", "--password", default="", help="Password (NetExec / SMBMap)")
    scan.add_argument(
        "--tools", default="",
        help=f"Pilih tools (comma-separated). Available: {','.join(ALL_TOOLS)}",
    )
    scan.add_argument("--lhost",  default="", help="LHOST reverse shell (auto-detect jika kosong)")
    scan.add_argument("--lport",  type=int, default=0, help="LPORT reverse shell (default: 4444)")

    # ── Setup & check ────────────────────────────────────────────────
    mgmt = parser.add_argument_group("Setup & Management")
    mgmt.add_argument("--setup",          action="store_true", help="Build/install semua tools dari source")
    mgmt.add_argument("--check",          action="store_true", help="Cek status binary + timeouts")
    mgmt.add_argument("--check-updates",  action="store_true", help="Cek versi installed vs GitHub latest")
    mgmt.add_argument("--update-cves",    action="store_true", help="Update CVE→MSF mapping dari GitHub")
    mgmt.add_argument("--update-tools",   action="store_true", help="git pull semua source tools")
    mgmt.add_argument("--update-script",  action="store_true", help="Update CrushGear script (git pull)")
    mgmt.add_argument("--github-token",   default="", metavar="TOKEN",
                      help="GitHub API token (opsional, tingkatkan rate limit)")

    # ── Help ─────────────────────────────────────────────────────────
    help_grp = parser.add_argument_group("Help")
    help_grp.add_argument("-h", "--help",      action="store_true", help="Tampilkan help singkat")
    help_grp.add_argument("--help-full",       action="store_true", help="Tampilkan help lengkap + semua info")

    args = parser.parse_args()

    # ── Route commands ───────────────────────────────────────────────

    if args.help_full:
        print_help()
        return

    if args.help or (not any(vars(args).values())):
        print_banner()
        parser.print_help()
        console.print(
            "\n[dim]Tip: gunakan [bold]--help-full[/bold] untuk dokumentasi lengkap dengan tabel alur & semua commands[/dim]\n"
        )
        return

    if args.setup:
        import setup_tools
        setup_tools.main()
        return

    if args.check:
        print_banner()
        check_tools(load_config())
        return

    if args.check_updates:
        print_banner()
        cfg     = load_config()
        binaries = cfg.get("binaries", {})
        results = asyncio.run(
            check_tool_versions(binaries, token=args.github_token, use_cache=False)
        )
        print_version_table(results)
        return

    if args.update_cves:
        print_banner()
        asyncio.run(update_cve_mapping(token=args.github_token))
        return

    if args.update_tools:
        print_banner()
        asyncio.run(update_tool_sources(PARENT_DIR, token=args.github_token))
        return

    if args.update_script:
        print_banner()
        console.rule("[bold]CrushGear Script Update[/bold]")
        console.print("[dim]Checking for updates…[/dim]")
        has_upd, count, latest = asyncio.run(check_script_update())
        if not has_upd:
            console.print("[green]✓ Script sudah versi terbaru.[/green]")
        else:
            console.print(
                f"[yellow]  {count} commit baru ditemukan[/yellow]\n"
                f"  [dim]Latest: {latest}[/dim]\n"
                f"[dim]Menjalankan git pull…[/dim]"
            )
            ok, out = asyncio.run(update_script())
            if ok:
                console.print(f"[green]✓ CrushGear berhasil diupdate![/green]")
                console.print(f"[dim]{out}[/dim]")
                console.print(
                    "\n[bold]Restart script untuk menggunakan versi terbaru:[/bold]\n"
                    "  python3 crushgear.py ..."
                )
            else:
                console.print(f"[red]✗ Update gagal:[/red]\n{out}")
        return

    if not args.target:
        print_banner()
        parser.print_help()
        console.print(
            "\n[dim]Tip: [bold]python3 crushgear.py --help-full[/bold] untuk dokumentasi lengkap[/dim]\n"
        )
        sys.exit(1)

    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
