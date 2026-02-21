"""
CrushGear Updater
─────────────────
Handles:
  • Startup notification  — checks tool versions (cached 6h)
  • --check-updates       — show version table for all tools
  • --update-cves         — fetch new CVEs from nuclei-templates + MSF search
  • --update-tools        — git pull each source directory
"""

import asyncio
import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ── GitHub repos for each tool ───────────────────────────────────────────────
GITHUB_REPOS: dict[str, str] = {
    "nmap":        "",                            # system pkg, no GitHub release check
    "amass":       "owasp-amass/amass",
    "httpx":       "projectdiscovery/httpx",
    "feroxbuster": "epi052/feroxbuster",
    "nuclei":      "projectdiscovery/nuclei",
    "smbmap":      "ShawnDEvans/smbmap",
    "metasploit":  "rapid7/metasploit-framework",
    "netexec":     "Pennyw0rth/NetExec",
}

NUCLEI_TEMPLATES_REPO = "projectdiscovery/nuclei-templates"
MSF_REPO              = "rapid7/metasploit-framework"

CHECK_INTERVAL      = 6  * 3600   # seconds between startup version checks
CVE_UPDATE_INTERVAL = 24 * 3600   # seconds between full CVE refreshes
MSF_SEARCH_DELAY    = 2.0          # seconds between GitHub search API calls (rate limiting)
MSF_MAX_PAGES       = 10           # max pages of MSF search results (100 results/page)

CONFIG_FILE   = Path(__file__).parent.parent / "config.json"
CRUSHGEAR_DIR = Path(__file__).parent.parent   # root of the crushgear repo


# ─────────────────────────────────────────────────────────────────────────────
# Low-level helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}


def _save_config(cfg: dict):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


async def _fetch_json(
    url: str,
    timeout: int = 15,
    token: str = "",
) -> Optional[dict | list]:
    """HTTP GET returning parsed JSON, in a thread executor."""
    import urllib.request

    headers = {
        "User-Agent": "CrushGear/1.0",
        "Accept":     "application/vnd.github+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def _get():
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())

    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _get), timeout=timeout + 2
        )
    except Exception:
        return None


def _path_to_module(rb_path: str) -> str:
    """
    Convert GitHub file path to MSF `use` string.
    modules/exploits/windows/smb/ms17_010.rb → exploit/windows/smb/ms17_010
    """
    p = rb_path.replace("modules/", "").replace(".rb", "")
    p = p.replace("exploits/",   "exploit/")
    p = p.replace("auxiliaries/", "auxiliary/")
    p = p.replace("payloads/",   "payload/")
    p = p.replace("posts/",      "post/")
    return p


def _guess_payload(module_path: str) -> Optional[str]:
    """Guess a sensible default payload from module path."""
    p = module_path.lower()
    if any(k in p for k in ("auxiliary", "scanner", "gather", "admin", "dos")):
        return None
    if "windows" in p:
        return "windows/x64/meterpreter/reverse_tcp"
    if "linux" in p or "unix" in p:
        return "linux/x64/meterpreter/reverse_tcp"
    if "php" in p:
        return "php/meterpreter/reverse_tcp"
    if "java" in p or "multi/http" in p or "multi/misc" in p:
        return "java/meterpreter/reverse_tcp"
    return "linux/x64/meterpreter/reverse_tcp"


def _extract_cve_from_path(path: str) -> Optional[str]:
    """
    Extract CVE ID from a file path like:
      modules/exploits/multi/misc/cve_2021_44228.rb
      modules/auxiliary/scanner/http/log4shell_header_injection.rb  ← no CVE in name
    """
    stem = Path(path).stem  # e.g. cve_2021_44228
    m = re.match(r"(cve_\d{4}_\d{4,})", stem, re.IGNORECASE)
    if m:
        return m.group(1).upper().replace("_", "-")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Tool version checking
# ─────────────────────────────────────────────────────────────────────────────

_VERSION_CMD: dict[str, list[str]] = {
    "nmap":        ["nmap", "--version"],
    "amass":       ["amass", "-version"],
    "httpx":       ["httpx", "-version"],
    "feroxbuster": ["feroxbuster", "--version"],
    "nuclei":      ["nuclei", "-version"],
    "smbmap":      ["smbmap", "--version"],
    "netexec":     ["nxc", "--version"],
    "metasploit":  ["msfconsole", "--version"],
}


async def _get_installed_version(tool_name: str, binary: str) -> str:
    cmd = _VERSION_CMD.get(tool_name, [binary, "--version"])
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=6)
        output = stdout.decode(errors="replace")
        m = re.search(r"v?(\d+\.\d+[\d.]*(?:-\w+)?)", output)
        return f"v{m.group(1)}" if m else output.strip()[:20] or "installed"
    except Exception:
        return "N/A"


async def _get_latest_release(repo: str, token: str = "") -> str:
    if not repo:
        return "N/A"
    data = await _fetch_json(
        f"https://api.github.com/repos/{repo}/releases/latest",
        token=token,
    )
    if isinstance(data, dict):
        tag = data.get("tag_name", "")
        name = data.get("name", "")
        return tag or name or "N/A"
    return "N/A"


async def check_tool_versions(
    binaries: dict,
    token: str = "",
    use_cache: bool = True,
) -> list[dict]:
    """
    Compare installed vs latest GitHub release for each tool.
    Returns list of {tool, installed, latest, needs_update, repo}
    """
    cfg = _load_config()
    cache = cfg.get("_version_cache", {})
    now = time.time()
    cache_age = now - cache.get("_ts", 0)

    if use_cache and cache_age < CHECK_INTERVAL and cache.get("results"):
        return cache["results"]

    tasks = []
    tool_list = list(GITHUB_REPOS.keys())

    for tool in tool_list:
        repo   = GITHUB_REPOS[tool]
        binary = binaries.get(
            {"netexec": "nxc", "metasploit": "msfconsole"}.get(tool, tool), ""
        )
        tasks.append(_get_installed_version(tool, binary))
        tasks.append(_get_latest_release(repo, token))

    flat = await asyncio.gather(*tasks, return_exceptions=True)

    results = []
    for i, tool in enumerate(tool_list):
        installed = flat[i * 2]
        latest    = flat[i * 2 + 1]
        if isinstance(installed, Exception): installed = "N/A"
        if isinstance(latest,    Exception): latest    = "N/A"

        needs_update = (
            installed not in ("N/A", "installed")
            and latest not in ("N/A", "")
            and installed != latest
        )
        results.append({
            "tool":         tool,
            "repo":         GITHUB_REPOS[tool],
            "installed":    installed,
            "latest":       latest,
            "needs_update": needs_update,
        })

    # Cache
    cfg["_version_cache"] = {"_ts": now, "results": results}
    _save_config(cfg)
    return results


def print_version_table(results: list[dict]):
    table = Table(title="[bold]Tool Version Status[/bold]", show_lines=True)
    table.add_column("Tool",       style="bold", min_width=14)
    table.add_column("Installed",  min_width=12)
    table.add_column("Latest",     min_width=12)
    table.add_column("Status",     min_width=14)
    table.add_column("Repo")

    for r in results:
        if r["installed"] == "N/A":
            status = "[red]NOT INSTALLED[/red]"
        elif r["needs_update"]:
            status = "[yellow]UPDATE AVAILABLE[/yellow]"
        else:
            status = "[green]UP TO DATE[/green]"
        repo_link = f"[dim]github.com/{r['repo']}[/dim]" if r["repo"] else "[dim]system pkg[/dim]"
        table.add_row(r["tool"], r["installed"], r["latest"], status, repo_link)

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# CVE mapping updater
# ─────────────────────────────────────────────────────────────────────────────

async def fetch_nuclei_cve_ids(token: str = "") -> list[str]:
    """
    Fetch all CVE template IDs from projectdiscovery/nuclei-templates.
    Uses the GitHub tree API, cached to avoid repeated calls.
    """
    cfg = _load_config()
    cache = cfg.get("_nuclei_cve_cache", {})
    if time.time() - cache.get("_ts", 0) < CVE_UPDATE_INTERVAL and cache.get("cves"):
        console.print(f"  [dim]nuclei-templates CVE list: using cache ({len(cache['cves'])} CVEs)[/dim]")
        return cache["cves"]

    console.print("  [dim]Fetching nuclei-templates CVE list from GitHub…[/dim]")

    # Fetch the repo tree (recursive) – may be truncated for large repos
    data = await _fetch_json(
        f"https://api.github.com/repos/{NUCLEI_TEMPLATES_REPO}/git/trees/main?recursive=1",
        timeout=45,
        token=token,
    )

    cve_ids: list[str] = []
    if isinstance(data, dict):
        for item in data.get("tree", []):
            path: str = item.get("path", "")
            if path.startswith("cves/") and path.endswith(".yaml"):
                stem = Path(path).stem.upper()
                if re.match(r"CVE-\d{4}-\d+", stem):
                    cve_ids.append(stem)

    cve_ids = sorted(set(cve_ids))
    console.print(f"  [dim]Found {len(cve_ids)} CVE templates in nuclei-templates[/dim]")

    cfg["_nuclei_cve_cache"] = {"_ts": time.time(), "cves": cve_ids}
    _save_config(cfg)
    return cve_ids


async def fetch_msf_cve_modules(
    token: str = "",
    max_pages: int = MSF_MAX_PAGES,
) -> dict[str, dict]:
    """
    Search metasploit-framework for modules whose filename contains a CVE ID.
    Returns { "CVE-XXXX-YYYY": {"module": "...", "payload": "..."} }
    Uses GitHub code search API, paginated.
    """
    cfg = _load_config()
    cache = cfg.get("_msf_module_cache", {})
    if time.time() - cache.get("_ts", 0) < CVE_UPDATE_INTERVAL and cache.get("modules"):
        console.print(f"  [dim]MSF module cache: {len(cache['modules'])} CVE→module entries[/dim]")
        return cache["modules"]

    console.print("  [dim]Fetching MSF CVE modules from GitHub (this may take a minute)…[/dim]")
    modules: dict[str, dict] = {}

    for page in range(1, max_pages + 1):
        url = (
            f"https://api.github.com/search/code"
            f"?q=cve_+in:path+repo:{MSF_REPO}+extension:rb"
            f"&per_page=100&page={page}"
        )
        data = await _fetch_json(url, timeout=20, token=token)
        if not isinstance(data, dict):
            break

        items = data.get("items", [])
        if not items:
            break

        for item in items:
            path: str = item.get("path", "")
            cve_id = _extract_cve_from_path(path)
            if cve_id and "/modules/" in path:
                module_str = _path_to_module(path)
                payload    = _guess_payload(module_str)
                if cve_id not in modules:
                    modules[cve_id] = {
                        "module":  module_str,
                        "payload": payload,
                        "source":  "auto-discovered",
                    }

        console.print(f"  [dim]  page {page}: {len(items)} results, total mapped: {len(modules)}[/dim]")

        if len(items) < 100:
            break
        if page < max_pages:
            await asyncio.sleep(MSF_SEARCH_DELAY)

    console.print(f"  [dim]MSF CVE module scan complete: {len(modules)} entries found[/dim]")
    cfg["_msf_module_cache"] = {"_ts": time.time(), "modules": modules}
    _save_config(cfg)
    return modules


async def update_cve_mapping(token: str = "") -> tuple[int, int]:
    """
    Fetch new CVEs from nuclei-templates and cross-reference with MSF modules.
    Saves discovered CVE→MSF mappings to config.json under 'discovered_cves'.
    Returns (new_entries_count, total_entries_count).
    """
    from core.feed import CVE_TO_MSF

    console.rule("[bold]CVE Mapping Update[/bold]")

    nuclei_cves = await fetch_nuclei_cve_ids(token)
    msf_modules = await fetch_msf_cve_modules(token)

    known = set(CVE_TO_MSF.keys())

    cfg = _load_config()
    discovered: dict = cfg.get("discovered_cves", {})

    new_count = 0
    for cve_id in nuclei_cves:
        if cve_id in known or cve_id in discovered:
            continue
        # Try to find MSF module
        if cve_id in msf_modules:
            discovered[cve_id] = msf_modules[cve_id]
            new_count += 1

    cfg["discovered_cves"] = discovered
    cfg["_cve_last_update"] = datetime.now().isoformat()
    _save_config(cfg)

    total = len(known) + len(discovered)
    console.print(
        f"\n  [green]✓[/green] Static CVEs:     [bold]{len(known)}[/bold]\n"
        f"  [green]✓[/green] Discovered CVEs:  [bold]{len(discovered)}[/bold] "
        f"([green]+{new_count} new[/green])\n"
        f"  [bold]Total coverage:   {total} CVEs → MSF modules[/bold]"
    )
    return new_count, total


def get_full_cve_map(config_file: Optional[Path] = None) -> dict:
    """Merge static CVE_TO_MSF with config.json discovered_cves."""
    from core.feed import CVE_TO_MSF
    base = dict(CVE_TO_MSF)
    try:
        cfg_path = config_file or CONFIG_FILE
        cfg = json.loads(cfg_path.read_text())
        extra = cfg.get("discovered_cves", {})
        base.update(extra)
    except Exception:
        pass
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Tool source update (git pull + rebuild)
# ─────────────────────────────────────────────────────────────────────────────

async def _git_pull(src_dir: Path, label: str = "") -> tuple[bool, str]:  # noqa: ARG001
    if not src_dir.exists():
        return False, "directory not found"
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "pull",
            cwd=str(src_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode(errors="replace").strip()
        ok = proc.returncode == 0
        return ok, output
    except Exception as exc:
        return False, str(exc)


async def check_script_update() -> tuple[bool, int, str]:
    """
    Check whether the crushgear git repo has new commits on the remote.
    Does a silent `git fetch` then counts commits in HEAD..origin/<branch>.
    Returns: (has_update, commit_count, latest_commit_subject)
    """
    try:
        # 1. Fetch remote quietly (no merge)
        fetch = await asyncio.create_subprocess_exec(
            "git", "fetch", "--quiet",
            cwd=str(CRUSHGEAR_DIR),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(fetch.wait(), timeout=15)

        # 2. Get current tracking branch (e.g. origin/main)
        branch_proc = await asyncio.create_subprocess_exec(
            "git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}",
            cwd=str(CRUSHGEAR_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        branch_out, _ = await asyncio.wait_for(branch_proc.communicate(), timeout=5)
        upstream = branch_out.decode(errors="replace").strip() or "origin/main"

        # 3. Count commits that are on remote but not local
        log_proc = await asyncio.create_subprocess_exec(
            "git", "log", f"HEAD..{upstream}", "--oneline",
            cwd=str(CRUSHGEAR_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        log_out, _ = await asyncio.wait_for(log_proc.communicate(), timeout=10)
        commits = [l for l in log_out.decode(errors="replace").splitlines() if l.strip()]
        return bool(commits), len(commits), (commits[0] if commits else "")
    except Exception:
        return False, 0, ""


async def update_script() -> tuple[bool, str]:
    """
    Pull the latest version of crushgear from git (git pull).
    Returns: (success, output_message)
    """
    return await _git_pull(CRUSHGEAR_DIR, "crushgear-script")


async def update_tool_sources(parent_dir: Path, token: str = "") -> list[dict]:
    """
    git pull every tool source directory, then re-run setup_tools.
    """
    console.rule("[bold]Tool Source Update[/bold]")

    SRC_DIRS = {
        "netexec":     parent_dir / "NetExec",
        "smbmap":      parent_dir / "smbmap-master",
        "amass":       parent_dir / "amass",
        "httpx":       parent_dir / "httpx",
        "nuclei":      parent_dir / "nuclei",
        "feroxbuster": parent_dir / "feroxbuster",
        "metasploit":  parent_dir / "metasploit-framework-master",
    }

    tasks = [
        _git_pull(src, name) for name, src in SRC_DIRS.items()
    ]
    pull_results = await asyncio.gather(*tasks)

    results = []
    table = Table(title="[bold]Git Pull Results[/bold]", show_lines=True)
    table.add_column("Tool", style="bold", min_width=14)
    table.add_column("Status", min_width=10)
    table.add_column("Output")

    for (name, _src), (ok, out) in zip(SRC_DIRS.items(), pull_results):
        status = "[green]OK[/green]" if ok else "[red]FAILED[/red]"
        short  = out.splitlines()[0][:80] if out else "-"
        table.add_row(name, status, short)
        results.append({"tool": name, "ok": ok, "output": out})  # type: ignore[possibly-undefined]

    console.print(table)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Startup check (fast, cached, non-blocking)
# ─────────────────────────────────────────────────────────────────────────────

async def startup_check(binaries: dict, token: str = "") -> list[dict]:
    """
    Quick version check shown at startup.
    Uses cached results if fresh enough.
    Returns list of tools needing update.
    """
    try:
        results = await asyncio.wait_for(
            check_tool_versions(binaries, token=token, use_cache=True),
            timeout=8,
        )
        return [r for r in results if r["needs_update"]]
    except asyncio.TimeoutError:
        return []
    except Exception:
        return []


async def ensure_nuclei_templates(binary: str) -> bool:
    """
    Ensure nuclei templates are downloaded and up-to-date.
    - Auto-downloads if templates are missing or fewer than 100 files found.
    - Auto-updates if templates are older than 7 days.
    Returns True if templates are ready to use.
    """
    # Nuclei v3 default template locations (in priority order)
    # Must match _find_template_dir() in wrappers/nuclei.py
    template_dirs = [
        Path.home() / ".local" / "nuclei-templates",           # v3 default (most common)
        Path.home() / ".local" / "share" / "nuclei-templates", # XDG compliant path
        Path.home() / "nuclei-templates",                       # manual / older install
        Path.home() / ".config" / "nuclei" / "templates",      # some v3 variants
        Path("/usr/share/nuclei-templates"),                    # system-wide
        Path("/opt/nuclei-templates"),                          # custom install
    ]

    template_dir: Optional[Path] = None
    template_count = 0

    for d in template_dirs:
        if d.exists() and d.is_dir():
            count = sum(1 for _ in d.rglob("*.yaml"))
            if count > 100:
                template_dir = d
                template_count = count
                break

    needs_download = template_dir is None
    needs_update = False
    age_days = 0.0

    if template_dir:
        age_days = (time.time() - template_dir.stat().st_mtime) / 86400
        needs_update = age_days > 7

    if needs_download:
        console.print(
            "[bold yellow]⚠  Nuclei templates not found — downloading now...[/bold yellow]"
        )
    elif needs_update:
        console.print(
            f"[dim]Nuclei templates: {template_count:,} templates "
            f"(last updated {age_days:.0f}d ago) — updating...[/dim]"
        )
    else:
        console.print(
            f"[dim]Nuclei templates: [green]{template_count:,}[/green] templates ready "
            f"({age_days:.0f}d old)[/dim]"
        )
        return True

    # Run nuclei -update-templates
    console.print(f"  [dim]Running: {binary} -update-templates[/dim]")
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, "-update-templates",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        output = stdout.decode(errors="replace").strip()
        if proc.returncode == 0:
            console.print("[green]  ✓ Nuclei templates updated successfully[/green]")
            return True
        else:
            console.print(
                f"[yellow]  ⚠ Template update exited {proc.returncode}[/yellow]\n"
                f"  [dim]{output[:300]}[/dim]"
            )
            return not needs_download  # usable if we had templates before
    except asyncio.TimeoutError:
        console.print("[red]  ✗ Template download timed out (300s)[/red]")
        return not needs_download
    except Exception as exc:
        console.print(f"[red]  ✗ Template update failed: {exc}[/red]")
        return not needs_download


def print_startup_notification(
    outdated: list[dict],
    cve_total: int,
    last_cve_update: str,
    script_update: tuple[bool, int, str] = (False, 0, ""),
):
    has_script_update, commit_count, latest_commit = script_update
    if not outdated and not last_cve_update and not has_script_update:
        return

    lines = []

    # ── CrushGear script update (highest priority) ───────────────────
    if has_script_update:
        lines.append(
            f" [bold bright_red]★ CrushGear script update tersedia![/bold bright_red]"
            f"  [dim]{commit_count} commit baru[/dim]"
        )
        if latest_commit:
            lines.append(f"   [dim]Latest: {latest_commit[:72]}[/dim]")
        lines.append(
            "   Run: [bold bright_green]python3 crushgear.py --update-script[/bold bright_green]"
        )
        lines.append("")

    # ── Tool updates ──────────────────────────────────────────────────
    if outdated:
        tools_str = ", ".join(
            f"[yellow]{r['tool']}[/yellow] {r['installed']}→{r['latest']}"
            for r in outdated
        )
        lines.append(f" Tool updates: {tools_str}")
        lines.append(" Run: [bold]python3 crushgear.py --update-tools[/bold]")

    # ── CVE coverage info ─────────────────────────────────────────────
    if last_cve_update:
        lines.append(
            f" CVE coverage: [bold]{cve_total} entries[/bold] "
            f"  Last updated: [dim]{last_cve_update[:10]}[/dim]"
        )
        lines.append(" Run: [bold]python3 crushgear.py --update-cves[/bold]  to refresh")

    if lines:
        border = "bright_red" if has_script_update else "yellow"
        title  = (
            "[bold bright_red]★ CrushGear Update Available ★[/bold bright_red]"
            if has_script_update
            else "[bold yellow]CrushGear Update Info[/bold yellow]"
        )
        console.print(Panel(
            "\n".join(lines),
            title=title,
            border_style=border,
            padding=(0, 2),
        ))
