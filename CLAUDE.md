# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CrushGear is an **authorized penetration testing automation framework** that orchestrates 8 security tools in a 4-phase pipeline. It is designed for authorized security testing, CTF competitions, educational purposes, and security research only.

**Critical Context**: This is a security testing tool. All modifications must:
- Maintain compatibility with authorized security testing workflows
- Preserve the phased execution architecture
- Never reduce security controls or safety checks
- Follow responsible disclosure practices

## High-Level Architecture

### Phased Execution Pipeline

CrushGear uses a **sequential feed-forward architecture** where each phase consumes output from previous phases:

```
Phase 0 (Port Scanning)
  └─> nmap (2-stage: fast SYN scan → detailed service scan)
       ├─> Feed: open ports, services, OS detection
       │
Phase 1 (Reconnaissance) ← consumes nmap feed
  ├─> amass (subdomain enumeration from domains)
  └─> httpx (probe web services on nmap-discovered ports)
       ├─> Feed: discovered hosts, live URLs
       │
Phase 2 (Scanning & Enumeration) ← consumes Phase 0+1 feeds
  ├─> netexec (SMB/SSH/LDAP enum on hosts from amass + nmap port 445)
  ├─> smbmap (SMB share enum on SMB hosts)
  ├─> nuclei (vulnerability scan on httpx URLs)
  └─> feroxbuster (directory bruteforce on httpx URLs)
       ├─> Feed: CVE findings, shares, directories
       │
Phase 3 (Exploitation) ← consumes all previous feeds
  └─> metasploit (auto-exploit based on nuclei CVEs + nmap services)
       └─> Output: shells + auto post-exploitation
```

### Core Components

**Entry Point**: `crushgear.py`
- CLI argument parsing
- Config loading from `config.json`
- Binary path resolution (supports both system-installed and local `bin/` directory)
- LHOST/LPORT configuration with interactive network segment detection
- Orchestrates the entire phased execution via `core/runner.py`

**Runner** (`core/runner.py`):
- Async execution of tool phases using `asyncio.gather()`
- Phase factories: Phase 2 and 3 are built dynamically based on feed data
- Per-tool timeout management (configurable via `config.json`)
- Result collection and status tracking via `ToolResult` dataclass

**Feed System** (`core/feed.py`):
- Parses tool outputs into structured data for next phase
- Key parsers:
  - `parse_nmap()`: Extracts ports, services, OS from grepable format
  - `parse_httpx()`: Extracts live URLs from JSON output
  - `parse_nuclei()`: Extracts CVE findings from JSON output
  - `build_msf_rc()`: Generates Metasploit resource script from CVE findings
- CVE → Metasploit module mapping (188 static + auto-discovered from GitHub)

**Target System** (`core/target.py`):
- Auto-detects target type: IP, Domain, URL, CIDR
- DNS resolution for domains
- CIDR expansion for network ranges
- Unified `TargetInfo` dataclass used across all wrappers

**Wrappers** (`wrappers/*.py`):
- All tools inherit from `BaseTool` abstract class
- Each wrapper implements `build_command()` → returns command list or `[]` to skip
- Access to feed data via `self.feed` dict
- Credentials via `self.username` / `self.password`
- Special wrapper: `metasploit.py` generates `.rc` resource scripts dynamically

**Reporter** (`core/reporter.py`):
- Rich terminal output formatting
- Per-tool status indicators with color coding
- Summary tables: execution time, status, output files
- Credential summary extraction from tool outputs

**Updater** (`core/updater.py`):
- GitHub API integration for version checks
- CVE mapping updates from nuclei-templates + metasploit-framework repos
- Tool source updates via `git pull`
- Nuclei template management (auto-download/update)
- CrushGear script self-update

## Development Commands

### Running Scans

```bash
# Basic scan (all tools, all phases)
python3 crushgear.py -t <target>

# With credentials (for SMB/NetExec)
python3 crushgear.py -t 192.168.1.1 -u admin -p password

# Selective tools (skip phases)
python3 crushgear.py -t <target> --tools nmap,amass,httpx,nuclei

# Custom reverse shell config
python3 crushgear.py -t <target> --lhost 10.0.0.1 --lport 9001
```

### Setup & Diagnostics

```bash
# Install/build all tools
python3 crushgear.py --setup
# Or via installer:
bash install.sh                  # Pre-built binaries (recommended)
bash install.sh --full           # Build from source (includes full Metasploit)
bash install.sh --update         # Safe update: git pull + CVE update (no folder deletion)

# Check tool status
python3 crushgear.py --check

# Check for updates
python3 crushgear.py --check-updates

# Update CVE mapping
python3 crushgear.py --update-cves
python3 crushgear.py --update-cves --github-token <token>  # Higher rate limit

# Update tool sources (git pull all repos)
python3 crushgear.py --update-tools

# Update CrushGear script itself
python3 crushgear.py --update-script

# Fix missing tools only
bash install.sh --fix
```

### Testing

```bash
# Test single phase (modify crushgear.py temporarily)
python3 crushgear.py -t <target> --tools nmap

# Test feed parsing (check results directory)
python3 -c "from core.feed import parse_nmap; print(parse_nmap(Path('results/<dir>')))"

# Test CVE mapping
python3 -c "from core.updater import get_full_cve_map; print(get_full_cve_map(Path('config.json')))"
```

## Code Architecture Notes

### Binary Resolution Logic
- Check `config.json` binaries first (supports relative paths from project root)
- Fallback to system PATH via `shutil.which()`
- For tools like metasploit: supports symlinks in `bin/` pointing to external installs

### Feed Data Structure
Feed dict passed between phases:
```python
{
    "hosts": ["192.168.1.1", ...],          # from amass
    "urls": ["http://...", ...],            # from httpx
    "smb_hosts": ["192.168.1.1", ...],      # from nmap port 445
    "windows_hosts": [...],                 # from nmap OS detection
    "findings": [{                          # from nuclei
        "cve": "CVE-2021-44228",
        "host": "http://...",
        "severity": "critical",
        ...
    }],
    "nmap": {                               # from parse_nmap()
        "192.168.1.1": {
            "ports": [22, 80, 445],
            "services": {22: "ssh", 80: "http"},
            "products": {22: "OpenSSH 8.2"},
            "os_guess": "Linux 5.x"
        }
    },
    "extra_cve_map": {...}                  # CVE → MSF module mapping
}
```

### Async Execution Model
- All tools in same phase run in parallel via `asyncio.gather()`
- Phases run sequentially (must complete before next phase starts)
- Each tool gets independent timeout (no global timeout)
- Stdout/stderr captured in real-time and written to `results/{target}_{timestamp}/`

### Config File Structure
`config.json` contains:
```json
{
    "binaries": {
        "nmap": "/usr/bin/nmap",
        "amass": "bin/amass",           // relative to project root
        "msfconsole": "bin/msfconsole"
    },
    "timeouts": {
        "nmap": 900,
        "amass": 1800,
        "nuclei": 900,
        "default": 300
    },
    "lhost": "0.0.0.0",                 // or specific IP
    "lport": 4444,
    "discovered_cves": {...},           // auto-populated by --update-cves
    "_cve_last_update": "2025-01-15T..."
}
```

### Metasploit Integration
- Metasploit runs via resource scripts (`.rc` files)
- `build_msf_rc()` generates scripts dynamically from CVE findings
- Includes automatic post-exploitation: hashdump, cred dump, user enum
- LHOST/LPORT configured via interactive prompt if not specified
- Auto-kills processes holding LPORT before starting to prevent bind failures

## Important Implementation Details

### LHOST Detection
- Interactive prompt asks if target is same network segment
- Auto-detects local IPs via `ip` command (Linux) or `ifconfig` (macOS)
- Option to fetch public IP via `api.ipify.org` for cross-segment attacks
- Validates IP format and allows hostnames for tunneling scenarios (ngrok, etc.)

### Nmap 2-Phase Strategy
1. Fast SYN scan: `-p- --min-rate 2000` (all 65535 ports, no service detection)
2. Detailed scan: `-sV -sC -O` on discovered ports only
3. Includes extensive NSE scripts for AD/SMB/web vuln detection

### CVE Mapping System
- Static mapping: 188 CVEs → MSF modules hardcoded
- Dynamic discovery: queries GitHub for nuclei templates + MSF modules
- Updates cached in `config.json` under `discovered_cves`
- Merge logic: static + discovered, no duplicates

### Error Handling
- Tools that return non-zero exit code are marked `ERROR` but don't stop execution
- Missing binaries are `SKIPPED` (command returns empty list)
- Timeouts kill process and mark `ERROR` but save partial output
- All exceptions caught per-tool (isolation principle)

## File Naming Conventions

- Tool wrappers: `wrappers/{toolname}.py` (lowercase, underscores for multi-word like `httpx_tool.py`)
- Core modules: `core/{module}.py` (singular nouns: `runner`, `feed`, `target`)
- Output files: `results/{target}_{timestamp}/{tool}.txt` or `.json`
- Temp files: `tempfile.mkstemp(prefix="crushgear_", suffix=".rc")`

## Security Testing Guidelines

**This tool is for authorized security testing only.** When modifying:

1. **Never remove safety checks** in target validation or credential handling
2. **Preserve the phased architecture** - phases must execute sequentially
3. **Maintain feed isolation** - tools should only access data explicitly fed to them
4. **Keep credential logging minimal** - only store what's necessary for reports
5. **CVE mapping must be accurate** - test mappings against known vulnerable systems
6. **Metasploit auto-exploitation requires review** - new CVE mappings need validation

## Common Modification Scenarios

### Adding a New Tool

1. Create `wrappers/newtool.py` inheriting from `BaseTool`
2. Implement `build_command()` method
3. Register in appropriate phase in `crushgear.py` (phase1/phase2/phase3)
4. Add to `ALL_TOOLS` list
5. Add binary key to `BINARY_KEY_MAP`
6. Add default timeout to `TOOL_TIMEOUTS` in `runner.py`
7. Add color to `TOOL_COLORS` in `runner.py`
8. If tool generates structured output, add parser to `feed.py`

### Adding a New CVE Mapping

Edit `core/feed.py` → `STATIC_CVE_MAP` dict:
```python
STATIC_CVE_MAP = {
    "CVE-XXXX-XXXXX": "exploit/category/module_name",
    ...
}
```

Or rely on auto-discovery via `--update-cves` (recommended).

### Modifying Phase Logic

Edit `core/runner.py` → `run_phased()` function:
- Phase 0-1 are static lists
- Phase 2-3 use factory functions that receive feed dict
- All phases call `run_phase()` which handles parallel execution

### Changing Output Format

Edit `core/reporter.py`:
- `print_summary()` for final summary table
- `write_result_file()` for per-tool output files
- `print_credential_summary()` for credential extraction

## Dependencies

- **Python 3.9+** required
- Key libraries:
  - `rich` - terminal formatting
  - `jinja2` - Metasploit RC template rendering
  - `aiofiles` - async file I/O
- External tools (installed via `--setup`):
  - nmap (system package)
  - Go 1.21+ for building amass, httpx, nuclei
  - Rust/cargo for feroxbuster
  - Ruby 3.0+ for Metasploit (full source mode)

## Output Structure

All results saved to `results/{target}_{timestamp}/`:
```
results/192_168_1_1_20260223_143022/
├── nmap.txt          # grepable format
├── amass.txt         # discovered hosts
├── httpx.json        # live URLs + metadata
├── netexec.txt       # SMB enum results
├── smbmap.txt        # share listings
├── nuclei.json       # vulnerability findings
├── feroxbuster.txt   # discovered directories
└── metasploit.txt    # exploitation + post-exploit output
```

## Installation Modes

- **Default**: Pre-built binaries (fast, no compilation)
- **--full**: Build from source (includes full Metasploit with all modules)
- **--update**: Safe update via git pull (preserves local folders)
- **--fix**: Re-install only missing tools
- **--force**: Nuclear option - deletes and re-clones everything (use with caution)

## Troubleshooting Development Issues

### "Binary not found" errors
1. Run `python3 crushgear.py --check` to see status
2. Check `config.json` binaries section
3. Verify binary exists in `bin/` or system PATH
4. Re-run `python3 crushgear.py --setup` or `bash install.sh --fix`

### Phase feed not working
1. Check output file exists in results directory
2. Verify parser function in `feed.py` matches tool output format
3. Add debug prints to `collect_all_feed()` to trace feed data
4. Ensure tool wrapper saves output to correct filename

### Timeout too short
Edit `config.json` timeouts section or modify `TOOL_TIMEOUTS` in `runner.py`

### CVE mapping not working
1. Run `python3 crushgear.py --update-cves`
2. Check `config.json` for `discovered_cves` section
3. Verify nuclei output includes CVE IDs
4. Review `build_msf_rc()` in `feed.py` for mapping logic
