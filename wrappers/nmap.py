import subprocess
import re
import shutil
import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetType


# NSE scripts for targeted AD/SMB/web/network vulnerability detection.
# These run ON TOP of -sC default scripts (additive, no conflict).
AD_SMB_SCRIPTS = ",".join([
    # SMB vulnerability checks
    "smb-vuln-ms17-010",     # EternalBlue — check before Metasploit
    "smb-vuln-ms08-067",     # MS08-067 — legacy but common in labs
    "smb-vuln-ms10-054",     # BlueScreen via malformed SMB (informational)
    "smb-vuln-ms10-061",     # Print Spooler impersonation
    "smb-security-mode",     # Check if SMB signing required/disabled
    "smb2-security-mode",    # SMBv2 signing status (critical for NTLM relay)
    # SMB enumeration
    "smb-enum-shares",       # Enumerate shares + permissions
    "smb-enum-users",        # Enumerate local/domain users via SMB
    "smb-enum-groups",       # Enumerate local groups
    "smb-enum-domains",      # Enumerate Active Directory domain info
    "smb-enum-sessions",     # Active SMB sessions
    "smb-os-discovery",      # Detailed OS + domain discovery
    # LDAP / Active Directory
    "ldap-rootdse",          # LDAP root DSE — domain, forest, naming contexts
    "ldap-search",           # Generic LDAP search for AD objects
    # RDP
    "rdp-vuln-ms12-020",     # MS12-020 RDP DoS/info
    "rdp-enum-encryption",   # Check RDP encryption level
    # SSL/TLS
    "ssl-heartbleed",        # CVE-2014-0160 Heartbleed check
    "ssl-poodle",            # CVE-2014-3566 POODLE check
    "ssl-cert",              # Certificate info (SANs, expiry, org)
    "ssl-enum-ciphers",      # Cipher suite enumeration (weak ciphers)
    "ssl-dh-params",         # Logjam / weak Diffie-Hellman check
    # HTTP
    "http-auth-finder",      # Detect HTTP auth methods (NTLM, Basic, Digest)
    "http-title",            # Page title
    "http-methods",          # Allowed HTTP methods (PUT/DELETE = file upload risk)
    "http-shellshock",       # CVE-2014-6271 Shellshock check
    "http-robots.txt",       # Robots.txt content discovery
    "http-server-header",    # Extract Server header (fingerprint)
    "http-open-redirect",    # Open redirect detection
    "http-php-version",      # PHP version disclosure
    # FTP
    "ftp-anon",              # Anonymous FTP login
    "ftp-vuln-cve2010-4221", # ProFTPD remote code exec
    # SNMP
    "snmp-info",             # SNMP system info (community strings)
    "snmp-interfaces",       # Network interfaces via SNMP
    "snmp-brute",            # Brute-force community strings
    # VNC
    "vnc-info",              # VNC version + auth method
    "vnc-brute",             # VNC password bruteforce
    # MySQL
    "mysql-info",            # MySQL version + auth
    "mysql-empty-password",  # Check root with empty password
    "mysql-databases",       # List accessible databases
    # MSSQL
    "ms-sql-info",           # MSSQL version + instance info
    "ms-sql-empty-password", # SA account with empty password
    "ms-sql-config",         # MSSQL configuration
    # Oracle
    "oracle-tns-version",    # Oracle TNS version
    # Redis
    "redis-info",            # Redis server info (unauthenticated)
    # MongoDB
    "mongodb-info",          # MongoDB server info
    "mongodb-databases",     # List accessible databases
    # SSH
    "ssh-auth-methods",      # Supported SSH authentication methods
    "ssh-hostkey",           # SSH host key fingerprint
    # Misc
    "banner",                # Generic banner grab (any service)
    "finger",                # Finger protocol user enum
    "rpcinfo",               # RPC service enumeration
    "nfs-ls",                # NFS share listing
    "nfs-showmount",         # NFS showmount
])

# ─────────────────────────────────────────────────────────────────────────────
# Two-Phase Nmap Strategy
# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 (FAST): SYN scan ALL 65535 ports with high rate → find every open port
# Phase 2 (DEEP): Service detection + NSE scripts ONLY on ports found in phase 1
#
# Result: discovers non-standard ports automatically (no manual list needed)
# while keeping the deep scan fast by limiting it to confirmed open ports.
# ─────────────────────────────────────────────────────────────────────────────

def _run_fast_portscan(binary: str, target_str: str) -> list[str]:
    """
    Phase 1: Quick SYN scan of all 65535 TCP ports.
    Returns list of open port numbers as strings.
    Falls back to top-1000 defaults on failure.
    """
    try:
        result = subprocess.run(
            [
                binary,
                "-sS" if shutil.which("id") else "-sT",  # SYN if root, else connect
                "-T4",
                "-Pn",
                "--open",
                "-p-",                # all 65535 ports
                "--min-rate", "2000", # fast discovery (safe for LAN; reduce for WAN)
                "--max-retries", "1",
                "--host-timeout", "5m",
                "--oG", "-",          # grepable to stdout
                target_str,
            ],
            capture_output=True, text=True, timeout=360,
        )
        ports: list[str] = []
        for line in result.stdout.splitlines():
            # Grepable format: "Ports: 22/open/tcp, 80/open/tcp, ..."
            m = re.search(r"Ports:\s+(.+)", line)
            if not m:
                continue
            for entry in m.group(1).split(","):
                parts = entry.strip().split("/")
                if len(parts) >= 2 and parts[1] == "open":
                    ports.append(parts[0])
        return ports if ports else []
    except Exception:
        return []


class NmapTool(BaseTool):
    name = "nmap"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target
        target_str = t.cidr if t.type == TargetType.CIDR else t.host

        # ── Phase 1: fast full-port discovery ───────────────────────
        open_ports = _run_fast_portscan(self.binary, target_str)

        if open_ports:
            # Only scan ports that are actually open → deep scan is fast
            port_spec = ",".join(open_ports)
        else:
            # Fallback: top-10000 ports covers 99.99% of real targets
            port_spec = None  # will use --top-ports

        # ── Phase 2: deep scan (service + OS + NSE) on open ports ───
        cmd = [
            self.binary,
            "-sV",                     # service/version detection
            "-sC",                     # default NSE scripts (broad baseline)
            "-O",                      # OS detection (requires root)
            "--open",                  # show only open ports
            "-T4",                     # aggressive timing
            "-Pn",                     # skip host ping (works on firewalled hosts)
            "--version-intensity", "7",# thorough version probe (0-9)
        ]

        if port_spec:
            cmd += ["-p", port_spec]
        else:
            cmd += ["--top-ports", "10000"]

        cmd += [
            # ── NSE scripts — AD, SMB, web, network vuln checks ──────
            "--script",          AD_SMB_SCRIPTS,
            # ── Output ───────────────────────────────────────────────
            "-oG", "-",          # grepable stdout (required by feed parser)
            "--reason",          # why port is in its state
            # ── Reliability ──────────────────────────────────────────
            "--script-timeout",  "20s",
            "--min-parallelism", "10",
            "--max-retries",     "2",
            "--host-timeout",    "45m",
            target_str,
        ]
        return cmd
