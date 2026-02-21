from wrappers.base import BaseTool
from core.target import TargetType


# NSE scripts for targeted AD/SMB vulnerability detection.
# These run ON TOP of -sC default scripts (no conflict, additive).
# Organized by category for clarity.
AD_SMB_SCRIPTS = ",".join([
    # SMB vulnerability checks
    "smb-vuln-ms17-010",     # EternalBlue — check before Metasploit
    "smb-vuln-ms08-067",     # MS08-067 — legacy but common in labs
    "smb-vuln-ms10-054",     # BlueScreen via malformed SMB (informational)
    "smb-vuln-ms10-061",     # Print Spooler impersonation
    "smb-security-mode",     # Check if SMB signing is required/disabled
    "smb2-security-mode",    # SMBv2 signing status (critical for NTLM relay)
    # SMB enumeration
    "smb-enum-shares",       # Enumerate shares + permissions (deeper than -sC)
    "smb-enum-users",        # Enumerate local/domain users via SMB
    "smb-enum-groups",       # Enumerate local groups
    "smb-enum-domains",      # Enumerate Active Directory domain info
    "smb-enum-sessions",     # Active SMB sessions
    "smb-os-discovery",      # Detailed OS + domain discovery
    # LDAP / Active Directory
    "ldap-rootdse",          # LDAP root DSE — domain, forest, naming contexts
    "ldap-search",           # Generic LDAP search for AD objects
    # RDP
    "rdp-vuln-ms12-020",     # MS12-020 RDP DoS/info (still common in labs)
    "rdp-enum-encryption",   # Check RDP encryption level
    # SSL/TLS
    "ssl-heartbleed",        # CVE-2014-0160 Heartbleed check
    "ssl-poodle",            # CVE-2014-3566 POODLE check
    "ssl-cert",              # Certificate info (SANs, expiry, org)
    "ssl-enum-ciphers",      # Cipher suite enumeration (weak ciphers)
    # HTTP
    "http-auth-finder",      # Detect HTTP auth methods (NTLM, Basic, Digest)
    "http-title",            # Page title (already in -sC but explicit is safer)
    "http-methods",          # Allowed HTTP methods (PUT/DELETE = file upload risk)
    "http-shellshock",       # CVE-2014-6271 Shellshock check
    "http-robots.txt",       # Robots.txt content discovery
    # FTP
    "ftp-anon",              # Anonymous FTP login (already in -sC, explicit)
    "ftp-vuln-cve2010-4221", # ProFTPD remote code exec
    # SNMP
    "snmp-info",             # SNMP system info (community strings)
    "snmp-interfaces",       # Network interfaces via SNMP
    # VNC
    "vnc-info",              # VNC version + auth method
    "vnc-brute",             # VNC password bruteforce (only runs if open)
    # MySQL
    "mysql-info",            # MySQL version + auth
    "mysql-empty-password",  # Check root with empty password
    # MSSQL
    "ms-sql-info",           # MSSQL version + instance info
    "ms-sql-empty-password", # SA account with empty password
])


class NmapTool(BaseTool):
    name = "nmap"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target

        if t.type == TargetType.CIDR:
            target_str = t.cidr
        else:
            target_str = t.host

        return [
            self.binary,
            "-sV",               # service/version detection
            "-sC",               # default NSE scripts (broad baseline)
            "-O",                # OS detection (requires root)
            "--open",            # show only open ports (less noise)
            "-T4",               # aggressive timing (safe for LAN; use T3 for WAN)
            "-Pn",               # skip ping — works on firewalled/Windows hosts
            "--version-intensity", "7",  # thorough version detection (0-9, default=7)
            "-p", (
                # ── Standard services ────────────────────────────────
                "21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,"
                "464,465,587,593,631,636,993,995,"
                # ── Active Directory / Windows ────────────────────────
                "3268,3269,5985,5986,47001,"
                "49152,49153,49154,49155,49156,49157,"
                # ── Remote access ────────────────────────────────────
                "3389,5900,5901,5902,5903,"
                # ── Databases ────────────────────────────────────────
                "1433,1521,3306,5432,6379,7474,8086,"
                "9200,9300,11211,27017,27018,"
                # ── Web / App servers ────────────────────────────────
                "80,443,1080,3000,4848,5000,7001,7002,7443,7777,"
                "8000,8008,8080,8081,8082,8083,8088,8090,8443,8444,"
                "8888,8983,9000,9090,9091,10000,10443,"
                # ── DevOps / Cloud ───────────────────────────────────
                "2375,2376,4243,6443,8001,8500,9092,9093,9100,9418,"
                "15672,16686,5601,"
                # ── Other ────────────────────────────────────────────
                "512,513,514,1099,1723,2049,2181,3690,4444,161,162"
            ),
            # ── NSE: targeted AD/SMB/web vulnerability scripts ───────
            "--script",          AD_SMB_SCRIPTS,
            # ── Output ───────────────────────────────────────────────
            "-oG", "-",          # grepable output to stdout (required by feed parser)
            "--reason",          # show why port is in its state
            # ── Reliability / performance ────────────────────────────
            "--script-timeout",  "15s",  # NSE scripts won't hang indefinitely
            "--min-parallelism", "10",   # minimum probe parallelism (faster on LAN)
            "--max-retries",     "2",    # limit retries per probe
            "--host-timeout",    "30m",  # max time per host (prevents single host blocking scan)
            target_str,
        ]
