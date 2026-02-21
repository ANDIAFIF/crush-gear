import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetType


# File patterns to auto-download if found during recursive smbmap scan.
# These are high-value files commonly found in internal SMB shares.
INTERESTING_PATTERNS = "|".join([
    r".*\.xml",        # configuration files (web.config, etc.)
    r".*\.config",     # application configs
    r".*\.conf",       # unix-style config files
    r".*\.ini",        # initialization files (often contain credentials)
    r".*\.env",        # environment files (.env — DB passwords, API keys)
    r".*\.bak",        # backup files (copies of sensitive originals)
    r".*password.*",   # anything named "password"
    r".*passwd.*",     # /etc/passwd-like files
    r".*secret.*",     # secret files
    r".*credential.*", # credential stores
    r".*\.kdbx",       # KeePass database
    r".*\.key",        # private keys
    r".*\.pem",        # PEM certificates/keys
    r".*\.pfx",        # PKCS#12 cert bundles (contains private key)
    r".*\.p12",        # PKCS#12 (same)
    r".*id_rsa.*",     # SSH private keys
    r".*\.rdp",        # RDP connection files (may contain saved passwords)
    r".*unattend.*",   # Windows unattended install (contains base64 admin password)
    r".*sysprep.*",    # sysprep files (contain admin credentials)
    r".*Groups\.xml",  # GPP Groups.xml (contains encrypted credentials)
    r".*datasources.*",# JBOSS/Tomcat datasource configs (DB credentials)
    r".*\.sql",        # SQL dumps (data + sometimes credentials)
    r".*\.ps1",        # PowerShell scripts (may hardcode credentials)
    r".*\.bat",        # Batch scripts (may hardcode credentials)
    r".*\.sh",         # Shell scripts (may hardcode credentials)
])


class SmbmapTool(BaseTool):
    name = "smbmap"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target

        # ── Resolve target hosts ─────────────────────────────────────
        # Priority: nmap-confirmed SMB hosts (port 445) → amass hosts → CIDR all IPs
        smb_hosts   = self.feed.get("smb_hosts", [])
        amass_hosts = self.feed.get("hosts", [])

        if smb_hosts:
            all_hosts = smb_hosts
        elif amass_hosts:
            all_hosts = amass_hosts
        elif t.type == TargetType.CIDR:
            all_hosts = [str(ip) for ip in t.hosts[:254]]
        else:
            all_hosts = [t.host]

        # ── Credential flags ─────────────────────────────────────────
        # Always pass explicit auth — avoids smbmap prompting or failing silently.
        # domain: inject if discovered from netexec feed
        if self.username and self.password:
            cred_flags = f"-u '{self.username}' -p '{self.password}'"
            domain = self.feed.get("domain", "")
            if domain:
                cred_flags += f" -d '{domain}'"
        else:
            # Explicit null/anonymous session
            cred_flags = "-u '' -p ''"

        # ── smbmap flags ─────────────────────────────────────────────
        # -R              : recursive listing (enumerate directories and files)
        # --depth 8       : how deep to recurse (8 = thorough, realistic for pentest)
        # -g              : grep/print interesting file content inline
        # -A <pattern>    : auto-download files matching regex pattern
        # --no-write-check: skip write access checks (less IDS noise, faster)
        # -q              : quiet mode (suppress banner)
        base_flags = f"-R --depth 8 -A '{INTERESTING_PATTERNS}' -q"

        # ── Write host list to temp file ─────────────────────────────
        hosts_file = Path(tempfile.mktemp(prefix="crushgear_smb_", suffix=".txt"))
        hosts_file.write_text("\n".join(all_hosts) + "\n")

        # ── Per-host loop with clear separators ──────────────────────
        # smbmap does not support multi-host natively, so loop in bash.
        # Each host gets its own section header so output is readable.
        loop_cmd = (
            f"while IFS= read -r h; do "
            f"  echo ''; "
            f"  echo '=== smbmap: '\"$h\"' ==='; "
            f"  {self.binary} {cred_flags} -H \"$h\" {base_flags} 2>&1; "
            f"  echo ''; "
            f"done < {hosts_file}"
        )
        return ["bash", "-c", loop_cmd]
