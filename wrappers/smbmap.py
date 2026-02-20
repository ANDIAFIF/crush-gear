import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetInfo, TargetType


class SmbmapTool(BaseTool):
    name = "smbmap"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target

        # Prefer SMB hosts from nmap, then amass, then original target
        smb_hosts = self.feed.get("smb_hosts", [])
        amass_hosts = self.feed.get("hosts", [])
        all_hosts = smb_hosts or amass_hosts

        if len(all_hosts) > 1:
            # Build a bash one-liner to loop smbmap over all hosts
            cred_part = ""
            if self.username:
                cred_part += f" -u '{self.username}'"
            if self.password:
                cred_part += f" -p '{self.password}'"
            # Write host list to a temp file
            hosts_file = Path(tempfile.mktemp(prefix="crushgear_smb_", suffix=".txt"))
            hosts_file.write_text("\n".join(all_hosts) + "\n")
            loop_cmd = (
                f"while IFS= read -r h; do "
                f"  {self.binary}{cred_part} -H \"$h\" 2>&1; "
                f"done < {hosts_file}"
            )
            return ["bash", "-c", loop_cmd]
        elif len(all_hosts) == 1:
            host = all_hosts[0]
        elif t.type == TargetType.CIDR:
            host = t.hosts[0] if t.hosts else t.cidr
        else:
            host = t.host

        cmd = [self.binary, "-H", host]
        if self.username:
            cmd += ["-u", self.username]
        if self.password:
            cmd += ["-p", self.password]
        return cmd
