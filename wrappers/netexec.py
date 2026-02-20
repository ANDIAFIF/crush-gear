import tempfile
from pathlib import Path
from wrappers.base import BaseTool
from core.target import TargetInfo, TargetType


class NetExecTool(BaseTool):
    name = "netexec"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target

        # Prefer SMB-specific hosts from nmap feed
        smb_hosts = self.feed.get("smb_hosts", [])
        amass_hosts = self.feed.get("hosts", [])
        all_hosts = smb_hosts or amass_hosts

        if all_hosts:
            # Write to temp file — nxc accepts a file of hosts
            hosts_file = Path(tempfile.mktemp(prefix="crushgear_nxc_", suffix=".txt"))
            hosts_file.write_text("\n".join(all_hosts) + "\n")
            target_str = str(hosts_file)
        elif t.type == TargetType.CIDR:
            target_str = t.cidr
        else:
            target_str = t.host

        cmd = [self.binary, "smb", target_str]
        cmd += self._cred_args()
        cmd += ["--shares", "--users"]
        return cmd
