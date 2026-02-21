from wrappers.base import BaseTool
from core.target import TargetInfo, TargetType


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
            "-sV",          # service/version detection
            "-sC",          # default NSE scripts
            "-O",           # OS detection
            "--open",       # show only open ports
            "-T4",          # aggressive timing (faster on LAN; use T3 for WAN)
            "-Pn",          # skip ping/host discovery (works on firewalled hosts)
            "-p", (
                # Common services
                "21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,"
                "465,587,631,636,993,995,"
                # Windows AD / SMB / WinRM
                "464,593,636,3268,3269,5985,5986,47001,49152,49153,49154,"
                # Remote access
                "3389,5900,5901,5902,5903,"
                # Databases
                "1433,1521,3306,5432,6379,7474,8086,9200,9300,11211,27017,27018,"
                # Web / App servers + DevOps
                "80,443,1080,3000,4848,5000,7001,7002,7443,7777,"
                "8000,8008,8080,8081,8082,8083,8088,8090,8443,8444,"
                "8888,8983,9000,9090,9091,10000,10443,"
                "2375,2376,4243,6443,8001,8500,9092,9093,9100,9418,"
                "15672,16686,5601,"
                # Other
                "512,513,514,1099,1723,2049,2181,3690,4444,6443,8161"
            ),
            "-oG", "-",     # grepable output to stdout (required by feed parser)
            "--reason",
            target_str,
        ]
