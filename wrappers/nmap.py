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
            "-p", "21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,"
                  "465,587,631,636,993,995,1433,1521,1723,2049,3306,3389,"
                  "3690,4444,4848,5000,5432,5900,5985,5986,6379,7001,7443,"
                  "8000,8080,8081,8443,8888,9000,9090,9200,9300,10000,"
                  "27017,27018,47001,49152",
            "-oG", "-",     # grepable output to stdout for easy parsing
            "--reason",
            target_str,
        ]
