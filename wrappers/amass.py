from wrappers.base import BaseTool
from core.target import TargetType


class AmassTool(BaseTool):
    name = "amass"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target

        # amass v4/v5: `amass enum` is the subdomain enumeration subcommand.
        # -passive  → OSINT-only, no active DNS bruteforce
        # -timeout  → hard cap in MINUTES; without this amass can hang forever
        # -json     → one JSON object per line, required by feed parser
        #
        # Known behaviour: amass v5 exits with code 1 even on success when
        # some API sources fail. The runner marks this ERROR but the output
        # file still contains valid hostnames — this is expected.

        if t.type == TargetType.CIDR:
            return [
                self.binary, "enum",
                "-passive",
                "-cidr",    t.cidr,
                "-timeout", "25",   # minutes
                "-json",
            ]

        # IP, DOMAIN, URL → use host for DNS-based enumeration
        domain = t.host
        return [
            self.binary, "enum",
            "-passive",
            "-d",       domain,
            "-timeout", "25",       # minutes
            "-json",
        ]
