from wrappers.base import BaseTool
from core.target import TargetType


class AmassTool(BaseTool):
    name = "amass"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target

        # amass v4/v5: `amass enum` is the subdomain enumeration subcommand.
        #
        # Flag notes:
        # -passive  → OSINT-only, no active DNS probing (safe, no target noise)
        # -active   → active DNS enumeration (zone transfers, cert transparency, etc.)
        # -brute    → DNS bruteforce with built-in wordlist (active mode only)
        # -ip       → include resolved IP addresses in output (feeds nmap later)
        # -src      → show which OSINT source found each hostname
        # -timeout  → hard cap in MINUTES; without this amass can hang for hours
        # -json     → one JSON object per line, required by feed parser
        # -r        → custom resolvers (use reliable public DNS)
        #
        # Known behaviour: amass v5 exits with code 1 even on success when
        # some API sources fail. The runner marks this ERROR but the output
        # file still contains valid hostnames — this is expected and normal.

        # Reliable public DNS resolvers (faster + more complete than ISP DNS)
        resolvers = "8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1,9.9.9.9,208.67.222.222"

        if t.type == TargetType.CIDR:
            # For CIDR: passive OSINT to find hostnames resolving to these IPs
            # Active mode + brute doesn't help for RFC1918 internal ranges,
            # but passive checks certificate transparency and reverse DNS.
            # Note: -ip and -src removed in Amass v5
            return [
                self.binary, "enum",
                "-passive",
                "-cidr",    t.cidr,
                "-timeout", "25",    # minutes
                "-json",
                "-r",       resolvers,
            ]

        # IP, DOMAIN, URL → domain-based enumeration
        domain = t.host
        # Note: -ip, -src, -rf removed in Amass v5
        return [
            self.binary, "enum",
            "-passive",              # OSINT sources (no DNS bruteforce noise)
            "-active",               # active: zone transfer, cert transparency checks
            "-brute",                # DNS bruteforce with built-in wordlist
            "-d",       domain,
            "-timeout", "25",        # hard cap in minutes
            "-json",
            "-r",       resolvers,   # use fast public resolvers
        ]
