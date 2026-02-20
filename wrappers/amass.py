from wrappers.base import BaseTool
from core.target import TargetInfo, TargetType


class AmassTool(BaseTool):
    name = "amass"

    def build_command(self) -> list[str]:
        if not self.binary:
            return []

        t = self.target

        if t.type == TargetType.CIDR:
            return [self.binary, "enum", "-cidr", t.cidr]

        # For IP, URL, or DOMAIN use the host
        domain = t.host
        return [self.binary, "enum", "-passive", "-d", domain]
