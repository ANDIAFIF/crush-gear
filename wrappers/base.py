from abc import ABC, abstractmethod
from core.target import TargetInfo


class BaseTool(ABC):
    name: str = "base"

    def __init__(
        self,
        target: TargetInfo,
        binary: str,
        username: str = "",
        password: str = "",
        feed: dict | None = None,
    ):
        self.target = target
        self.binary = binary
        self.username = username
        self.password = password
        # Feed data from previous phases:
        # {
        #   "hosts":   [str, ...]   ← from amass
        #   "urls":    [str, ...]   ← from httpx (live web targets)
        #   "findings":[{cve, host, ...}]  ← from nuclei
        # }
        self.feed: dict = feed or {}

    @abstractmethod
    def build_command(self) -> list[str]:
        """Return the command list to execute, or empty list to skip."""
        ...

    def _cred_args(self) -> list[str]:
        args = []
        if self.username:
            args += ["-u", self.username]
        if self.password:
            args += ["-p", self.password]
        return args

    @property
    def feed_hosts(self) -> list[str]:
        return self.feed.get("hosts", [])

    @property
    def feed_urls(self) -> list[str]:
        return self.feed.get("urls", [])

    @property
    def feed_findings(self) -> list[dict]:
        return self.feed.get("findings", [])
