import re
import socket
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse


class TargetType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    CIDR = "cidr"


@dataclass
class TargetInfo:
    raw: str
    type: TargetType
    host: str
    ip: str = ""
    url: str = ""
    cidr: str = ""
    hosts: list = field(default_factory=list)


def _resolve_host(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""


def _expand_cidr(cidr: str) -> list[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return []


def parse_target(raw: str) -> TargetInfo:
    raw = raw.strip()

    # URL detection
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        ip = _resolve_host(host) if not _is_ip(host) else host
        return TargetInfo(
            raw=raw,
            type=TargetType.URL,
            host=host,
            ip=ip,
            url=raw,
        )

    # CIDR detection
    if "/" in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
            hosts = _expand_cidr(raw)
            return TargetInfo(
                raw=raw,
                type=TargetType.CIDR,
                host=raw,
                cidr=raw,
                hosts=hosts,
            )
        except ValueError:
            pass

    # IP detection
    if _is_ip(raw):
        return TargetInfo(
            raw=raw,
            type=TargetType.IP,
            host=raw,
            ip=raw,
            url=f"http://{raw}",
        )

    # Domain
    ip = _resolve_host(raw)
    return TargetInfo(
        raw=raw,
        type=TargetType.DOMAIN,
        host=raw,
        ip=ip,
        url=f"http://{raw}",
    )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
