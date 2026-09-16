from dataclasses import dataclass
from enum import Enum


class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    SHA256 = "sha256"
    IP_PORT = "ip:port"

@dataclass
class IOC:
    type: IOCType
    value: str
    sources: set[str]