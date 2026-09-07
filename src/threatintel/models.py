from enum import Enum
from dataclasses import dataclass

class IOCType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    SHA256 = "sha256"

@dataclass
class IOC:
    type: IOCType
    value: str
    sources: set[str]