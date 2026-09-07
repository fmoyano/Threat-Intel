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

ioc1 = IOC(
    IOCType.DOMAIN,
    "evil.com",
    {"feed_a"},
)

ioc2 = IOC(
    IOCType.DOMAIN,
    "evil.com",
    {"feed_b"},
)

print(ioc1 == ioc2)
