import ipaddress

from threatintel.models import IOC, IOCType


def normalize_ip_port(value: str) -> str:
    ip_port = value.split(":")
    if len(ip_port) != 2:
        raise ValueError("IP:PORT format malformed.")

    ip = normalize_ip(ip_port[0])
    port = int(ip_port[1])

    min_port_number_allowed = 0
    max_port_number_allowed = 65535
    if port < min_port_number_allowed or port > max_port_number_allowed:
        raise ValueError(f"{port} is not a valid port number between {min_port_number_allowed} \
            and {max_port_number_allowed}")

    return ":".join([ip, str(port)])

def normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))

def normalize_domain(value: str) -> str:    
    domain = value.lower().removesuffix(".")

    if len(domain) > 253:
        raise ValueError("Domain name too long: expected 253 characters or less.")

    labels = domain.split(".")
    if len(labels) < 2:
        raise ValueError("Too few labels for domain: expected 2 labels at least.")

    for label in labels:
        if len(label) > 63:
            raise ValueError(f"Label {label} too long: expected 63 characters or less for labels.")
        if not label:
            raise ValueError("Empty labels not allowed")
        if label[0] == "-" or label[-1] == "-":
            raise ValueError(f"Labels cannot start or end with ""-"".")

        for ch in label:
            if not ((ch.isalnum() and ch.isascii()) or ch == "-"):
                raise ValueError(f"Character {ch} no allowed in label {label}")

    return ".".join(labels)

def normalize_sha256(value: str) -> str:
    sha256 = value.lower()

    if len(sha256) != 64:
        raise ValueError("Valid sha256 must be 64 hexadecimal characters.")

    for ch in sha256:
        if ch not in "abcdef0123456789":
            raise ValueError(f"Char {ch} not valid hex digit.")

    return sha256

def normalize_ioc(ioc: IOC) -> IOC:
    if ioc.type == IOCType.DOMAIN:
        normalized_value = normalize_domain(ioc.value)
    elif ioc.type == IOCType.IP:
        normalized_value = normalize_ip(ioc.value)
    elif ioc.type == IOCType.SHA256:
        normalized_value = normalize_sha256(ioc.value)
    elif ioc.type == IOCType.IP_PORT:
        normalized_value = normalize_ip_port(ioc.value)
    else:
        raise ValueError(f"Unsupported IOC type: {ioc.type}")

    return IOC(ioc.type, normalized_value, set(ioc.sources))