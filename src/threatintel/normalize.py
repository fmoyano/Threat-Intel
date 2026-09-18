import ipaddress
from urllib.parse import urlsplit, urlunsplit

from threatintel.models import IOC, IOCType
    

def normalize_ip_port(value: str) -> str:
    ip_port = value.split(":")
    if len(ip_port) != 2:
        raise ValueError("Incorrect IP:PORT format.")

    ip = normalize_ip(ip_port[0])

    if not ip_port[1]:
        raise ValueError("Empty port.")

    if not (ip_port[1].isnumeric() and ip_port[1].isascii()):
        raise ValueError("Expected numeric ascii integer for port.")

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
            raise ValueError("Labels cannot start or end with ""-"".")

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

def normalize_url(value: str) -> str:
    urlinfo = urlsplit(value)

    if urlinfo.scheme not in {"http", "https"}:
        raise ValueError("Unsupported scheme.")

    if not urlinfo.hostname:
        raise ValueError("Missing hostname.")

    # Accessing an out of range port or a
    # non-integer one will throw ValueError
    port = urlinfo.port    
    
    # url_info.hostname is already lowercase
    hostname = urlinfo.hostname

    hostname_with_no_dots = hostname.replace(".", "")
    potential_ipv4_address =   (hostname_with_no_dots.isnumeric() and
                                hostname_with_no_dots.isascii())
    potential_ipv6_address = ":" in hostname
    
    if potential_ipv4_address:
        hostname = normalize_ip(hostname)
    elif potential_ipv6_address:        
        hostname = normalize_ip(hostname)
        hostname = "[" + hostname + "]"
    else:
        hostname = normalize_domain(hostname)

    netloc = hostname
    if port is not None:
        netloc += ":" + str(port)

    if urlinfo.username is not None:
        userinfo = urlinfo.username

        if urlinfo.password is not None:
            userinfo += ":" + urlinfo.password

        netloc = userinfo + "@" + netloc    
 
    return urlunsplit(
        (urlinfo.scheme,
        netloc,
        urlinfo.path,
        urlinfo.query,
        urlinfo.fragment))


def normalize_ioc(ioc: IOC) -> IOC:
    if ioc.type == IOCType.DOMAIN:
        normalized_value = normalize_domain(ioc.value)
    elif ioc.type == IOCType.IP:
        normalized_value = normalize_ip(ioc.value)
    elif ioc.type == IOCType.SHA256:
        normalized_value = normalize_sha256(ioc.value)
    elif ioc.type == IOCType.IP_PORT:
        normalized_value = normalize_ip_port(ioc.value)
    elif ioc.type == IOCType.URL:
        normalized_value = normalize_url(ioc.value)
    else:
        raise ValueError(f"Unsupported IOC type: {ioc.type}")

    return IOC(ioc.type, normalized_value, set(ioc.sources))