from threatintel.models import IOC, IOCType

def parse_ioc(data: dict) -> IOC:
    if not isinstance(data, dict):
        raise ValueError("IOC entry must be an object.")

    if not {"type", "value", "source"}.issubset(data):
        raise ValueError("Missing required field.")

    if not isinstance(data["type"], str) or not isinstance(data["value"], str) or not isinstance(data["source"], str):
        raise ValueError("IOC fields type, value and source must be strings.")

    return IOC(IOCType(data["type"]), data["value"], {data["source"]})

def parse_iocs(data: list[dict]) -> list[IOC]:
    if not isinstance(data, list):
        raise ValueError("IOC data must be a list.")

    return [parse_ioc(d) for d in data]