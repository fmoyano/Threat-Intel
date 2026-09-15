from threatintel.parser import parse_ioc
from threatintel.models import IOC, IOCType

MAPPED_TYPES = {"domain": IOCType.DOMAIN.value, "sha256_hash": IOCType.SHA256.value}

def threatfox_adapt_ioc_list(data: dict) -> list[IOC]:

    if not isinstance(data, dict) or not data or data.get("query_status", "error") != "ok":
        raise ValueError("Malformed input.")

    actual_data = data.get("data")
    if not isinstance(actual_data, list):
        raise ValueError("Missing IOC list.")

    adapted_data = []
    for d in actual_data:
        if not isinstance(d, dict):
            raise ValueError("Expected dictionary for IOC entry.")
       
        if "ioc_type" not in d or not isinstance(d["ioc_type"], str):
            raise ValueError("ioc_type field missing or with wrong type.")

        if d["ioc_type"] not in MAPPED_TYPES:
            continue

        if "ioc" not in d:
            raise ValueError("Missing required IOC field.")

        new_dict = {"type": MAPPED_TYPES[d["ioc_type"]], "value": d["ioc"], "source": "threatfox"}
        adapted_data.append(parse_ioc(new_dict))

    return adapted_data