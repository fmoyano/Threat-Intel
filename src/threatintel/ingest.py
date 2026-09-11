import json
from threatintel.models import IOC
from threatintel.parser import parse_iocs

def load_iocs_from_json(path: str) -> list[IOC]:
    with open(path, "r", encoding="utf-8") as file:
        return parse_iocs(json.load(file))