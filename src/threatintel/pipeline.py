from threatintel.models import IOC
from threatintel.normalize import normalize_ioc
from threatintel.deduplicate import deduplicate_iocs

def process_iocs(iocs: list[IOC]) -> list[IOC]:
    return deduplicate_iocs([normalize_ioc(ioc) for ioc in iocs])