from threatintel.deduplicate import deduplicate_iocs
from threatintel.models import IOC
from threatintel.normalize import normalize_ioc


def process_iocs(iocs: list[IOC]) -> list[IOC]:
    return deduplicate_iocs([normalize_ioc(ioc) for ioc in iocs])