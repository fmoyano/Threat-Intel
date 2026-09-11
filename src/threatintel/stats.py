from dataclasses import dataclass
from threatintel.models import IOCType, IOC

@dataclass
class Stats:
    indicators_processed: int
    unique_indicators: int
    duplicates: int
    count_by_type: dict[IOCType, int]

def compute_stats(loaded_iocs: list[IOC], processed_iocs: list[IOC]) -> Stats:
    indicators_processed = len(loaded_iocs)
    unique_indicators = len(processed_iocs)

    # For now, this works as the only reason why we remove iocs is because they're duplicates
    # If later we discard indicators for other reasons, this is not correct any longer
    duplicates = indicators_processed - unique_indicators

    count_by_type: dict[IOCType, int] = {ioc_type: 0 for ioc_type in IOCType}    
    for ioc in processed_iocs:
        count_by_type[ioc.type] += 1

    return Stats(indicators_processed, unique_indicators, duplicates, count_by_type)