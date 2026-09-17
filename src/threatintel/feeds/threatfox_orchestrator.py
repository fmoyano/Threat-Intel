from threatintel.config import get_threatfox_auth_key
from threatintel.feeds.threatfox_adapter import threatfox_adapt_ioc_list
from threatintel.feeds.threatfox_client import fetch_recent_iocs
from threatintel.models import IOC


def get_threatfox_iocs(days: int = 1) -> list[IOC]:        
    return threatfox_adapt_ioc_list(fetch_recent_iocs(get_threatfox_auth_key(), days))