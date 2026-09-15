import requests

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

def fetch_recent_iocs(auth_key: str, days: int = 1) -> dict:
    if days < 1 or days > 7:
        raise ValueError("Days must be in the range 1-7.")

    response = requests.post(THREATFOX_API_URL, 
        headers = {"Auth-Key": auth_key},
        json = {"query": "get_iocs", "days": days},
        timeout = 5)

    response.raise_for_status()
    return response.json()