import os

THREATFOX_AUTH_KEY_ENV_VAR = "THREATFOX_AUTH_KEY"

def get_threatfox_auth_key() -> str:
    if key := os.getenv(THREATFOX_AUTH_KEY_ENV_VAR):
        return key

    raise RuntimeError("ThreatFox key not configured/found.")