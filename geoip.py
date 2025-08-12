# geoip.py
import requests
from config import GEOIP_ENABLED, GEOIP_ENDPOINT

def lookup(ip: str):
    if not GEOIP_ENABLED:
        return None
    try:
        r = requests.get(GEOIP_ENDPOINT + ip, timeout=3)
        if r.status_code == 200:
            j = r.json()
            if j.get("status") == "success":
                return {
                    "lat": j.get("lat"),
                    "lon": j.get("lon"),
                    "country": j.get("country"),
                    "city": j.get("city"),
                    "isp": j.get("isp")
                }
    except Exception:
        return None
    return None
