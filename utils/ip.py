# utils/ip.py
import re

def is_private_ip(ip: str) -> bool:
    # RFC1918
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        bool(re.match(r"^172\.(1[6-9]|2[0-9]|3[01])\.", ip))
    )
