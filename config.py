# config.py
import os

# General
DEBUG = False
MAX_PACKETS = int(os.getenv("LPA_MAX_PACKETS", "2000"))
ALERT_SCORE_THRESHOLD = float(os.getenv("LPA_ALERT_THRESHOLD", "0.85"))
SUSPICIOUS_SCORE_THRESHOLD = float(os.getenv("LPA_SUSPICIOUS_THRESHOLD", "0.6"))
CAPTURE_INTERFACE = os.getenv("LPA_IFACE", None)
BPF_FILTER = os.getenv("LPA_BPF", "ip")
PROMISCUOUS = os.getenv("LPA_PROMISCUOUS", "1") == "1"

# Resolve project root for portable paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Siren / Sound settings
SIREN_ENABLED = True
SIREN_HIGH_MP3 = os.path.join(BASE_DIR, "assets", "sounds", "high_danger.mp3")
SIREN_SUSPICIOUS_MP3 = os.path.join(BASE_DIR, "assets", "sounds", "suspicious_beep.mp3")

# Modes: high | suspicious | safe
DEFAULT_SIREN_MODE = os.getenv("LPA_DEFAULT_MODE", "safe")

# Paths
LOG_ALERTS = os.path.join(BASE_DIR, "logs", "alerts.log")
LOG_PACKETS = os.path.join(BASE_DIR, "logs", "packet_analysis.log")
