# alerts.py - Pygame-backed siren with debounce so it plays reliably
import time
from threading import Lock

try:
    import pygame
    pygame.mixer.init()
except Exception as e:
    pygame = None  # allow server to run even without audio

import config

# preload sounds if pygame is available
SOUNDS = {}
if pygame:
    try:
        SOUNDS["high"] = config.SIREN_HIGH_MP3
        SOUNDS["suspicious"] = config.SIREN_SUSPICIOUS_MP3
        SOUNDS["safe"] = config.SIREN_SAFE_MP3
    except Exception:
        SOUNDS["high"] = getattr(config, "SIREN_HIGH_MP3", "")
        SOUNDS["suspicious"] = getattr(config, "SIREN_SUSPICIOUS_MP3", "")
        SOUNDS["safe"] = getattr(config, "SIREN_SAFE_MP3", "")

_state = {"mode": "safe"}
_last_play = {"high": 0.0, "suspicious": 0.0, "safe": 0.0}
lock = Lock()

# minimum seconds between same-level plays
THROTTLE = {"high": 3.0, "suspicious": 2.0, "safe": 1.0}

def _play(mode: str):
    if not pygame:
        return
    path = SOUNDS.get(mode)
    if not path:
        return
    try:
        pygame.mixer.music.load(path)
        pygame.mixer.music.play()
    except Exception:
        # keep server stable if audio fails
        pass

def set_mode(mode: str):
    mode = mode.lower()
    if mode not in ("safe","suspicious","high"):
        mode = "safe"
    with lock:
        prev = _state["mode"]
        _state["mode"] = mode
        # play when mode changes "upwards"
        order = {"safe":0, "suspicious":1, "high":2}
        if order.get(mode,0) > order.get(prev,0):
            _play(mode)

def trigger_event(mode: str):
    """Called on every packet; plays with debounce."""
    mode = mode.lower()
    if mode not in ("safe","suspicious","high"):
        mode = "safe"
    now = time.time()
    with lock:
        # always keep current mode for UI
        _state["mode"] = mode
        last = _last_play.get(mode, 0.0)
        if (now - last) >= THROTTLE.get(mode, 2.0):
            _play(mode)
            _last_play[mode] = now

def get_state():
    with lock:
        return dict(_state)
