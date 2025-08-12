# classifier.py
from collections import defaultdict, deque
from typing import Dict, Tuple
import os
from datetime import datetime, timedelta
import joblib
import numpy as np
from config import MODEL_PATH, SCALER_PATH, ALERT_SCORE_THRESHOLD, SUSPICIOUS_SCORE_THRESHOLD

# Optional ML model
_model = None
_scaler = None

if os.path.exists(MODEL_PATH):
    try:
        _model = joblib.load(MODEL_PATH)
    except Exception:
        _model = None

if os.path.exists(SCALER_PATH):
    try:
        _scaler = joblib.load(SCALER_PATH)
    except Exception:
        _scaler = None

# Simple state for heuristic detection
_syn_counts = defaultdict(int)
_last_reset = datetime.utcnow()

BLACKLISTED_PORTS = {23, 2323, 3389, 4444, 5900}  # telnet, rdp, vnc, etc.
BLACKLISTED_IPS = set()  # extend via threat intel later

def _reset_if_needed():
    global _last_reset, _syn_counts
    if datetime.utcnow() - _last_reset > timedelta(seconds=30):
        _syn_counts = defaultdict(int)
        _last_reset = datetime.utcnow()

def _heuristic_features(pkt: Dict) -> np.ndarray:
    # Very tiny feature vector as example
    size = pkt.get("length", 0)
    dport = pkt.get("dport", 0) or 0
    sport = pkt.get("sport", 0) or 0
    proto = {"TCP":0, "UDP":1, "ICMP":2}.get(pkt.get("proto","TCP"),0)
    return np.array([size, dport, sport, proto], dtype=float).reshape(1,-1)

def classify_packet(pkt: Dict) -> Tuple[str, float]:
    """Return (label, score) where label in {'benign','suspicious','malicious'}"""
    # Heuristic checks
    _reset_if_needed()
    label = "benign"
    score = 0.1

    # Port check
    if (pkt.get("dport") in BLACKLISTED_PORTS) or (pkt.get("sport") in BLACKLISTED_PORTS):
        label = "suspicious"; score = max(score, 0.65)

    # SYN flood style (if TCP & flags contain 'S' without 'A')
    if pkt.get("proto") == "TCP" and pkt.get("tcp_flags") == "S":
        src = pkt.get("src")
        _syn_counts[src] += 1
        if _syn_counts[src] > 100:
            label = "malicious"; score = max(score, 0.9)

    # Blacklisted IP check
    if pkt.get("src") in BLACKLISTED_IPS:
        label = "malicious"; score = max(score, 0.95)

    # Optional ML override if model exists
    if _model is not None:
        feats = _heuristic_features(pkt)
        try:
            if _scaler is not None:
                feats = _scaler.transform(feats)
            prob = float(_model.predict_proba(feats)[0,1]) if hasattr(_model, "predict_proba") else float(_model.predict(feats)[0])
            # Map probability bands
            if prob >= ALERT_SCORE_THRESHOLD:
                return "malicious", prob
            elif prob >= SUSPICIOUS_SCORE_THRESHOLD:
                return "suspicious", prob
            else:
                return "benign", prob
        except Exception:
            pass

    return label, score
