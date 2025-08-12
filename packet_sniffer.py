# packet_sniffer.py
import time
from typing import List, Dict
from alerts import trigger_event

# In-memory stores used by the dashboard
_PACKETS: List[Dict] = []
_ALERTS: List[Dict] = []

MAX_PACKETS = 2000
MAX_ALERTS = 500

# Stats window for the chart
SERIES_WINDOW_SEC = 180  # last 3 minutes
BIN_SIZE_SEC = 5         # 5-second bins


def _canonical_label(lbl: str) -> str:
    l = (lbl or "").lower()
    if l in ("malicious", "high", "danger", "attack"):
        return "malicious"
    if l in ("suspicious", "anomalous", "warning"):
        return "suspicious"
    # everything else treated as safe/normal traffic
    return "safe"


def get_packets():
    return _PACKETS[-MAX_PACKETS:]


def get_alerts():
    return _ALERTS[-MAX_ALERTS:]


def _now_str():
    return time.strftime("%H:%M:%S")


def inject_packet(label: str = "malicious") -> Dict:
    """
    Simulator helper. Pretends a packet was captured and classified.
    Adds to PACKETS, maybe ALERTS, and triggers the siren for non-safe labels.
    """
    lbl = _canonical_label(label)
    score = 0.95 if lbl == "malicious" else 0.72 if lbl == "suspicious" else 0.08
    now = time.time()

    pkt = {
        "t": now,                  # epoch seconds (for charts)
        "ts": _now_str(),          # display string
        "src": "10.0.0.2",
        "dst": "10.0.0.20",
        "proto": "TCP",
        "sport": 4444,
        "dport": 445,
        "length": 512,
        "label": lbl,
        "score": score,
    }
    _PACKETS.append(pkt)
    if len(_PACKETS) > MAX_PACKETS:
        del _PACKETS[:-MAX_PACKETS]

    if lbl in ("malicious", "suspicious"):
        _ALERTS.append(pkt)
        if len(_ALERTS) > MAX_ALERTS:
            del _ALERTS[:-MAX_ALERTS]
        trigger_event("high" if lbl == "malicious" else "suspicious")

    return pkt


# Placeholder for future: real sniffing using scapy
def start_sniffer_once():
    # not used for simulator; keep as a stub
    pass


def get_stats() -> Dict:
    """
    Returns aggregate counters and a rolling time-series for charts.
    {
      total, by_label: {safe, suspicious, malicious},
      series: { t0, bin_size, points: [{total, safe, suspicious, malicious}, ...] }
    }
    """
    # Totals
    total = len(_PACKETS)
    by_label = {"safe": 0, "suspicious": 0, "malicious": 0}
    for p in _PACKETS:
        by_label[_canonical_label(p.get("label"))] += 1

    # Time-series
    now = time.time()
    start = now - SERIES_WINDOW_SEC
    bins = max(1, SERIES_WINDOW_SEC // BIN_SIZE_SEC)
    points = [{"total": 0, "safe": 0, "suspicious": 0, "malicious": 0} for _ in range(bins)]

    for p in _PACKETS:
        t = p.get("t") or now
        if t < start:
            continue
        idx = int((t - start) // BIN_SIZE_SEC)
        if 0 <= idx < bins:
            lbl = _canonical_label(p.get("label"))
            points[idx]["total"] += 1
            points[idx][lbl] += 1

    return {
        "total": total,
        "by_label": by_label,
        "series": {
            "t0": start,
            "bin_size": BIN_SIZE_SEC,
            "points": points,
        },
    }
