# app.py - Flask backend for Live Packet Analyzer (with PDF export + assets + siren hooks)
import io
import random
from datetime import datetime, timezone
from collections import deque
from threading import Lock
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file, send_from_directory

# ---- Config ----
try:
    import config
    CAPTURE_INTERFACE = getattr(config, "CAPTURE_INTERFACE", None)
    BPF_FILTER = getattr(config, "BPF_FILTER", "")
except Exception:
    CAPTURE_INTERFACE = None
    BPF_FILTER = ""

# ---- Alerts / Siren integration ----
_current_siren_mode = "safe"
def _noop(*args, **kwargs): ...
siren_set_mode = _noop
siren_get_state = lambda : {"mode": _current_siren_mode}
siren_trigger_event = _noop
try:
    from alerts import set_mode as _set_mode  # optional
    from alerts import get_state as _get_state
    from alerts import trigger_event as _trigger
    def siren_set_mode(mode:str):
        global _current_siren_mode
        _set_mode(mode)
        _current_siren_mode = mode
    def siren_get_state():
        try:
            return _get_state()
        except Exception:
            return {"mode": _current_siren_mode}
    def siren_trigger_event(mode:str):
        _trigger(mode)
except Exception:
    def siren_set_mode(mode:str):
        global _current_siren_mode
        _current_siren_mode = mode
    def siren_get_state():
        return {"mode": _current_siren_mode}
    def siren_trigger_event(mode:str):
        global _current_siren_mode
        _current_siren_mode = mode

# ---- In-memory stores ----
PACKETS = deque(maxlen=1200)   # last 1200 packets
ALERTS  = deque(maxlen=500)
SERIES  = deque(maxlen=180)    # per-second buckets (last 3 minutes)
COUNTS  = {"total":0, "safe":0, "suspicious":0, "malicious":0}
lock = Lock()

def _now_sec():
    return int(datetime.now(timezone.utc).timestamp())

def _iso_now():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")

def _touch_buckets():
    """Ensure SERIES has a bucket for current second (fill gaps with zeros)."""
    now = _now_sec()
    if not SERIES:
        SERIES.append({"t": now, "safe":0, "suspicious":0, "malicious":0, "total":0})
        return
    last_t = SERIES[-1]["t"]
    if now == last_t:
        return
    for t in range(last_t+1, now+1):
        SERIES.append({"t": t, "safe":0, "suspicious":0, "malicious":0, "total":0})
    # decide siren from the most recent completed bucket
    prev = SERIES[-2] if len(SERIES) >= 2 else None
    if prev:
        if prev["malicious"] > 0:
            siren_set_mode("high")
        elif prev["suspicious"] > 0:
            siren_set_mode("suspicious")
        else:
            siren_set_mode("safe")

def _record_packet(packet:dict):
    label = (packet.get("label") or "safe").lower()
    if label not in ("safe","suspicious","malicious"):
        label = "safe"
    with lock:
        _touch_buckets()
        PACKETS.append(packet)
        COUNTS["total"] += 1
        COUNTS[label] += 1
        SERIES[-1][label] += 1
        SERIES[-1]["total"] += 1
        if label in ("suspicious","malicious"):
            ALERTS.append({"ts": packet["ts"], "src": packet.get("src"), "label": label})
    # immediate siren event (backend state)
    if label == "malicious":
        siren_trigger_event("high")
    elif label == "suspicious":
        siren_trigger_event("suspicious")
    else:
        siren_trigger_event("safe")

# ---- Flask ----
BASE_DIR = Path(__file__).resolve().parent
ASSETS_DIR = BASE_DIR / "assets"

app = Flask(__name__, template_folder="templates", static_folder="static")

# Serve your /assets (so /assets/sounds/xxx.mp3 works)
@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(ASSETS_DIR, filename)

@app.route("/")
def index():
    return render_template("index.html", iface=CAPTURE_INTERFACE or "auto", bpf=BPF_FILTER)

@app.get("/api/packets")
def api_packets():
    with lock:
        return jsonify(list(PACKETS))

@app.get("/api/alerts")
def api_alerts():
    with lock:
        return jsonify(list(ALERTS))

@app.get("/api/siren")
def api_siren_get():
    state = siren_get_state()
    mode = state.get("mode", "safe")
    return jsonify({"mode": mode})

@app.post("/api/siren")
def api_siren_post():
    data = request.get_json(force=True, silent=True) or {}
    mode = data.get("mode","safe")
    siren_set_mode(mode)
    return jsonify({"ok": True, "mode": mode})

@app.post("/api/inject")
def api_inject():
    """Used by simulate_stream.py to push synthetic traffic."""
    data = request.get_json(force=True, silent=True) or {}
    label = (data.get("label") or "safe").lower()
    pkt = {
        "ts": _iso_now(),
        "src": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
        "dst": f"172.16.{random.randint(0,31)}.{random.randint(1,254)}",
        "proto": random.choice(["TCP","UDP","ICMP"]),
        "sport": random.randint(1024,65535),
        "dport": random.choice([22,53,80,443,3389,8080]),
        "length": random.randint(60,1500),
        "label": label,
        "score": {"safe":0.01,"suspicious":0.62,"malicious":0.93}.get(label, 0.02)
    }
    _record_packet(pkt)
    return jsonify({"ok": True})

@app.get("/api/stats")
def api_stats():
    with lock:
        _touch_buckets()
        labels = [datetime.fromtimestamp(b["t"], tz=timezone.utc).strftime("%H:%M:%S") for b in SERIES]
        series = {
            "labels": labels,
            "total": [b["total"] for b in SERIES],
            "safe": [b["safe"] for b in SERIES],
            "suspicious": [b["suspicious"] for b in SERIES],
            "malicious": [b["malicious"] for b in SERIES],
        }
        counts = dict(COUNTS)
    return jsonify({"series": series, "counts": counts})

# -------- PDF EXPORT --------
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import mm

def _filter_packets(filter_key:str):
    with lock:
        if filter_key == "all":
            data = list(PACKETS)
        else:
            data = [p for p in PACKETS if (p.get("label") or "safe").lower() == filter_key]
    return data

def _counts_for(data):
    c = {"total": len(data), "safe":0, "suspicious":0, "malicious":0}
    for p in data:
        c[(p.get("label") or "safe").lower()] += 1
    return c

def _pdf_filename(filter_key:str):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"live_packet_report_{filter_key}_{ts}.pdf"

@app.get("/api/export")
def api_export_pdf():
    """
    /api/export?filter=all|safe|suspicious|malicious
    Returns a generated PDF of current logs.
    """
    filter_key = (request.args.get("filter") or "all").lower()
    if filter_key not in ("all","safe","suspicious","malicious"):
        filter_key = "all"

    rows = _filter_packets(filter_key)
    counts = _counts_for(rows)

    # Build PDF in-memory
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=14*mm,
        rightMargin=14*mm,
        topMargin=16*mm,
        bottomMargin=16*mm,
        title="Live Packet Analyzer Report"
    )

    styles = getSampleStyleSheet()
    title = Paragraph("Live Packet Analyzer — Traffic Report", styles["Title"])
    meta1 = Paragraph(f"Filter: <b>{filter_key.title()}</b>", styles["Normal"])
    meta2 = Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"])
    SpacerSmall = Spacer(0, 6)

    # Summary table
    summary_data = [
        ["Total", "Safe", "Suspicious", "Malicious"],
        [str(counts["total"]), str(counts["safe"]), str(counts["suspicious"]), str(counts["malicious"])]
    ]
    summary = Table(summary_data, colWidths=[30*mm, 30*mm, 30*mm, 30*mm])
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0b1730")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,0), 6),
        ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#1e293b")),
    ]))

    # Logs table
    table_head = ["Time","Src","Dst","Proto","SP","DP","Len","Label","Score"]
    data = [table_head]
    for p in rows:
        data.append([
            p.get("ts",""),
            p.get("src",""),
            p.get("dst",""),
            p.get("proto",""),
            p.get("sport",""),
            p.get("dport",""),
            p.get("length",""),
            (p.get("label") or "").title(),
            f'{p.get("score","")}'
        ])

    col_widths = [22*mm, 28*mm, 28*mm, 14*mm, 12*mm, 12*mm, 14*mm, 22*mm, 16*mm]
    logs = Table(data, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0b1730")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 9),
        ("ALIGN", (0,0), (-1,0), "CENTER"),

        ("FONTSIZE", (0,1), (-1,-1), 8),
        ("TEXTCOLOR", (0,1), (-1,-1), colors.HexColor("#0a0e1a")),
        ("ALIGN", (0,1), (-1,-1), "CENTER"),
        ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#1e293b")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#edf2ff"), colors.HexColor("#eaf0ff")]),
    ])

    # Color the label column cells
    label_col = 7
    for i, p in enumerate(rows, start=1):
        lab = (p.get("label") or "safe").lower()
        if lab == "malicious":
            bg = colors.HexColor("#ffe5e7"); fg = colors.HexColor("#b91c1c")
        elif lab == "suspicious":
            bg = colors.HexColor("#fff3d6"); fg = colors.HexColor("#b45309")
        else:
            bg = colors.HexColor("#dcfce7"); fg = colors.HexColor("#166534")
        style.add("BACKGROUND", (label_col, i), (label_col, i), bg)
        style.add("TEXTCOLOR", (label_col, i), (label_col, i), fg)
        style.add("FONTNAME", (label_col, i), (label_col, i), "Helvetica-Bold")

    logs.setStyle(style)

    elements = [
        title, Spacer(0, 4),
        meta1, meta2, SpacerSmall,
        summary, Spacer(0, 10),
        Paragraph("Logs", styles["Heading2"]),
        logs
    ]

    # Header/Footer
    def _draw_header_footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#1e293b"))
        canvas.setFillColor(colors.HexColor("#0f172a"))
        # top line
        canvas.line(doc.leftMargin, doc.height + doc.topMargin,
                    doc.width + doc.leftMargin, doc.height + doc.topMargin)
        # footer
        canvas.setFillColor(colors.HexColor("#334155"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(doc.leftMargin, 10*mm, "Live Packet Analyzer — generated by backend")
        canvas.drawRightString(doc.leftMargin + doc.width, 10*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(elements, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
    buf.seek(0)
    filename = _pdf_filename(filter_key)
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)

# ---- Optional: hook a live sniffer if available ----
try:
    from packet_sniffer import start_sniffing  # optional
    def _on_live_packet(pkt_dict):
        _record_packet(pkt_dict)
    try:
        start_sniffing(callback=_on_live_packet)
    except Exception:
        pass
except Exception:
    pass

if __name__ == "__main__":
    _touch_buckets()
    app.run(host="0.0.0.0", port=5000, threaded=True)
