# Live Packet Analyzer

A real-time network packet analyzer and threat monitor built with Python and Flask. It classifies traffic as **Safe**, **Suspicious**, or **Malicious**, plays **custom siren sounds** for alerts, and provides **one-click PDF exports** of logs (All, Safe, Suspicious, Malicious). Includes a traffic **simulator** for easy demos.

---

## Features

* Live dashboard with auto-updating table and charts
* Three-level classification: Safe, Suspicious, Malicious
* Custom browser sirens for Suspicious and Malicious events
* One-click PDF reports:

  * All logs (total)
  * Safe only
  * Suspicious only
  * Malicious only
* Socket.IO streaming for smooth UI updates
* Optional traffic simulator to demo without sniffing
* Lightweight REST APIs for integration

---

## Tech Stack

* **Backend:** Python, Flask, Flask-SocketIO, Eventlet
* **Networking:** Scapy (optional when sniffing)
* **Data:** Pandas
* **PDF:** ReportLab
* **Audio (browser):** HTML5 Audio
* **Frontend:** Vanilla JS, HTML, CSS

---

## Project Structure

```
live-packet-analyzer/
├─ app.py                      # Flask app (API, sockets, PDF export, siren config)
├─ simulate_stream.py          # Traffic simulator (injects mixed events)
├─ index.html                  # Dashboard UI
├─ requirements.txt            # Python dependencies
├─ static/
│  ├─ css/
│  │  └─ main.css              # Styles
│  ├─ audio/
│  │  └─ sirens/               # Put your .mp3/.wav here
│  └─ img/                     # Optional screenshots, logos
└─ .gitattributes              # (Recommended) LFS tracking for large assets
```

---

## Prerequisites

* Python **3.11**
* Windows 10/11, macOS, or Linux
* If you plan to sniff live traffic:

  * **Windows:** install **Npcap** (in WinPcap API-compatible mode)
  * **Linux/macOS:** run the sniffer with sufficient privileges (e.g., `sudo`)
* For large media assets (sirens, images), **Git LFS** is recommended

---

## Quick Start (Windows)

```powershell
# 1) Clone your repo
git clone https://github.com/syed-abdul-mateen/live-packet-analyzer.git
cd live-packet-analyzer

# 2) Create & activate a virtual environment
py -3.11 -m venv .venv
.\.venv\Scripts\activate

# 3) Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4) Run the app
python app.py
# App will print the URLs (e.g., http://127.0.0.1:5000)

# 5) (Optional) In another terminal, start the simulator
.\.venv\Scripts\activate
python simulate_stream.py
```

Open the dashboard at `http://127.0.0.1:5000`.

---

## Configuring Siren Sounds

1. Place your audio files here:

```
static/audio/sirens/
  ├─ malicious.mp3
  └─ suspicious.mp3
```

2. If you prefer different filenames or a different folder, update the siren configuration near the top of **`app.py`** (look for constants such as `SIREN_BASE_PATH`, `MALICIOUS_SIREN`, `SUSPICIOUS_SIREN`).
3. Refresh the browser once after changing files.

> Note: Browsers may block autoplay. Click anywhere on the page once to allow audio if needed.

---

## PDF Export

In the dashboard header you will find four buttons:

* **Download All Logs (PDF)** – all records and totals
* **Download Safe (PDF)** – only Safe records
* **Download Suspicious (PDF)** – only Suspicious records
* **Download Malicious (PDF)** – only Malicious records

Each generates a professional PDF using ReportLab and triggers a download in your browser.

---

## Using the Simulator

If you do not want to sniff real traffic, use:

```bash
python simulate_stream.py
```

It sends mixed events (Safe/Suspicious/Malicious) into the running server so you can see the UI, sounds, counters, and PDF exports working.

---

## APIs (High-Level)

* `GET /api/packets` – latest packets/logs for the table
* `GET /api/stats` – counts per severity and totals
* `GET /api/alerts` – recent alert feed
* `GET /api/siren` – configuration for audio files
* `POST /api/inject` – used by the simulator to push events
* `GET /api/export?scope=all|safe|suspicious|malicious` – generates a PDF report

Socket stream: the dashboard subscribes via Socket.IO for live updates.

---

## Troubleshooting

**ReportLab not found**
Run `pip install -r requirements.txt` again (ensure the venv is active).

**Sirens not playing**

* Confirm files exist under `static/audio/sirens/` and the names match the config.
* Click the page once to satisfy browser autoplay rules.
* Check browser console for 404s (missing file path).
* Ensure volume is up and not muted in the browser tab.
* Clear cache (hard refresh).

**No live packets when sniffing**

* Windows: install **Npcap** and run PowerShell/CMD as Administrator.
* Linux/macOS: run with `sudo` or proper capabilities.
* Otherwise, use `simulate_stream.py` to verify everything else.

**Development server warning**
Flask’s built-in server is for development only. For production, run behind a proper WSGI server/reverse proxy.

---

## Git LFS (Recommended for Audio/Images)

```bash
git lfs install
git lfs track "*.mp3" "*.wav" "*.png" "*.jpg"
git add .gitattributes
git add static/audio/sirens/*.mp3 static/audio/sirens/*.wav static/img/*
git commit -m "Add siren audio and images via LFS"
git push origin main
```

---

## Security Notice

This project is for educational and demo purposes. If you enable live capture, ensure you have authorization on the network you analyze and comply with local laws and organizational policies.

---

## Roadmap

* Configurable rules and thresholds from the UI
* Persistence to SQLite/CSV for long-running sessions
* Advanced reports with charts in the PDF
* Interface and process selection for sniffing
* Docker packaging

---

## License

MIT (recommended). Add a `LICENSE` file if you wish to open-source.

---

## Acknowledgments

Built with the open-source Python ecosystem: Flask, Socket.IO, Scapy, Pandas, ReportLab.
