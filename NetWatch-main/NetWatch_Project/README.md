# NetWatch — Network & URL Security Monitor

NetWatch is an integrated Python/Tkinter security utility that combines network diagnostics with heuristic malicious-URL analysis.

## Integrated features
- **Security Dashboard** — quick activity counters and recent URL assessments.
- **URL Security Analyzer** — 0–10 heuristic risk score, suspicious indicators, classification, and persistent history.
- DNS lookup with SQLite history.
- Ping monitoring with latency/status history.
- TCP scanning of common ports.
- Network traffic snapshots using `psutil`.
- Integrated PDF/text reporting including URL security results.
- SQLite persistence across sessions.

## URL analysis
The URL analyzer is rule-based. It checks indicators such as HTTP instead of HTTPS, IP-address URLs, `@`, unusual length, excessive subdomains, suspicious keywords, repeated special characters, and known URL shorteners. A score is an indicator of risk, **not proof that a URL is malicious or safe**.

## Requirements
- Python 3.10+
- `psutil`
- `reportlab` (optional for PDF reports)

Install:
```bash
pip install -r requirements.txt
```

Run:
```bash
python main.py
```

## Project structure
- `main.py` — entrypoint
- `gui/app.py` — integrated desktop interface
- `network/url_detector.py` — URL risk engine
- `network/dns.py` — DNS resolver
- `network/ping.py` — ping helper
- `network/scanner.py` — TCP port scanner
- `network/monitor.py` — traffic monitor
- `database/db.py` — SQLite persistence
- `database/models.py` — data models
- `reports/generator.py` — integrated report generation

## Safety / scope
Only scan systems and networks you own or are authorized to test. The URL module is a heuristic educational security feature and does not replace a reputation service, sandbox, or antivirus engine.
