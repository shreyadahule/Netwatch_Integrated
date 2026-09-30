# NetWatch — Integrated Network & URL Security Monitor

This final project combines the original **NetWatch network utility suite** with the supplied **Malicious URL Detector** into one desktop application.

### Run
1. Open a terminal in `NetWatch_Project`.
2. Install dependencies:
   `pip install -r requirements.txt`
3. Start:
   `python main.py`

### What was integrated
- URL Security Analyzer (from the supplied `mk.py`) is now a first-class NetWatch module.
- URL scans are stored in the same SQLite database as DNS, ping, port and network-usage data.
- Dashboard shows URL activity plus network-security activity.
- Reports now include URL security scan history.
- Existing DNS, ping, port scanning and network monitoring remain available.
- Background operations are protected with error handling so a failed network operation does not crash the UI.

### Important
URL detection uses heuristics. It raises indicators based on URL structure and keywords; it is not a definitive malware/phishing verdict. Only scan systems and networks you own or are authorized to test.
