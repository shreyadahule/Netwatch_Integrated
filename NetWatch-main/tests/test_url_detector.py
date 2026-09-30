import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "NetWatch_Project"))

from network.url_detector import URLDetector

def test_safe_looking_url():
    assert URLDetector.classification(URLDetector.check_url("https://example.com")[0]) == "SAFE-LOOKING"

def test_high_risk_indicators():
    score, reasons = URLDetector.check_url("http://192.168.1.1/login/verify_account")
    assert score >= 6
    assert reasons
