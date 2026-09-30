from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import List, Tuple


class URLDetector:
    """Heuristic malicious-URL detector integrated with NetWatch.

    This is a rule-based indicator scanner, not a definitive malware/phishing verdict.
    """

    SUSPICIOUS_WORDS = [
        "login", "verify", "verification", "password", "account",
        "update", "secure", "bank", "free", "winner", "claim", "confirm",
    ]
    SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"]

    @classmethod
    def check_url(cls, url: str) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []
        url = url.strip()

        if not url:
            return 0, ["URL is empty"]

        test_url = url if url.startswith(("http://", "https://")) else "http://" + url
        parsed = urlparse(test_url)
        domain = parsed.netloc.lower()
        hostname = parsed.hostname or ""

        if test_url.startswith("http://"):
            score += 1
            reasons.append("Uses HTTP instead of HTTPS")

        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_pattern, domain.split(":")[0]):
            score += 3
            reasons.append("Uses an IP address instead of a domain")

        if "@" in url:
            score += 3
            reasons.append("Contains '@' symbol")

        if len(url) > 100:
            score += 2
            reasons.append("URL is unusually long")

        if hostname.count(".") >= 3:
            score += 2
            reasons.append("Contains too many subdomains")

        found_words = [word for word in cls.SUSPICIOUS_WORDS if word in url.lower()]
        if found_words:
            score += min(len(found_words), 3)
            reasons.append("Suspicious keywords: " + ", ".join(found_words))

        special_chars = url.count("-") + url.count("_")
        if special_chars >= 5:
            score += 2
            reasons.append("Contains many special characters")

        if any(shortener in hostname for shortener in cls.SHORTENERS):
            score += 2
            reasons.append("Uses a URL shortening service")

        return min(score, 10), reasons

    @staticmethod
    def classification(score: int) -> str:
        if score <= 2:
            return "SAFE-LOOKING"
        if score <= 5:
            return "SUSPICIOUS"
        return "POTENTIALLY MALICIOUS"
