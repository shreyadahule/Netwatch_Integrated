from __future__ import annotations

import socket
from typing import Optional


class DNSHandler:
    """Simple DNS resolver wrapper."""

    @staticmethod
    def resolve(domain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None
