from __future__ import annotations

import socket
from typing import List, Tuple

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
}


class PortScanner:
    """Simple TCP port scanner."""

    @staticmethod
    def scan_port(target: str, port: int, timeout: float = 1.0) -> Tuple[int, str, str]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.connect((target, port))
                return port, "Open", SERVICE_NAMES.get(port, "Unknown")
            except OSError:
                return port, "Closed", SERVICE_NAMES.get(port, "Unknown")

    @staticmethod
    def scan_ports(target: str, ports: List[int]) -> List[Tuple[int, str, str]]:
        results: List[Tuple[int, str, str]] = []
        for port in ports:
            results.append(PortScanner.scan_port(target, port))
        return results

    @staticmethod
    def common_ports() -> List[int]:
        return COMMON_PORTS.copy()
