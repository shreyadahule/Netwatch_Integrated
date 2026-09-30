from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class DNSRecord:
    """Represents one DNS lookup record."""

    id: Optional[int] = None
    domain: str = ""
    ip: str = ""
    timestamp: Optional[datetime] = None


@dataclass
class PingRecord:
    """Represents one ping result."""

    id: Optional[int] = None
    target: str = ""
    latency: Optional[float] = None
    status: str = ""
    timestamp: Optional[datetime] = None


@dataclass
class PortScanRecord:
    """Represents one port scan result."""

    id: Optional[int] = None
    target: str = ""
    port: int = 0
    status: str = ""
    service_name: str = ""
    timestamp: Optional[datetime] = None


@dataclass
class UsageRecord:
    """Represents one network usage sample."""

    id: Optional[int] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    upload_speed: float = 0.0
    download_speed: float = 0.0
    timestamp: Optional[datetime] = None


@dataclass
class ReportRecord:
    """Represents one generated report."""

    id: Optional[int] = None
    report_name: str = ""
    file_path: str = ""
    timestamp: Optional[datetime] = None


@dataclass
class URLScanRecord:
    """Represents one heuristic URL security scan."""

    id: Optional[int] = None
    url: str = ""
    risk_score: int = 0
    classification: str = ""
    reasons: str = ""
    timestamp: Optional[datetime] = None
