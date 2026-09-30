from __future__ import annotations

import psutil
import time
from typing import Tuple


class NetworkMonitor:
    """Collect network usage statistics via psutil."""

    def __init__(self) -> None:
        net = psutil.net_io_counters()
        self._last_bytes_sent = net.bytes_sent
        self._last_bytes_recv = net.bytes_recv
        self._last_update = time.time()

    def get_usage(self) -> Tuple[int, int, float, float]:
        net = psutil.net_io_counters()
        current_time = time.time()
        elapsed = max(current_time - self._last_update, 1e-6)

        bytes_sent = net.bytes_sent
        bytes_recv = net.bytes_recv
        upload_speed = max((bytes_sent - self._last_bytes_sent) / elapsed, 0.0)
        download_speed = max((bytes_recv - self._last_bytes_recv) / elapsed, 0.0)

        self._last_bytes_sent = bytes_sent
        self._last_bytes_recv = bytes_recv
        self._last_update = current_time
        return bytes_sent, bytes_recv, upload_speed, download_speed
