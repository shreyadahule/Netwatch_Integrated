from __future__ import annotations

import platform
import re
import subprocess
from typing import Optional, Tuple


class PingHandler:
    """Cross-platform wrapper for one ICMP ping."""

    @staticmethod
    def ping(target: str, timeout: int = 2) -> Tuple[bool, Optional[float]]:
        try:
            if platform.system().lower() == "windows":
                command = ["ping", "-n", "1", "-w", str(timeout * 1000), target]
            else:
                command = ["ping", "-c", "1", "-W", str(timeout), target]

            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            output = (completed.stdout or "") + "\n" + (completed.stderr or "")
            success = completed.returncode == 0
            match = re.search(r"(?:time[=<]|Average = )\s*([0-9]+(?:\.[0-9]+)?)\s*ms", output, re.IGNORECASE)
            latency = float(match.group(1)) if match else None
            return success, latency
        except (OSError, ValueError):
            return False, None
