from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Iterable

from database.db import DatabaseManager


class ReportGenerator:
    """Generate summary reports from NetWatch history."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self.output_dir = Path(__file__).resolve().parent
        self.output_dir.mkdir(parents=True, exist_ok=True)

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen.canvas import Canvas
        except ImportError:  # pragma: no cover
            self._pdf_support = False
        else:
            self._pdf_support = True
            self._letter = letter
            self._Canvas = Canvas

    def create_report(self) -> str:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"netwatch_report_{timestamp}.{'pdf' if self._pdf_support else 'txt'}"
        report_path = self.output_dir / filename

        dns_history = self.db.get_dns_history(20)
        ping_history = self.db.get_ping_history(20)
        port_history = self.db.get_port_scan_history(50)
        usage_history = self.db.get_usage_logs(20)
        url_history = self.db.get_url_scan_history(50)

        if self._pdf_support:
            self._write_pdf(report_path, dns_history, ping_history, port_history, usage_history, url_history)
        else:
            self._write_text(report_path, dns_history, ping_history, port_history, usage_history, url_history)

        self.db.insert_report_history(filename, str(report_path), datetime.utcnow().isoformat(sep=" ", timespec="seconds"))
        return str(report_path)

    def _write_text(
        self,
        report_path: Path,
        dns_history: list[tuple[str, str, str]],
        ping_history: list[tuple[str, float | None, str, str]],
        port_history: list[tuple[str, int, str, str, str]],
        usage_history: list[tuple[int, int, float, float, str]],
        url_history: list[tuple[str, int, str, str, str]],
    ) -> None:
        with report_path.open("w", encoding="utf-8") as output:
            output.write("NetWatch Summary Report\n")
            output.write(f"Generated: {datetime.utcnow().isoformat(sep=' ', timespec='seconds')}\n\n")
            output.write("DNS History:\n")
            for domain, ip, timestamp in dns_history:
                output.write(f"  {timestamp} - {domain} -> {ip}\n")
            output.write("\nPing History:\n")
            for target, latency, status, timestamp in ping_history:
                latency_text = f"{latency:.1f} ms" if latency is not None else "N/A"
                output.write(f"  {timestamp} - {target} - {status} - {latency_text}\n")
            output.write("\nPort Scan History:\n")
            for target, port, status, service, timestamp in port_history:
                output.write(f"  {timestamp} - {target}:{port} {service} - {status}\n")
            output.write("\nURL Security Scan History:\n")
            for url, score, classification, reasons, timestamp in url_history:
                output.write(f"  {timestamp} - {classification} ({score}/10) - {url} - {reasons}\n")
            output.write("\nNetwork Usage History:\n")
            for sent, received, upload, download, timestamp in usage_history:
                output.write(
                    f"  {timestamp} - Sent: {sent} B, Received: {received} B, Upload: {upload:.2f} B/s, Download: {download:.2f} B/s\n"
                )

    def _write_pdf(
        self,
        report_path: Path,
        dns_history: list[tuple[str, str, str]],
        ping_history: list[tuple[str, float | None, str, str]],
        port_history: list[tuple[str, int, str, str, str]],
        usage_history: list[tuple[int, int, float, float, str]],
        url_history: list[tuple[str, int, str, str, str]],
    ) -> None:
        canvas = self._Canvas(str(report_path), pagesize=self._letter)
        canvas.setFont("Helvetica-Bold", 16)
        canvas.drawString(40, 760, "NetWatch Summary Report")
        canvas.setFont("Helvetica", 10)
        canvas.drawString(40, 740, f"Generated: {datetime.utcnow().isoformat(sep=' ', timespec='seconds')}")

        y = 720
        y = self._draw_section(canvas, y, "DNS History", [f"{ts} - {domain} -> {ip}" for domain, ip, ts in dns_history])
        y = self._draw_section(canvas, y, "Ping History", [f"{ts} - {target} - {status} - {f'{latency:.1f} ms' if latency is not None else 'N/A'}" for target, latency, status, ts in ping_history])
        y = self._draw_section(canvas, y, "Port Scan History", [f"{ts} - {target}:{port} {service} - {status}" for target, port, status, service, ts in port_history])
        y = self._draw_section(canvas, y, "URL Security Scan History", [f"{ts} - {classification} ({score}/10) - {url} - {reasons}" for url, score, classification, reasons, ts in url_history])
        y = self._draw_section(canvas, y, "Network Usage History", [f"{ts} - Sent: {sent}B, Received: {received}B, Upload: {upload:.2f} B/s, Download: {download:.2f} B/s" for sent, received, upload, download, ts in usage_history])
        canvas.save()

    def _draw_section(self, canvas: "Canvas", y: float, title: str, lines: Iterable[str]) -> float:
        canvas.setFont("Helvetica-Bold", 12)
        canvas.drawString(40, y, title)
        y -= 18
        canvas.setFont("Helvetica", 9)
        for line in lines:
            if y < 40:
                canvas.showPage()
                y = 760
                canvas.setFont("Helvetica", 9)
            canvas.drawString(46, y, line)
            y -= 14
        y -= 12
        return y
