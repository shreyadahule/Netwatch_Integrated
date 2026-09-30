from __future__ import annotations

import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk, messagebox
from typing import Callable, Optional

from database.db import DatabaseManager
from network.dns import DNSHandler
from network.monitor import NetworkMonitor
from network.ping import PingHandler
from network.scanner import PortScanner
from network.url_detector import URLDetector
from reports.generator import ReportGenerator


class NetWatchApp:
    """Integrated NetWatch desktop security and network monitoring suite."""

    def __init__(self, root: Optional[tk.Tk] = None) -> None:
        self.root = root or tk.Tk()
        self.root.title("NetWatch — Network & URL Security Monitor")
        self.root.geometry("1050x700")
        self.root.minsize(900, 600)

        self.db = DatabaseManager()
        self.monitor = NetworkMonitor()
        self.report_generator = ReportGenerator(self.db)

        self._configure_style()
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self._create_dashboard_tab()
        self._create_url_tab()
        self._create_dns_tab()
        self._create_ping_tab()
        self._create_scanner_tab()
        self._create_usage_tab()
        self._create_reports_tab()
        self._refresh_dashboard()

    def run(self) -> None:
        self.root.mainloop()

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10))
        style.configure("Card.TLabelframe", padding=12)
        style.configure("CardValue.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=(12, 8))
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _create_treeview(self, parent: tk.Widget, columns: list[str], headings: list[str],
                         widths: Optional[list[int]] = None) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        widths = widths or [130] * len(columns)
        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, anchor="center", width=width)
        tree.pack(fill="both", expand=True, padx=10, pady=10)
        return tree

    def _create_frame(self, title: str) -> ttk.Frame:
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        return frame

    def _create_dashboard_tab(self) -> None:
        frame = self._create_frame("Dashboard")
        ttk.Label(frame, text="NetWatch Security Dashboard", style="Title.TLabel").pack(anchor="w", padx=18, pady=(18, 2))
        ttk.Label(frame, text="One workspace for URL risk checks, DNS, connectivity, ports, traffic and reports.",
                  style="Subtitle.TLabel").pack(anchor="w", padx=18, pady=(0, 18))

        cards = ttk.Frame(frame)
        cards.pack(fill="x", padx=18)
        self.dashboard_vars = {}
        for key, title in [("urls", "URL Scans"), ("dns", "DNS Lookups"), ("ping", "Ping Checks"), ("ports", "Open Ports")]:
            card = ttk.LabelFrame(cards, text=title, style="Card.TLabelframe")
            card.pack(side="left", fill="both", expand=True, padx=5)
            var = tk.StringVar(value="0")
            self.dashboard_vars[key] = var
            ttk.Label(card, textvariable=var, style="CardValue.TLabel").pack(pady=15)

        activity = ttk.LabelFrame(frame, text="Latest URL Security Checks", style="Card.TLabelframe")
        activity.pack(fill="both", expand=True, padx=18, pady=18)
        self.dashboard_url_history = self._create_treeview(
            activity, ["url", "score", "classification", "timestamp"],
            ["URL", "Risk /10", "Assessment", "Time"], [430, 100, 180, 180]
        )

    def _refresh_dashboard(self) -> None:
        url_rows = self.db.get_url_scan_history(5)
        self.dashboard_vars["urls"].set(str(len(self.db.get_url_scan_history(1000))))
        self.dashboard_vars["dns"].set(str(len(self.db.get_dns_history(1000))))
        self.dashboard_vars["ping"].set(str(len(self.db.get_ping_history(1000))))
        self.dashboard_vars["ports"].set(str(sum(1 for _, _, status, _, _ in self.db.get_port_scan_history(1000) if status == "Open")))
        self._refresh_treeview_rows(
            self.dashboard_url_history,
            [(url, f"{score}/10", classification, ts) for url, score, classification, _, ts in url_rows]
        )

    def _create_url_tab(self) -> None:
        frame = self._create_frame("URL Security")
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=12, pady=12)
        ttk.Label(top, text="URL:").grid(row=0, column=0, sticky="w")
        self.url_entry = ttk.Entry(top, width=75)
        self.url_entry.grid(row=0, column=1, padx=8, pady=5, sticky="ew")
        top.columnconfigure(1, weight=1)
        self.url_button = ttk.Button(top, text="Analyze URL", style="Accent.TButton", command=self._scan_url)
        self.url_button.grid(row=0, column=2, padx=5)
        ttk.Label(top, text="Heuristic analysis: indicators raise a 0–10 risk score; not a definitive verdict.").grid(
            row=1, column=1, sticky="w", pady=(3, 0)
        )

        self.url_result_var = tk.StringVar(value="Enter a URL and click Analyze URL.")
        self.url_result_label = ttk.Label(frame, textvariable=self.url_result_var, wraplength=950)
        self.url_result_label.pack(anchor="w", padx=20, pady=8)

        self.url_history = self._create_treeview(
            frame, ["url", "score", "classification", "reasons", "timestamp"],
            ["URL", "Risk /10", "Assessment", "Indicators", "Timestamp"],
            [300, 80, 160, 350, 170]
        )
        self._refresh_url_history()

    def _scan_url(self) -> None:
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Required", "Enter a URL to analyze.")
            return
        score, reasons = URLDetector.check_url(url)
        classification = URLDetector.classification(score)
        timestamp = datetime.utcnow().isoformat(sep=" ", timespec="seconds")
        reason_text = "; ".join(reasons) if reasons else "No suspicious indicators detected."
        self.db.insert_url_scan(url, score, classification, reason_text, timestamp)

        if score <= 2:
            prefix = "🟢"
        elif score <= 5:
            prefix = "🟠"
        else:
            prefix = "🔴"
        self.url_result_var.set(f"{prefix} {classification}  •  Risk Score: {score}/10  •  {reason_text}")
        self._refresh_url_history()
        self._refresh_dashboard()

    def _create_dns_tab(self) -> None:
        frame = self._create_frame("DNS Lookup")
        control = ttk.Frame(frame); control.pack(fill="x", padx=10, pady=10)
        ttk.Label(control, text="Domain:").grid(row=0, column=0, sticky="w")
        self.dns_entry = ttk.Entry(control, width=50); self.dns_entry.grid(row=0, column=1, padx=6, pady=4)
        ttk.Button(control, text="Lookup", style="Accent.TButton", command=self._lookup_dns).grid(row=0, column=2, padx=6)
        self.dns_result_var = tk.StringVar(); ttk.Label(control, textvariable=self.dns_result_var).grid(row=1, column=0, columnspan=3, sticky="w")
        self.dns_history = self._create_treeview(frame, ["domain", "ip", "timestamp"], ["Domain", "IP", "Timestamp"], [280, 220, 220])
        self._refresh_dns_history()

    def _create_ping_tab(self) -> None:
        frame = self._create_frame("Ping Monitor")
        control = ttk.Frame(frame); control.pack(fill="x", padx=10, pady=10)
        ttk.Label(control, text="Target Host/IP:").grid(row=0, column=0, sticky="w")
        self.ping_entry = ttk.Entry(control, width=50); self.ping_entry.grid(row=0, column=1, padx=6, pady=4)
        self.ping_button = ttk.Button(control, text="Ping", style="Accent.TButton", command=self._ping_target); self.ping_button.grid(row=0, column=2, padx=6)
        self.ping_result_var = tk.StringVar(); ttk.Label(control, textvariable=self.ping_result_var).grid(row=1, column=0, columnspan=3, sticky="w")
        self.ping_history = self._create_treeview(frame, ["target", "latency", "status", "timestamp"], ["Target", "Latency (ms)", "Status", "Timestamp"], [260, 130, 140, 220])
        self._refresh_ping_history()

    def _create_scanner_tab(self) -> None:
        frame = self._create_frame("Port Scanner")
        control = ttk.Frame(frame); control.pack(fill="x", padx=10, pady=10)
        ttk.Label(control, text="Target Host/IP:").grid(row=0, column=0, sticky="w")
        self.scan_entry = ttk.Entry(control, width=50); self.scan_entry.grid(row=0, column=1, padx=6, pady=4)
        self.scan_button = ttk.Button(control, text="Scan Ports", style="Accent.TButton", command=self._scan_ports); self.scan_button.grid(row=0, column=2, padx=6)
        self.scan_result_var = tk.StringVar(); ttk.Label(control, textvariable=self.scan_result_var).grid(row=1, column=0, columnspan=3, sticky="w")
        self.scan_history = self._create_treeview(frame, ["target", "port", "status", "service", "timestamp"], ["Target", "Port", "Status", "Service", "Timestamp"], [220, 80, 100, 120, 190])
        self._refresh_scan_history()

    def _create_usage_tab(self) -> None:
        frame = self._create_frame("Network Usage")
        control = ttk.Frame(frame); control.pack(fill="x", padx=10, pady=10)
        self.usage_button = ttk.Button(control, text="Refresh Usage", style="Accent.TButton", command=self._refresh_usage); self.usage_button.grid(row=0, column=0, sticky="w")
        self.upload_var = tk.StringVar(value="Upload: 0 B/s"); self.download_var = tk.StringVar(value="Download: 0 B/s"); self.total_var = tk.StringVar(value="Total Sent: 0 B, Total Received: 0 B")
        ttk.Label(control, textvariable=self.upload_var).grid(row=1, column=0, sticky="w", pady=2)
        ttk.Label(control, textvariable=self.download_var).grid(row=2, column=0, sticky="w", pady=2)
        ttk.Label(control, textvariable=self.total_var).grid(row=3, column=0, sticky="w", pady=2)
        self.usage_history = self._create_treeview(frame, ["sent", "received", "upload", "download", "timestamp"], ["Bytes Sent", "Bytes Received", "Upload B/s", "Download B/s", "Timestamp"], [150, 150, 140, 140, 200])
        self._refresh_usage_history()

    def _create_reports_tab(self) -> None:
        frame = self._create_frame("Reports")
        control = ttk.Frame(frame); control.pack(fill="x", padx=10, pady=10)
        self.report_button = ttk.Button(control, text="Generate Report", style="Accent.TButton", command=self._generate_report); self.report_button.pack(side="left")
        self.report_status_var = tk.StringVar(value="Ready to create a summary report including URL security history.")
        ttk.Label(control, textvariable=self.report_status_var).pack(side="left", padx=10)
        self.report_history = self._create_treeview(frame, ["name", "path", "timestamp"], ["Report Name", "Path", "Created"], [260, 520, 200])
        self._refresh_report_history()

    def _lookup_dns(self) -> None:
        domain = self.dns_entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Required", "Enter a domain name to look up."); return
        ip = DNSHandler.resolve(domain)
        if ip:
            self.dns_result_var.set(f"{domain} resolved to {ip}")
            self.db.insert_dns_history(domain, ip, self._now())
            self._refresh_dns_history(); self._refresh_dashboard()
        else:
            self.dns_result_var.set(f"Unable to resolve {domain}.")

    def _ping_target(self) -> None:
        target = self.ping_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Enter a host or IP address to ping."); return
        self.ping_button.config(state="disabled"); self.ping_result_var.set("Pinging...")
        self._run_thread(self._ping_worker, self._ping_done, target)

    def _ping_worker(self, target: str) -> tuple[str, Optional[float], str]:
        success, latency = PingHandler.ping(target)
        status = "Success" if success else "Failed"
        self.db.insert_ping_history(target, latency, status, self._now())
        return target, latency, status

    def _ping_done(self, result: tuple[str, Optional[float], str]) -> None:
        target, latency, status = result
        self.ping_result_var.set(f"Ping {status} for {target}: {f'{latency:.1f} ms' if latency is not None else 'N/A'}")
        self.ping_button.config(state="normal"); self._refresh_ping_history(); self._refresh_dashboard()

    def _scan_ports(self) -> None:
        target = self.scan_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Enter a host or IP address to scan."); return
        self.scan_button.config(state="disabled"); self.scan_result_var.set("Scanning ports...")
        self._run_thread(self._scan_worker, self._scan_done, target)

    def _scan_worker(self, target: str) -> list[tuple[int, str, str]]:
        results = PortScanner.scan_ports(target, PortScanner.common_ports())
        timestamp = self._now()
        for port, status, service in results:
            self.db.insert_port_scan(target, port, status, service, timestamp)
        return results

    def _scan_done(self, results: list[tuple[int, str, str]]) -> None:
        open_ports = [port for port, status, _ in results if status == "Open"]
        self.scan_result_var.set("Open ports: " + ", ".join(map(str, open_ports)) if open_ports else "No open ports found.")
        self.scan_button.config(state="normal"); self._refresh_scan_history(); self._refresh_dashboard()

    def _refresh_usage(self) -> None:
        try:
            sent, recv, upload, download = self.monitor.get_usage()
            self.db.insert_usage_log(sent, recv, upload, download, self._now())
            self.upload_var.set(f"Upload: {self._format_bytes(upload)}/s")
            self.download_var.set(f"Download: {self._format_bytes(download)}/s")
            self.total_var.set(f"Total Sent: {self._format_bytes(sent)}, Total Received: {self._format_bytes(recv)}")
            self._refresh_usage_history()
        except RuntimeError as exc:
            messagebox.showerror("Monitor Error", str(exc))

    def _generate_report(self) -> None:
        self.report_button.config(state="disabled"); self.report_status_var.set("Generating integrated report...")
        self._run_thread(self._report_worker, self._report_done)

    def _report_worker(self) -> str:
        return self.report_generator.create_report()

    def _report_done(self, report_path: str) -> None:
        self.report_status_var.set(f"Report saved to {report_path}")
        self.report_button.config(state="normal"); self._refresh_report_history()

    def _run_thread(self, worker: Callable[..., object], callback: Callable[[object], None], *args: object) -> None:
        def task() -> None:
            try:
                result = worker(*args)
            except Exception as exc:
                self.root.after(0, lambda: messagebox.showerror("Operation Error", str(exc)))
                self.root.after(0, lambda: callback(None))
                return
            self.root.after(0, lambda: callback(result))
        threading.Thread(target=task, daemon=True).start()

    def _refresh_treeview_rows(self, tree: ttk.Treeview, rows: list[tuple]) -> None:
        tree.delete(*tree.get_children())
        for row in rows:
            tree.insert("", "end", values=row)

    def _refresh_url_history(self) -> None:
        rows = self.db.get_url_scan_history(50)
        self._refresh_treeview_rows(self.url_history, rows)

    def _refresh_treeview(self, tree: ttk.Treeview, rows: list[tuple]) -> None:
        self._refresh_treeview_rows(tree, rows)

    def _refresh_dns_history(self) -> None:
        self._refresh_treeview(self.dns_history, self.db.get_dns_history(20))

    def _refresh_ping_history(self) -> None:
        rows = self.db.get_ping_history(20)
        self._refresh_treeview(self.ping_history, [(t, f"{l:.1f}" if l is not None else "N/A", s, ts) for t, l, s, ts in rows])

    def _refresh_scan_history(self) -> None:
        self._refresh_treeview(self.scan_history, self.db.get_port_scan_history(50))

    def _refresh_usage_history(self) -> None:
        rows = self.db.get_usage_logs(20)
        self._refresh_treeview(self.usage_history, [(self._format_bytes(s), self._format_bytes(r), self._format_bytes(u) + "/s", self._format_bytes(d) + "/s", ts) for s, r, u, d, ts in rows])

    def _refresh_report_history(self) -> None:
        self._refresh_treeview(self.report_history, self.db.get_report_history(20))

    @staticmethod
    def _format_bytes(value: float) -> str:
        for threshold, unit in [(1 << 30, "GB"), (1 << 20, "MB"), (1 << 10, "KB")]:
            if value >= threshold:
                return f"{value / threshold:.2f} {unit}"
        return f"{value:.0f} B"

    @staticmethod
    def _now() -> str:
        return datetime.utcnow().isoformat(sep=" ", timespec="seconds")
