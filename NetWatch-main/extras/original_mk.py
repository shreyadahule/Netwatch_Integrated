import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse
import re


# ---------------- URL DETECTOR ----------------

def check_url(url):
    score = 0
    reasons = []

    url = url.strip()

    if not url:
        return 0, ["URL is empty"]

    # Add scheme if missing
    test_url = url
    if not test_url.startswith(("http://", "https://")):
        test_url = "http://" + test_url

    parsed = urlparse(test_url)
    domain = parsed.netloc.lower()

    # 1. HTTP instead of HTTPS
    if test_url.startswith("http://"):
        score += 1
        reasons.append("Uses HTTP instead of HTTPS")

    # 2. IP address instead of domain
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, domain.split(":")[0]):
        score += 3
        reasons.append("Uses an IP address instead of a domain")

    # 3. @ symbol
    if "@" in url:
        score += 3
        reasons.append("Contains '@' symbol")

    # 4. Very long URL
    if len(url) > 100:
        score += 2
        reasons.append("URL is unusually long")

    # 5. Too many subdomains
    hostname = parsed.hostname or ""
    if hostname.count(".") >= 3:
        score += 2
        reasons.append("Contains too many subdomains")

    # 6. Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "password",
        "account",
        "update",
        "secure",
        "bank",
        "free",
        "winner",
        "claim",
        "confirm"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url.lower():
            found_words.append(word)

    if found_words:
        score += min(len(found_words), 3)
        reasons.append(
            "Suspicious keywords: " + ", ".join(found_words)
        )

    # 7. Suspicious characters
    special_chars = url.count("-") + url.count("_")

    if special_chars >= 5:
        score += 2
        reasons.append("Contains many special characters")

    # 8. URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly"
    ]

    if any(shortener in hostname for shortener in shorteners):
        score += 2
        reasons.append("Uses a URL shortening service")

    # Limit score
    score = min(score, 10)

    return score, reasons


# ---------------- GUI ----------------

def scan_url():
    url = url_entry.get().strip()

    if not url:
        messagebox.showwarning(
            "Warning",
            "Please enter a URL."
        )
        return

    score, reasons = check_url(url)

    result_box.delete("1.0", tk.END)

    if score <= 2:
        result = "🟢 URL LOOKS SAFE"
    elif score <= 5:
        result = "🟠 SUSPICIOUS URL"
    else:
        result = "🔴 POTENTIALLY MALICIOUS"

    result_box.insert(tk.END, result + "\n\n")
    result_box.insert(tk.END, f"Risk Score: {score}/10\n\n")

    if reasons:
        result_box.insert(tk.END, "Reasons:\n")

        for reason in reasons:
            result_box.insert(tk.END, "• " + reason + "\n")
    else:
        result_box.insert(
            tk.END,
            "No suspicious indicators detected."
        )


def clear_url():
    url_entry.delete(0, tk.END)
    result_box.delete("1.0", tk.END)


# ---------------- WINDOW ----------------

root = tk.Tk()
root.title("Malicious URL Detector")
root.geometry("650x500")
root.resizable(False, False)

# Background
root.configure(bg="#111827")

# Title
title = tk.Label(
    root,
    text="🔐 Malicious URL Detector",
    font=("Arial", 24, "bold"),
    bg="#111827",
    fg="white"
)

title.pack(pady=25)

# Subtitle
subtitle = tk.Label(
    root,
    text="Check a URL for common malicious indicators",
    font=("Arial", 11),
    bg="#111827",
    fg="#9CA3AF"
)

subtitle.pack()

# URL label
url_label = tk.Label(
    root,
    text="Enter URL:",
    font=("Arial", 12, "bold"),
    bg="#111827",
    fg="white"
)

url_label.pack(anchor="w", padx=50, pady=(30, 5))

# URL input
url_entry = tk.Entry(
    root,
    font=("Arial", 13),
    width=55,
    bg="#1F2937",
    fg="white",
    insertbackground="white",
    relief="flat"
)

url_entry.pack(ipady=10, padx=50)

# Buttons frame
button_frame = tk.Frame(
    root,
    bg="#111827"
)

button_frame.pack(pady=20)

# Scan button
scan_button = tk.Button(
    button_frame,
    text="🔍 CHECK URL",
    font=("Arial", 11, "bold"),
    bg="#2563EB",
    fg="white",
    padx=25,
    pady=10,
    relief="flat",
    cursor="hand2",
    command=scan_url
)

scan_button.pack(side="left", padx=10)

# Clear button
clear_button = tk.Button(
    button_frame,
    text="CLEAR",
    font=("Arial", 11, "bold"),
    bg="#374151",
    fg="white",
    padx=25,
    pady=10,
    relief="flat",
    cursor="hand2",
    command=clear_url
)

clear_button.pack(side="left", padx=10)

# Result label
result_label = tk.Label(
    root,
    text="Result",
    font=("Arial", 13, "bold"),
    bg="#111827",
    fg="white"
)

result_label.pack(anchor="w", padx=50)

# Result box
result_box = tk.Text(
    root,
    height=10,
    width=65,
    font=("Consolas", 11),
    bg="#1F2937",
    fg="white",
    insertbackground="white",
    relief="flat",
    padx=15,
    pady=10
)

result_box.pack(padx=50, pady=10)

# Start application
root.mainloop()