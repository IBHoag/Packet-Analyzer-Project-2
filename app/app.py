from flask import Flask, render_template, request, redirect, url_for
import threading
import math
import re
import logging

logging.basicConfig(
    filename="analysis.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


app = Flask(__name__)

# ---------------------------------------------------------
# Global DNS buffer for live capture (Phase 5)
# ---------------------------------------------------------
dns_buffer = []
buffer_lock = threading.Lock()

# ---------------------------------------------------------
# Domain Classification Logic (Phase 4)
# ---------------------------------------------------------

SUSPICIOUS_TLDS = [".xyz", ".ru", ".top", ".click", ".zip", ".kim"]
KNOWN_BAD_DOMAINS = ["malicious.com", "bad-domain.ru", "evilcorp.xyz"]


def entropy(s):
    """Calculate Shannon entropy of a string."""
    probabilities = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log(p, 2) for p in probabilities)


def classify_domain(domain):
    """Return a risk label and score based on domain characteristics."""
    score = 0

    # Suspicious TLDs
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 40

    # Known malicious domains
    if domain in KNOWN_BAD_DOMAINS:
        score += 60

    # High entropy (DNS tunneling)
    if entropy(domain) > 4.0:
        score += 30

    # Excessive subdomains
    if domain.count(".") > 3:
        score += 20

    # Very long domain names
    if len(domain) > 40:
        score += 20

    # Convert score to label
    if score >= 60:
        label = "Suspicious"
    elif score >= 30:
        label = "Warning"
    else:
        label = "None"

    return label, score


# ---------------------------------------------------------
# DNSRecord Data Model (Phase 6)
# ---------------------------------------------------------

class DNSRecord:
    def __init__(self, timestamp, client_ip, query, alert, score):
        self.timestamp = timestamp
        self.client_ip = client_ip
        self.query = query
        self.alert = alert
        self.score = score

    @classmethod
    def from_raw(cls, timestamp, client_ip, query):
        """Build a DNSRecord from raw packet data."""
        label, score = classify_domain(query)
        return cls(timestamp, client_ip, query, label, score)


# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------

def add_live_dns_record(timestamp, client_ip, query):
    """Add a DNS record to the live buffer."""
    global dns_buffer
    with buffer_lock:
        record = DNSRecord.from_raw(timestamp, client_ip, query)
        dns_buffer.append(record)
    
def get_dns_data():
    """
    Combines dummy data + live captured DNS packets.
    Returns a list of DNSRecord objects.
    """

    # Dummy data (safe to delete later)
    raw_dns = [
        ("2026-04-26 16:12:30", "192.168.1.10", "example.com"),
        ("2026-04-26 16:12:31", "192.168.1.15", "suspicious-domain.xyz"),
        ("2026-04-26 16:12:32", "192.168.1.22", "ajd92k3md9q0x1z8.com")
    ]

    # Add live DNS packets
    with buffer_lock:
        for entry in dns_buffer:
            raw_dns.append((entry.timestamp, entry.client_ip, entry.query))

    # Convert raw data → DNSRecord objects
    dns_records = []
    for (timestamp, client_ip, query) in raw_dns:
        logging.info(f"DNS Query: {query} from {client_ip}")
        dns_records.append(DNSRecord.from_raw(timestamp, client_ip, query))

    return dns_records


# Dummy packet list for home page
dummy_packets = [
    {"src": "192.168.1.10", "dst": "8.8.8.8", "protocol": "DNS", "info": "Query: example.com"},
    {"src": "192.168.1.15", "dst": "192.168.1.1", "protocol": "ARP", "info": "Who has 192.168.1.1?"},
]


# -----------------------------
# Flask Routes
# -----------------------------

@app.route("/")
def index():
    return render_template("index.html", packets=dummy_packets)


@app.route("/start")
def start_capture():
    print("Capture started (placeholder)")
    return redirect(url_for("index"))


@app.route("/stop")
def stop_capture():
    print("Capture stopped (placeholder)")
    return redirect(url_for("index"))


@app.route("/dns")
def dns_page():
    dns_data = get_dns_data()
    return render_template("dns.html", dns_data=dns_data)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files["pcapfile"]
        print("Uploaded file:", file.filename)
        return redirect(url_for("index"))
    return render_template("upload.html")


# -----------------------------
# Live Capture Thread
# -----------------------------

def start_live_capture():
    print("Live capture thread started (placeholder)")
    # Example:
    # add_live_dns_record("2026-04-26 16:20:00", "192.168.1.50", "test.com")


# -----------------------------
# Run App
# -----------------------------

if __name__ == "__main__":
    capture_thread = threading.Thread(target=start_live_capture, daemon=True)
    capture_thread.start()
    app.run(debug=True)

import csv
from flask import make_response

@app.route("/export")
def export_csv():
    dns_data = get_dns_data()

    output = []
    output.append(["Timestamp", "Client IP", "Query", "Alert", "Score"])

    for record in dns_data:
        output.append([
            record.timestamp,
            record.client_ip,
            record.query,
            record.alert,
            record.score
        ])

    response = make_response("\n".join([",".join(map(str, row)) for row in output]))
    response.headers["Content-Disposition"] = "attachment; filename=dns_report.csv"
    response.headers["Content-Type"] = "text/csv"

    return response
