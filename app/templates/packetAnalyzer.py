# Import necessary libraries
from flask import Flask, render_template, jsonify, request  # Flask web framework and helper functions
from scapy.all import sniff, DNS, IP, TCP, UDP, ICMP  # Scapy for packet sniffing / added dns, IP, TCP, UDP, ICMP
import threading  # For running sniffing in background without freezing the web app
import time  # To pause between background sniffing sessions

# Initialize the Flask app
app = Flask(__name__)

# Global state variables
capturing = False  # Tracks whether packet capturing is active
captured_packets = []  # Stores captured packet data (up to 100 packets)
packet_stats = {  # Stores count of packets by protocol type
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'Other': 0
}

current_filter = "ALL" # for filtering variables 

# Function to handle each sniffed packet
def packet_handler(pkt):
    global packet_stats

    # Get the protocol name of the packet (e.g., TCP, UDP, etc.)
    # Detect protocol properly
    if pkt.haslayer(TCP):
        proto = "TCP"
        packet_stats["TCP"] += 1
    elif pkt.haslayer(UDP):
        proto = "UDP"
        packet_stats["UDP"] += 1
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        packet_stats["ICMP"] += 1
    else:
        proto = "Other"
        packet_stats["Other"] += 1

    #defualt values
    src = 'N/A'
    dst = 'N/A'
    domain = ''
    pkt_type = 'OTHER'

    #Get IP information
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
    #DNS feature
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        pkt_type = "DNS"
        try:
            domain = pkt[DNS].qd.qname.decode()
        except:
            domain = "Unknown"

    # Extract packet source, destination, protocol, and summary
    captured_packets.append({
        'src': src,
        'dst': dst,
        'proto': proto,
        'summary': pkt.summary(),
        'type': pkt_type,
        'domain': domain,
        'details': pkt.show(dump=True)
    })
        #packet breakdown
 
    if len(captured_packets) > 100:
        captured_packets.pop(0)

# Sniff packets continuously (not used directly, reserved for future use)
def start_sniff():
    sniff(prn=packet_handler, store=False)

# Function to sniff packets in the background thread
def background_sniff():
    global capturing
    while capturing:
        sniff(prn=packet_handler, store=False, timeout=5)  # Sniff for 5 seconds
        time.sleep(1)  # Pause to reduce CPU load

# Route: Home page
@app.route('/')
def index():
    return render_template('index.html')  # Loads the frontend page

# Route: Start capturing packets
@app.route('/start')
def start():
    global capturing
    capturing = True
    thread = threading.Thread(target=background_sniff)  # Run sniffing in a separate thread
    thread.start()
    return jsonify({'status': 'started'})  # Return JSON response to frontend

# Route: Stop capturing packets
@app.route('/stop')
def stop():
    global capturing
    capturing = False
    return jsonify({'status': 'stopped'})

# Route: Return captured packet data to frontend / upadted packet route with filtering
@app.route('/packets')
def packets():
    if current_filter == "DNS":
        filtered = [p for p in captured_packets if p["type"] == "DNS"]
    else:
        filtered = captured_packets

    return jsonify(filtered)

# Route: Return packet statistics to frontend
@app.route('/stats')
def stats():
    return jsonify(packet_stats)

# Run the app in debug mode (useful during development) /
@app.route('/set_filter/<filter_type>')
def set_filter(filter_type):
    global current_filter
    current_filter = filter_type
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(debug=True)
