# Import necessary libraries
from flask import Flask, render_template, jsonify, request  # Flask web framework and helper functions
from scapy.all import sniff  # Scapy for packet sniffing
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

# Function to handle each sniffed packet
def packet_handler(pkt):
    global packet_stats

    # Get the protocol name of the packet (e.g., TCP, UDP, etc.)
    proto = pkt.payload.name

    # Update statistics based on protocol
    if proto in packet_stats:
        packet_stats[proto] += 1
    else:
        packet_stats['Other'] += 1

    # Extract packet source, destination, protocol, and summary
    captured_packets.append({
        'src': pkt[0][1].src if hasattr(pkt[0][1], 'src') else 'N/A',
        'dst': pkt[0][1].dst if hasattr(pkt[0][1], 'dst') else 'N/A',
        'proto': proto,
        'summary': pkt.summary()
    })

    # Keep only the 100 most recent packets to avoid memory overflow
    if len(captured_packets) > 100:
        captured_packets.pop(0)

# Sniff packets continuously (not used directly, reserved for future use)
def start_sniff():
    sniff(prn=packet_handler, store=False)

# Function to sniff packets in the background thread
def background_sniff():
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

# Route: Return captured packet data to frontend
@app.route('/packets')
def packets():
    return jsonify(captured_packets)

# Route: Return packet statistics to frontend
@app.route('/stats')
def stats():
    return jsonify(packet_stats)


# Start of My New Code!!

from scapy.all import DNS, DNSQR, DNSRR, IP, rdpcap

# Stores the current protocal filter
selected_protocol = "ALL"

# Override packet_handler with enhanced version (keeps original above untouched) also adds better detection, protocol filtering and dns extraction.
def packet_handler(pkt):
    global packet_stats, selected_protocol

    # Better protocol detector than the previous. Is more accurate.
    if pkt.haslayer("TCP"):
        proto = "TCP"
    elif pkt.haslayer("UDP"):
        proto = "UDP"
    elif pkt.haslayer("ICMP"):
        proto = "ICMP"
    else:
        proto = "Other"

    # Protocol filter This will skip anything that does not match the selected filter
    if selected_protocol != "ALL" and proto != selected_protocol:
        return

    # Stats
    packet_stats[proto] = packet_stats.get(proto, 0) + 1

    # IP info
    src = pkt[IP].src if pkt.haslayer(IP) else 'N/A'
    dst = pkt[IP].dst if pkt.haslayer(IP) else 'N/A'

    # defaults for DNS
    dns_query = "N/A"
    dns_type = "N/A"
    dns_ip = "N/A"
    dns_rcode = "N/A"

    # DNS processing This only runs if packet has a DNS layer.
    if pkt.haslayer(DNS):
        dns_layer = pkt[DNS]

        dns_type = "Query" if dns_layer.qr == 0 else "Response"

 	# This extracts the domain name
        if pkt.haslayer(DNSQR):
            dns_query = pkt[DNSQR].qname.decode(errors='ignore')

	#Extracts resolved IP
        if dns_layer.qr == 1 and pkt.haslayer(DNSRR):
            dns_ip = str(pkt[DNSRR].rdata)

	# Extracts DNS status code
        dns_rcode = str(dns_layer.rcode)

    # Store packet
    captured_packets.append({
        'src': src,
        'dst': dst,
        'proto': proto,
        'dns_query': dns_query,
        'dns_type': dns_type,
        'dns_ip': dns_ip,
        'dns_rcode': dns_rcode,
        'summary': pkt.summary()
    })

	# Not new same as before
    if len(captured_packets) > 100:
        captured_packets.pop(0)


# Protocol filter
@app.route('/set_filter', methods=['POST'])
def set_filter():
    global selected_protocol

    # Gets the selected protocol from the UI
    selected_protocol = request.json.get('protocol', 'ALL')
    return jsonify({'status': 'ok'})


# PCAP upload route. Allows for an upload of a PCAP file.
@app.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    global captured_packets

    file = request.files.get('file')

    # Sees if file exists
    if not file:
        return jsonify({'error': 'No file uploaded'})

    # only allows valid pcap file formats nothing else
    if not file.filename.endswith(('.pcap', '.pcapng')):
        return jsonify({'error': 'Invalid file type'})

    # reads the packet of the file
    packets = rdpcap(file)

    #clears old data before the new file is loaded
    captured_packets.clear()

    # Processes each packet using the same logic as the live capture
    for pkt in packets:
        packet_handler(pkt)

    return jsonify({'status': 'PCAP processed'})

# End of my new code

# Run the app in debug mode (useful during development)
if __name__ == '__main__':
    app.run(debug=True)