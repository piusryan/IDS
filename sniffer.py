from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading, time
from collections import Counter

captured_packets = []      # Shared list of packets for dashboard
alerts = []                # Stores intrusion alerts

time_window = 2          # seconds
packet_threshold = 500     # threshold for "suspicious" traffic

# Global IP counter
ip_counter = Counter()

def reset_counters():
    """Reset IP counters periodically"""
    global ip_counter
    while True:
        time.sleep(time_window)
        ip_counter.clear()

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Detect protocol type
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "OTHER"

        # Store packet info (keep only last 50 packets)
        captured_packets.append({"src": src_ip, "dst": dst_ip, "proto": proto})
        if len(captured_packets) > 10:
            captured_packets.pop(0)  # remove oldest

        # Count packets per source
        ip_counter[src_ip] += 1

        # Intrusion detection rule
        if ip_counter[src_ip] > packet_threshold:
            alert_msg = f"🚨 Intrusion detected! Suspicious traffic from {src_ip}"
            if alert_msg not in alerts:  # avoid duplicates
                alerts.append(alert_msg)
                if len(alerts) > 10:
                    alerts.pop(0)  # keep only latest 10
                print(alert_msg)

def start_sniffing():
    # Reset counters in background
    threading.Thread(target=reset_counters, daemon=True).start()
    sniff(filter="ip", prn=packet_callback, store=False)
