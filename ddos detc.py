from collections import defaultdict
from time import time
from scapy.all import IP, TCP, wrpcap

# Constants
PACKET_THRESHOLD = 1000
TIME_WINDOW = 60  # seconds

# This dictionary will hold the number of packets from each IP address
packet_counts = defaultdict(int)
# This dictionary will track when a packet from an IP was last received
packet_times = defaultdict(list)


def packet_callback(packet):
    # Parse the packet using scapy
    scapy_packet = IP(packet.get_payload())
    print(f"From: {scapy_packet[0][1].src}, To: {scapy_packet[0][1].dst}, Protocol: {scapy_packet[0][1].proto}")
    wrpcap("packets.pcap", scapy_packet, append=True)

    src_ip = scapy_packet[0][1].src

    # Track the time and count for each packet
    current_time = time()
    packet_times[src_ip].append(current_time)
    packet_counts[src_ip] += 1

    # Remove packets that are outside the time window
    while packet_times[src_ip] and packet_times[src_ip][0] < current_time - TIME_WINDOW:
        packet_times[src_ip].pop(0)
        packet_counts[src_ip] -= 1

    # Alert if threshold is exceeded
    if packet_counts[src_ip] > PACKET_THRESHOLD:
        print(f"Alert! Potential DDoS attack detected from {src_ip}.")
        packet_counts[src_ip] = 0

    # Check for SYN-FIN packets
    if TCP in scapy_packet and scapy_packet[TCP].flags == 0x03:
        print("Alert! SYN-FIN packet detected.")
        packet.drop()
    else:
        packet.accept()

