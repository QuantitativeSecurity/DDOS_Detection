Packet Analysis Script

This script is designed to analyze incoming network packets, specifically looking for patterns that might indicate a Distributed Denial of Service (DDoS) attack or malicious TCP packets.
Features:

    DDoS Detection: The script checks if the number of packets from a single IP address exceeds a certain threshold (PACKET_THRESHOLD) within a set time window (TIME_WINDOW). If this happens, an alert is printed, indicating a potential DDoS attack from that IP.

    SYN-FIN Detection: TCP packets with both the SYN and FIN flags set are unusual and might indicate a malicious sender. If such a packet is detected, an alert is generated, and the packet is dropped.

    Packet Logging: Each processed packet is saved to a pcap file (packets.pcap).

Usage:

    Ensure you have the scapy library installed.
    Use the script in conjunction with a packet capture or interception tool that can pass packets to the packet_callback function.
    Adjust PACKET_THRESHOLD and TIME_WINDOW as necessary based on your network's typical traffic patterns and desired sensitivity.

Note:

This is a basic packet analysis tool and might not catch sophisticated attacks or false positives. Always monitor your network and adjust parameters as necessary.
