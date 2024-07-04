import sys
from scapy.all import *

def packet_callback(packet):
    # Check if the packet contains IP and TCP layers
    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Extract source and destination IP addresses and ports
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Print relevant information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: TCP, Source Port: {src_port}, Destination Port: {dst_port}")

def main(interface):
    # Start packet sniffing on specified interface
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Check if the script is being run directly
    if len(sys.argv) < 2:
        # If not, print usage message and exit
        print("Usage: python sniffer.py <interface>")
        sys.exit(1)

    # Call main function with specified interface
    main(sys.argv[1])