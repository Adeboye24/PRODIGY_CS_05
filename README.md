# PRODIGY_CS_05
PACKET SNIFFER TOOL
python sniffingtool.py
from scapy.all import *
import threading
import time
import sys
import logging

# Set up logging without sensitive data
logging.basicConfig(filename='sniffer.log', level=logging.INFO)

# Global variable to control sniffing
sniffing = False

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Mask payload and protocol details
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        # Mask payload content in logs
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload (masked): <data>")

        logging.info(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}")

    print("\n")

def start_sniffing(duration):
    global sniffing
    sniffing = True
    logging.info("Sniffing started")
    print(f"Sniffing for {duration} seconds...")
    sniff(prn=packet_callback, timeout=duration)
    stop_sniffing()

def stop_sniffing():
    global sniffing
    sniffing = False
    logging.info("Sniffing stopped")
    print("Sniffing stopped.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python sniffer.py <duration_in_seconds>")
        sys.exit(1)

    try:
        duration = int(sys.argv[1])
        if duration <= 0:
            raise ValueError
    except ValueError:
        print("Duration must be a positive integer.")
        sys.exit(1)

    print("Starting packet sniffer...")
    start_sniffing(duration)

if __name__ == "__main__":
    main()
ll\
