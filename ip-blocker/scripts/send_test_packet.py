#!/usr/bin/env python3
from scapy.all import IP, TCP, send
import time

# TARGET: change this to the IP you want to test
dst = "34.222.107.115"

# SOURCE IPs to spoof (use TEST ranges like 203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24)
fake_srcs = ["203.0.113.5", "198.51.100.7", "192.0.2.9"]

# number of packets per source
pkts_per_src = 1
delay_between_packets = 0.5  # seconds

for s in fake_srcs:
    for _ in range(pkts_per_src):
        pkt = IP(src=s, dst=dst) / TCP(dport=80, sport=12345, flags="S")
        send(pkt, verbose=False)
        print(f"sent spoofed SYN from {s} -> {dst}:80")
        time.sleep(delay_between_packets)

