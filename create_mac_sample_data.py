#!/usr/bin/env python3
"""
Create sample PCAP files with specific MAC addresses for testing MAC-based RU-DU detection.
Uses the user's specific DU MAC addresses: 00:11:22:33:44:67 and 00:11:22:33:44:66
"""

import os
from scapy.all import *

def create_directories():
    """Create sample data directories."""
    os.makedirs("./pcap_files", exist_ok=True)
    print("Created directories for sample data")

def create_normal_mac_pcap():
    """Create normal PCAP with balanced RU-DU communication using specific MAC addresses."""
    print("Creating normal PCAP with MAC-based detection...")
    
    packets = []
    du_mac = "00:11:22:33:44:67"  # Actual DU MAC address
    ru_mac = "6c:ad:ad:00:03:2a"  # Actual RU MAC address
    
    # Create 200 packets with balanced bidirectional communication
    for i in range(200):
        if i % 2 == 0:
            # DU to RU communication (F1-C control plane)
            packet = Ether(src=du_mac, dst=ru_mac) / \
                    IP(src="192.168.2.10", dst="192.168.1.20") / \
                    UDP(sport=38472, dport=38472) / \
                    Raw(b"F1-C Control Data")
        else:
            # RU to DU response (F1-U user plane)
            packet = Ether(src=ru_mac, dst=du_mac) / \
                    IP(src="192.168.1.20", dst="192.168.2.10") / \
                    UDP(sport=2152, dport=2152) / \
                    Raw(b"F1-U User Data")
        
        packet.time = 1734700000.0 + i * 0.001  # 1ms intervals
        packets.append(packet)
    
    wrpcap("./pcap_files/normal_mac_traffic.pcap", packets)
    print(f"Normal MAC-based PCAP created with DU MAC: {du_mac}")

def create_unidirectional_mac_anomaly():
    """Create PCAP with unidirectional communication anomaly using specific MAC addresses."""
    print("Creating unidirectional MAC anomaly PCAP...")
    
    packets = []
    du_mac = "00:11:22:33:44:67"  # Actual DU MAC address
    ru_mac = "6c:ad:ad:00:03:2a"  # Actual RU MAC address
    
    # Create 200 packets - only DU to RU, no responses
    for i in range(200):
        if i % 2 == 0:
            # DU to RU communication (F1-C control plane) - NO RESPONSE
            packet = Ether(src=du_mac, dst=ru_mac) / \
                    IP(src="192.168.2.10", dst="192.168.1.20") / \
                    UDP(sport=38472, dport=38472) / \
                    Raw(b"F1-C Control Data")
        else:
            # DU to RU communication (F1-U user plane) - NO RESPONSE
            packet = Ether(src=du_mac, dst=ru_mac) / \
                    IP(src="192.168.2.10", dst="192.168.1.20") / \
                    UDP(sport=2152, dport=2152) / \
                    Raw(b"F1-U User Data")
        
        packet.time = 1734700000.0 + i * 0.001
        packets.append(packet)
    
    wrpcap("./pcap_files/unidirectional_mac_anomaly.pcap", packets)
    print(f"Unidirectional MAC anomaly PCAP created with DU MAC: {du_mac}")

def create_missing_plane_mac_anomaly():
    """Create PCAP with missing user plane using specific MAC addresses."""
    print("Creating missing plane MAC anomaly PCAP...")
    
    packets = []
    du_mac = "00:11:22:33:44:67"  # Actual DU MAC address
    ru_mac = "6c:ad:ad:00:03:2a"  # Actual RU MAC address
    
    # Create 160 packets - only control plane, no user plane
    for i in range(160):
        if i % 2 == 0:
            # DU to RU communication (F1-C control plane only)
            packet = Ether(src=du_mac, dst=ru_mac) / \
                    IP(src="192.168.2.10", dst="192.168.1.20") / \
                    UDP(sport=38472, dport=38472) / \
                    Raw(b"F1-C Control Data")
        else:
            # RU to DU response (F1-C control plane only)
            packet = Ether(src=ru_mac, dst=du_mac) / \
                    IP(src="192.168.1.20", dst="192.168.2.10") / \
                    UDP(sport=38472, dport=38472) / \
                    Raw(b"F1-C Control Response")
        
        packet.time = 1734700000.0 + i * 0.001
        packets.append(packet)
    
    wrpcap("./pcap_files/missing_plane_mac_anomaly.pcap", packets)
    print(f"Missing plane MAC anomaly PCAP created with DU MAC: {du_mac}")

def main():
    """Create all MAC-based sample data files."""
    print("Creating MAC-based sample data for telecom anomaly detection...")
    print(f"Using DU MAC addresses: 00:11:22:33:44:67, 00:11:22:33:44:66")
    print(f"Using RU MAC pattern: AA:BB:CC:*")
    print()
    
    create_directories()
    create_normal_mac_pcap()
    create_unidirectional_mac_anomaly()
    create_missing_plane_mac_anomaly()
    
    print()
    print("MAC-based sample data creation complete!")
    print("Files created:")
    print("  - normal_mac_traffic.pcap (balanced RU-DU communication)")
    print("  - unidirectional_mac_anomaly.pcap (DU sending, RU not responding)")
    print("  - missing_plane_mac_anomaly.pcap (missing user plane data)")

if __name__ == "__main__":
    main()