#!/usr/bin/env python3
"""
PCAP File Analyzer for Production Telecom Networks
Analyzes PCAP files and displays detailed packet contents with RU-DU communication detection.

Production MAC Addresses:
- RU: 6c:ad:ad:00:03:2a
- DU: 00:11:22:33:44:67

Usage: python3 pcap_analyzer.py <pcap_file>
"""

import sys
import os

# Suppress warnings
import warnings
warnings.filterwarnings("ignore")
os.environ['PYTHONWARNINGS'] = 'ignore'

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, UDP, TCP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

from collections import defaultdict
from datetime import datetime

class ProductionPCAPAnalyzer:
    """Analyzes PCAP files for production telecom networks with specific RU-DU MAC addresses."""
    
    def __init__(self):
        # Production MAC addresses
        self.RU_MAC = "6c:ad:ad:00:03:2a"
        self.DU_MAC = "00:11:22:33:44:67"
        
        # Telecom protocol ports
        self.TELECOM_PORTS = {
            38472: "F1-C Control",
            2152: "F1-U User", 
            36412: "NGAP",
            36413: "S1-MME",
            4789: "VXLAN",
            2123: "GTP-C"
        }
    
    def is_ru_mac(self, mac):
        """Check if MAC address belongs to RU."""
        if not mac:
            return False
        return mac.lower().startswith(self.RU_MAC.lower()[:8])  # Match first 8 chars
    
    def is_du_mac(self, mac):
        """Check if MAC address belongs to DU.""" 
        if not mac:
            return False
        return mac.lower().startswith(self.DU_MAC.lower()[:8])  # Match first 8 chars
    
    def identify_protocol(self, packet):
        """Identify telecom protocol from packet."""
        protocol = "Unknown"
        plane = "Other"
        
        if packet.haslayer(UDP):
            port = packet[UDP].dport
            sport = packet[UDP].sport
            
            for p, name in self.TELECOM_PORTS.items():
                if port == p or sport == p:
                    protocol = name
                    if "Control" in name or "NGAP" in name or "S1-MME" in name:
                        plane = "Control"
                    elif "User" in name or "GTP" in name:
                        plane = "User"
                    break
        
        return protocol, plane
    
    def analyze_pcap(self, pcap_file):
        """Analyze PCAP file and display detailed information."""
        
        if not os.path.exists(pcap_file):
            print(f"Error: PCAP file '{pcap_file}' not found.")
            return
        
        print(f"PCAP File Analysis: {pcap_file}")
        print("=" * 80)
        print(f"Production RU MAC: {self.RU_MAC}")
        print(f"Production DU MAC: {self.DU_MAC}")
        print("=" * 80)
        
        try:
            packets = scapy.rdpcap(pcap_file)
            print(f"Total packets loaded: {len(packets)}")
            print()
            
            # Statistics
            ru_packets = 0
            du_packets = 0
            ru_to_du = 0
            du_to_ru = 0
            control_plane = 0
            user_plane = 0
            other_traffic = 0
            protocol_stats = defaultdict(int)
            
            print("PACKET ANALYSIS:")
            print("-" * 80)
            
            for i, packet in enumerate(packets[:50]):  # Show first 50 packets
                if not packet.haslayer(Ether):
                    continue
                
                src_mac = packet[Ether].src.lower()
                dst_mac = packet[Ether].dst.lower()
                
                # Check for RU-DU communication
                is_ru_src = self.is_ru_mac(src_mac)
                is_du_src = self.is_du_mac(src_mac)
                is_ru_dst = self.is_ru_mac(dst_mac)
                is_du_dst = self.is_du_mac(dst_mac)
                
                if is_ru_src:
                    ru_packets += 1
                if is_du_src:
                    du_packets += 1
                
                if is_ru_src and is_du_dst:
                    ru_to_du += 1
                elif is_du_src and is_ru_dst:
                    du_to_ru += 1
                
                # Get protocol info
                protocol, plane = self.identify_protocol(packet)
                protocol_stats[protocol] += 1
                
                if plane == "Control":
                    control_plane += 1
                elif plane == "User":
                    user_plane += 1
                else:
                    other_traffic += 1
                
                # Display packet details
                timestamp = "N/A"
                if hasattr(packet, 'time'):
                    timestamp = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S.%f")[:-3]
                
                size = len(packet)
                
                print(f"Packet {i+1:3d}: {timestamp}")
                print(f"  MAC: {src_mac} -> {dst_mac}")
                
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    print(f"  IP:  {src_ip} -> {dst_ip}")
                    
                    if packet.haslayer(UDP):
                        sport = packet[UDP].sport
                        dport = packet[UDP].dport
                        print(f"  UDP: {sport} -> {dport}")
                    elif packet.haslayer(TCP):
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                        print(f"  TCP: {sport} -> {dport}")
                
                print(f"  Protocol: {protocol} ({plane} Plane)")
                print(f"  Size: {size} bytes")
                
                # Highlight RU-DU communication
                if (is_ru_src and is_du_dst) or (is_du_src and is_ru_dst):
                    direction = "RU->DU" if is_ru_src else "DU->RU"
                    print(f"  *** {direction} COMMUNICATION ***")
                
                print()
                
                if i >= 49:  # Limit to first 50 packets
                    remaining = len(packets) - 50
                    if remaining > 0:
                        print(f"... and {remaining} more packets")
                    break
            
            # Summary statistics
            print("\n" + "=" * 80)
            print("SUMMARY STATISTICS:")
            print("=" * 80)
            print(f"Total packets: {len(packets)}")
            print(f"RU packets: {ru_packets}")
            print(f"DU packets: {du_packets}")
            print(f"RU->DU communication: {ru_to_du}")
            print(f"DU->RU communication: {du_to_ru}")
            print(f"Control plane traffic: {control_plane}")
            print(f"User plane traffic: {user_plane}")
            print(f"Other traffic: {other_traffic}")
            
            print(f"\nProtocol distribution:")
            for protocol, count in protocol_stats.items():
                percentage = (count / len(packets)) * 100
                print(f"  {protocol}: {count} ({percentage:.1f}%)")
            
            # Anomaly detection
            print(f"\nANOMALY DETECTION:")
            print("-" * 40)
            
            if du_to_ru > 0 and ru_to_du == 0:
                print("⚠️  UNIDIRECTIONAL COMMUNICATION DETECTED")
                print(f"   DU sending {du_to_ru} packets to RU with no responses")
                print("   This indicates RU is not receiving or responding to data")
            elif ru_to_du > 0 and du_to_ru == 0:
                print("⚠️  REVERSE UNIDIRECTIONAL COMMUNICATION")
                print(f"   RU sending {ru_to_du} packets to DU with no responses")
            elif du_to_ru > 0 and ru_to_du > 0:
                print("✓  Bidirectional RU-DU communication detected")
                ratio = min(du_to_ru, ru_to_du) / max(du_to_ru, ru_to_du)
                if ratio < 0.1:
                    print(f"⚠️  Imbalanced communication (ratio: {ratio:.2f})")
            else:
                print("ℹ️  No RU-DU communication detected in this capture")
            
            if control_plane == 0 and user_plane > 0:
                print("⚠️  Missing control plane traffic")
            elif user_plane == 0 and control_plane > 0:
                print("⚠️  Missing user plane traffic")
            
        except Exception as e:
            print(f"Error analyzing PCAP file: {e}")

def main():
    """Main function."""
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_analyzer.py <pcap_file>")
        print("\nExample:")
        print("  python3 pcap_analyzer.py network_capture.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyzer = ProductionPCAPAnalyzer()
    analyzer.analyze_pcap(pcap_file)

if __name__ == "__main__":
    main()