#!/usr/bin/env python3
# Production usage example

import os
import sys

print("Telecom Anomaly Detection - Production Ready")
print("RU MAC: 6c:ad:ad:00:03:2a")
print("DU MAC: 00:11:22:33:44:67")
print()

# Example usage commands
print("Usage Examples:")
print("1. Analyze single PCAP file:")
print("   python3 pcap_analyzer.py your_capture.pcap")
print()
print("2. Analyze folder of files:")
print("   python3 run_system.py /path/to/network/captures")
print()
print("3. Start web interface:")
print("   streamlit run app.py --server.port 5000")
print()

if len(sys.argv) > 1:
    pcap_file = sys.argv[1]
    if os.path.exists(pcap_file):
        print(f"Analyzing: {pcap_file}")
        os.system(f"python3 pcap_analyzer.py {pcap_file}")
    else:
        print(f"File not found: {pcap_file}")
