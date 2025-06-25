#!/usr/bin/env python3
# Quick start script for production deployment

import os
import sys

def main():
    print("Telecom Anomaly Detection System - Production")
    print("=" * 50)
    print("RU MAC: 6c:ad:ad:00:03:2a")
    print("DU MAC: 00:11:22:33:44:67")
    print()
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if os.path.exists(target):
            print(f"Analyzing: {target}")
            if target.endswith('.pcap'):
                print("Using PCAP analyzer...")
                os.system(f"python3 pcap_analyzer.py {target}")
            else:
                print("Using full system...")
                os.system(f"python3 run_system.py {target}")
        else:
            print(f"Path not found: {target}")
    else:
        print("Usage Examples:")
        print("  python3 quick_start.py /path/to/file.pcap")
        print("  python3 quick_start.py /path/to/folder")
        print("  python3 quick_start.py /path/to/file.hdf5")

if __name__ == "__main__":
    main()
