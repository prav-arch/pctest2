#!/usr/bin/env python3
"""
Simple execution script for the Telecom Anomaly Detection System.
Run this to start analyzing your PCAP and HDF files for anomalies.

Usage:
    python3 run_system.py                    # Use default directories
    python3 run_system.py /path/to/folder    # Use specific folder
"""

import sys
import os
from telecom_anomaly_detector import TelecomAnomalyDetector

def main():
    """Run the telecom anomaly detection system."""
    print("Starting Telecom Anomaly Detection System...")
    print("=" * 60)
    
    # Check if folder path is provided as argument
    input_folder = None
    if len(sys.argv) > 1:
        input_folder = sys.argv[1]
        if not os.path.exists(input_folder):
            print(f"Error: Folder '{input_folder}' does not exist.")
            return 1
        print(f"Processing files from folder: {input_folder}")
    else:
        print("Using default configured directories")
    
    try:
        # Initialize the detector with optional folder
        detector = TelecomAnomalyDetector(input_folder=input_folder)
        
        # Run analysis on all available files
        detector.process_all_files()
        
        print("\n" + "=" * 60)
        print("Analysis completed successfully!")
        
    except Exception as e:
        print(f"Error running analysis: {str(e)}")
        if input_folder:
            print(f"Make sure the folder '{input_folder}' contains PCAP or HDF files.")
        else:
            print("Make sure you have PCAP or HDF files in the configured directories.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())