#!/usr/bin/env python3
"""
Simple execution script for the Telecom Anomaly Detection System.
Run this to start analyzing your PCAP and HDF files for anomalies.
"""

import sys
import os
from telecom_anomaly_detector import TelecomAnomalyDetector

def main():
    """Run the telecom anomaly detection system."""
    print("Starting Telecom Anomaly Detection System...")
    print("=" * 60)
    
    try:
        # Initialize the detector
        detector = TelecomAnomalyDetector()
        
        # Run analysis on all available files
        detector.process_all_files()
        
        print("\n" + "=" * 60)
        print("Analysis completed successfully!")
        
    except Exception as e:
        print(f"Error running analysis: {str(e)}")
        print("Make sure you have PCAP or HDF files in the configured directories.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())