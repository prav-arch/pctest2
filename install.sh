#!/bin/bash
# Enhanced production installation

echo "Telecom Anomaly Detection - Enhanced Production Setup"
echo "====================================================="

# Install dependencies
pip install scapy h5py scikit-learn numpy pandas streamlit

# Create directories
mkdir -p logs models data

# Set permissions
chmod +x run_system.py pcap_analyzer.py

echo ""
echo "Enhanced features:"
echo "  ✓ Production logging for HDF file diagnostics"
echo "  ✓ Custom path support (searches only specified folder)"
echo "  ✓ Enhanced error reporting and file discovery"
echo "  ✓ Support for .hdf, .hdf5, .h5 extensions"
echo ""
echo "Usage:"
echo "  python3 run_system.py /production/data  # Custom path"
echo "  python3 run_system.py                   # Default dirs"
echo ""
echo "MAC addresses configured:"
echo "  RU: 6c:ad:ad:00:03:2a"
echo "  DU: 00:11:22:33:44:67"
