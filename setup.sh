#!/bin/bash
# Quick setup for production deployment

echo "Telecom Anomaly Detection System Setup"
echo "======================================"

# Install dependencies
echo "Installing Python dependencies..."
pip install scapy h5py scikit-learn numpy pandas streamlit

# Create directories
mkdir -p logs models data

# Set permissions
chmod +x run_system.py
chmod +x pcap_analyzer.py

echo ""
echo "Setup complete! Your system supports:"
echo "  PCAP files: .pcap, .cap"
echo "  HDF files: .hdf, .hdf5, .h5"
echo "  Log files: .txt, .log"
echo ""
echo "Production MAC addresses configured:"
echo "  RU: 6c:ad:ad:00:03:2a"
echo "  DU: 00:11:22:33:44:67"
echo ""
echo "Usage:"
echo "  python3 run_system.py /path/to/data"
echo "  python3 pcap_analyzer.py file.pcap"
echo "  streamlit run app.py --server.port 5000"
