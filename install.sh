#!/bin/bash
# Automated installation script

echo "Telecom Anomaly Detection System - Production Setup"
echo "=================================================="

# Install Python dependencies
echo "Installing Python dependencies..."
pip install scapy h5py scikit-learn numpy pandas streamlit

# Create directories
echo "Creating directories..."
mkdir -p logs models data

# Set executable permissions  
chmod +x run_system.py
chmod +x pcap_analyzer.py

echo ""
echo "Installation complete!"
echo ""
echo "Quick start:"
echo "  python3 run_system.py /path/to/your/data"
echo ""
echo "PCAP analysis:"
echo "  python3 pcap_analyzer.py /path/to/file.pcap"
echo ""
echo "Web interface:"
echo "  streamlit run app.py --server.port 5000"
echo ""
echo "Your production MAC addresses are pre-configured:"
echo "  RU: 6c:ad:ad:00:03:2a"
echo "  DU: 00:11:22:33:44:67"
