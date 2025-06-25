#!/bin/bash
# Production installation script

echo "Installing Telecom Anomaly Detection System..."

# Install Python dependencies
pip install scapy h5py scikit-learn numpy pandas streamlit

# Create directories
mkdir -p logs
mkdir -p models
mkdir -p data

# Set permissions
chmod +x quick_start.py
chmod +x run_system.py
chmod +x pcap_analyzer.py

echo "Installation complete!"
echo ""
echo "Quick start:"
echo "  python3 quick_start.py /path/to/your/data"
echo ""
echo "PCAP analysis:"
echo "  python3 pcap_analyzer.py /path/to/file.pcap"
echo ""
echo "Web interface:"
echo "  streamlit run app.py --server.port 5000"
