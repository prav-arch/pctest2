#!/bin/bash
# Linux Setup Script for Telecom Anomaly Detection System
# Run this script as root or with sudo permissions

set -e

echo "=========================================="
echo "Telecom Anomaly Detection System Setup"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root or with sudo"
    exit 1
fi

# Create Linux directory structure for telecom data
echo "Creating directory structure..."

# PCAP directories
mkdir -p /var/log/telecom/pcap
mkdir -p /opt/telecom/pcap
mkdir -p /data/telecom/pcap
mkdir -p /home/telecom/pcap
mkdir -p /usr/local/telecom/pcap
mkdir -p /tmp/telecom/pcap

# HDF directories
mkdir -p /var/log/telecom/hdf
mkdir -p /opt/telecom/hdf
mkdir -p /data/telecom/hdf
mkdir -p /home/telecom/hdf
mkdir -p /usr/local/telecom/hdf
mkdir -p /tmp/telecom/hdf

# Model and results directories
mkdir -p /var/lib/telecom/models
mkdir -p /var/log/telecom/results
mkdir -p /var/log/telecom

echo "Directory structure created successfully."

# Set appropriate permissions
echo "Setting permissions..."
chmod 755 /var/log/telecom
chmod 755 /var/lib/telecom
chmod 755 /opt/telecom
chmod 755 /data/telecom
chmod 755 /home/telecom
chmod 755 /usr/local/telecom
chmod 777 /tmp/telecom  # Temporary directory with wider permissions

echo "Permissions set successfully."

# Install Python dependencies
echo "Installing Python dependencies..."
python3 -m pip install --upgrade pip
python3 -m pip install scapy h5py scikit-learn numpy pandas

echo "Python dependencies installed."

# Create telecom user (optional)
if ! id "telecom" &>/dev/null; then
    echo "Creating telecom user..."
    useradd -r -s /bin/bash -d /home/telecom telecom
    chown -R telecom:telecom /home/telecom
fi

# Copy script files to system location
echo "Installing telecom anomaly detector..."
mkdir -p /opt/telecom/bin
cp telecom_anomaly_detector.py /opt/telecom/bin/
cp config.py /opt/telecom/bin/
cp linux_config.py /opt/telecom/bin/
cp utils.py /opt/telecom/bin/
chmod +x /opt/telecom/bin/telecom_anomaly_detector.py

# Create production wrapper script
cat > /opt/telecom/bin/telecom-detector-linux << 'EOF'
#!/bin/bash
# Production Linux wrapper for Telecom Anomaly Detector
cd /opt/telecom/bin
export PYTHONPATH="/opt/telecom/bin:$PYTHONPATH"
python3 -c "
import sys
sys.path.insert(0, '/opt/telecom/bin')
from telecom_anomaly_detector import TelecomAnomalyDetector, main
from linux_config import LinuxConfig

# Override config with Linux production settings
class LinuxTelecomAnomalyDetector(TelecomAnomalyDetector):
    def __init__(self):
        super().__init__()
        self.config = LinuxConfig()  # Use production Linux config

if __name__ == '__main__':
    import telecom_anomaly_detector
    telecom_anomaly_detector.TelecomAnomalyDetector = LinuxTelecomAnomalyDetector
    main()
"
EOF

chmod +x /opt/telecom/bin/telecom-detector-linux

# Create symlinks for easy execution
ln -sf /opt/telecom/bin/telecom_anomaly_detector.py /usr/local/bin/telecom-detector
ln -sf /opt/telecom/bin/telecom-detector-linux /usr/local/bin/telecom-detector-production

echo "Installation completed successfully!"

echo ""
echo "=========================================="
echo "Setup Complete"
echo "=========================================="
echo "Directory structure:"
echo "  PCAP files: /var/log/telecom/pcap, /opt/telecom/pcap, /data/telecom/pcap"
echo "  HDF files: /var/log/telecom/hdf, /opt/telecom/hdf, /data/telecom/hdf"
echo "  Models: /var/lib/telecom/models"
echo "  Logs: /var/log/telecom/"
echo ""
echo "Usage:"
echo "  Development mode: telecom-detector"
echo "  Production mode: telecom-detector-production"
echo "  Direct execution: python3 /opt/telecom/bin/telecom_anomaly_detector.py"
echo ""
echo "Make sure to place your PCAP and HDF files in the appropriate directories."